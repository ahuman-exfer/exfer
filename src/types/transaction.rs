use super::hash::Hash256;
use super::{DS_ADDR, DS_SIG, DS_TX, DS_WTXID};

/// Serialization errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerError {
    UnexpectedEof,
    InvalidData(String),
    InvalidLength,
}

impl std::fmt::Display for SerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SerError::UnexpectedEof => write!(f, "unexpected end of data"),
            SerError::InvalidData(msg) => write!(f, "invalid data: {}", msg),
            SerError::InvalidLength => write!(f, "list count exceeds protocol limit"),
        }
    }
}

impl std::error::Error for SerError {}

// ── VarBytes helpers (u16 LE length prefix) ──

fn serialize_varbytes(data: &[u8]) -> Result<Vec<u8>, SerError> {
    let len: u16 = u16::try_from(data.len()).map_err(|_| {
        SerError::InvalidData(format!("varbytes length {} exceeds u16::MAX", data.len()))
    })?;
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
    Ok(buf)
}

fn deserialize_varbytes(data: &[u8]) -> Result<(&[u8], usize), SerError> {
    if data.len() < 2 {
        return Err(SerError::UnexpectedEof);
    }
    let len = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
    if data.len() < 2 + len {
        return Err(SerError::UnexpectedEof);
    }
    Ok((&data[2..2 + len], 2 + len))
}

// ── TxInput (body only — no witness) ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInput {
    pub prev_tx_id: Hash256,
    pub output_index: u32,
}

impl TxInput {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36);
        buf.extend_from_slice(self.prev_tx_id.as_bytes());
        buf.extend_from_slice(&self.output_index.to_le_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), SerError> {
        if data.len() < 36 {
            return Err(SerError::UnexpectedEof);
        }
        let mut tx_id_bytes = [0u8; 32];
        tx_id_bytes.copy_from_slice(&data[0..32]);
        let output_index = u32::from_le_bytes(data[32..36].try_into().unwrap());
        Ok((
            TxInput {
                prev_tx_id: Hash256(tx_id_bytes),
                output_index,
            },
            36,
        ))
    }
}

// ── TxOutput ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    pub value: u64,
    /// Script bytes (Phase 1: 32-byte pubkey hash).
    pub script: Vec<u8>,
    /// Optional datum (Phase 1: always None).
    pub datum: Option<Vec<u8>>,
    /// Optional datum hash (Phase 1: always None).
    pub datum_hash: Option<Hash256>,
}

impl TxOutput {
    /// Compute a Phase 1 pubkey hash script from a public key.
    pub fn pubkey_hash_from_key(pubkey: &[u8; 32]) -> Hash256 {
        Hash256::domain_hash(DS_ADDR, pubkey)
    }

    /// Create a Phase 1 output locked to a pubkey hash.
    pub fn new_p2pkh(value: u64, pubkey: &[u8; 32]) -> Self {
        let hash = Self::pubkey_hash_from_key(pubkey);
        TxOutput {
            value,
            script: hash.0.to_vec(),
            datum: None,
            datum_hash: None,
        }
    }

    /// Serialize output (canonical form, used in body and for state root leaf value).
    pub fn serialize(&self) -> Result<Vec<u8>, SerError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.value.to_le_bytes());
        buf.extend_from_slice(&serialize_varbytes(&self.script)?);
        match &self.datum {
            Some(d) => {
                buf.push(1);
                buf.extend_from_slice(&serialize_varbytes(d)?);
            }
            None => buf.push(0),
        }
        match &self.datum_hash {
            Some(h) => {
                buf.push(1);
                buf.extend_from_slice(h.as_bytes());
            }
            None => buf.push(0),
        }
        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), SerError> {
        if data.len() < 8 {
            return Err(SerError::UnexpectedEof);
        }
        let mut pos = 0;
        let value = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let (script_bytes, consumed) = deserialize_varbytes(&data[pos..])?;
        let script = script_bytes.to_vec();
        pos += consumed;

        if pos >= data.len() {
            return Err(SerError::UnexpectedEof);
        }
        let has_datum = data[pos];
        pos += 1;
        if has_datum > 1 {
            return Err(SerError::InvalidData(format!(
                "non-canonical has_datum flag: {} (expected 0 or 1)",
                has_datum
            )));
        }
        let datum = if has_datum == 1 {
            let (d, consumed) = deserialize_varbytes(&data[pos..])?;
            if d.len() > crate::types::MAX_DATUM_SIZE {
                return Err(SerError::InvalidData(format!(
                    "datum size {} exceeds maximum {}",
                    d.len(),
                    crate::types::MAX_DATUM_SIZE
                )));
            }
            pos += consumed;
            Some(d.to_vec())
        } else {
            None
        };

        if pos >= data.len() {
            return Err(SerError::UnexpectedEof);
        }
        let has_datum_hash = data[pos];
        pos += 1;
        if has_datum_hash > 1 {
            return Err(SerError::InvalidData(format!(
                "non-canonical has_datum_hash flag: {} (expected 0 or 1)",
                has_datum_hash
            )));
        }
        let datum_hash = if has_datum_hash == 1 {
            if data.len() < pos + 32 {
                return Err(SerError::UnexpectedEof);
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            Some(Hash256(h))
        } else {
            None
        };

        Ok((
            TxOutput {
                value,
                script,
                datum,
                datum_hash,
            },
            pos,
        ))
    }
}

// ── TxWitness ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxWitness {
    /// Witness data (Phase 1: pubkey(32) || signature(64) = 96 bytes).
    pub witness: Vec<u8>,
    /// Optional redeemer (Phase 1: always None).
    pub redeemer: Option<Vec<u8>>,
}

impl TxWitness {
    pub fn serialize(&self) -> Result<Vec<u8>, SerError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&serialize_varbytes(&self.witness)?);
        match &self.redeemer {
            Some(r) => {
                buf.push(1);
                buf.extend_from_slice(&serialize_varbytes(r)?);
            }
            None => buf.push(0),
        }
        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), SerError> {
        let mut pos = 0;
        let (witness_bytes, consumed) = deserialize_varbytes(&data[pos..])?;
        let witness = witness_bytes.to_vec();
        pos += consumed;

        if pos >= data.len() {
            return Err(SerError::UnexpectedEof);
        }
        let has_redeemer = data[pos];
        pos += 1;
        if has_redeemer > 1 {
            return Err(SerError::InvalidData(format!(
                "non-canonical has_redeemer flag: {} (expected 0 or 1)",
                has_redeemer
            )));
        }
        let redeemer = if has_redeemer == 1 {
            let (r, consumed) = deserialize_varbytes(&data[pos..])?;
            if r.len() > crate::types::MAX_REDEEMER_SIZE {
                return Err(SerError::InvalidData(format!(
                    "redeemer size {} exceeds maximum {}",
                    r.len(),
                    crate::types::MAX_REDEEMER_SIZE
                )));
            }
            pos += consumed;
            Some(r.to_vec())
        } else {
            None
        };

        Ok((TxWitness { witness, redeemer }, pos))
    }
}

// ── Transaction ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub witnesses: Vec<TxWitness>,
}

impl Transaction {
    /// Serialize tx_header: input_count(u16 LE) + output_count(u16 LE) = 4 bytes.
    pub fn serialize_header(&self) -> Result<Vec<u8>, SerError> {
        let input_count: u16 = u16::try_from(self.inputs.len()).map_err(|_| {
            SerError::InvalidData(format!(
                "input count {} exceeds u16::MAX",
                self.inputs.len()
            ))
        })?;
        let output_count: u16 = u16::try_from(self.outputs.len()).map_err(|_| {
            SerError::InvalidData(format!(
                "output count {} exceeds u16::MAX",
                self.outputs.len()
            ))
        })?;
        let mut buf = Vec::with_capacity(4);
        buf.extend_from_slice(&input_count.to_le_bytes());
        buf.extend_from_slice(&output_count.to_le_bytes());
        Ok(buf)
    }

    /// Serialize tx_body: inputs[] + outputs[] (no witnesses).
    pub fn serialize_body(&self) -> Result<Vec<u8>, SerError> {
        let mut buf = Vec::new();
        for input in &self.inputs {
            buf.extend_from_slice(&input.serialize());
        }
        for output in &self.outputs {
            buf.extend_from_slice(&output.serialize()?);
        }
        Ok(buf)
    }

    /// The signing bytes = tx_header || tx_body (same bytes used for TxId, without domain separator).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, SerError> {
        let mut buf = self.serialize_header()?;
        buf.extend_from_slice(&self.serialize_body()?);
        Ok(buf)
    }

    /// TxId = SHA-256("EXFER-TX" || tx_header || tx_body). Witnesses EXCLUDED.
    /// Returns Err if field sizes exceed u16::MAX.
    pub fn tx_id(&self) -> Result<Hash256, SerError> {
        Ok(Hash256::domain_hash(DS_TX, &self.signing_bytes()?))
    }

    /// Witness-committed transaction hash = SHA-256("EXFER-WTXID" || full serialization).
    /// Includes witnesses. Used in block tx_root to prevent block malleability.
    /// Returns Err if field sizes exceed u16::MAX.
    pub fn wtx_id(&self) -> Result<Hash256, SerError> {
        Ok(Hash256::domain_hash(DS_WTXID, &self.serialize()?))
    }

    /// Build the message that is signed/verified:
    /// `"EXFER-SIG" || genesis_block_id(32) || signing_bytes`.
    ///
    /// The genesis block ID binds signatures to this chain, preventing
    /// cross-chain transaction replay.
    /// Returns Err if field sizes exceed u16::MAX.
    pub fn sig_message(&self) -> Result<Vec<u8>, SerError> {
        let signing = self.signing_bytes()?;
        let genesis_id = &*crate::genesis::GENESIS_BLOCK_ID;
        let mut msg = Vec::with_capacity(DS_SIG.len() + 32 + signing.len());
        msg.extend_from_slice(DS_SIG);
        msg.extend_from_slice(genesis_id.as_bytes());
        msg.extend_from_slice(&signing);
        Ok(msg)
    }

    /// Full serialization: tx_header + tx_body + tx_witnesses.
    pub fn serialize(&self) -> Result<Vec<u8>, SerError> {
        let mut buf = self.serialize_header()?;
        buf.extend_from_slice(&self.serialize_body()?);
        for witness in &self.witnesses {
            buf.extend_from_slice(&witness.serialize()?);
        }
        Ok(buf)
    }

    /// Deserialize a full transaction.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), SerError> {
        if data.len() < 4 {
            return Err(SerError::UnexpectedEof);
        }
        let mut pos = 0;

        let input_count = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let output_count = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;

        // Reject impossible counts before allocating.
        // Min sizes: TxInput=36, TxOutput=12, TxWitness=3 (1 per input).
        let remaining = data.len().saturating_sub(pos);
        let min_needed = input_count
            .saturating_mul(36)
            .saturating_add(output_count.saturating_mul(12))
            .saturating_add(input_count.saturating_mul(3));
        if remaining < min_needed {
            return Err(SerError::UnexpectedEof);
        }

        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let (input, consumed) = TxInput::deserialize(&data[pos..])?;
            inputs.push(input);
            pos += consumed;
        }

        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let (output, consumed) = TxOutput::deserialize(&data[pos..])?;
            outputs.push(output);
            pos += consumed;
        }

        let mut witnesses = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let (witness, consumed) = TxWitness::deserialize(&data[pos..])?;
            witnesses.push(witness);
            pos += consumed;
        }

        Ok((
            Transaction {
                inputs,
                outputs,
                witnesses,
            },
            pos,
        ))
    }

    /// Returns true if this is a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prev_tx_id == Hash256::ZERO
    }

    /// Total serialized size in bytes. Returns None if fields exceed wire limits.
    pub fn serialized_size(&self) -> Result<usize, SerError> {
        Ok(self.serialize()?.len())
    }
}

/// An outpoint uniquely identifies a UTXO.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    pub tx_id: Hash256,
    pub output_index: u32,
}

impl OutPoint {
    pub fn new(tx_id: Hash256, output_index: u32) -> Self {
        OutPoint {
            tx_id,
            output_index,
        }
    }

    #[allow(dead_code)]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36);
        buf.extend_from_slice(self.tx_id.as_bytes());
        buf.extend_from_slice(&self.output_index.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_p1_coinbase() -> Transaction {
        let pubkey = [1u8; 32];
        Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(10_000_000_000, &pubkey)],
            witnesses: vec![TxWitness {
                witness: vec![], // coinbase witness is empty
                redeemer: None,
            }],
        }
    }

    #[test]
    fn test_tx_id_deterministic() {
        let tx = make_p1_coinbase();
        assert_eq!(tx.tx_id().unwrap(), tx.tx_id().unwrap());
    }

    #[test]
    fn test_tx_id_excludes_witness() {
        let mut tx1 = make_p1_coinbase();
        let mut tx2 = make_p1_coinbase();
        tx1.witnesses[0].witness = vec![0xAA; 96];
        tx2.witnesses[0].witness = vec![0xBB; 96];
        assert_eq!(tx1.tx_id().unwrap(), tx2.tx_id().unwrap());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let tx = make_p1_coinbase();
        let bytes = tx.serialize().unwrap();
        let (tx2, consumed) = Transaction::deserialize(&bytes).unwrap();
        assert_eq!(tx, tx2);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_is_coinbase() {
        let tx = make_p1_coinbase();
        assert!(tx.is_coinbase());
    }

    #[test]
    fn test_not_coinbase() {
        let tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::sha256(b"something"),
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(1000, &[2u8; 32])],
            witnesses: vec![TxWitness {
                witness: vec![0; 96],
                redeemer: None,
            }],
        };
        assert!(!tx.is_coinbase());
    }

    #[test]
    fn test_output_with_datum() {
        let out = TxOutput {
            value: 1000,
            script: vec![0x42; 32],
            datum: Some(vec![0xDE, 0xAD]),
            datum_hash: None,
        };
        let bytes = out.serialize().unwrap();
        let (out2, consumed) = TxOutput::deserialize(&bytes).unwrap();
        assert_eq!(out, out2);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_output_with_datum_hash() {
        let out = TxOutput {
            value: 1000,
            script: vec![0x42; 32],
            datum: None,
            datum_hash: Some(Hash256::sha256(b"test")),
        };
        let bytes = out.serialize().unwrap();
        let (out2, consumed) = TxOutput::deserialize(&bytes).unwrap();
        assert_eq!(out, out2);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_little_endian_integers() {
        let input = TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 1,
        };
        let bytes = input.serialize();
        // output_index 1 in LE: [1, 0, 0, 0]
        assert_eq!(&bytes[32..36], &[1, 0, 0, 0]);
    }

    #[test]
    fn test_pubkey_hash() {
        let pk = [0x42u8; 32];
        let h = TxOutput::pubkey_hash_from_key(&pk);
        let expected = Hash256::domain_hash(DS_ADDR, &pk);
        assert_eq!(h, expected);
    }
}
