use super::hash::Hash256;
use super::transaction::{SerError, Transaction};

pub const HEADER_SIZE: usize = 156;

/// Block header — fixed 156 bytes, little-endian integers.
///
/// Layout:
///   version(4) + height(8) + prev_block_id(32) + timestamp(8) +
///   difficulty_target(32) + nonce(8) + tx_root(32) + state_root(32) = 156
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub prev_block_id: Hash256,
    pub timestamp: u64,
    /// Full 256-bit target (big-endian for comparison, raw bytes in header).
    pub difficulty_target: Hash256,
    pub nonce: u64,
    pub tx_root: Hash256,
    pub state_root: Hash256,
}

impl BlockHeader {
    /// Serialize to exactly 156 bytes (little-endian integers, raw bytes for hashes).
    pub fn serialize(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.version.to_le_bytes());
        buf[4..12].copy_from_slice(&self.height.to_le_bytes());
        buf[12..44].copy_from_slice(self.prev_block_id.as_bytes());
        buf[44..52].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[52..84].copy_from_slice(self.difficulty_target.as_bytes());
        buf[84..92].copy_from_slice(&self.nonce.to_le_bytes());
        buf[92..124].copy_from_slice(self.tx_root.as_bytes());
        buf[124..156].copy_from_slice(self.state_root.as_bytes());
        buf
    }

    /// Deserialize from exactly 156 bytes.
    pub fn deserialize(data: &[u8; HEADER_SIZE]) -> Self {
        BlockHeader {
            version: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            height: u64::from_le_bytes(data[4..12].try_into().unwrap()),
            prev_block_id: {
                let mut h = [0u8; 32];
                h.copy_from_slice(&data[12..44]);
                Hash256(h)
            },
            timestamp: u64::from_le_bytes(data[44..52].try_into().unwrap()),
            difficulty_target: {
                let mut h = [0u8; 32];
                h.copy_from_slice(&data[52..84]);
                Hash256(h)
            },
            nonce: u64::from_le_bytes(data[84..92].try_into().unwrap()),
            tx_root: {
                let mut h = [0u8; 32];
                h.copy_from_slice(&data[92..124]);
                Hash256(h)
            },
            state_root: {
                let mut h = [0u8; 32];
                h.copy_from_slice(&data[124..156]);
                Hash256(h)
            },
        }
    }

    /// Block ID = SHA-256(header_bytes). NOT Argon2id.
    pub fn block_id(&self) -> Hash256 {
        Hash256::sha256(&self.serialize())
    }
}

/// A full block: header + transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Serialize block: header(156) || tx_count(u32 LE) || transactions...
    /// Returns Err if any transaction has fields exceeding wire limits.
    pub fn serialize(&self) -> Result<Vec<u8>, SerError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.header.serialize());
        buf.extend_from_slice(&(self.transactions.len() as u32).to_le_bytes());
        for tx in &self.transactions {
            buf.extend_from_slice(&tx.serialize()?);
        }
        Ok(buf)
    }

    /// Deserialize a full block from bytes.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), SerError> {
        if data.len() < HEADER_SIZE + 4 {
            return Err(SerError::UnexpectedEof);
        }

        let header_bytes: &[u8; HEADER_SIZE] = data[..HEADER_SIZE]
            .try_into()
            .map_err(|_| SerError::UnexpectedEof)?;
        let header = BlockHeader::deserialize(header_bytes);
        let mut pos = HEADER_SIZE;

        let tx_count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        // P1-7: Cap allocation to prevent OOM on untrusted input
        let max_txs = super::MAX_BLOCK_SIZE / super::MIN_TX_SIZE;
        if tx_count > max_txs {
            return Err(SerError::InvalidData(format!(
                "tx_count {} exceeds maximum {}",
                tx_count, max_txs
            )));
        }

        let mut transactions = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            let (tx, consumed) = Transaction::deserialize(&data[pos..])?;
            transactions.push(tx);
            pos += consumed;
        }

        Ok((
            Block {
                header,
                transactions,
            },
            pos,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            height: 0,
            prev_block_id: Hash256::ZERO,
            timestamp: 1700000000,
            difficulty_target: Hash256::ZERO,
            nonce: 42,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        }
    }

    #[test]
    fn test_header_serialize_size() {
        let header = test_header();
        let bytes = header.serialize();
        assert_eq!(bytes.len(), 156);
    }

    #[test]
    fn test_header_roundtrip() {
        let header = test_header();
        let bytes = header.serialize();
        let header2 = BlockHeader::deserialize(&bytes);
        assert_eq!(header, header2);
    }

    #[test]
    fn test_little_endian_encoding() {
        let header = BlockHeader {
            version: 1,
            height: 0,
            prev_block_id: Hash256::ZERO,
            timestamp: 0,
            difficulty_target: Hash256::ZERO,
            nonce: 0,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        };
        let bytes = header.serialize();
        // Version 1 in little-endian: [1, 0, 0, 0]
        assert_eq!(&bytes[0..4], &[1, 0, 0, 0]);
    }

    #[test]
    fn test_block_id_deterministic() {
        let header = test_header();
        assert_eq!(header.block_id(), header.block_id());
    }

    #[test]
    fn test_block_id_changes_with_nonce() {
        let mut h1 = test_header();
        let mut h2 = test_header();
        h1.nonce = 1;
        h2.nonce = 2;
        assert_ne!(h1.block_id(), h2.block_id());
    }
}
