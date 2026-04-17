//! Authenticated RPC output lookup (v1.4.2 Fix 1).
//!
//! Defends the wallet against malicious or compromised RPC endpoints that lie
//! about UTXO `value` or `script` fields. Every wallet spend path — normal
//! send, HtlcClaim / HtlcReclaim, covenant spends — routes through
//! [`authenticated_output_lookup`]. The helper re-fetches the full funding
//! transaction via `get_transaction`, deserializes it locally under a strict
//! parse (no trailing bytes), verifies its hash against the requested txid,
//! and enforces byte-equality between the output's script and a locally
//! reconstructed `expected_script`.
//!
//! Once the strict-parse + txid check passes, the tx serialization is
//! self-authenticating against the requested txid; the `value` and `script`
//! fields come from bytes the RPC cannot forge without breaking SHA-256.
//!
//! ## Residual trust (documented in CHANGELOG)
//! With this fix a malicious RPC can still:
//! - Omit UTXOs (availability attack — wallet shows lower balance)
//! - Return already-spent outpoints (wallet discovers at broadcast time)
//! - Lie about confirmation depth / tip height
//! - Lie about coinbase maturity unless block height is authenticated separately
//!
//! Those are availability / UX issues, not theft. Closing them fully requires
//! SPV-style inclusion proofs and a locally-maintained header chain, which is
//! out of scope for this release.

use crate::types::transaction::Transaction;
use crate::types::Hash256;

/// Errors produced by authenticated output lookup.
///
/// The `TxIdMismatch`, `TrailingBytes`, and `ScriptMismatch` variants are
/// cryptographically diagnostic: each indicates the RPC returned data that
/// a correctly-functioning endpoint could not have returned for the requested
/// txid. Callers should surface a clear message distinguishing these from
/// a transport error and must not retry automatically against the same
/// endpoint.
#[derive(Debug, Clone)]
pub enum AuthError {
    /// Underlying RPC transport / JSON-RPC error (network, HTTP, JSON parse).
    Rpc(String),
    /// `get_transaction` response did not contain a `tx_hex` string field.
    MissingTxHex,
    /// `tx_hex` was not valid hexadecimal.
    InvalidHex(String),
    /// Transaction deserialization failed.
    Deserialize(String),
    /// Transaction deserialized but trailing bytes remain
    /// (valid-prefix-plus-garbage attack).
    TrailingBytes { consumed: usize, total: usize },
    /// Computed tx_id of the deserialized transaction did not equal the
    /// requested txid.
    TxIdMismatch {
        requested: Hash256,
        computed: Hash256,
    },
    /// Requested output index is out of bounds for the authenticated tx.
    OutputIndexOutOfBounds { index: u32, n_outputs: usize },
    /// Output script did not byte-equal the locally-reconstructed
    /// `expected_script`.
    ScriptMismatch { expected: Vec<u8>, actual: Vec<u8> },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Rpc(e) => write!(f, "RPC error: {}", e),
            AuthError::MissingTxHex => {
                write!(f, "RPC response missing tx_hex field")
            }
            AuthError::InvalidHex(e) => {
                write!(f, "RPC returned invalid hex for tx_hex: {}", e)
            }
            AuthError::Deserialize(e) => write!(
                f,
                "RPC returned transaction data that failed to deserialize: {} \
                 — endpoint may be malicious or compromised",
                e
            ),
            AuthError::TrailingBytes { consumed, total } => write!(
                f,
                "RPC returned transaction data with {} trailing byte(s) after \
                 a valid transaction (consumed {} of {}) — endpoint may be \
                 malicious or compromised",
                total.saturating_sub(*consumed),
                consumed,
                total
            ),
            AuthError::TxIdMismatch {
                requested,
                computed,
            } => write!(
                f,
                "RPC returned transaction data that does not match requested \
                 txid — endpoint may be malicious or compromised\n  \
                 requested: {}\n  computed:  {}",
                requested, computed
            ),
            AuthError::OutputIndexOutOfBounds { index, n_outputs } => write!(
                f,
                "output index {} out of bounds (authenticated tx has {} output(s))",
                index, n_outputs
            ),
            AuthError::ScriptMismatch { expected, actual } => write!(
                f,
                "authenticated output script does not match locally-reconstructed \
                 expected script — endpoint may be malicious or compromised\n  \
                 expected ({} bytes): {}\n  actual   ({} bytes): {}",
                expected.len(),
                hex::encode(expected),
                actual.len(),
                hex::encode(actual),
            ),
        }
    }
}

impl std::error::Error for AuthError {}

/// Authenticate a transaction-hex payload against a requested txid, an output
/// index, and (optionally) an expected output script. Pure — no I/O.
///
/// Verification, in order:
/// 1. **Strict parse:** [`Transaction::deserialize`] succeeds AND the returned
///    `consumed` byte count equals `raw.len()`. Rejects valid-prefix-plus-garbage.
/// 2. **Txid match:** recomputed `tx_id()` of the deserialized transaction
///    byte-equals `requested_txid`.
/// 3. **Output in bounds:** `output_index < tx.outputs.len()`.
/// 4. **Script match (if provided):** `tx.outputs[output_index].script`
///    byte-equals `expected_script`.
///
/// Exposed separately from [`authenticated_output_lookup`] so unit tests and
/// fuzz targets can exercise the authentication logic without a live RPC.
pub fn authenticate_tx_hex(
    raw: &[u8],
    requested_txid: Hash256,
    output_index: u32,
    expected_script: Option<&[u8]>,
) -> Result<(u64, Vec<u8>), AuthError> {
    let (tx, consumed) = Transaction::deserialize(raw)
        .map_err(|e| AuthError::Deserialize(format!("{:?}", e)))?;

    if consumed != raw.len() {
        return Err(AuthError::TrailingBytes {
            consumed,
            total: raw.len(),
        });
    }

    let computed = tx
        .tx_id()
        .map_err(|e| AuthError::Deserialize(format!("tx_id computation failed: {:?}", e)))?;
    if computed != requested_txid {
        return Err(AuthError::TxIdMismatch {
            requested: requested_txid,
            computed,
        });
    }

    let n_outputs = tx.outputs.len();
    let output = tx
        .outputs
        .get(output_index as usize)
        .ok_or(AuthError::OutputIndexOutOfBounds {
            index: output_index,
            n_outputs,
        })?;

    if let Some(expected) = expected_script {
        if output.script.as_slice() != expected {
            return Err(AuthError::ScriptMismatch {
                expected: expected.to_vec(),
                actual: output.script.clone(),
            });
        }
    }

    Ok((output.value, output.script.clone()))
}

/// Fetch a transaction output via RPC and authenticate it end-to-end.
///
/// Uses the `get_transaction` JSON-RPC method. See [`authenticate_tx_hex`]
/// for authentication semantics.
pub fn authenticated_output_lookup(
    rpc_url: &str,
    requested_txid: Hash256,
    output_index: u32,
    expected_script: Option<&[u8]>,
) -> Result<(u64, Vec<u8>), AuthError> {
    let response = crate::rpc::rpc_call(
        rpc_url,
        "get_transaction",
        serde_json::json!({"hash": hex::encode(requested_txid.as_bytes())}),
    )
    .map_err(AuthError::Rpc)?;

    let tx_hex_str = response
        .get("tx_hex")
        .and_then(|v| v.as_str())
        .ok_or(AuthError::MissingTxHex)?;

    let raw = hex::decode(tx_hex_str).map_err(|e| AuthError::InvalidHex(e.to_string()))?;

    authenticate_tx_hex(&raw, requested_txid, output_index, expected_script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::transaction::{OutPoint, TxInput, TxOutput, TxWitness};

    /// Build a minimal single-input, single-output transaction with the given
    /// output value and script. Returns (tx, raw, txid).
    fn make_tx(value: u64, script: Vec<u8>) -> (Transaction, Vec<u8>, Hash256) {
        let tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput {
                value,
                script,
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        let raw = tx.serialize().expect("serialize");
        let txid = tx.tx_id().expect("tx_id");
        (tx, raw, txid)
    }

    #[test]
    fn authenticates_correct_tx() {
        let script = b"locked-script".to_vec();
        let (_tx, raw, txid) = make_tx(1_000_000, script.clone());
        let (value, got_script) =
            authenticate_tx_hex(&raw, txid, 0, Some(&script)).expect("authenticates");
        assert_eq!(value, 1_000_000);
        assert_eq!(got_script, script);
    }

    #[test]
    fn rejects_tx_with_trailing_garbage() {
        let (_tx, mut raw, txid) = make_tx(1_000_000, b"script".to_vec());
        raw.extend_from_slice(b"\x00\xff\xde\xad"); // trailing garbage
        let err = authenticate_tx_hex(&raw, txid, 0, None).expect_err("must reject");
        assert!(
            matches!(err, AuthError::TrailingBytes { .. }),
            "expected TrailingBytes, got {:?}",
            err
        );
    }

    #[test]
    fn rejects_txid_mismatch() {
        let (_tx, raw, _txid) = make_tx(1_000_000, b"script".to_vec());
        let wrong = Hash256([0xaa; 32]);
        let err = authenticate_tx_hex(&raw, wrong, 0, None).expect_err("must reject");
        assert!(
            matches!(err, AuthError::TxIdMismatch { .. }),
            "expected TxIdMismatch, got {:?}",
            err
        );
    }

    #[test]
    fn rejects_script_mismatch() {
        let script = b"real-script".to_vec();
        let (_tx, raw, txid) = make_tx(1_000_000, script);
        let err = authenticate_tx_hex(&raw, txid, 0, Some(b"different-script"))
            .expect_err("must reject");
        assert!(
            matches!(err, AuthError::ScriptMismatch { .. }),
            "expected ScriptMismatch, got {:?}",
            err
        );
    }

    #[test]
    fn rejects_output_index_out_of_bounds() {
        let (_tx, raw, txid) = make_tx(1_000_000, b"s".to_vec());
        let err = authenticate_tx_hex(&raw, txid, 5, None).expect_err("must reject");
        assert!(
            matches!(err, AuthError::OutputIndexOutOfBounds { index: 5, n_outputs: 1 }),
            "expected OutputIndexOutOfBounds, got {:?}",
            err
        );
    }

    #[test]
    fn rejects_malformed_tx_hex() {
        let err = authenticate_tx_hex(&[0xff; 2], Hash256::ZERO, 0, None).expect_err("reject");
        assert!(
            matches!(err, AuthError::Deserialize(_)),
            "expected Deserialize, got {:?}",
            err
        );
    }

    #[test]
    fn empty_input_rejected_cleanly() {
        let err = authenticate_tx_hex(&[], Hash256::ZERO, 0, None).expect_err("reject");
        assert!(
            matches!(err, AuthError::Deserialize(_)),
            "expected Deserialize for empty input, got {:?}",
            err
        );
    }

    /// Understated-value test: an attacker controlling RPC cannot cause the
    /// authenticated value to be less than the actual on-chain value; the
    /// output value comes from the deserialized tx bytes, which are committed
    /// to by the txid. A lower value would change the tx_id and be caught by
    /// the tx_id match check.
    ///
    /// This test verifies that no path in `authenticate_tx_hex` reads a
    /// caller-supplied value — it's always taken from the parsed output.
    #[test]
    fn authenticated_value_comes_from_deserialized_tx() {
        let script = b"script".to_vec();
        let (_tx, raw, txid) = make_tx(999, script.clone());
        let (value, _) = authenticate_tx_hex(&raw, txid, 0, Some(&script)).expect("ok");
        assert_eq!(value, 999, "value must come from the parsed output");
    }

    #[test]
    fn multi_output_indexing() {
        let tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![
                TxOutput {
                    value: 111,
                    script: b"s0".to_vec(),
                    datum: None,
                    datum_hash: None,
                },
                TxOutput {
                    value: 222,
                    script: b"s1".to_vec(),
                    datum: None,
                    datum_hash: None,
                },
                TxOutput {
                    value: 333,
                    script: b"s2".to_vec(),
                    datum: None,
                    datum_hash: None,
                },
            ],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        let raw = tx.serialize().unwrap();
        let txid = tx.tx_id().unwrap();
        let (v, s) = authenticate_tx_hex(&raw, txid, 1, Some(b"s1")).unwrap();
        assert_eq!(v, 222);
        assert_eq!(s, b"s1");
    }

    /// Suppress an unused import warning for OutPoint (kept because future
    /// callers of this test module will need it).
    #[allow(dead_code)]
    fn _touch_outpoint() -> OutPoint {
        OutPoint {
            tx_id: Hash256::ZERO,
            output_index: 0,
        }
    }
}
