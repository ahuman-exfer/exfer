//! Hash Time-Locked Contract (HTLC) for atomic swaps.
//!
//! Two spending paths:
//! 1. **Hash path**: receiver reveals preimage + signs (before timeout)
//! 2. **Timeout path**: sender reclaims after block height exceeds timeout

use serde::{Deserialize, Serialize};

use super::builder::ScriptBuilder;
use crate::script::ast::{Combinator, Program};
use crate::script::serialize::{deserialize_program, serialize_program};
use crate::script::value::Value;
use crate::types::hash::Hash256;

/// Create an HTLC script.
///
/// **Hash path** witness: `[Left(Unit)][preimage_bytes][msg][sig_receiver]`
/// **Timeout path** witness: `[Right(Unit)][msg][sig_sender]`
pub fn htlc(
    sender_key: &[u8; 32],
    receiver_key: &[u8; 32],
    hash_lock: &Hash256,
    timeout_height: u64,
) -> Program {
    let mut b = ScriptBuilder::new();

    // Hash path: hash_eq(lock) AND sig_check(receiver)
    let hash_check = b.hash_eq(hash_lock);
    let receiver_check = b.sig_check(receiver_key);
    let hash_path = b.and(hash_check, receiver_check);

    // Timeout path: height_gt(timeout) AND sig_check(sender)
    let timeout_check = b.height_gt(timeout_height);
    let sender_check = b.sig_check(sender_key);
    let timeout_path = b.and(timeout_check, sender_check);

    // Dispatch based on witness selector
    let selector = b.witness();
    let case_node = b.case(hash_path, timeout_path);
    let _root = b.comp(selector, case_node);
    b.build()
}

// ---------------------------------------------------------------------------
// Shared HTLC observability types.
//
// Canonical wire shapes for any tooling that exposes HTLC lifecycle data
// over JSON-RPC — wallet daemons, indexers, block explorers, audit pipelines.
// Living in the upstream crate is what lets independent observers agree on
// a single schema by construction; schema drift between them is impossible
// if they all import these names.
//
// Binary `[u8; 32]` fields serialize as lowercase hex strings to match the
// convention used elsewhere in the JSON-RPC surface (see `src/rpc.rs`).
// ---------------------------------------------------------------------------

/// Lifecycle state of an on-chain HTLC, observable to any indexer that
/// follows the chain.
///
/// `#[non_exhaustive]` so future variants (e.g. `PartiallyClaimed` for a
/// multi-arm covenant) can be added without breaking downstream consumers.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HtlcState {
    /// Outpoint is still in the UTXO set and `current_height <= timeout_height`.
    Locked,
    /// Outpoint is still in the UTXO set but `current_height > timeout_height`.
    /// The sender may now reclaim; the receiver can still claim until that
    /// happens.
    LockedExpired,
    /// Outpoint was spent via the hash (claim) arm.
    Claimed,
    /// Outpoint was spent via the timeout (reclaim) arm.
    Reclaimed,
    /// Observer has heard of this `lock_tx_id` but has not yet classified
    /// the outpoint (e.g. follower is still catching up). Transient.
    Unknown,
}

/// Relationship of the observing party to an HTLC.
///
/// `#[non_exhaustive]` so future variants (e.g. `Custodian` for multi-sig
/// flows) can be added without breaking downstream consumers.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HtlcRole {
    /// Observer owns the sender key only.
    Sender,
    /// Observer owns the receiver key only.
    Receiver,
    /// Observer owns both keys (rare but valid — e.g. self-locked timelocks).
    Both,
    /// Multi-tenant indexers: neither key is owned by the observer.
    Observer,
}

/// The four parameters that uniquely identify an HTLC template instance —
/// the return shape of [`try_parse_htlc`], the inverse of [`htlc`].
///
/// Binary `[u8; 32]` fields serialize as lowercase hex strings to match the
/// convention used elsewhere in the JSON-RPC surface (see `src/rpc.rs`). All
/// four fields are protocol-bound widths, so they are genuinely fixed-size.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HtlcParams {
    #[serde(with = "hex_bytes32_serde")]
    pub sender: [u8; 32],
    #[serde(with = "hex_bytes32_serde")]
    pub receiver: [u8; 32],
    #[serde(with = "hex_bytes32_serde")]
    pub hash_lock: [u8; 32],
    pub timeout_height: u64,
}

/// Detail of a claim (hash path) spend.
///
/// `preimage` is variable-length: the hash arm of [`htlc`] reads
/// `Value::Bytes(preimage)` from the witness and SHA-256s it, with no
/// length constraint on the input — a preimage is any byte string whose
/// hash equals the lock. Recording it as raw `Vec<u8>` (rendered as
/// lowercase hex on the JSON wire) is the only shape that can faithfully
/// round-trip every valid claim.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HtlcClaimRecord {
    #[serde(with = "hex_bytes32_serde")]
    pub tx_id: [u8; 32],
    #[serde(with = "hex_bytes_serde")]
    pub preimage: Vec<u8>,
    pub block_height: u64,
    pub input_index: u32,
}

/// Detail of a reclaim (timeout path) spend.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HtlcReclaimRecord {
    #[serde(with = "hex_bytes32_serde")]
    pub tx_id: [u8; 32],
    pub block_height: u64,
    pub input_index: u32,
}

/// A single HTLC's observable record. The shape any indexer or wallet
/// daemon exposes via JSON-RPC for one outpoint identified by
/// `(lock_tx_id, output_index)`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HtlcRecord {
    #[serde(with = "hex_bytes32_serde")]
    pub lock_tx_id: [u8; 32],
    pub output_index: u32,
    pub params: HtlcParams,
    pub amount: u64,
    /// Block height that confirmed the lock. `None` if the lock is still
    /// in the mempool (optimistic-record case in wallet daemons).
    pub lock_block_height: Option<u64>,
    pub state: HtlcState,
    pub claim: Option<HtlcClaimRecord>,
    pub reclaim: Option<HtlcReclaimRecord>,
    pub role: HtlcRole,
    /// Tip height seen by the observer when this record was last written.
    /// Lets a consumer detect staleness without trusting wall-clock time.
    pub last_indexed_height: u64,
}

/// Attempts to decode an output script as an HTLC produced by [`htlc`].
///
/// Returns the original four parameters if the script structurally matches
/// the canonical template. The strategy:
///
/// 1. Deserialize the script to a [`Program`] AST.
/// 2. Walk every node and collect candidate constants: exactly two 32-byte
///    `Bytes` values (the pubkeys), one `Hash` (the hashlock), one `U64`
///    (the timeout).
/// 3. For each of the two possible (sender, receiver) orderings,
///    reconstruct what [`htlc`] would produce and compare the resulting
///    serialised bytes to the input.
///
/// Equality of the serialised bytes is sufficient because both
/// [`ScriptBuilder::build`] and [`serialize_program`] are deterministic,
/// so two structurally identical programs always serialise to identical
/// byte sequences. This makes [`try_parse_htlc`] robust against scripts
/// that happen to embed the right constants in the wrong structural
/// positions — they will fail the byte comparison.
///
/// Returns `None` if the script is malformed, contains the wrong number
/// or types of constants, or its structure does not match the template.
pub fn try_parse_htlc(script_bytes: &[u8]) -> Option<HtlcParams> {
    let program = deserialize_program(script_bytes).ok()?;

    // Collect candidate constants.
    let mut pubkeys: Vec<[u8; 32]> = Vec::new();
    let mut hash_lock_candidate: Option<Hash256> = None;
    let mut timeout_candidate: Option<u64> = None;

    for node in &program.nodes {
        let Combinator::Const(v) = node else { continue };
        match v {
            Value::Bytes(b) if b.len() == 32 => {
                if pubkeys.len() >= 2 {
                    // Template only contains two 32-byte Bytes constants.
                    return None;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                pubkeys.push(arr);
            }
            Value::Hash(h) => {
                if hash_lock_candidate.is_some() {
                    return None;
                }
                hash_lock_candidate = Some(*h);
            }
            Value::U64(n) => {
                if timeout_candidate.is_some() {
                    return None;
                }
                timeout_candidate = Some(*n);
            }
            // Other constants (e.g. Value::Bool(false) from boolean and())
            // are part of the template and ignored here. Disallowing them
            // would break this check the moment the template adds another
            // bool short-circuit; we rely on the final byte-compare to
            // reject anything that isn't the exact template.
            _ => {}
        }
    }

    if pubkeys.len() != 2 {
        return None;
    }
    let hash_lock = hash_lock_candidate?;
    let timeout_height = timeout_candidate?;

    let make_candidate = |sender: [u8; 32], receiver: [u8; 32]| HtlcParams {
        sender,
        receiver,
        hash_lock: hash_lock.0,
        timeout_height,
    };

    let try_candidate = |c: &HtlcParams| -> bool {
        let reconstructed = htlc(
            &c.sender,
            &c.receiver,
            &Hash256(c.hash_lock),
            c.timeout_height,
        );
        serialize_program(&reconstructed) == script_bytes
    };

    let candidate_a = make_candidate(pubkeys[0], pubkeys[1]);
    if try_candidate(&candidate_a) {
        return Some(candidate_a);
    }
    let candidate_b = make_candidate(pubkeys[1], pubkeys[0]);
    if try_candidate(&candidate_b) {
        return Some(candidate_b);
    }
    None
}

// ---------------------------------------------------------------------------
// Serde helper: `[u8; 32]` <-> lowercase hex string.
// ---------------------------------------------------------------------------

mod hex_bytes32_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32-byte hex value, got {} bytes",
                v.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

/// Variable-length companion to [`hex_bytes32_serde`], used by
/// [`HtlcClaimRecord::preimage`] which is not bound to a fixed width.
mod hex_bytes_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_pubkey(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(seed).wrapping_mul(7);
        }
        k
    }

    fn fixed_hash(seed: u8) -> Hash256 {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(seed).wrapping_mul(13);
        }
        Hash256(h)
    }

    #[test]
    fn try_parse_htlc_roundtrip_recovers_all_params() {
        let sender = fixed_pubkey(1);
        let receiver = fixed_pubkey(2);
        let hash_lock = fixed_hash(3);
        let timeout = 1_234_567u64;

        let program = htlc(&sender, &receiver, &hash_lock, timeout);
        let bytes = serialize_program(&program);

        let parsed = try_parse_htlc(&bytes).expect("template script must parse");
        assert_eq!(parsed.sender, sender);
        assert_eq!(parsed.receiver, receiver);
        assert_eq!(parsed.hash_lock, hash_lock.0);
        assert_eq!(parsed.timeout_height, timeout);
    }

    #[test]
    fn try_parse_htlc_distinguishes_sender_from_receiver() {
        // Sender and receiver play structurally different roles. Swapping
        // them produces a different script — and the parsed result must
        // reflect the actual on-chain assignment, not be ambiguous.
        let a = fixed_pubkey(10);
        let b = fixed_pubkey(20);
        let lock = fixed_hash(30);

        let prog_ab = htlc(&a, &b, &lock, 1000);
        let bytes_ab = serialize_program(&prog_ab);
        let prog_ba = htlc(&b, &a, &lock, 1000);
        let bytes_ba = serialize_program(&prog_ba);

        assert_ne!(
            bytes_ab, bytes_ba,
            "HTLC is asymmetric in sender/receiver"
        );

        let parsed_ab = try_parse_htlc(&bytes_ab).unwrap();
        assert_eq!(parsed_ab.sender, a);
        assert_eq!(parsed_ab.receiver, b);

        let parsed_ba = try_parse_htlc(&bytes_ba).unwrap();
        assert_eq!(parsed_ba.sender, b);
        assert_eq!(parsed_ba.receiver, a);
    }

    #[test]
    fn try_parse_htlc_rejects_empty_input() {
        assert_eq!(try_parse_htlc(&[]), None);
    }

    #[test]
    fn try_parse_htlc_rejects_random_bytes() {
        let garbage = [0xAAu8; 64];
        assert_eq!(try_parse_htlc(&garbage), None);
    }

    #[test]
    fn try_parse_htlc_rejects_unrelated_program() {
        let prog = Program::single(Combinator::Unit);
        let bytes = serialize_program(&prog);
        assert_eq!(try_parse_htlc(&bytes), None);
    }

    #[test]
    fn try_parse_htlc_rejects_tampered_byte() {
        let sender = fixed_pubkey(5);
        let receiver = fixed_pubkey(6);
        let lock = fixed_hash(7);
        let prog = htlc(&sender, &receiver, &lock, 500);
        let mut bytes = serialize_program(&prog);

        // Flip the high bit of a byte in the middle of the payload. Either
        // the script will fail to deserialize, or it will deserialize to a
        // structure that the byte-compare step rejects, or — if the flipped
        // byte happens to land inside one of the parameter constants —
        // we'll get back a *different* HtlcParams. In none of those cases
        // should the original four-tuple be returned.
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x80;

        match try_parse_htlc(&bytes) {
            None => {}
            Some(parsed) => {
                let unchanged = parsed.sender == sender
                    && parsed.receiver == receiver
                    && parsed.hash_lock == lock.0
                    && parsed.timeout_height == 500;
                assert!(
                    !unchanged,
                    "tampered script must not parse to the original parameters"
                );
            }
        }
    }

    #[test]
    fn htlc_params_serde_rejects_short_pubkey() {
        let bad_json = r#"{
            "sender": "abcd",
            "receiver": "0000000000000000000000000000000000000000000000000000000000000001",
            "hash_lock": "0000000000000000000000000000000000000000000000000000000000000002",
            "timeout_height": 100
        }"#;
        assert!(serde_json::from_str::<HtlcParams>(bad_json).is_err());
    }

    // ------------------------------------------------------------------
    // Observer-DTO serde tests
    // ------------------------------------------------------------------

    #[test]
    fn htlc_state_serde_uses_snake_case() {
        for (state, expected) in [
            (HtlcState::Locked, "\"locked\""),
            (HtlcState::LockedExpired, "\"locked_expired\""),
            (HtlcState::Claimed, "\"claimed\""),
            (HtlcState::Reclaimed, "\"reclaimed\""),
            (HtlcState::Unknown, "\"unknown\""),
        ] {
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(json, expected);
            let parsed: HtlcState = serde_json::from_str(expected).unwrap();
            assert_eq!(parsed, state);
        }
    }

    #[test]
    fn htlc_role_serde_uses_snake_case() {
        for (role, expected) in [
            (HtlcRole::Sender, "\"sender\""),
            (HtlcRole::Receiver, "\"receiver\""),
            (HtlcRole::Both, "\"both\""),
            (HtlcRole::Observer, "\"observer\""),
        ] {
            let json = serde_json::to_string(&role).unwrap();
            assert_eq!(json, expected);
            let parsed: HtlcRole = serde_json::from_str(expected).unwrap();
            assert_eq!(parsed, role);
        }
    }

    #[test]
    fn htlc_record_round_trips_through_json() {
        let record = HtlcRecord {
            lock_tx_id: fixed_pubkey(0xAA),
            output_index: 7,
            params: HtlcParams {
                sender: fixed_pubkey(1),
                receiver: fixed_pubkey(2),
                hash_lock: fixed_hash(3).0,
                timeout_height: 9_999,
            },
            amount: 1_000_000,
            lock_block_height: Some(42),
            state: HtlcState::Claimed,
            claim: Some(HtlcClaimRecord {
                tx_id: fixed_pubkey(0xBB),
                preimage: b"exfer htlc test preimage 2026".to_vec(),
                block_height: 44,
                input_index: 0,
            }),
            reclaim: None,
            role: HtlcRole::Receiver,
            last_indexed_height: 50,
        };

        let json = serde_json::to_string(&record).unwrap();
        let back: HtlcRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);

        // Spot-check that bytes serialise as lowercase hex strings (the
        // wire convention used by the rest of the JSON-RPC surface).
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let lock_hex = v["lock_tx_id"].as_str().unwrap();
        assert_eq!(lock_hex.len(), 64);
        assert!(lock_hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(lock_hex, lock_hex.to_lowercase());

        // The variable-length preimage was 29 bytes — confirm it
        // serialised as a 58-char hex string (not padded, not truncated).
        let pre_hex = v["claim"]["preimage"].as_str().unwrap();
        assert_eq!(pre_hex.len(), 58);
        assert_eq!(pre_hex, hex::encode(b"exfer htlc test preimage 2026"),);
    }

    #[test]
    fn htlc_claim_record_round_trips_arbitrary_preimage_lengths() {
        // Includes 0: an empty preimage is theoretically valid — SHA-256
        // of the empty byte string is a well-defined digest, and any
        // producer that emits one must still round-trip through this
        // shape.
        for len in [0usize, 1, 5, 29, 32, 33, 100, 256] {
            let preimage: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let record = HtlcClaimRecord {
                tx_id: [0xCC; 32],
                preimage: preimage.clone(),
                block_height: 1,
                input_index: 0,
            };
            let json = serde_json::to_string(&record).unwrap();
            let back: HtlcClaimRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(back, record, "round trip must work for length {len}");
            assert_eq!(back.preimage, preimage);
        }
    }

    #[test]
    fn htlc_claim_record_serialises_preimage_as_lowercase_hex() {
        let record = HtlcClaimRecord {
            tx_id: [0u8; 32],
            preimage: b"exfer htlc test preimage 2026".to_vec(),
            block_height: 0,
            input_index: 0,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
        let hex_str = v["preimage"].as_str().unwrap();
        assert_eq!(
            hex_str,
            "65786665722068746c63207465737420707265696d6167652032303236"
        );
        assert!(hex_str.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn htlc_reclaim_record_round_trips_through_json() {
        let record = HtlcReclaimRecord {
            tx_id: fixed_pubkey(0xDD),
            block_height: 7,
            input_index: 0,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: HtlcReclaimRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }
}
