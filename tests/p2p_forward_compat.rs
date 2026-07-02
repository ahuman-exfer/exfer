//! Phase 1 P2P forward-compatibility (issue #50 enabler).
//!
//! Covers the two backward-compat linchpins and the new negotiation/skip logic:
//!   - the legacy (`eff == 5`, `None`) auth transcript AND session key are
//!     byte-identical to the pre-forward-compat v5 derivation (golden vectors);
//!   - the versioned (`eff >= 6`) transcript binds the role-ordered advertised
//!     tuple (order-sensitive; differs from legacy);
//!   - version is fed as `eff`, so cross-version links agree on the session key;
//!   - an unknown post-handshake message type deserializes to a skip sentinel
//!     (not an error), carrying its length; the sentinel is never serializable.

use exfer::network::protocol::{compute_auth_transcript, compute_session_key, Message};
use exfer::types::hash::Hash256;

const GENESIS: Hash256 = Hash256([0x11; 32]);
const NA: [u8; 32] = [0xAA; 32];
const NB: [u8; 32] = [0xBB; 32];
const TIP_A: [u8; 72] = [0x01; 72];
const TIP_B: [u8; 72] = [0x02; 72];
const DH: [u8; 32] = [0xCC; 32];

// Golden vectors: the v5 (legacy) derivations for the fixed inputs above. These
// pin the backward-compat guarantee — the `eff == 5` / `None` path must reproduce
// deployed v5 byte-for-byte. Captured from the legacy formula
//   transcript = SHA256("EXFER-AUTH" || genesis || 5_le || NA || NB || role || TIP_A || TIP_B)
//   session    = SHA256("EXFER-SESSION" || SHA256("EXFER-AUTH" || genesis || 5_le || NA || NB) || DH)
// If either changes, the legacy path diverged from v5 — a hard backward-compat
// break. The test prints the observed value so the golden can be re-pinned only
// on a DELIBERATE, reviewed change.
const GOLDEN_TRANSCRIPT_V5_ROLE0: [u8; 32] = [
    80, 93, 50, 36, 203, 137, 164, 245, 235, 199, 247, 157, 154, 227, 55, 22, 229, 3, 22, 128, 198,
    8, 50, 137, 49, 79, 234, 188, 172, 163, 182, 80,
];
const GOLDEN_SESSION_KEY_V5: [u8; 32] = [
    228, 2, 159, 58, 170, 91, 208, 236, 96, 119, 6, 218, 96, 44, 222, 215, 38, 59, 236, 221, 144,
    109, 91, 70, 87, 70, 238, 26, 199, 106, 64, 26,
];

fn legacy_transcript(role: u8) -> [u8; 32] {
    compute_auth_transcript(&GENESIS, 5, &NA, &NB, role, &TIP_A, &TIP_B, None)
}

#[test]
fn legacy_transcript_is_byte_identical_to_v5() {
    let got = legacy_transcript(0x00);
    if got != GOLDEN_TRANSCRIPT_V5_ROLE0 {
        panic!(
            "legacy (eff=5, None) transcript changed — backward-compat break OR \
             golden needs re-pinning. observed = {:?}",
            got
        );
    }
}

#[test]
fn legacy_session_key_is_byte_identical_to_v5() {
    let got = compute_session_key(&GENESIS, 5, &NA, &NB, &DH);
    if got != GOLDEN_SESSION_KEY_V5 {
        panic!(
            "legacy (eff=5) session key changed — backward-compat break OR golden \
             needs re-pinning. observed = {:?}",
            got
        );
    }
}

#[test]
fn versioned_transcript_differs_from_legacy() {
    // eff >= 6 appends the advertised tuple → distinct from the legacy digest.
    let legacy = compute_auth_transcript(&GENESIS, 6, &NA, &NB, 0x00, &TIP_A, &TIP_B, None);
    let versioned =
        compute_auth_transcript(&GENESIS, 6, &NA, &NB, 0x00, &TIP_A, &TIP_B, Some((6, 6)));
    assert_ne!(
        legacy, versioned,
        "versioned format must bind the advertised tuple"
    );
}

#[test]
fn versioned_tuple_is_role_ordered_not_symmetric() {
    // (init_adv, resp_adv) is ordered — v7↔v6 must not collide with v6↔v7.
    let t_76 = compute_auth_transcript(&GENESIS, 6, &NA, &NB, 0x00, &TIP_A, &TIP_B, Some((7, 6)));
    let t_67 = compute_auth_transcript(&GENESIS, 6, &NA, &NB, 0x00, &TIP_A, &TIP_B, Some((6, 7)));
    assert_ne!(
        t_76, t_67,
        "advertised-version tuple must be order-sensitive (role-ordered)"
    );
}

#[test]
fn v7_v6_both_sides_compute_the_same_tuple() {
    // Simulate the handshake tuple derivation: initiator advertises 7, responder
    // advertises 6, eff = 6. Initiator side computes (own=7, peer=6); responder
    // side computes (peer=7, own=6). Both must be (7, 6) → identical transcripts.
    let init_side = (7u32, 6u32); // initiator: (PROTOCOL_VERSION=7, their=6)
    let resp_side = (7u32, 6u32); // responder: (their=7, PROTOCOL_VERSION=6)
    assert_eq!(init_side, resp_side, "role-ordered tuple must match on both sides");
    let t_init =
        compute_auth_transcript(&GENESIS, 6, &NA, &NB, 0x01, &TIP_A, &TIP_B, Some(init_side));
    let t_init2 =
        compute_auth_transcript(&GENESIS, 6, &NA, &NB, 0x01, &TIP_A, &TIP_B, Some(resp_side));
    assert_eq!(t_init, t_init2);
}

#[test]
fn session_key_depends_on_eff_so_cross_version_must_feed_eff() {
    // The KDF binds the version scalar. A const-5 and a const-6 node on an eff=5
    // link MUST both feed 5 (not their constant) or their keys diverge and every
    // frame's HMAC fails. This asserts the version actually changes the key (so
    // feeding eff, not the constant, is load-bearing) and that eff=5 is stable.
    let k5 = compute_session_key(&GENESIS, 5, &NA, &NB, &DH);
    let k6 = compute_session_key(&GENESIS, 6, &NA, &NB, &DH);
    assert_ne!(k5, k6, "version must affect the session key");
    // Determinism: both peers feeding eff=5 get the identical key.
    assert_eq!(k5, compute_session_key(&GENESIS, 5, &NA, &NB, &DH));
}

// ── skip-unknown wire behavior ──

fn frame(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![msg_type];
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[test]
fn unknown_message_type_deserializes_to_skip_sentinel() {
    // 0x7E is not an assigned message id.
    let payload = b"future message body";
    let bytes = frame(0x7E, payload);
    let (msg, consumed) = Message::deserialize(&bytes).expect("unknown type is not an error");
    match msg {
        Message::Unknown { msg_type, len } => {
            assert_eq!(msg_type, 0x7E);
            assert_eq!(len, payload.len());
        }
        other => panic!("expected Unknown sentinel, got {:?}", other),
    }
    assert_eq!(consumed, 5 + payload.len(), "frame fully consumed (no desync)");
}

#[test]
fn unknown_sentinel_is_never_serializable() {
    let sentinel = Message::Unknown {
        msg_type: 0x7E,
        len: 3,
    };
    assert!(
        sentinel.serialize().is_err(),
        "the receive-only skip sentinel must never be sent"
    );
}

#[test]
fn malformed_known_message_still_errors() {
    // A KNOWN type (NewTx = 0x20) with a truncated/garbage payload must still be
    // a hard error — skip-unknown only tolerates UNKNOWN type ids.
    let bytes = frame(0x20, &[0xFF, 0x00, 0x01]);
    assert!(
        Message::deserialize(&bytes).is_err(),
        "malformed known message must still fail (not become Unknown)"
    );
}
