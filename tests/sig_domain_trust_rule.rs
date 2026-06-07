//! Trust rule for signers, default expectation (issue #32).
//!
//! The signer holds no `--expect-genesis`, so the expectation is the compiled
//! canonical genesis id. A node reporting anything else must be rejected
//! BEFORE any bind or sign — default-deny is the only thing keeping a
//! colliding deterministic-coinbase outpoint non-replayable.
//!
//! PROCESS ISOLATION: `ensure_signature_domain` latches a process-global
//! "established" flag on first success, and `bind_signature_domain` is a
//! process-global `OnceLock`. This file therefore holds exactly ONE test fn
//! and orders its scenarios so every rejection is exercised before the first
//! success latches the flag.

mod sig_domain_common;

use exfer::genesis;
use exfer::wallet::auth::{ensure_signature_domain, AuthError};
use sig_domain_common::MockNode;

#[test]
fn default_expectation_rejects_foreign_then_accepts_legacy_node() {
    let canonical = *genesis::GENESIS_BLOCK_ID;

    // 1. Node reports a FOREIGN genesis id → GenesisDomainMismatch, before
    //    any bind. A malicious node cannot move this signer into its domain.
    let foreign_hex = hex::encode([0xCD; 32]);
    let mock = MockNode::serve(serde_json::json!({
        "height": 7,
        "block_id": hex::encode([0x11; 32]),
        "genesis_block_id": foreign_hex,
    }));
    match ensure_signature_domain(&mock.url) {
        Err(AuthError::GenesisDomainMismatch { expected, reported }) => {
            assert_eq!(expected, canonical);
            assert_eq!(reported.as_bytes(), &[0xCD; 32]);
        }
        other => panic!("expected GenesisDomainMismatch, got {:?}", other),
    }
    assert!(
        !genesis::signature_domain_is_bound(),
        "a rejected node must not have bound anything"
    );
    assert_eq!(genesis::signature_domain(), canonical);
    drop(mock);

    // 2. Node reports a MALFORMED genesis id → GenesisMalformed, no bind.
    let mock = MockNode::serve(serde_json::json!({
        "height": 7,
        "block_id": hex::encode([0x11; 32]),
        "genesis_block_id": "not-hex-at-all",
    }));
    match ensure_signature_domain(&mock.url) {
        Err(AuthError::GenesisMalformed(s)) => assert_eq!(s, "not-hex-at-all"),
        other => panic!("expected GenesisMalformed, got {:?}", other),
    }
    assert!(!genesis::signature_domain_is_bound());
    drop(mock);

    // 2b. Well-formed hex but wrong length is also malformed.
    let mock = MockNode::serve(serde_json::json!({
        "height": 7,
        "block_id": hex::encode([0x11; 32]),
        "genesis_block_id": "abcd",
    }));
    assert!(
        matches!(
            ensure_signature_domain(&mock.url),
            Err(AuthError::GenesisMalformed(_))
        ),
        "short hex must be GenesisMalformed"
    );
    assert!(!genesis::signature_domain_is_bound());
    drop(mock);

    // 3. LEGACY node (no genesis_block_id field) with the default canonical
    //    expectation → accepted WITHOUT binding: the unbound fallback domain
    //    is exactly what such a node verifies. This is the
    //    old-client/old-node compatibility path — must stay byte-identical.
    let mock = MockNode::serve(serde_json::json!({
        "height": 7,
        "block_id": hex::encode([0x11; 32]),
    }));
    ensure_signature_domain(&mock.url).expect("legacy node + canonical expectation is accepted");
    assert!(
        !genesis::signature_domain_is_bound(),
        "legacy-node acceptance must not bind — the fallback is already correct"
    );
    assert_eq!(genesis::signature_domain(), canonical);
    drop(mock);

    // 4. Established: later calls are a no-op fast path — no RPC at all.
    let mock = MockNode::serve(serde_json::json!({
        "height": 7,
        "block_id": hex::encode([0x11; 32]),
        "genesis_block_id": hex::encode([0xEE; 32]),
    }));
    ensure_signature_domain(&mock.url).expect("established domain short-circuits");
    assert!(
        mock.methods_seen().is_empty(),
        "established domain must not re-fetch (TOCTOU: bind exactly what was checked)"
    );
}
