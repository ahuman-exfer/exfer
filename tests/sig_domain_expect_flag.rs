//! Trust rule with a named `--expect-genesis` expectation (issue #32).
//!
//! The operator names the chain they intend to sign on (here: the devnet
//! genesis id, a compiled constant — the only id `--expect-genesis devnet`
//! sugar can produce). The signer must reject a node reporting any OTHER id
//! (including the canonical one), reject a node that cannot be verified at
//! all, and on a match bind exactly the checked id — entering devnet
//! consensus mode wholesale (domain AND maturity, composed).
//!
//! PROCESS ISOLATION: `set_expected_genesis`, the established-flag, and the
//! domain `OnceLock` are process globals — exactly ONE test fn, rejections
//! ordered before the success that latches the flag. The devnet bind at the
//! end poisons `sig_message` for any later test in this binary: never add a
//! second test fn here.

mod sig_domain_common;

use exfer::genesis;
use exfer::wallet::auth::{ensure_signature_domain, set_expected_genesis, AuthError};
use sig_domain_common::MockNode;

#[test]
fn named_expectation_default_deny_then_devnet_bind_composes() {
    let canonical = *genesis::GENESIS_BLOCK_ID;
    let devnet_id = genesis::devnet_genesis_block().header.block_id();

    set_expected_genesis(devnet_id).expect("first set succeeds");
    // The expectation is set-once too: a process that could re-aim its
    // expectation mid-run reintroduces the two-domain footgun upstream.
    assert!(
        set_expected_genesis(canonical).is_err(),
        "expectation must be set-once"
    );

    // 1. Node that reports NO genesis id cannot satisfy an explicit
    //    expectation → GenesisUnreported.
    let mock = MockNode::serve(serde_json::json!({
        "height": 3,
        "block_id": hex::encode([0x22; 32]),
    }));
    match ensure_signature_domain(&mock.url) {
        Err(AuthError::GenesisUnreported { expected }) => assert_eq!(expected, devnet_id),
        other => panic!("expected GenesisUnreported, got {:?}", other),
    }
    assert!(!genesis::signature_domain_is_bound());
    drop(mock);

    // 2. Node reporting the CANONICAL id when devnet was named → mismatch.
    //    Default-deny cuts both ways: the expectation is what the operator
    //    named, not whatever familiar id a node can produce.
    let mock = MockNode::serve(serde_json::json!({
        "height": 3,
        "block_id": hex::encode([0x22; 32]),
        "genesis_block_id": hex::encode(canonical.as_bytes()),
    }));
    match ensure_signature_domain(&mock.url) {
        Err(AuthError::GenesisDomainMismatch { expected, reported }) => {
            assert_eq!(expected, devnet_id);
            assert_eq!(reported, canonical);
        }
        other => panic!("expected GenesisDomainMismatch, got {:?}", other),
    }
    assert!(!genesis::signature_domain_is_bound());
    drop(mock);

    // 3. Node reporting the named devnet id → accepted, and the bind is the
    //    EXACT checked id. Joining the devnet chain enters devnet consensus
    //    mode wholesale: domain + coinbase maturity 1 (types::enter_devnet),
    //    so the wallet's maturity filter matches the chain it now spends on.
    assert_eq!(
        exfer::types::coinbase_maturity(),
        exfer::types::COINBASE_MATURITY,
        "pre-bind: canonical maturity"
    );
    let mock = MockNode::serve(serde_json::json!({
        "height": 3,
        "block_id": hex::encode([0x22; 32]),
        "genesis_block_id": hex::encode(devnet_id.as_bytes()),
    }));
    ensure_signature_domain(&mock.url).expect("named devnet id accepted");
    assert!(genesis::signature_domain_is_bound());
    assert_eq!(genesis::signature_domain(), devnet_id);
    assert_eq!(
        exfer::types::coinbase_maturity(),
        exfer::types::DEVNET_COINBASE_MATURITY,
        "devnet bind must compose maturity with the domain"
    );
}
