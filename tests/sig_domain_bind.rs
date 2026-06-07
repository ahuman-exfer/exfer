//! Signature-domain bind semantics (issue #32).
//!
//! PROCESS ISOLATION: `bind_signature_domain` is a process-global `OnceLock`,
//! so this file holds exactly ONE test fn and exercises the full bind
//! lifecycle sequentially. Binding here poisons `sig_message` for every later
//! test in the same binary — never add a second test fn to this file, and
//! never move these assertions into a shared test binary (the byte-equality
//! pin in audit_fix_tests_56.rs relies on its binary staying unbound).

use exfer::genesis;
use exfer::types::hash::Hash256;
use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::DS_SIG;

fn test_tx() -> Transaction {
    Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"sig-domain-bind-test"),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(100, &[0; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    }
}

#[test]
fn bind_lifecycle_set_once_rebind_same_ok_rebind_other_err() {
    let canonical = *genesis::GENESIS_BLOCK_ID;
    let devnet_id = genesis::devnet_genesis_block().header.block_id();
    assert_ne!(canonical, devnet_id, "devnet genesis must be distinct");

    // Unbound: fallback is the compiled canonical id.
    assert!(!genesis::signature_domain_is_bound());
    assert_eq!(genesis::signature_domain(), canonical);

    // Bind the devnet id: sig_message immediately signs in the devnet domain.
    genesis::bind_signature_domain(devnet_id).expect("first bind succeeds");
    assert!(genesis::signature_domain_is_bound());
    assert_eq!(genesis::signature_domain(), devnet_id);
    let sig_msg = test_tx().sig_message().unwrap();
    assert_eq!(
        &sig_msg[DS_SIG.len()..DS_SIG.len() + 32],
        devnet_id.as_bytes(),
        "sig_message must bind the overridden domain"
    );

    // Re-bind with the SAME id: idempotent Ok — every pre-sign helper routes
    // through the bind, so multi-lookup flows hit it more than once.
    genesis::bind_signature_domain(devnet_id).expect("same-id rebind is Ok");
    assert_eq!(genesis::signature_domain(), devnet_id);

    // Re-bind with a DIFFERENT id: Err carrying the bound id — one process
    // must never sign transactions in two domains.
    let foreign = Hash256([0xAB; 32]);
    match genesis::bind_signature_domain(foreign) {
        Err(bound) => assert_eq!(bound, devnet_id, "Err must report the bound id"),
        Ok(()) => panic!("re-binding a different id must fail"),
    }
    // Domain unchanged after the failed rebind.
    assert_eq!(genesis::signature_domain(), devnet_id);
    let sig_msg2 = test_tx().sig_message().unwrap();
    assert_eq!(&sig_msg2[DS_SIG.len()..DS_SIG.len() + 32], devnet_id.as_bytes());
}
