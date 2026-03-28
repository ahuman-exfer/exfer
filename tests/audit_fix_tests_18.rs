//! Audit fix tests — round 18 (findings P1×3, P2×1).

// ── P1-a: Block identity commits witnesses via wtx_id ──

#[test]
fn p1a_wtx_id_differs_from_tx_id_when_witness_nonempty() {
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(1000, &[0xAA; 32])],
        witnesses: vec![TxWitness {
            witness: vec![1, 2, 3, 4], // non-empty witness
            redeemer: None,
        }],
    };

    // tx_id excludes witnesses, wtx_id includes them — they must differ
    // when the witness is non-empty.
    assert_ne!(
        tx.tx_id().unwrap(),
        tx.wtx_id().unwrap(),
        "wtx_id must differ from tx_id when witnesses are non-empty"
    );
}

#[test]
fn p1a_different_witnesses_produce_different_wtx_ids() {
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let base = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(1000, &[0xBB; 32])],
        witnesses: vec![TxWitness {
            witness: vec![1, 2, 3],
            redeemer: None,
        }],
    };

    let altered = Transaction {
        witnesses: vec![TxWitness {
            witness: vec![4, 5, 6],
            redeemer: None,
        }],
        ..base.clone()
    };

    // Same body → same tx_id
    assert_eq!(
        base.tx_id().unwrap(),
        altered.tx_id().unwrap(),
        "tx_id must be identical"
    );
    // Different witnesses → different wtx_id
    assert_ne!(
        base.wtx_id().unwrap(),
        altered.wtx_id().unwrap(),
        "wtx_id must differ when witnesses differ"
    );
}

#[test]
fn p1a_ds_wtxid_constant_exists() {
    assert_eq!(exfer::types::DS_WTXID, b"EXFER-WTXID");
}

#[test]
fn p1a_block_malleability_prevented() {
    use exfer::consensus::validation::compute_tx_root;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    // Two transactions with identical body but different witnesses
    let tx1 = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(500, &[0xCC; 32])],
        witnesses: vec![TxWitness {
            witness: vec![10, 20, 30],
            redeemer: None,
        }],
    };
    let tx2 = Transaction {
        witnesses: vec![TxWitness {
            witness: vec![40, 50, 60],
            redeemer: None,
        }],
        ..tx1.clone()
    };

    // tx_ids are the same (by design)
    assert_eq!(tx1.tx_id().unwrap(), tx2.tx_id().unwrap());

    // But tx_roots must differ — blocks containing these are distinguishable
    let root1 = compute_tx_root(&[tx1]).unwrap();
    let root2 = compute_tx_root(&[tx2]).unwrap();
    assert_ne!(
        root1, root2,
        "tx_root must differ when witnesses differ — block malleability prevented"
    );
}

// ── P1-b: Output scripts must return Bool to be spendable ──

#[test]
fn p1c_max_invalid_blocks_per_peer_constant() {
    assert_eq!(
        exfer::types::MAX_INVALID_BLOCKS_PER_PEER,
        3,
        "MAX_INVALID_BLOCKS_PER_PEER must be 3"
    );
}
