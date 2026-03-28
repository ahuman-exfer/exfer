//! Audit fix tests — round 21 (findings P1×2, P2×2).

// ── P1-a: Coinbase outputs enforce dust threshold and script validity ──

#[test]
fn p1a_coinbase_dust_rejects_below_200() {
    use exfer::consensus::validation::validate_coinbase;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let reward = 100_000_000u64;
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![
            TxOutput::new_p2pkh(reward - 100, &[1; 32]),
            TxOutput::new_p2pkh(100, &[2; 32]), // below dust (200)
        ],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    let result = validate_coinbase(&tx, 0, reward);
    assert!(
        result.is_err(),
        "coinbase output below dust must be rejected"
    );
}

#[test]
fn p1a_coinbase_dust_accepts_at_threshold() {
    use exfer::consensus::validation::validate_coinbase;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let reward = 100_000_000u64;
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![
            TxOutput::new_p2pkh(reward - 200, &[1; 32]),
            TxOutput::new_p2pkh(200, &[2; 32]), // exactly at dust threshold
        ],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    let result = validate_coinbase(&tx, 0, reward);
    assert!(
        result.is_ok(),
        "coinbase output at dust threshold must be accepted: {:?}",
        result.err()
    );
}

// ── P1-b: Fee model charges for Phase-2 output typecheck ──

#[test]
fn p1b_output_typecheck_cost_constant_exists() {
    assert_eq!(
        exfer::types::OUTPUT_TYPECHECK_COST,
        1_000,
        "OUTPUT_TYPECHECK_COST must be 1000"
    );
}

#[test]
fn p1b_phase1_outputs_still_free() {
    use exfer::consensus::cost::tx_cost;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    // Phase 1 script = 32 bytes (pubkey hash) — should have zero typecheck cost
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"prev"),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(1000, &[1; 32])],
        witnesses: vec![TxWitness {
            witness: vec![0u8; 96],
            redeemer: None,
        }],
    };

    let cost = tx_cost(&tx).unwrap();
    // Phase 1 output script is 32 bytes, so output_typecheck_cost should be 0
    // script_eval = 5000 + ceil(sig_msg_bytes/64) × 8 (data-proportional Ed25519 cost)
    let sig_msg_bytes = tx.sig_message().unwrap().len() as u64;
    let script_eval = 5000 + sig_msg_bytes.div_ceil(64) * 8;
    let tx_bytes = tx.serialize().unwrap().len() as u64;
    let expected_deser = exfer::consensus::cost::ceil_div_u128(tx_bytes, 64).unwrap();
    #[allow(clippy::identity_op)]
    let expected = script_eval + 0 + 2 + 0 + expected_deser + 200 + 1000;
    assert_eq!(
        cost, expected,
        "Phase 1 outputs must have zero typecheck cost"
    );
}

// ── P2-a: state_root commits UTXO metadata (height, is_coinbase) ──

#[test]
fn p2a_different_height_different_leaf_value() {
    use exfer::chain::smt::leaf_value;

    let output_bytes = b"test output";
    let v1 = leaf_value(output_bytes, 100, false);
    let v2 = leaf_value(output_bytes, 101, false);
    assert_ne!(
        v1, v2,
        "different heights must produce different leaf values"
    );
}

#[test]
fn p2a_coinbase_flag_changes_leaf_value() {
    use exfer::chain::smt::leaf_value;

    let output_bytes = b"test output";
    let v1 = leaf_value(output_bytes, 100, false);
    let v2 = leaf_value(output_bytes, 100, true);
    assert_ne!(
        v1, v2,
        "coinbase vs non-coinbase must produce different leaf values"
    );
}

#[test]
fn p2b_max_witness_size_matches_wire() {
    assert_eq!(
        exfer::types::MAX_WITNESS_SIZE,
        65_535,
        "MAX_WITNESS_SIZE must be 65535 (u16 VarBytes wire limit, matching SPEC.md)"
    );
}

#[test]
fn p2b_max_script_nodes_fits_u16() {
    assert_eq!(
        exfer::types::MAX_SCRIPT_NODES,
        65_535,
        "MAX_SCRIPT_NODES must be 65535 (u16::MAX) to fit wire count prefix"
    );
}

// ── P2-b follow-up: serialize returns Result, no expect/panic ──

#[test]
fn p2b_oversized_script_returns_err() {
    use exfer::types::transaction::TxOutput;

    // Script larger than u16::MAX (65535) bytes
    let out = TxOutput {
        value: 1000,
        script: vec![0x42; 70_000],
        datum: None,
        datum_hash: None,
    };
    let result = out.serialize();
    assert!(
        result.is_err(),
        "TxOutput::serialize must return Err for oversized script, not panic"
    );
}

#[test]
fn p2b_oversized_witness_returns_err() {
    use exfer::types::transaction::TxWitness;

    let w = TxWitness {
        witness: vec![0u8; 70_000],
        redeemer: None,
    };
    let result = w.serialize();
    assert!(
        result.is_err(),
        "TxWitness::serialize must return Err for oversized witness, not panic"
    );
}

#[test]
fn p2b_oversized_datum_returns_err() {
    use exfer::types::transaction::TxOutput;

    let out = TxOutput {
        value: 1000,
        script: vec![0x42; 32],
        datum: Some(vec![0xDE; 70_000]),
        datum_hash: None,
    };
    let result = out.serialize();
    assert!(
        result.is_err(),
        "TxOutput::serialize must return Err for oversized datum, not panic"
    );
}

#[test]
fn p2b_oversized_redeemer_returns_err() {
    use exfer::types::transaction::TxWitness;

    let w = TxWitness {
        witness: vec![0u8; 96],
        redeemer: Some(vec![0xBE; 70_000]),
    };
    let result = w.serialize();
    assert!(
        result.is_err(),
        "TxWitness::serialize must return Err for oversized redeemer, not panic"
    );
}

// ── P3: tx_id/wtx_id/sig_message return Result, no expect/panic ──

#[test]
fn p3_oversized_tx_tx_id_returns_err() {
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 1000,
            script: vec![0x42; 70_000], // exceeds u16::MAX
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    assert!(
        tx.tx_id().is_err(),
        "tx_id must return Err for oversized tx, not panic"
    );
    assert!(
        tx.wtx_id().is_err(),
        "wtx_id must return Err for oversized tx, not panic"
    );
    assert!(
        tx.sig_message().is_err(),
        "sig_message must return Err for oversized tx, not panic"
    );
}

// ── P3 hardening: Block::serialize, Message::serialize, apply/undo return Result ──

#[test]
fn p3h_block_serialize_oversized_tx_returns_err() {
    use exfer::types::block::Block;
    use exfer::types::block::BlockHeader;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let block = Block {
        header: BlockHeader {
            version: 1,
            height: 0,
            prev_block_id: Hash256::ZERO,
            timestamp: 0,
            difficulty_target: Hash256::ZERO,
            nonce: 0,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput {
                value: 1000,
                script: vec![0x42; 70_000], // exceeds u16::MAX
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        }],
    };
    assert!(
        block.serialize().is_err(),
        "Block::serialize must return Err for oversized tx, not panic"
    );
}
