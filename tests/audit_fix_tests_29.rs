// Round 29 audit fix tests — P0 (covenant sig binding), P1 (block-rate refund removed),
// P2 (coinbase witness constraints), P3 (Phase1 detection deterministic).

// ── P0: Covenant signatures bound to transaction data ─────────────────

#[test]
fn p2_coinbase_witness_runtime_test() {
    // Runtime test: coinbase with non-empty witness must fail validation
    use exfer::consensus::validation::validate_coinbase;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let reward = exfer::consensus::reward::block_reward(0);

    // Valid coinbase (baseline)
    let valid_cb = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(reward, &[0x42; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    assert!(
        validate_coinbase(&valid_cb, 0, reward).is_ok(),
        "valid coinbase must pass"
    );

    // Coinbase with non-empty witness must fail (at height > 0;
    // height 0 is exempt for the genesis NIST Beacon attestation)
    let bad_witness_cb = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 1, // height 1
        }],
        outputs: vec![TxOutput::new_p2pkh(reward, &[0x42; 32])],
        witnesses: vec![TxWitness {
            witness: vec![0xFF; 32],
            redeemer: None,
        }],
    };
    assert!(
        validate_coinbase(&bad_witness_cb, 1, reward).is_err(),
        "coinbase with non-empty witness must fail at height > 0"
    );

    // Coinbase with redeemer must fail
    let bad_redeemer_cb = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(reward, &[0x42; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: Some(vec![0x01]),
        }],
    };
    assert!(
        validate_coinbase(&bad_redeemer_cb, 0, reward).is_err(),
        "coinbase with redeemer must fail"
    );
}

// ── P3: Phase 1 script detection is deterministic ─────────────────────

#[test]
fn p3_is_phase1_script_runtime_deterministic() {
    // Runtime test: is_phase1_script must be purely length-based
    use exfer::consensus::validation::is_phase1_script;

    // 32 bytes = Phase 1
    assert!(is_phase1_script(&[0u8; 32]), "32 bytes must be Phase 1");
    assert!(
        is_phase1_script(&[0xFF; 32]),
        "32 bytes (any content) must be Phase 1"
    );

    // Non-32 bytes = not Phase 1
    assert!(
        !is_phase1_script(&[0u8; 31]),
        "31 bytes must not be Phase 1"
    );
    assert!(
        !is_phase1_script(&[0u8; 33]),
        "33 bytes must not be Phase 1"
    );
    assert!(!is_phase1_script(&[]), "empty must not be Phase 1");
}
