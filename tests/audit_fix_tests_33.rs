//! Audit fix tests — round 33 (P1 + P2×2).
//!
//! P1: HTLC template uses EqHash jet (Hash256×Hash256→Bool), not EqBytes (Bytes×Bytes→Bool).
//! P2-a: Wallet enforces DUST_THRESHOLD on outputs.
//! P2-b: Introspection jets (TxInputs/TxOutputs) priced proportional to tx fan-in/out.

// ── P1: HTLC type correctness via EqHash jet ──

#[cfg(feature = "testnet")]
#[test]
fn p1_htlc_typechecks() {
    use exfer::covenants::htlc;
    use exfer::script::typecheck::typecheck;
    use exfer::types::hash::Hash256;

    let pk = [1u8; 32];
    let lock = Hash256::sha256(b"test-preimage");
    let program = htlc::htlc(&pk, &pk, &lock, 1000);
    let result = typecheck(&program);
    assert!(
        result.is_ok(),
        "HTLC must typecheck with EqHash: {:?}",
        result.err()
    );
}

// ── P2-a: Wallet dust threshold enforcement ──

#[cfg(feature = "testnet")]
#[test]
fn p2a_wallet_rejects_sub_dust_amount() {
    use exfer::chain::state::{UtxoEntry, UtxoSet};
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{OutPoint, TxOutput};
    use exfer::types::DUST_THRESHOLD;
    use exfer::wallet::wallet::{Wallet, WalletError};

    let w = Wallet::generate();
    let mut utxo_set = UtxoSet::new();
    utxo_set
        .insert(
            OutPoint::new(Hash256::sha256(b"fund"), 0),
            UtxoEntry {
                output: TxOutput::new_p2pkh(10_000_000, &w.pubkey()),
                height: 0,
                is_coinbase: false,
            },
        )
        .expect("insert test UTXO");

    let result = w.build_transaction(
        Hash256::sha256(b"recv"),
        DUST_THRESHOLD - 1,
        1000,
        &utxo_set,
        1000,
    );
    assert!(
        matches!(result, Err(WalletError::DustOutput(_))),
        "should reject sub-dust recipient: {:?}",
        result
    );
}

#[cfg(feature = "testnet")]
#[test]
fn p2a_wallet_folds_sub_dust_change_into_fee() {
    use exfer::chain::state::{UtxoEntry, UtxoSet};
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{OutPoint, TxOutput};
    use exfer::types::DUST_THRESHOLD;
    use exfer::wallet::wallet::Wallet;

    let w = Wallet::generate();
    let mut utxo_set = UtxoSet::new();
    // Fund with amount that leaves sub-dust change
    let fund_amount = 10_000u64;
    let send_amount = fund_amount - 1000 - (DUST_THRESHOLD - 1); // change = DUST_THRESHOLD - 1
    utxo_set
        .insert(
            OutPoint::new(Hash256::sha256(b"fund2"), 0),
            UtxoEntry {
                output: TxOutput::new_p2pkh(fund_amount, &w.pubkey()),
                height: 0,
                is_coinbase: false,
            },
        )
        .expect("insert test UTXO");

    let tx = w
        .build_transaction(
            Hash256::sha256(b"recv2"),
            send_amount,
            1000,
            &utxo_set,
            1000,
        )
        .expect("should succeed with sub-dust change folded into fee");
    // Should have only 1 output (recipient), no change output
    assert_eq!(
        tx.outputs.len(),
        1,
        "sub-dust change should be folded into fee, not emitted as output"
    );
}

// ── P2-b: Introspection jet pricing ──

#[cfg(feature = "testnet")]
#[test]
fn p2b_tx_inputs_cost_scales_with_count() {
    use exfer::script::jets::context::{ScriptContext, TxInputInfo};
    use exfer::script::jets::JetId;
    use exfer::script::value::Value;
    use exfer::types::hash::Hash256;

    let make_ctx = |n: usize| -> ScriptContext {
        let inputs: Vec<TxInputInfo> = (0..n)
            .map(|_| TxInputInfo {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
                value: 1000,
                script_hash: Hash256::ZERO,
            })
            .collect();
        ScriptContext {
            tx_inputs: inputs.into(),
            tx_outputs: vec![].into(),
            self_index: 0,
            block_height: 0,
            sig_hash: vec![].into(),
        }
    };

    let u = Value::Unit;
    let cost_1 = JetId::TxInputs.runtime_cost(&u, &make_ctx(1));
    let cost_100 = JetId::TxInputs.runtime_cost(&u, &make_ctx(100));
    assert!(
        cost_100 > cost_1 * 10,
        "TxInputs cost should scale: 1-input={}, 100-input={}",
        cost_1,
        cost_100
    );
}

#[cfg(feature = "testnet")]
#[test]
fn p2b_tx_outputs_cost_scales_with_count() {
    use exfer::script::jets::context::{ScriptContext, TxOutputInfo};
    use exfer::script::jets::JetId;
    use exfer::script::value::Value;
    use exfer::types::hash::Hash256;

    let make_ctx = |n: usize| -> ScriptContext {
        let outputs: Vec<TxOutputInfo> = (0..n)
            .map(|_| TxOutputInfo {
                value: 1000,
                script_hash: Hash256::ZERO,
                datum_hash: None,
            })
            .collect();
        ScriptContext {
            tx_inputs: vec![].into(),
            tx_outputs: outputs.into(),
            self_index: 0,
            block_height: 0,
            sig_hash: vec![].into(),
        }
    };

    let u = Value::Unit;
    let cost_1 = JetId::TxOutputs.runtime_cost(&u, &make_ctx(1));
    let cost_100 = JetId::TxOutputs.runtime_cost(&u, &make_ctx(100));
    assert!(
        cost_100 > cost_1 * 10,
        "TxOutputs cost should scale: 1-output={}, 100-output={}",
        cost_1,
        cost_100
    );
}
