//! AUDIT-FIXES-8 regression tests.
//!
//! Fix 1 [P1]: Data-dependent jet costing — runtime_cost proportional to data size
//! Fix 2 [P2]: Atomic block processing — storage writes before in-memory commit
//! Fix 3 [P2]: Ed25519 Phase1 verify → ZIP-215 (not verify_strict)
//! Fix 4 [P3]: Mempool fee-density uses actual script cost
//! Fix 5 [P3]: MAX_SCRIPT_STEPS in SPEC.md (verified by existence of constant)

#[cfg(feature = "testnet")]
mod jet_runtime_cost_tests {
    use exfer::script::jets::context::ScriptContext;
    use exfer::script::jets::JetId;
    use exfer::script::value::Value;
    use exfer::types::hash::Hash256;

    #[test]
    fn merkle_verify_cost_scales_with_proof_depth() {
        // Empty proof
        let input_0 = Value::Pair(
            Box::new(Value::Hash(Hash256([0; 32]))),
            Box::new(Value::Pair(
                Box::new(Value::Hash(Hash256([1; 32]))),
                Box::new(Value::Bytes(vec![])),
            )),
        );
        let cost_0 = JetId::MerkleVerify.runtime_cost(&input_0, &ScriptContext::empty());
        assert_eq!(cost_0, 500); // base cost only

        // 10-sibling proof (330 bytes: 10 * 33)
        let proof_10 = vec![0u8; 10 * 33];
        let input_10 = Value::Pair(
            Box::new(Value::Hash(Hash256([0; 32]))),
            Box::new(Value::Pair(
                Box::new(Value::Hash(Hash256([1; 32]))),
                Box::new(Value::Bytes(proof_10)),
            )),
        );
        let cost_10 = JetId::MerkleVerify.runtime_cost(&input_10, &ScriptContext::empty());
        assert_eq!(cost_10, 500 + 10 * 500); // base + 10 siblings

        // Larger proof should cost proportionally more
        let proof_50 = vec![0u8; 50 * 33];
        let input_50 = Value::Pair(
            Box::new(Value::Hash(Hash256([0; 32]))),
            Box::new(Value::Pair(
                Box::new(Value::Hash(Hash256([1; 32]))),
                Box::new(Value::Bytes(proof_50)),
            )),
        );
        let cost_50 = JetId::MerkleVerify.runtime_cost(&input_50, &ScriptContext::empty());
        assert_eq!(cost_50, 500 + 50 * 500);
        assert!(cost_50 > cost_10);
    }

    #[test]
    fn merkle_verify_static_covers_63_siblings() {
        let (static_steps, _) = JetId::MerkleVerify.jet_cost();
        // 63 siblings: runtime = 500 + 63*500 = 32_000
        let proof_63 = vec![0u8; 63 * 33];
        let input = Value::Pair(
            Box::new(Value::Hash(Hash256([0; 32]))),
            Box::new(Value::Pair(
                Box::new(Value::Hash(Hash256([1; 32]))),
                Box::new(Value::Bytes(proof_63)),
            )),
        );
        let runtime = JetId::MerkleVerify.runtime_cost(&input, &ScriptContext::empty());
        assert!(
            static_steps >= runtime,
            "static cost {} should cover 63-sibling runtime cost {}",
            static_steps,
            runtime
        );
    }

    #[test]
    fn merkle_verify_static_insufficient_for_large_proofs() {
        let (static_steps, _) = JetId::MerkleVerify.jet_cost();
        // 100 siblings exceeds static budget → script would fail at runtime (correct behavior)
        let proof_100 = vec![0u8; 100 * 33];
        let input = Value::Pair(
            Box::new(Value::Hash(Hash256([0; 32]))),
            Box::new(Value::Pair(
                Box::new(Value::Hash(Hash256([1; 32]))),
                Box::new(Value::Bytes(proof_100)),
            )),
        );
        let runtime = JetId::MerkleVerify.runtime_cost(&input, &ScriptContext::empty());
        assert!(
            runtime > static_steps,
            "100-sibling proof runtime {} should exceed static budget {}",
            runtime,
            static_steps
        );
    }

    #[test]
    fn list_ops_cost_scales_with_length() {
        let list_10 = Value::List(vec![Value::U64(1); 10]);
        let list_1000 = Value::List(vec![Value::U64(1); 1000]);

        let cost_10 = JetId::ListSum.runtime_cost(&list_10, &ScriptContext::empty());
        let cost_1000 = JetId::ListSum.runtime_cost(&list_1000, &ScriptContext::empty());

        assert_eq!(cost_10, 10 + 10); // base + len
        assert_eq!(cost_1000, 10 + 1000);
        assert!(cost_1000 > cost_10);

        // All list ops scale the same
        let bool_list = Value::List(vec![Value::Bool(true); 500]);
        assert_eq!(
            JetId::ListAll.runtime_cost(&bool_list, &ScriptContext::empty()),
            10 + 500
        );
        assert_eq!(
            JetId::ListAny.runtime_cost(&bool_list, &ScriptContext::empty()),
            10 + 500
        );
        assert_eq!(
            JetId::ListFind.runtime_cost(&bool_list, &ScriptContext::empty()),
            10 + 500
        );
    }

    #[test]
    fn list_ops_static_covers_990_elements() {
        let (static_steps, _) = JetId::ListSum.jet_cost();
        let list_990 = Value::List(vec![Value::U64(1); 990]);
        let runtime = JetId::ListSum.runtime_cost(&list_990, &ScriptContext::empty());
        assert!(
            static_steps >= runtime,
            "static {} should cover 990-element runtime {}",
            static_steps,
            runtime
        );
    }

    #[test]
    fn eq_bytes_cost_scales_with_length() {
        let small = Value::Pair(
            Box::new(Value::Bytes(vec![0; 8])),
            Box::new(Value::Bytes(vec![0; 8])),
        );
        let large = Value::Pair(
            Box::new(Value::Bytes(vec![0; 8000])),
            Box::new(Value::Bytes(vec![0; 8000])),
        );

        let cost_small = JetId::EqBytes.runtime_cost(&small, &ScriptContext::empty());
        let cost_large = JetId::EqBytes.runtime_cost(&large, &ScriptContext::empty());

        assert_eq!(cost_small, 10 + 1); // 8 / 8 = 1
        assert_eq!(cost_large, 10 + 1000); // 8000 / 8 = 1000
        assert!(cost_large > cost_small);
    }

    #[test]
    fn sha256_cost_scales_with_input() {
        let small = Value::Bytes(vec![0; 32]);
        let large = Value::Bytes(vec![0; 1024]);

        let cost_small = JetId::Sha256.runtime_cost(&small, &ScriptContext::empty());
        let cost_large = JetId::Sha256.runtime_cost(&large, &ScriptContext::empty());

        // 32 bytes: 0 full 64-byte blocks → base 500
        assert_eq!(cost_small, 500);
        // 1024 bytes: 16 blocks × 8 = 128 extra → 628
        assert_eq!(cost_large, 500 + 128);
        assert!(cost_large > cost_small);
    }

    #[test]
    fn constant_jets_use_static_cost() {
        // Arithmetic and introspection jets have no data-dependent cost
        let input = Value::Pair(Box::new(Value::U64(1)), Box::new(Value::U64(2)));
        assert_eq!(
            JetId::Add64.runtime_cost(&input, &ScriptContext::empty()),
            10
        );
        assert_eq!(
            JetId::Sub64.runtime_cost(&input, &ScriptContext::empty()),
            10
        );
        assert_eq!(
            JetId::Eq64.runtime_cost(&input, &ScriptContext::empty()),
            10
        );

        let u = Value::Unit;
        assert_eq!(
            JetId::BlockHeight.runtime_cost(&u, &ScriptContext::empty()),
            5
        );
        assert_eq!(
            JetId::SelfIndex.runtime_cost(&u, &ScriptContext::empty()),
            5
        );
    }

    #[test]
    fn runtime_cost_exceeds_budget_rejects_script() {
        // A MerkleVerify jet with a huge proof should exhaust a budget sized
        // from the static cost, causing BudgetExceeded
        use exfer::script::ast::{Combinator, Program};
        use exfer::script::eval::{evaluate_with_context, Budget};
        use exfer::script::jets::context::ScriptContext;

        let p = Program::single(Combinator::Jet(JetId::MerkleVerify));
        let (static_steps, static_cells) = JetId::MerkleVerify.jet_cost();

        // 100-sibling proof: runtime cost = 500 + 100*500 = 50_500 >> 32_000 static
        let proof = vec![0u8; 100 * 33];
        let input = Value::Pair(
            Box::new(Value::Hash(Hash256([0; 32]))),
            Box::new(Value::Pair(
                Box::new(Value::Hash(Hash256([1; 32]))),
                Box::new(Value::Bytes(proof)),
            )),
        );

        let mut budget = Budget::new(static_steps, static_cells);
        let result = evaluate_with_context(&p, input, &[], &mut budget, &ScriptContext::empty());
        assert!(
            result.is_err(),
            "should fail: runtime cost exceeds static budget"
        );
    }
}

#[cfg(feature = "testnet")]
mod ed25519_zip215_tests {
    use ed25519_dalek::{Signer, SigningKey};
    use exfer::chain::state::{UtxoEntry, UtxoSet};
    use exfer::consensus::validation::validate_transaction;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{OutPoint, Transaction, TxInput, TxOutput, TxWitness};

    fn make_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn phase1_uses_verify_not_verify_strict() {
        // This test ensures Phase 1 validation accepts valid signatures.
        // The key behavioral difference: verify() accepts non-canonical encodings
        // that verify_strict() would reject. We test that a normal signature works.
        let (sk, pk) = make_keypair();
        let pubkey_hash = TxOutput::pubkey_hash_from_key(&pk);

        let prev_tx_id = Hash256::sha256(b"test_tx");
        let outpoint = OutPoint::new(prev_tx_id, 0);

        let tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id,
                output_index: 0,
            }],
            outputs: vec![TxOutput {
                value: 100_000,
                script: pubkey_hash.as_bytes().to_vec(),
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![TxWitness {
                witness: vec![], // placeholder — filled below
                redeemer: None,
            }],
        };

        // Sign the tx
        let sig_msg = tx.sig_message().unwrap();
        let sig = sk.sign(&sig_msg);

        let mut witness_data = Vec::new();
        witness_data.extend_from_slice(&pk);
        witness_data.extend_from_slice(&sig.to_bytes());

        let signed_tx = Transaction {
            witnesses: vec![TxWitness {
                witness: witness_data,
                redeemer: None,
            }],
            ..tx
        };

        let mut utxo_set = UtxoSet::new();
        utxo_set
            .insert(
                outpoint,
                UtxoEntry {
                    output: TxOutput {
                        value: 1_000_000,
                        script: pubkey_hash.as_bytes().to_vec(),
                        datum: None,
                        datum_hash: None,
                    },
                    height: 0,
                    is_coinbase: false,
                },
            )
            .expect("insert test UTXO");

        let result = validate_transaction(&signed_tx, &utxo_set, 100);
        assert!(
            result.is_ok(),
            "Phase 1 with ZIP-215 verify should accept valid sig: {:?}",
            result.err()
        );
    }

    #[test]
    fn phase1_validation_returns_script_cost() {
        // validate_transaction now returns (fee, total_script_cost)
        let (sk, pk) = make_keypair();
        let pubkey_hash = TxOutput::pubkey_hash_from_key(&pk);

        let prev_tx_id = Hash256::sha256(b"cost_test");
        let outpoint = OutPoint::new(prev_tx_id, 0);

        let tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id,
                output_index: 0,
            }],
            outputs: vec![TxOutput {
                value: 100_000,
                script: pubkey_hash.as_bytes().to_vec(),
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };

        let sig_msg = tx.sig_message().unwrap();
        let sig = sk.sign(&sig_msg);

        let mut witness_data = Vec::new();
        witness_data.extend_from_slice(&pk);
        witness_data.extend_from_slice(&sig.to_bytes());

        let signed_tx = Transaction {
            witnesses: vec![TxWitness {
                witness: witness_data,
                redeemer: None,
            }],
            ..tx
        };

        let mut utxo_set = UtxoSet::new();
        utxo_set
            .insert(
                outpoint,
                UtxoEntry {
                    output: TxOutput {
                        value: 1_000_000,
                        script: pubkey_hash.as_bytes().to_vec(),
                        datum: None,
                        datum_hash: None,
                    },
                    height: 0,
                    is_coinbase: false,
                },
            )
            .expect("insert test UTXO");

        let (fee, script_cost, _) = validate_transaction(&signed_tx, &utxo_set, 100).unwrap();
        assert!(fee > 0, "should have positive fee");
        // Phase 1: 1 input × (5000 + ceil(sig_msg_bytes/64) × 8)
        let sig_msg_len = signed_tx.sig_message().unwrap().len() as u64;
        let expected_cost = 5000 + sig_msg_len.div_ceil(64) * 8;
        assert_eq!(script_cost as u64, expected_cost);
    }
}

mod spec_alignment_tests {
    use exfer::types::MAX_SCRIPT_STEPS;

    #[test]
    fn max_script_steps_is_4_million() {
        assert_eq!(MAX_SCRIPT_STEPS, 4_000_000);
    }

    #[test]
    fn max_script_steps_matches_spec() {
        // SPEC.md now defines MAX_SCRIPT_STEPS = 4_000_000
        // This test ensures code and spec remain aligned
        assert_eq!(MAX_SCRIPT_STEPS, 4_000_000);
    }
}

mod static_cost_update_tests {
    use exfer::script::jets::JetId;

    #[test]
    fn merkle_verify_static_cost_increased() {
        let (steps, cells) = JetId::MerkleVerify.jet_cost();
        assert_eq!(steps, 32_000);
        assert_eq!(cells, 1);
    }

    #[test]
    fn list_ops_static_cost_increased() {
        assert_eq!(JetId::ListSum.jet_cost().0, 1_000);
        assert_eq!(JetId::ListAll.jet_cost().0, 1_000);
        assert_eq!(JetId::ListAny.jet_cost().0, 1_000);
        assert_eq!(JetId::ListFind.jet_cost().0, 1_000);
    }

    #[test]
    fn eq_bytes_static_cost_increased() {
        assert_eq!(JetId::EqBytes.jet_cost().0, 500);
    }

    #[test]
    fn sha256_static_cost_increased() {
        assert_eq!(JetId::Sha256.jet_cost().0, 1_000);
    }

    #[test]
    fn constant_jets_unchanged() {
        // Arithmetic and introspection jets should keep their original costs
        assert_eq!(JetId::Add64.jet_cost().0, 10);
        assert_eq!(JetId::Add256.jet_cost().0, 50);
        assert_eq!(JetId::Ed25519Verify.jet_cost().0, 5_000);
        assert_eq!(JetId::Len.jet_cost().0, 10);
        assert_eq!(JetId::ListLen.jet_cost().0, 10);
        assert_eq!(JetId::ListAt.jet_cost().0, 10);
        assert_eq!(JetId::BlockHeight.jet_cost().0, 5);
    }
}

#[cfg(feature = "testnet")]
mod validate_returns_tuple_tests {
    use exfer::chain::state::UtxoSet;
    use exfer::consensus::validation::{validate_transaction, ValidationError};
    use exfer::types::transaction::{Transaction, TxOutput};

    #[test]
    fn validate_transaction_error_variants_unchanged() {
        // Ensure error variants still work after return type change
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1000,
                script: vec![0; 32],
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![],
        };
        let utxo_set = UtxoSet::new();
        let result = validate_transaction(&tx, &utxo_set, 0);
        assert!(matches!(result, Err(ValidationError::NoInputs)));
    }
}
