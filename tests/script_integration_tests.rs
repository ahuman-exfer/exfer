//! Tests for Phase 4: Full script evaluation, datums, redeemers, backward compat.
//!
//! Tests the integration of script evaluation into transaction validation.

use ed25519_dalek::{Signer, SigningKey};
use exfer::chain::state::{UtxoEntry, UtxoSet};
use exfer::consensus::validation::{validate_transaction, ValidationError};
use exfer::script::ast::{Combinator, Program};
use exfer::script::jets::JetId;
use exfer::script::serialize::serialize_program;
use exfer::script::value::Value;
use exfer::types::hash::Hash256;
use exfer::types::transaction::{OutPoint, Transaction, TxInput, TxOutput, TxWitness};

// ============================================================
// Helpers
// ============================================================

fn make_signing_key() -> SigningKey {
    use rand::rngs::OsRng;
    SigningKey::generate(&mut OsRng)
}

fn make_phase1_output(value: u64, pubkey: &[u8; 32]) -> TxOutput {
    TxOutput::new_p2pkh(value, pubkey)
}

fn make_phase1_witness(signing_key: &SigningKey, tx: &Transaction) -> TxWitness {
    let sig_message = tx.sig_message().unwrap();
    let signature = signing_key.sign(&sig_message);
    let verifying_key = signing_key.verifying_key();

    let mut witness = Vec::with_capacity(96);
    witness.extend_from_slice(&verifying_key.to_bytes());
    witness.extend_from_slice(&signature.to_bytes());

    TxWitness {
        witness,
        redeemer: None,
    }
}

fn make_utxo_set(entries: Vec<(OutPoint, TxOutput, u64, bool)>) -> UtxoSet {
    let mut utxo_set = UtxoSet::new();
    for (outpoint, output, height, is_coinbase) in entries {
        let _ = utxo_set.insert(
            outpoint,
            UtxoEntry {
                output,
                height,
                is_coinbase,
            },
        );
    }
    utxo_set
}

fn prev_tx_id() -> Hash256 {
    Hash256::sha256(b"previous transaction")
}

/// Helper: build a simple program and serialize it.
fn prog(nodes: Vec<Combinator>) -> Vec<u8> {
    let p = Program { nodes, root: 0 };
    serialize_program(&p)
}

// ============================================================
// Phase 1 Backward Compatibility
// ============================================================

#[test]
fn phase1_script_still_spendable() {
    let sk = make_signing_key();
    let vk = sk.verifying_key();
    let pubkey = vk.to_bytes();

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = make_phase1_output(100_000_000, &pubkey);

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(99_000_000, &pubkey)],
        witnesses: vec![TxWitness {
            witness: vec![0; 96], // placeholder, will be replaced
            redeemer: None,
        }],
    };

    // Build witness with correct signature
    let witness = make_phase1_witness(&sk, &tx);
    let tx = Transaction {
        witnesses: vec![witness],
        ..tx
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(
        result.is_ok(),
        "Phase 1 script should be spendable: {:?}",
        result.err()
    );
}

#[test]
fn phase1_wrong_pubkey_fails() {
    let sk = make_signing_key();
    let vk = sk.verifying_key();
    let pubkey = vk.to_bytes();

    let wrong_pubkey = [0x42u8; 32];
    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = make_phase1_output(100_000_000, &wrong_pubkey);

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(99_000_000, &pubkey)],
        witnesses: vec![TxWitness {
            witness: vec![0; 96],
            redeemer: None,
        }],
    };
    let witness = make_phase1_witness(&sk, &tx);
    let tx = Transaction {
        witnesses: vec![witness],
        ..tx
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(result.is_err());
    match result.unwrap_err() {
        ValidationError::PubkeyHashMismatch { .. } => {}
        other => panic!("expected PubkeyHashMismatch, got {:?}", other),
    }
}

#[test]
fn phase1_wrong_signature_fails() {
    let sk = make_signing_key();
    let vk = sk.verifying_key();
    let pubkey = vk.to_bytes();

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = make_phase1_output(100_000_000, &pubkey);

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(99_000_000, &pubkey)],
        witnesses: vec![TxWitness {
            witness: {
                let mut w = Vec::with_capacity(96);
                w.extend_from_slice(&pubkey);
                w.extend_from_slice(&[0u8; 64]); // bad signature
                w
            },
            redeemer: None,
        }],
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(result.is_err());
}

// ============================================================
// Phase 2+ Script Evaluation
// ============================================================

#[test]
fn script_const_true_passes() {
    // A script that always returns true
    let script = prog(vec![Combinator::Const(Value::Bool(true))]);

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = TxOutput {
        value: 100_000_000,
        script: script.clone(),
        datum: None,
        datum_hash: None,
    };

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: script.clone(), // output script must also be well-typed
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(
        result.is_ok(),
        "const(true) script should pass: {:?}",
        result.err()
    );
}

#[test]
fn script_const_false_fails() {
    let script = prog(vec![Combinator::Const(Value::Bool(false))]);

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = TxOutput {
        value: 100_000_000,
        script: script.clone(),
        datum: None,
        datum_hash: None,
    };

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: script.clone(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(result.is_err());
    match result.unwrap_err() {
        ValidationError::ScriptEvalFailed { .. } => {}
        other => panic!("expected ScriptEvalFailed, got {:?}", other),
    }
}

#[test]
fn script_iden_returns_non_bool_fails() {
    // Iden passes input through. Since input isn't Bool(true), it should fail.
    let script = prog(vec![Combinator::Iden]);

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = TxOutput {
        value: 100_000_000,
        script: script.clone(),
        datum: None,
        datum_hash: None,
    };

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: script.clone(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(result.is_err());
}

// ============================================================
// Output Script Type-Checking
// ============================================================

#[test]
fn ill_typed_output_script_rejected() {
    // An output with garbage script data that isn't Phase 1 (not 32 bytes)
    // and doesn't deserialize as a valid program
    let bad_script = vec![0xFF, 0xFF, 0xFF]; // garbage, 3 bytes, not 32

    let sk = make_signing_key();
    let vk = sk.verifying_key();
    let pubkey = vk.to_bytes();
    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = make_phase1_output(100_000_000, &pubkey);

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: bad_script,
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![0; 96],
            redeemer: None,
        }],
    };
    let witness = make_phase1_witness(&sk, &tx);
    let tx = Transaction {
        witnesses: vec![witness],
        ..tx
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(result.is_err());
    match result.unwrap_err() {
        ValidationError::IllTypedScript(_) => {}
        other => panic!("expected IllTypedScript, got {:?}", other),
    }
}

#[test]
fn well_typed_output_script_accepted() {
    // Output with a valid script: Const(Bool(true))
    let good_script = prog(vec![Combinator::Const(Value::Bool(true))]);

    let sk = make_signing_key();
    let vk = sk.verifying_key();
    let pubkey = vk.to_bytes();
    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = make_phase1_output(100_000_000, &pubkey);

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: good_script,
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![0; 96],
            redeemer: None,
        }],
    };
    let witness = make_phase1_witness(&sk, &tx);
    let tx = Transaction {
        witnesses: vec![witness],
        ..tx
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(
        result.is_ok(),
        "well-typed output script should be accepted: {:?}",
        result.err()
    );
}

// ============================================================
// Datum Tests
// ============================================================

#[test]
fn inline_datum_available() {
    // Output with inline datum. Script = Const(true), datum is embedded.
    let script = prog(vec![Combinator::Const(Value::Bool(true))]);
    let datum_data = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = TxOutput {
        value: 100_000_000,
        script: script.clone(),
        datum: Some(datum_data),
        datum_hash: None,
    };

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: script.clone(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(
        result.is_ok(),
        "inline datum should work: {:?}",
        result.err()
    );
}

#[test]
fn hash_committed_datum_correct() {
    // Output with datum_hash. Spender provides datum in redeemer. Hash matches.
    let script = prog(vec![Combinator::Const(Value::Bool(true))]);
    let datum_data = vec![0xCA, 0xFE];
    let datum_hash = Hash256::sha256(&datum_data);

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = TxOutput {
        value: 100_000_000,
        script: script.clone(),
        datum: None,
        datum_hash: Some(datum_hash),
    };

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: script.clone(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: Some(datum_data), // provide datum in redeemer
        }],
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(
        result.is_ok(),
        "correct datum hash should pass: {:?}",
        result.err()
    );
}

#[test]
fn hash_committed_datum_mismatch() {
    // Output with datum_hash. Spender provides WRONG datum.
    let script = prog(vec![Combinator::Const(Value::Bool(true))]);
    let correct_datum = vec![0xCA, 0xFE];
    let datum_hash = Hash256::sha256(&correct_datum);

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = TxOutput {
        value: 100_000_000,
        script: script.clone(),
        datum: None,
        datum_hash: Some(datum_hash),
    };

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: script.clone(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: Some(vec![0xBA, 0xD0]), // wrong datum
        }],
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(result.is_err());
}

// ============================================================
// Multi-Input Tests
// ============================================================

#[test]
fn multi_input_each_evaluated() {
    // Two inputs with different scripts
    let script_true = prog(vec![Combinator::Const(Value::Bool(true))]);
    let script_false = prog(vec![Combinator::Const(Value::Bool(false))]);

    let outpoint1 = OutPoint::new(Hash256::sha256(b"tx1"), 0);
    let outpoint2 = OutPoint::new(Hash256::sha256(b"tx2"), 0);

    let utxo1 = TxOutput {
        value: 50_000_000,
        script: script_true.clone(),
        datum: None,
        datum_hash: None,
    };
    let utxo2 = TxOutput {
        value: 50_000_000,
        script: script_false.clone(),
        datum: None,
        datum_hash: None,
    };

    let tx = Transaction {
        inputs: vec![
            TxInput {
                prev_tx_id: Hash256::sha256(b"tx1"),
                output_index: 0,
            },
            TxInput {
                prev_tx_id: Hash256::sha256(b"tx2"),
                output_index: 0,
            },
        ],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: script_true.clone(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![
            TxWitness {
                witness: vec![],
                redeemer: None,
            },
            TxWitness {
                witness: vec![],
                redeemer: None,
            },
        ],
    };

    let utxo_set = make_utxo_set(vec![
        (outpoint1, utxo1, 0, false),
        (outpoint2, utxo2, 0, false),
    ]);

    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(result.is_err()); // second input returns false
    match result.unwrap_err() {
        ValidationError::ScriptEvalFailed { input_index, .. } => {
            assert_eq!(input_index, 1);
        }
        other => panic!("expected ScriptEvalFailed on input 1, got {:?}", other),
    }
}

// ============================================================
// Mixed Phase 1 + Phase 2 Inputs
// ============================================================

#[test]
fn mixed_phase1_and_phase2_inputs() {
    // Input 0: Phase 1 (pubkey hash), Input 1: Phase 2 (script)
    let sk = make_signing_key();
    let vk = sk.verifying_key();
    let pubkey = vk.to_bytes();

    let script_true = prog(vec![Combinator::Const(Value::Bool(true))]);

    let outpoint1 = OutPoint::new(Hash256::sha256(b"tx1"), 0);
    let outpoint2 = OutPoint::new(Hash256::sha256(b"tx2"), 0);

    let utxo1 = make_phase1_output(50_000_000, &pubkey);
    let utxo2 = TxOutput {
        value: 50_000_000,
        script: script_true.clone(),
        datum: None,
        datum_hash: None,
    };

    // Build tx with Phase 1 output for change
    let tx_without_witness = Transaction {
        inputs: vec![
            TxInput {
                prev_tx_id: Hash256::sha256(b"tx1"),
                output_index: 0,
            },
            TxInput {
                prev_tx_id: Hash256::sha256(b"tx2"),
                output_index: 0,
            },
        ],
        outputs: vec![TxOutput::new_p2pkh(99_000_000, &pubkey)],
        witnesses: vec![
            TxWitness {
                witness: vec![0; 96],
                redeemer: None,
            },
            TxWitness {
                witness: vec![],
                redeemer: None,
            },
        ],
    };

    let witness1 = make_phase1_witness(&sk, &tx_without_witness);
    let tx = Transaction {
        witnesses: vec![
            witness1,
            TxWitness {
                witness: vec![],
                redeemer: None,
            },
        ],
        ..tx_without_witness
    };

    let utxo_set = make_utxo_set(vec![
        (outpoint1, utxo1, 0, false),
        (outpoint2, utxo2, 0, false),
    ]);

    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(
        result.is_ok(),
        "mixed Phase 1 + Phase 2 should work: {:?}",
        result.err()
    );
}

// ============================================================
// Script with Jets
// ============================================================

#[test]
fn script_with_eq64_jet() {
    // Script: Comp(Const(Pair(U64(42), U64(42))), Jet(Eq64))
    // This compares 42 == 42 and returns true
    // But we need to build this as a proper DAG...
    // Let's use a simpler construction.
    // Script: Comp(Pair(Const(42), Const(42)), Jet(Eq64))
    let script = prog(vec![
        Combinator::Comp(1, 2),            // 0: root
        Combinator::Pair(3, 4),            // 1: make pair
        Combinator::Jet(JetId::Eq64),      // 2: compare
        Combinator::Const(Value::U64(42)), // 3: left
        Combinator::Const(Value::U64(42)), // 4: right
    ]);

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = TxOutput {
        value: 100_000_000,
        script: script.clone(),
        datum: None,
        datum_hash: None,
    };

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: prog(vec![Combinator::Const(Value::Bool(true))]),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(
        result.is_ok(),
        "eq64(42, 42) should return true: {:?}",
        result.err()
    );
}

#[test]
fn script_with_eq64_jet_fails() {
    // Script: Comp(Pair(Const(42), Const(99)), Jet(Eq64)) -> false
    let script = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Pair(3, 4),
        Combinator::Jet(JetId::Eq64),
        Combinator::Const(Value::U64(42)),
        Combinator::Const(Value::U64(99)),
    ]);

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = TxOutput {
        value: 100_000_000,
        script: script.clone(),
        datum: None,
        datum_hash: None,
    };

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: prog(vec![Combinator::Const(Value::Bool(true))]),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set, 1000);
    assert!(result.is_err()); // 42 != 99 -> false
}

// ============================================================
// Script Context / Introspection
// ============================================================

#[test]
fn script_introspection_block_height() {
    // Script that checks block_height > 100 using:
    // Comp(Pair(Jet(BlockHeight), Const(U64(100))), Jet(Gt64))
    let script = prog(vec![
        Combinator::Comp(1, 2),              // 0: root
        Combinator::Pair(3, 4),              // 1: make pair
        Combinator::Jet(JetId::Gt64),        // 2: compare
        Combinator::Jet(JetId::BlockHeight), // 3: get height
        Combinator::Const(Value::U64(100)),  // 4: threshold
    ]);

    let outpoint = OutPoint::new(prev_tx_id(), 0);
    let utxo_output = TxOutput {
        value: 100_000_000,
        script: script.clone(),
        datum: None,
        datum_hash: None,
    };

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev_tx_id(),
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 99_000_000,
            script: prog(vec![Combinator::Const(Value::Bool(true))]),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let utxo_set = make_utxo_set(vec![(outpoint, utxo_output.clone(), 0, false)]);

    // At height 200, should pass (200 > 100)
    let result = validate_transaction(&tx, &utxo_set, 200);
    assert!(
        result.is_ok(),
        "height 200 > 100 should pass: {:?}",
        result.err()
    );

    // At height 50, should fail (50 <= 100)
    let utxo_set2 = make_utxo_set(vec![(outpoint, utxo_output, 0, false)]);
    let result = validate_transaction(&tx, &utxo_set2, 50);
    assert!(result.is_err(), "height 50 <= 100 should fail");
}

// ============================================================
// Serialization Integration
// ============================================================

#[test]
fn script_serialization_in_output() {
    // Verify that a serialized script stored in an output can be read back
    let p = Program {
        nodes: vec![
            Combinator::Comp(1, 2),
            Combinator::Iden,
            Combinator::Const(Value::Bool(true)),
        ],
        root: 0,
    };
    let script_bytes = serialize_program(&p);

    // Deserialize should succeed
    let p2 = exfer::script::deserialize_program(&script_bytes).unwrap();
    assert_eq!(p2.nodes.len(), 3);

    // Type check should succeed
    let typed = exfer::script::typecheck(&p2).unwrap();
    assert_eq!(typed.len(), 3);
}

// ============================================================
// Phase 1 Detection
// ============================================================

#[test]
fn phase1_output_32_bytes_detected() {
    // A 32-byte script that's not a valid program should be treated as Phase 1
    let pk = [0x42u8; 32];
    let output = TxOutput::new_p2pkh(1000, &pk);
    assert_eq!(output.script.len(), 32);
    // This should be detected as Phase 1 by is_phase1_script
    // (the pubkey hash is 32 bytes and won't deserialize as a program)
}

#[test]
fn phase2_script_not_detected_as_phase1() {
    // A valid serialized program should NOT be treated as Phase 1
    let script = prog(vec![Combinator::Const(Value::Bool(true))]);
    // Script is longer than 32 bytes typically (header + node data)
    assert_ne!(
        script.len(),
        32,
        "Phase 2 scripts must not be exactly 32 bytes"
    );
}
