//! Tests for Phase 5 covenant templates.

use exfer::covenants::builder::ScriptBuilder;
use exfer::covenants::{delegation, escrow, htlc, multisig, vault};
use exfer::script::eval::{evaluate, evaluate_with_context, Budget};
use exfer::script::jets::context::ScriptContext;
use exfer::script::serialize::{deserialize_program, serialize_program};
use exfer::script::typecheck::typecheck;
use exfer::script::value::Value;
use exfer::types::hash::Hash256;

use ed25519_dalek::{Signer, SigningKey};

// ── Helpers ──

fn make_keypair(seed: u8) -> (SigningKey, [u8; 32]) {
    let secret = [seed; 32];
    let sk = SigningKey::from_bytes(&secret);
    let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    (sk, pk_bytes)
}

fn sign(sk: &SigningKey, message: &[u8]) -> Vec<u8> {
    let sig = sk.sign(message);
    sig.to_bytes().to_vec()
}

fn witness_values(values: &[Value]) -> Vec<u8> {
    let mut data = Vec::new();
    for v in values {
        data.extend_from_slice(&v.serialize());
    }
    data
}

#[allow(dead_code)]
fn context_at_height(height: u64) -> ScriptContext {
    ScriptContext {
        tx_inputs: vec![].into(),
        tx_outputs: vec![].into(),
        self_index: 0,
        block_height: height,
        sig_hash: vec![].into(),
    }
}

fn context_with_sig_hash(height: u64, sig_hash: Vec<u8>) -> ScriptContext {
    ScriptContext {
        tx_inputs: vec![].into(),
        tx_outputs: vec![].into(),
        self_index: 0,
        block_height: height,
        sig_hash: sig_hash.into(),
    }
}

// ── ScriptBuilder basic tests ──

#[test]
fn builder_const_true() {
    let mut b = ScriptBuilder::new();
    let _root = b.const_true();
    let program = b.build();
    assert!(program.validate_structure().is_ok());
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&program, Value::Unit, &[], &mut budget).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn builder_const_false() {
    let mut b = ScriptBuilder::new();
    let _root = b.const_false();
    let program = b.build();
    assert!(program.validate_structure().is_ok());
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&program, Value::Unit, &[], &mut budget).unwrap();
    assert_eq!(result, Value::Bool(false));
}

#[test]
fn builder_and_true_true() {
    let mut b = ScriptBuilder::new();
    let a = b.const_true();
    let b_node = b.const_true();
    let _root = b.and(a, b_node);
    let program = b.build();
    assert!(program.validate_structure().is_ok());
    let mut budget = Budget::new(1000, 1000);
    let result = evaluate(&program, Value::Unit, &[], &mut budget).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn builder_and_true_false() {
    let mut b = ScriptBuilder::new();
    let a = b.const_true();
    let b_node = b.const_false();
    let _root = b.and(a, b_node);
    let program = b.build();
    let mut budget = Budget::new(1000, 1000);
    let result = evaluate(&program, Value::Unit, &[], &mut budget).unwrap();
    assert_eq!(result, Value::Bool(false));
}

#[test]
fn builder_and_false_true() {
    let mut b = ScriptBuilder::new();
    let a = b.const_false();
    let b_node = b.const_true();
    let _root = b.and(a, b_node);
    let program = b.build();
    let mut budget = Budget::new(1000, 1000);
    let result = evaluate(&program, Value::Unit, &[], &mut budget).unwrap();
    // Short-circuits: a is false, so result is false regardless of b
    assert_eq!(result, Value::Bool(false));
}

#[test]
fn builder_or_true_false() {
    let mut b = ScriptBuilder::new();
    let a = b.const_true();
    let b_node = b.const_false();
    let _root = b.or(a, b_node);
    let program = b.build();
    let mut budget = Budget::new(1000, 1000);
    let result = evaluate(&program, Value::Unit, &[], &mut budget).unwrap();
    // Short-circuits: a is true, so result is true
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn builder_or_false_true() {
    let mut b = ScriptBuilder::new();
    let a = b.const_false();
    let b_node = b.const_true();
    let _root = b.or(a, b_node);
    let program = b.build();
    let mut budget = Budget::new(1000, 1000);
    let result = evaluate(&program, Value::Unit, &[], &mut budget).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn builder_or_false_false() {
    let mut b = ScriptBuilder::new();
    let a = b.const_false();
    let b_node = b.const_false();
    let _root = b.or(a, b_node);
    let program = b.build();
    let mut budget = Budget::new(1000, 1000);
    let result = evaluate(&program, Value::Unit, &[], &mut budget).unwrap();
    assert_eq!(result, Value::Bool(false));
}

#[test]
fn builder_serialization_roundtrip() {
    let mut b = ScriptBuilder::new();
    let a = b.const_true();
    let b_node = b.const_false();
    let _root = b.and(a, b_node);
    let program = b.build();

    let bytes = serialize_program(&program);
    let deserialized = deserialize_program(&bytes).unwrap();
    assert_eq!(program.nodes.len(), deserialized.nodes.len());
    assert_eq!(program.root, deserialized.root);
}

// ── Multisig tests ──

#[test]
fn multisig_2of2_valid() {
    let (sk_a, pk_a) = make_keypair(1);
    let (sk_b, pk_b) = make_keypair(2);
    let program = multisig::multisig_2of2(&pk_a, &pk_b);
    assert!(program.validate_structure().is_ok());

    let message = b"test transaction data";
    let sig_a = sign(&sk_a, message);
    let sig_b = sign(&sk_b, message);

    let witness = witness_values(&[Value::Bytes(sig_a), Value::Bytes(sig_b)]);

    let ctx = context_with_sig_hash(0, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn multisig_2of2_one_invalid_sig() {
    let (sk_a, pk_a) = make_keypair(1);
    let (_sk_b, pk_b) = make_keypair(2);
    let program = multisig::multisig_2of2(&pk_a, &pk_b);

    let message = b"test transaction data";
    let sig_a = sign(&sk_a, message);
    let bad_sig = vec![0u8; 64]; // invalid signature

    let witness = witness_values(&[Value::Bytes(sig_a), Value::Bytes(bad_sig)]);

    let ctx = context_with_sig_hash(0, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    // First sig passes, second fails → AND returns false
    assert_eq!(result, Value::Bool(false));
}

#[test]
fn multisig_2of2_wrong_key() {
    let (sk_a, pk_a) = make_keypair(1);
    let (_sk_b, pk_b) = make_keypair(2);
    let (sk_c, _pk_c) = make_keypair(3);
    let program = multisig::multisig_2of2(&pk_a, &pk_b);

    let message = b"test transaction data";
    let sig_a = sign(&sk_a, message);
    let sig_c = sign(&sk_c, message); // signed by C, not B

    let witness = witness_values(&[Value::Bytes(sig_a), Value::Bytes(sig_c)]);

    let ctx = context_with_sig_hash(0, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(false));
}

#[test]
fn multisig_1of2_key_a() {
    let (sk_a, pk_a) = make_keypair(1);
    let (_sk_b, pk_b) = make_keypair(2);
    let program = multisig::multisig_1of2(&pk_a, &pk_b);
    assert!(program.validate_structure().is_ok());

    let message = b"test data";
    let sig_a = sign(&sk_a, message);

    // Selector: Left(Unit) for key A
    let witness = witness_values(&[Value::Left(Box::new(Value::Unit)), Value::Bytes(sig_a)]);

    let ctx = context_with_sig_hash(0, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn multisig_1of2_key_b() {
    let (_sk_a, pk_a) = make_keypair(1);
    let (sk_b, pk_b) = make_keypair(2);
    let program = multisig::multisig_1of2(&pk_a, &pk_b);

    let message = b"test data";
    let sig_b = sign(&sk_b, message);

    // Selector: Right(Unit) for key B
    let witness = witness_values(&[Value::Right(Box::new(Value::Unit)), Value::Bytes(sig_b)]);

    let ctx = context_with_sig_hash(0, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn multisig_2of3_ab_combination() {
    let (sk_a, pk_a) = make_keypair(1);
    let (sk_b, pk_b) = make_keypair(2);
    let (_sk_c, pk_c) = make_keypair(3);
    let program = multisig::multisig_2of3(&pk_a, &pk_b, &pk_c);
    assert!(program.validate_structure().is_ok());

    let message = b"2of3 test";
    let sig_a = sign(&sk_a, message);
    let sig_b = sign(&sk_b, message);

    // Selector: Left(Left(Unit)) for A+B
    let witness = witness_values(&[
        Value::Left(Box::new(Value::Left(Box::new(Value::Unit)))),
        Value::Bytes(sig_a),
        Value::Bytes(sig_b),
    ]);

    let ctx = context_with_sig_hash(0, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn multisig_2of3_bc_combination() {
    let (_sk_a, pk_a) = make_keypair(1);
    let (sk_b, pk_b) = make_keypair(2);
    let (sk_c, pk_c) = make_keypair(3);
    let program = multisig::multisig_2of3(&pk_a, &pk_b, &pk_c);

    let message = b"2of3 test";
    let sig_b = sign(&sk_b, message);
    let sig_c = sign(&sk_c, message);

    // Selector: Right(Unit) for B+C
    let witness = witness_values(&[
        Value::Right(Box::new(Value::Unit)),
        Value::Bytes(sig_b),
        Value::Bytes(sig_c),
    ]);

    let ctx = context_with_sig_hash(0, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

// ── HTLC tests ──

#[test]
fn htlc_hash_path_valid_preimage() {
    let (_sk_s, pk_s) = make_keypair(10);
    let (sk_r, pk_r) = make_keypair(11);

    let preimage = b"secret preimage";
    let hash_lock = Hash256::sha256(preimage);
    let program = htlc::htlc(&pk_s, &pk_r, &hash_lock, 1000);
    assert!(program.validate_structure().is_ok());

    let message = b"htlc claim";
    let sig_r = sign(&sk_r, message);

    // Hash path: Left(Unit) selector
    let witness = witness_values(&[
        Value::Left(Box::new(Value::Unit)),
        Value::Bytes(preimage.to_vec()),
        Value::Bytes(sig_r),
    ]);

    let ctx = context_with_sig_hash(500, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn htlc_hash_path_wrong_preimage() {
    let (_sk_s, pk_s) = make_keypair(10);
    let (sk_r, pk_r) = make_keypair(11);

    let preimage = b"secret preimage";
    let hash_lock = Hash256::sha256(preimage);
    let program = htlc::htlc(&pk_s, &pk_r, &hash_lock, 1000);

    let wrong_preimage = b"wrong preimage!";
    let message = b"htlc claim";
    let sig_r = sign(&sk_r, message);

    let witness = witness_values(&[
        Value::Left(Box::new(Value::Unit)),
        Value::Bytes(wrong_preimage.to_vec()),
        Value::Bytes(sig_r),
    ]);

    let ctx = context_with_sig_hash(500, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx);
    // hash_eq fails → AND short-circuits → false (or Err from unconsumed witness)
    match result {
        Ok(Value::Bool(false)) => {}
        Err(_) => {}
        other => panic!("expected script failure, got {:?}", other),
    }
}

#[test]
fn htlc_timeout_path_after_expiry() {
    let (sk_s, pk_s) = make_keypair(10);
    let (_sk_r, pk_r) = make_keypair(11);

    let hash_lock = Hash256::sha256(b"irrelevant");
    let program = htlc::htlc(&pk_s, &pk_r, &hash_lock, 1000);

    let message = b"timeout reclaim";
    let sig_s = sign(&sk_s, message);

    // Timeout path: Right(Unit) selector
    let witness = witness_values(&[Value::Right(Box::new(Value::Unit)), Value::Bytes(sig_s)]);

    // Block height 1500 > timeout 1000
    let ctx = context_with_sig_hash(1500, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn htlc_timeout_path_before_expiry() {
    let (sk_s, pk_s) = make_keypair(10);
    let (_sk_r, pk_r) = make_keypair(11);

    let hash_lock = Hash256::sha256(b"irrelevant");
    let program = htlc::htlc(&pk_s, &pk_r, &hash_lock, 1000);

    let message = b"too early";
    let sig_s = sign(&sk_s, message);

    let witness = witness_values(&[Value::Right(Box::new(Value::Unit)), Value::Bytes(sig_s)]);

    // Block height 500 < timeout 1000
    let ctx = context_with_sig_hash(500, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx);
    // height_gt(1000) fails at height 500 → false (or Err from unconsumed witness)
    match result {
        Ok(Value::Bool(false)) => {}
        Err(_) => {}
        other => panic!("expected script failure, got {:?}", other),
    }
}

// ── Escrow tests ──

#[test]
fn escrow_mutual_close() {
    let (sk_a, pk_a) = make_keypair(20);
    let (sk_b, pk_b) = make_keypair(21);
    let (_sk_arb, pk_arb) = make_keypair(22);
    let program = escrow::escrow(&pk_a, &pk_b, &pk_arb, 5000);
    assert!(program.validate_structure().is_ok());

    let message = b"mutual close";
    let sig_a = sign(&sk_a, message);
    let sig_b = sign(&sk_b, message);

    // Mutual: Left(Left(Unit))
    let witness = witness_values(&[
        Value::Left(Box::new(Value::Left(Box::new(Value::Unit)))),
        Value::Bytes(sig_a),
        Value::Bytes(sig_b),
    ]);

    let ctx = context_with_sig_hash(100, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn escrow_arbiter_decision() {
    let (_sk_a, pk_a) = make_keypair(20);
    let (_sk_b, pk_b) = make_keypair(21);
    let (sk_arb, pk_arb) = make_keypair(22);
    let program = escrow::escrow(&pk_a, &pk_b, &pk_arb, 5000);

    let message = b"arbiter says release";
    let sig_arb = sign(&sk_arb, message);

    // Arbiter: Left(Right(Unit))
    let witness = witness_values(&[
        Value::Left(Box::new(Value::Right(Box::new(Value::Unit)))),
        Value::Bytes(sig_arb),
    ]);

    let ctx = context_with_sig_hash(100, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn escrow_timeout_refund() {
    let (sk_a, pk_a) = make_keypair(20);
    let (_sk_b, pk_b) = make_keypair(21);
    let (_sk_arb, pk_arb) = make_keypair(22);
    let program = escrow::escrow(&pk_a, &pk_b, &pk_arb, 5000);

    let message = b"timeout refund";
    let sig_a = sign(&sk_a, message);

    // Timeout: Right(Unit)
    let witness = witness_values(&[Value::Right(Box::new(Value::Unit)), Value::Bytes(sig_a)]);

    // Block height 6000 > timeout 5000
    let ctx = context_with_sig_hash(6000, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

// ── Vault tests ──

#[test]
fn vault_normal_spend_after_locktime() {
    let (sk_p, pk_p) = make_keypair(30);
    let (_sk_r, pk_r) = make_keypair(31);
    let program = vault::vault(&pk_p, &pk_r, 2000);
    assert!(program.validate_structure().is_ok());

    let message = b"vault normal spend";
    let sig_p = sign(&sk_p, message);

    // Normal: Left(Unit)
    let witness = witness_values(&[Value::Left(Box::new(Value::Unit)), Value::Bytes(sig_p)]);

    // Block height 3000 > locktime 2000
    let ctx = context_with_sig_hash(3000, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn vault_normal_spend_before_locktime_fails() {
    let (sk_p, pk_p) = make_keypair(30);
    let (_sk_r, pk_r) = make_keypair(31);
    let program = vault::vault(&pk_p, &pk_r, 2000);

    let message = b"too early";
    let sig_p = sign(&sk_p, message);

    let witness = witness_values(&[Value::Left(Box::new(Value::Unit)), Value::Bytes(sig_p)]);

    // Block height 1000 < locktime 2000
    let ctx = context_with_sig_hash(1000, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx);
    // locktime not met → false (or Err from unconsumed witness)
    match result {
        Ok(Value::Bool(false)) => {}
        Err(_) => {}
        other => panic!("expected script failure, got {:?}", other),
    }
}

#[test]
fn vault_recovery_anytime() {
    let (_sk_p, pk_p) = make_keypair(30);
    let (sk_r, pk_r) = make_keypair(31);
    let program = vault::vault(&pk_p, &pk_r, 2000);

    let message = b"emergency recovery";
    let sig_r = sign(&sk_r, message);

    // Recovery: Right(Unit)
    let witness = witness_values(&[Value::Right(Box::new(Value::Unit)), Value::Bytes(sig_r)]);

    // Recovery works at any height, even before locktime
    let ctx = context_with_sig_hash(100, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

// ── Delegation tests ──

#[test]
fn delegation_owner_always_works() {
    let (sk_o, pk_o) = make_keypair(40);
    let (_sk_d, pk_d) = make_keypair(41);
    let program = delegation::delegation(&pk_o, &pk_d, 10_000);
    assert!(program.validate_structure().is_ok());

    let message = b"owner spend";
    let sig_o = sign(&sk_o, message);

    // Owner: Left(Unit)
    let witness = witness_values(&[Value::Left(Box::new(Value::Unit)), Value::Bytes(sig_o)]);

    // Works at any height
    let ctx = context_with_sig_hash(50_000, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn delegation_delegate_before_expiry() {
    let (_sk_o, pk_o) = make_keypair(40);
    let (sk_d, pk_d) = make_keypair(41);
    let program = delegation::delegation(&pk_o, &pk_d, 10_000);

    let message = b"delegate spend";
    let sig_d = sign(&sk_d, message);

    // Delegate: Right(Unit)
    let witness = witness_values(&[Value::Right(Box::new(Value::Unit)), Value::Bytes(sig_d)]);

    // Before expiry
    let ctx = context_with_sig_hash(5000, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn delegation_delegate_after_expiry_fails() {
    let (_sk_o, pk_o) = make_keypair(40);
    let (sk_d, pk_d) = make_keypair(41);
    let program = delegation::delegation(&pk_o, &pk_d, 10_000);

    let message = b"expired delegate";
    let sig_d = sign(&sk_d, message);

    let witness = witness_values(&[Value::Right(Box::new(Value::Unit)), Value::Bytes(sig_d)]);

    // After expiry
    let ctx = context_with_sig_hash(15_000, message.to_vec());
    let mut budget = Budget::new(100_000, 100_000);
    let result = evaluate_with_context(&program, Value::Unit, &witness, &mut budget, &ctx).unwrap();
    // sig passes but height_lt(10000) fails at height 15000 → false
    assert_eq!(result, Value::Bool(false));
}

// ── Type-checking tests ──

#[test]
fn all_covenants_typecheck() {
    let pk = [1u8; 32];

    let lock = Hash256::sha256(b"test");
    let programs = [
        multisig::multisig_2of2(&pk, &pk),
        multisig::multisig_1of2(&pk, &pk),
        multisig::multisig_2of3(&pk, &pk, &pk),
        htlc::htlc(&pk, &pk, &lock, 1000),
        escrow::escrow(&pk, &pk, &pk, 5000),
        vault::vault(&pk, &pk, 2000),
        delegation::delegation(&pk, &pk, 10000),
    ];

    for (i, program) in programs.iter().enumerate() {
        assert!(
            program.validate_structure().is_ok(),
            "program {} structure invalid",
            i
        );
        assert!(
            typecheck(program).is_ok(),
            "program {} type-check failed",
            i
        );
    }
}

#[test]
fn htlc_structure_valid() {
    let pk = [1u8; 32];
    let lock = Hash256::sha256(b"test");
    let program = htlc::htlc(&pk, &pk, &lock, 1000);
    assert!(program.validate_structure().is_ok());
}

#[test]
fn all_covenants_serialize_roundtrip() {
    let pk = [1u8; 32];
    let lock = Hash256::sha256(b"test");

    let programs = [
        multisig::multisig_2of2(&pk, &pk),
        multisig::multisig_1of2(&pk, &pk),
        htlc::htlc(&pk, &pk, &lock, 1000),
        escrow::escrow(&pk, &pk, &pk, 5000),
        vault::vault(&pk, &pk, 2000),
        delegation::delegation(&pk, &pk, 10000),
    ];

    for (i, program) in programs.iter().enumerate() {
        let bytes = serialize_program(program);
        let roundtripped = deserialize_program(&bytes)
            .unwrap_or_else(|e| panic!("program {} deserialize failed: {:?}", i, e));
        assert_eq!(
            program.nodes.len(),
            roundtripped.nodes.len(),
            "program {} node count mismatch",
            i
        );
        assert_eq!(
            program.root, roundtripped.root,
            "program {} root mismatch",
            i
        );
    }
}
