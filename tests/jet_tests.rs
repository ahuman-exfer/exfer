//! Tests for Phase 3: Jet implementations.
//!
//! Coverage: crypto, arithmetic (64 + 256), bytes, introspection, list ops.

use exfer::script::ast::{Combinator, Program};
use exfer::script::eval::{evaluate_with_context, Budget, EvalError};
use exfer::script::jets::context::{ScriptContext, TxInputInfo, TxOutputInfo};
use exfer::script::jets::JetId;
use exfer::script::value::Value;
use exfer::types::hash::Hash256;

/// Helper: evaluate a single jet on an input value.
fn eval_jet(jet: JetId, input: Value) -> Result<Value, EvalError> {
    let p = Program::single(Combinator::Jet(jet));
    let mut budget = Budget::new(100_000, 100_000);
    evaluate_with_context(&p, input, &[], &mut budget, &ScriptContext::empty())
}

/// Helper: evaluate a jet with a script context.
fn eval_jet_ctx(jet: JetId, input: Value, ctx: &ScriptContext) -> Result<Value, EvalError> {
    let p = Program::single(Combinator::Jet(jet));
    let mut budget = Budget::new(100_000, 100_000);
    evaluate_with_context(&p, input, &[], &mut budget, ctx)
}

fn u64_pair(a: u64, b: u64) -> Value {
    Value::Pair(Box::new(Value::U64(a)), Box::new(Value::U64(b)))
}

fn u256_pair(a: [u8; 32], b: [u8; 32]) -> Value {
    Value::Pair(Box::new(Value::U256(a)), Box::new(Value::U256(b)))
}

fn u256_from_u64(n: u64) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr[24..32].copy_from_slice(&n.to_be_bytes());
    arr
}

// ============================================================
// Arithmetic 64-bit
// ============================================================

#[test]
fn jet_add64_normal() {
    let r = eval_jet(JetId::Add64, u64_pair(10, 20)).unwrap();
    assert_eq!(r, Value::U64(30));
}

#[test]
fn jet_add64_overflow() {
    let r = eval_jet(JetId::Add64, u64_pair(u64::MAX, 1));
    assert!(r.is_err());
}

#[test]
fn jet_sub64_normal() {
    let r = eval_jet(JetId::Sub64, u64_pair(30, 10)).unwrap();
    assert_eq!(r, Value::U64(20));
}

#[test]
fn jet_sub64_underflow() {
    let r = eval_jet(JetId::Sub64, u64_pair(5, 10));
    assert!(r.is_err());
}

#[test]
fn jet_mul64_normal() {
    let r = eval_jet(JetId::Mul64, u64_pair(6, 7)).unwrap();
    assert_eq!(r, Value::U64(42));
}

#[test]
fn jet_mul64_overflow() {
    let r = eval_jet(JetId::Mul64, u64_pair(u64::MAX, 2));
    assert!(r.is_err());
}

#[test]
fn jet_div64_normal() {
    let r = eval_jet(JetId::Div64, u64_pair(42, 7)).unwrap();
    assert_eq!(r, Value::U64(6));
}

#[test]
fn jet_div64_truncating() {
    let r = eval_jet(JetId::Div64, u64_pair(10, 3)).unwrap();
    assert_eq!(r, Value::U64(3));
}

#[test]
fn jet_div64_by_zero() {
    let r = eval_jet(JetId::Div64, u64_pair(10, 0));
    assert!(r.is_err());
}

#[test]
fn jet_mod64_normal() {
    let r = eval_jet(JetId::Mod64, u64_pair(10, 3)).unwrap();
    assert_eq!(r, Value::U64(1));
}

#[test]
fn jet_mod64_by_zero() {
    let r = eval_jet(JetId::Mod64, u64_pair(10, 0));
    assert!(r.is_err());
}

#[test]
fn jet_eq64_true() {
    let r = eval_jet(JetId::Eq64, u64_pair(42, 42)).unwrap();
    assert_eq!(r, Value::Bool(true));
}

#[test]
fn jet_eq64_false() {
    let r = eval_jet(JetId::Eq64, u64_pair(1, 2)).unwrap();
    assert_eq!(r, Value::Bool(false));
}

#[test]
fn jet_lt64_true() {
    let r = eval_jet(JetId::Lt64, u64_pair(1, 2)).unwrap();
    assert_eq!(r, Value::Bool(true));
}

#[test]
fn jet_lt64_false() {
    let r = eval_jet(JetId::Lt64, u64_pair(2, 1)).unwrap();
    assert_eq!(r, Value::Bool(false));
}

#[test]
fn jet_gt64_true() {
    let r = eval_jet(JetId::Gt64, u64_pair(5, 3)).unwrap();
    assert_eq!(r, Value::Bool(true));
}

#[test]
fn jet_gt64_false() {
    let r = eval_jet(JetId::Gt64, u64_pair(3, 5)).unwrap();
    assert_eq!(r, Value::Bool(false));
}

#[test]
fn jet_add64_zero() {
    let r = eval_jet(JetId::Add64, u64_pair(0, 0)).unwrap();
    assert_eq!(r, Value::U64(0));
}

// ============================================================
// Arithmetic 256-bit
// ============================================================

#[test]
fn jet_add256_normal() {
    let a = u256_from_u64(100);
    let b = u256_from_u64(200);
    let r = eval_jet(JetId::Add256, u256_pair(a, b)).unwrap();
    match r {
        Value::U256(data) => assert_eq!(data, u256_from_u64(300)),
        other => panic!("expected U256, got {:?}", other),
    }
}

#[test]
fn jet_sub256_normal() {
    let a = u256_from_u64(300);
    let b = u256_from_u64(100);
    let r = eval_jet(JetId::Sub256, u256_pair(a, b)).unwrap();
    match r {
        Value::U256(data) => assert_eq!(data, u256_from_u64(200)),
        other => panic!("expected U256, got {:?}", other),
    }
}

#[test]
fn jet_sub256_underflow() {
    let a = u256_from_u64(1);
    let b = u256_from_u64(2);
    let r = eval_jet(JetId::Sub256, u256_pair(a, b));
    assert!(r.is_err());
}

#[test]
fn jet_mul256_normal() {
    let a = u256_from_u64(6);
    let b = u256_from_u64(7);
    let r = eval_jet(JetId::Mul256, u256_pair(a, b)).unwrap();
    match r {
        Value::U256(data) => assert_eq!(data, u256_from_u64(42)),
        other => panic!("expected U256, got {:?}", other),
    }
}

#[test]
fn jet_div256_normal() {
    let a = u256_from_u64(42);
    let b = u256_from_u64(7);
    let r = eval_jet(JetId::Div256, u256_pair(a, b)).unwrap();
    match r {
        Value::U256(data) => assert_eq!(data, u256_from_u64(6)),
        other => panic!("expected U256, got {:?}", other),
    }
}

#[test]
fn jet_div256_by_zero() {
    let a = u256_from_u64(42);
    let b = [0u8; 32];
    let r = eval_jet(JetId::Div256, u256_pair(a, b));
    assert!(r.is_err());
}

#[test]
fn jet_mod256_normal() {
    let a = u256_from_u64(10);
    let b = u256_from_u64(3);
    let r = eval_jet(JetId::Mod256, u256_pair(a, b)).unwrap();
    match r {
        Value::U256(data) => assert_eq!(data, u256_from_u64(1)),
        other => panic!("expected U256, got {:?}", other),
    }
}

#[test]
fn jet_eq256_true() {
    let a = u256_from_u64(42);
    let r = eval_jet(JetId::Eq256, u256_pair(a, a)).unwrap();
    assert_eq!(r, Value::Bool(true));
}

#[test]
fn jet_eq256_false() {
    let a = u256_from_u64(1);
    let b = u256_from_u64(2);
    let r = eval_jet(JetId::Eq256, u256_pair(a, b)).unwrap();
    assert_eq!(r, Value::Bool(false));
}

#[test]
fn jet_lt256_true() {
    let a = u256_from_u64(1);
    let b = u256_from_u64(2);
    let r = eval_jet(JetId::Lt256, u256_pair(a, b)).unwrap();
    assert_eq!(r, Value::Bool(true));
}

#[test]
fn jet_gt256_true() {
    let a = u256_from_u64(5);
    let b = u256_from_u64(3);
    let r = eval_jet(JetId::Gt256, u256_pair(a, b)).unwrap();
    assert_eq!(r, Value::Bool(true));
}

// ============================================================
// Byte ops
// ============================================================

#[test]
fn jet_cat_normal() {
    let input = Value::Pair(
        Box::new(Value::Bytes(vec![1, 2, 3])),
        Box::new(Value::Bytes(vec![4, 5])),
    );
    let r = eval_jet(JetId::Cat, input).unwrap();
    assert_eq!(r, Value::Bytes(vec![1, 2, 3, 4, 5]));
}

#[test]
fn jet_cat_empty() {
    let input = Value::Pair(
        Box::new(Value::Bytes(vec![])),
        Box::new(Value::Bytes(vec![1, 2])),
    );
    let r = eval_jet(JetId::Cat, input).unwrap();
    assert_eq!(r, Value::Bytes(vec![1, 2]));
}

#[test]
fn jet_slice_normal() {
    let input = Value::Pair(
        Box::new(Value::Bytes(vec![10, 20, 30, 40, 50])),
        Box::new(Value::Pair(
            Box::new(Value::U64(1)),
            Box::new(Value::U64(3)),
        )),
    );
    let r = eval_jet(JetId::Slice, input).unwrap();
    assert_eq!(r, Value::Bytes(vec![20, 30, 40]));
}

#[test]
fn jet_slice_out_of_bounds() {
    let input = Value::Pair(
        Box::new(Value::Bytes(vec![1, 2, 3])),
        Box::new(Value::Pair(
            Box::new(Value::U64(10)), // beyond end
            Box::new(Value::U64(5)),
        )),
    );
    let r = eval_jet(JetId::Slice, input).unwrap();
    assert_eq!(r, Value::Bytes(vec![])); // empty result
}

#[test]
fn jet_len_normal() {
    let r = eval_jet(JetId::Len, Value::Bytes(vec![1, 2, 3])).unwrap();
    assert_eq!(r, Value::U64(3));
}

#[test]
fn jet_len_empty() {
    let r = eval_jet(JetId::Len, Value::Bytes(vec![])).unwrap();
    assert_eq!(r, Value::U64(0));
}

#[test]
fn jet_eq_bytes_true() {
    let input = Value::Pair(
        Box::new(Value::Bytes(vec![1, 2, 3])),
        Box::new(Value::Bytes(vec![1, 2, 3])),
    );
    let r = eval_jet(JetId::EqBytes, input).unwrap();
    assert_eq!(r, Value::Bool(true));
}

#[test]
fn jet_eq_bytes_false() {
    let input = Value::Pair(
        Box::new(Value::Bytes(vec![1, 2, 3])),
        Box::new(Value::Bytes(vec![1, 2, 4])),
    );
    let r = eval_jet(JetId::EqBytes, input).unwrap();
    assert_eq!(r, Value::Bool(false));
}

// ============================================================
// Crypto
// ============================================================

#[test]
fn jet_sha256_normal() {
    let r = eval_jet(JetId::Sha256, Value::Bytes(b"hello".to_vec())).unwrap();
    match r {
        Value::Hash(h) => {
            // SHA-256("hello") is well-known
            let expected = Hash256::sha256(b"hello");
            assert_eq!(h, expected);
        }
        other => panic!("expected Hash, got {:?}", other),
    }
}

#[test]
fn jet_sha256_empty() {
    let r = eval_jet(JetId::Sha256, Value::Bytes(vec![])).unwrap();
    match r {
        Value::Hash(h) => {
            let expected = Hash256::sha256(b"");
            assert_eq!(h, expected);
        }
        other => panic!("expected Hash, got {:?}", other),
    }
}

#[test]
fn jet_ed25519_verify_valid() {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let message = b"test message";
    let signature = signing_key.sign(message);

    let input = Value::Pair(
        Box::new(Value::Bytes(message.to_vec())),
        Box::new(Value::Pair(
            Box::new(Value::Bytes(verifying_key.to_bytes().to_vec())),
            Box::new(Value::Bytes(signature.to_bytes().to_vec())),
        )),
    );
    let r = eval_jet(JetId::Ed25519Verify, input).unwrap();
    assert_eq!(r, Value::Bool(true));
}

#[test]
fn jet_ed25519_verify_invalid() {
    let input = Value::Pair(
        Box::new(Value::Bytes(b"message".to_vec())),
        Box::new(Value::Pair(
            Box::new(Value::Bytes(vec![0u8; 32])), // zero pubkey
            Box::new(Value::Bytes(vec![0u8; 64])), // zero sig
        )),
    );
    let r = eval_jet(JetId::Ed25519Verify, input).unwrap();
    assert_eq!(r, Value::Bool(false));
}

#[test]
fn jet_ed25519_verify_wrong_message() {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(b"correct message");

    let input = Value::Pair(
        Box::new(Value::Bytes(b"wrong message".to_vec())),
        Box::new(Value::Pair(
            Box::new(Value::Bytes(verifying_key.to_bytes().to_vec())),
            Box::new(Value::Bytes(signature.to_bytes().to_vec())),
        )),
    );
    let r = eval_jet(JetId::Ed25519Verify, input).unwrap();
    assert_eq!(r, Value::Bool(false));
}

#[test]
fn jet_ed25519_verify_short_key() {
    let input = Value::Pair(
        Box::new(Value::Bytes(b"msg".to_vec())),
        Box::new(Value::Pair(
            Box::new(Value::Bytes(vec![0u8; 16])), // too short
            Box::new(Value::Bytes(vec![0u8; 64])),
        )),
    );
    let r = eval_jet(JetId::Ed25519Verify, input).unwrap();
    assert_eq!(r, Value::Bool(false));
}

// ============================================================
// Introspection
// ============================================================

fn test_context() -> ScriptContext {
    ScriptContext {
        tx_inputs: vec![
            TxInputInfo {
                prev_tx_id: Hash256::sha256(b"tx0"),
                output_index: 0,
                value: 1000,
                script_hash: Hash256::sha256(b"script0"),
            },
            TxInputInfo {
                prev_tx_id: Hash256::sha256(b"tx1"),
                output_index: 1,
                value: 2000,
                script_hash: Hash256::sha256(b"script1"),
            },
        ]
        .into(),
        tx_outputs: vec![
            TxOutputInfo {
                value: 1500,
                script_hash: Hash256::sha256(b"out_script0"),
                datum_hash: None,
            },
            TxOutputInfo {
                value: 1400,
                script_hash: Hash256::sha256(b"out_script1"),
                datum_hash: Some(Hash256::sha256(b"datum1")),
            },
        ]
        .into(),
        self_index: 0,
        block_height: 12345,
        sig_hash: vec![].into(),
    }
}

#[test]
fn jet_tx_input_count() {
    let ctx = test_context();
    let r = eval_jet_ctx(JetId::TxInputCount, Value::Unit, &ctx).unwrap();
    assert_eq!(r, Value::U64(2));
}

#[test]
fn jet_tx_output_count() {
    let ctx = test_context();
    let r = eval_jet_ctx(JetId::TxOutputCount, Value::Unit, &ctx).unwrap();
    assert_eq!(r, Value::U64(2));
}

#[test]
fn jet_self_index() {
    let ctx = test_context();
    let r = eval_jet_ctx(JetId::SelfIndex, Value::Unit, &ctx).unwrap();
    assert_eq!(r, Value::U64(0));
}

#[test]
fn jet_block_height() {
    let ctx = test_context();
    let r = eval_jet_ctx(JetId::BlockHeight, Value::Unit, &ctx).unwrap();
    assert_eq!(r, Value::U64(12345));
}

#[test]
fn jet_tx_value() {
    let ctx = test_context();
    let r = eval_jet_ctx(JetId::TxValue, Value::U64(0), &ctx).unwrap();
    assert_eq!(r, Value::U64(1000));
}

#[test]
fn jet_tx_value_second_input() {
    let ctx = test_context();
    let r = eval_jet_ctx(JetId::TxValue, Value::U64(1), &ctx).unwrap();
    assert_eq!(r, Value::U64(2000));
}

#[test]
fn jet_tx_script_hash() {
    let ctx = test_context();
    let r = eval_jet_ctx(JetId::TxScriptHash, Value::U64(0), &ctx).unwrap();
    match r {
        Value::Hash(h) => assert_eq!(h, Hash256::sha256(b"script0")),
        other => panic!("expected Hash, got {:?}", other),
    }
}

#[test]
fn jet_tx_inputs() {
    let ctx = test_context();
    let r = eval_jet_ctx(JetId::TxInputs, Value::Unit, &ctx).unwrap();
    match r {
        Value::List(items) => assert_eq!(items.len(), 2),
        other => panic!("expected List, got {:?}", other),
    }
}

#[test]
fn jet_tx_outputs() {
    let ctx = test_context();
    let r = eval_jet_ctx(JetId::TxOutputs, Value::Unit, &ctx).unwrap();
    match r {
        Value::List(items) => assert_eq!(items.len(), 2),
        other => panic!("expected List, got {:?}", other),
    }
}

// ============================================================
// List ops
// ============================================================

#[test]
fn jet_list_len_normal() {
    let r = eval_jet(
        JetId::ListLen,
        Value::List(vec![Value::U64(1), Value::U64(2), Value::U64(3)]),
    )
    .unwrap();
    assert_eq!(r, Value::U64(3));
}

#[test]
fn jet_list_len_empty() {
    let r = eval_jet(JetId::ListLen, Value::List(vec![])).unwrap();
    assert_eq!(r, Value::U64(0));
}

#[test]
fn jet_list_at_normal() {
    let input = Value::Pair(
        Box::new(Value::List(vec![
            Value::U64(10),
            Value::U64(20),
            Value::U64(30),
        ])),
        Box::new(Value::U64(1)),
    );
    let r = eval_jet(JetId::ListAt, input).unwrap();
    assert_eq!(r, Value::some(Value::U64(20)));
}

#[test]
fn jet_list_at_out_of_bounds() {
    let input = Value::Pair(
        Box::new(Value::List(vec![Value::U64(10)])),
        Box::new(Value::U64(5)),
    );
    let r = eval_jet(JetId::ListAt, input).unwrap();
    assert_eq!(r, Value::none());
}

#[test]
fn jet_list_at_empty() {
    let input = Value::Pair(Box::new(Value::List(vec![])), Box::new(Value::U64(0)));
    let r = eval_jet(JetId::ListAt, input).unwrap();
    assert_eq!(r, Value::none());
}

#[test]
fn jet_list_sum_normal() {
    let r = eval_jet(
        JetId::ListSum,
        Value::List(vec![Value::U64(10), Value::U64(20), Value::U64(30)]),
    )
    .unwrap();
    assert_eq!(r, Value::U64(60));
}

#[test]
fn jet_list_sum_empty() {
    let r = eval_jet(JetId::ListSum, Value::List(vec![])).unwrap();
    assert_eq!(r, Value::U64(0));
}

#[test]
fn jet_list_sum_overflow() {
    let r = eval_jet(
        JetId::ListSum,
        Value::List(vec![Value::U64(u64::MAX), Value::U64(1)]),
    );
    assert!(r.is_err());
}

#[test]
fn jet_list_all_true() {
    let r = eval_jet(
        JetId::ListAll,
        Value::List(vec![Value::Bool(true), Value::Bool(true)]),
    )
    .unwrap();
    assert_eq!(r, Value::Bool(true));
}

#[test]
fn jet_list_all_false() {
    let r = eval_jet(
        JetId::ListAll,
        Value::List(vec![Value::Bool(true), Value::Bool(false)]),
    )
    .unwrap();
    assert_eq!(r, Value::Bool(false));
}

#[test]
fn jet_list_all_empty() {
    let r = eval_jet(JetId::ListAll, Value::List(vec![])).unwrap();
    assert_eq!(r, Value::Bool(true)); // vacuously true
}

#[test]
fn jet_list_any_true() {
    let r = eval_jet(
        JetId::ListAny,
        Value::List(vec![Value::Bool(false), Value::Bool(true)]),
    )
    .unwrap();
    assert_eq!(r, Value::Bool(true));
}

#[test]
fn jet_list_any_false() {
    let r = eval_jet(
        JetId::ListAny,
        Value::List(vec![Value::Bool(false), Value::Bool(false)]),
    )
    .unwrap();
    assert_eq!(r, Value::Bool(false));
}

#[test]
fn jet_list_any_empty() {
    let r = eval_jet(JetId::ListAny, Value::List(vec![])).unwrap();
    assert_eq!(r, Value::Bool(false));
}

#[test]
fn jet_list_find_found() {
    let r = eval_jet(
        JetId::ListFind,
        Value::List(vec![
            Value::Bool(false),
            Value::Bool(true),
            Value::Bool(true),
        ]),
    )
    .unwrap();
    assert_eq!(r, Value::some(Value::U64(1))); // first true at index 1
}

#[test]
fn jet_list_find_not_found() {
    let r = eval_jet(
        JetId::ListFind,
        Value::List(vec![Value::Bool(false), Value::Bool(false)]),
    )
    .unwrap();
    assert_eq!(r, Value::none());
}

#[test]
fn jet_list_find_empty() {
    let r = eval_jet(JetId::ListFind, Value::List(vec![])).unwrap();
    assert_eq!(r, Value::none());
}

// ============================================================
// Jet costs
// ============================================================

#[test]
fn jet_cost_values() {
    // Spot check some jet costs (static costs for budget sizing)
    assert_eq!(JetId::Sha256.jet_cost(), (1_000, 1));
    assert_eq!(JetId::Ed25519Verify.jet_cost(), (5_000, 1));
    assert_eq!(JetId::MerkleVerify.jet_cost(), (32_000, 1));
    assert_eq!(JetId::Add64.jet_cost(), (10, 1));
    assert_eq!(JetId::Add256.jet_cost(), (50, 1));
    assert_eq!(JetId::Cat.jet_cost(), (100, 1));
    assert_eq!(JetId::Len.jet_cost(), (10, 0));
    assert_eq!(JetId::EqBytes.jet_cost(), (500, 0));
    assert_eq!(JetId::TxInputCount.jet_cost(), (5, 0));
    assert_eq!(JetId::BlockHeight.jet_cost(), (5, 0));
    assert_eq!(JetId::ListLen.jet_cost(), (10, 0));
    assert_eq!(JetId::ListAt.jet_cost(), (10, 1));
    assert_eq!(JetId::ListSum.jet_cost(), (1_000, 0));
}

// ============================================================
// Jet type mismatch
// ============================================================

#[test]
fn jet_add64_type_mismatch() {
    let r = eval_jet(JetId::Add64, Value::Bool(true));
    assert!(r.is_err());
}

#[test]
fn jet_sha256_type_mismatch() {
    let r = eval_jet(JetId::Sha256, Value::U64(42));
    assert!(r.is_err());
}

#[test]
fn jet_len_type_mismatch() {
    let r = eval_jet(JetId::Len, Value::U64(42));
    assert!(r.is_err());
}

#[test]
fn jet_list_len_type_mismatch() {
    let r = eval_jet(JetId::ListLen, Value::U64(42));
    assert!(r.is_err());
}
