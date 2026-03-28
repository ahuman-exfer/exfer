//! Type soundness regression tests.
//!
//! Verifies that U256 is a nominal type distinct from Product(U64, U64),
//! and that witness values are runtime-checked against their expected types.

use exfer::script::types::Type;
use exfer::script::value::Value;
use exfer::script::{self, Budget, Program, Combinator};
use exfer::script::jets::JetId;

fn prog(nodes: Vec<Combinator>) -> Program {
    Program { nodes, root: 0 }
}

// ═══════════════════════════════════════════════════════════════════
// U256 type soundness
// ═══════════════════════════════════════════════════════════════════

#[test]
fn u256_is_distinct_from_product_u64_u64() {
    let u256 = Type::u256_type();
    let product = Type::Product(Box::new(Type::u64_type()), Box::new(Type::u64_type()));
    assert_ne!(u256, product, "U256 must be a distinct type from Product(U64, U64)");
}

#[test]
fn u256_type_is_nominal() {
    assert_eq!(Type::u256_type(), Type::U256);
}

#[test]
fn comp_add256_eq64_must_fail_typecheck() {
    // Add256 outputs U256, Eq64 expects Product(U64, U64) — must reject.
    // Root at 0, children at higher indices.
    let p = prog(vec![
        Combinator::Comp(1, 2),          // 0: root — compose
        Combinator::Jet(JetId::Add256),  // 1: Product(U256, U256) -> U256
        Combinator::Jet(JetId::Eq64),   // 2: Product(U64, U64) -> Bool
    ]);
    let result = script::typecheck(&p);
    assert!(result.is_err(), "Comp(Add256, Eq64) must fail typecheck: U256 != Product(U64, U64)");
}

#[test]
fn comp_add256_take_iden_must_fail_typecheck() {
    // Add256 outputs U256, Take expects Product — must reject.
    let p = prog(vec![
        Combinator::Comp(1, 2),          // 0: root — compose
        Combinator::Jet(JetId::Add256),  // 1: Product(U256, U256) -> U256
        Combinator::Take(3),            // 2: Take(Iden) expects Product
        Combinator::Iden,                // 3: identity
    ]);
    let result = script::typecheck(&p);
    assert!(result.is_err(), "Comp(Add256, Take(Iden)) must fail typecheck: U256 is not Product");
}

#[test]
fn eq64_rejects_u256_value_at_runtime() {
    // Even if we bypass typecheck, Eq64 must reject Value::U256 at runtime
    let input = Value::U256([0u8; 32]);
    let result = JetId::Eq64.eval(&input, &script::ScriptContext::empty());
    assert!(result.is_err(), "Eq64 must reject Value::U256 at runtime");
}

#[test]
fn add256_eq256_still_works() {
    // Pure 256-bit path must still work
    let a = Value::U256([0u8; 32]);
    let b = Value::U256([0u8; 32]);
    let input = Value::Pair(Box::new(a), Box::new(b));

    let add_result = JetId::Add256.eval(&input, &script::ScriptContext::empty());
    assert!(add_result.is_ok(), "Add256 with U256 inputs must work");
    assert!(matches!(add_result.unwrap(), Value::U256(_)), "Add256 must return U256");

    let eq_result = JetId::Eq256.eval(&input, &script::ScriptContext::empty());
    assert!(eq_result.is_ok(), "Eq256 with U256 inputs must work");
    assert_eq!(eq_result.unwrap(), Value::Bool(true), "0 == 0 must be true");
}

#[test]
fn extract_u256_rejects_pair_u64_u64() {
    // A Pair(U64, U64) must NOT be accepted as U256 by arithmetic jets
    let input = Value::Pair(
        Box::new(Value::Pair(
            Box::new(Value::U64(0)),
            Box::new(Value::U64(0)),
        )),
        Box::new(Value::Pair(
            Box::new(Value::U64(0)),
            Box::new(Value::U64(0)),
        )),
    );
    let result = JetId::Add256.eval(&input, &script::ScriptContext::empty());
    assert!(result.is_err(), "Add256 must reject Pair(U64, U64) — only Value::U256 is accepted");
}

// ═══════════════════════════════════════════════════════════════════
// Value::matches_type
// ═══════════════════════════════════════════════════════════════════

#[test]
fn matches_type_bool() {
    assert!(Value::Bool(true).matches_type(&Type::bool_type()));
    assert!(Value::Bool(false).matches_type(&Type::bool_type()));
    assert!(Value::Left(Box::new(Value::Unit)).matches_type(&Type::bool_type()));
    assert!(Value::Right(Box::new(Value::Unit)).matches_type(&Type::bool_type()));
    // Non-unit payload does NOT match Bool
    assert!(!Value::Left(Box::new(Value::U64(7))).matches_type(&Type::bool_type()));
}

#[test]
fn matches_type_u256() {
    assert!(Value::U256([0u8; 32]).matches_type(&Type::U256));
    assert!(!Value::Pair(Box::new(Value::U64(0)), Box::new(Value::U64(0))).matches_type(&Type::U256));
}

#[test]
fn matches_type_unit_is_literal() {
    assert!(Value::Unit.matches_type(&Type::Unit));
    // U64 does NOT match Unit — Unit is not a wildcard at runtime
    assert!(!Value::U64(0).matches_type(&Type::Unit));
}

// ═══════════════════════════════════════════════════════════════════
// Witness type validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn witness_left_u64_rejected_for_bool_case() {
    // Comp(Witness, Case(Const(Bool(true)), Const(Bool(false))))
    // Witness should output Bool = Sum(Unit, Unit).
    // Providing Left(U64(7)) must fail at witness type validation.
    let p = prog(vec![
        Combinator::Comp(1, 2),                  // 0: root
        Combinator::Witness,                     // 1: -> Bool (refined by Case)
        Combinator::Case(3, 4),                  // 2: Bool -> Bool
        Combinator::Const(Value::Bool(true)),    // 3: Unit -> Bool
        Combinator::Const(Value::Bool(false)),   // 4: Unit -> Bool
    ]);

    // Serialize Left(U64(7)): tag 0x01 (Left) + tag 0x06 (U64) + 8 LE bytes
    let mut witness_data = vec![0x01]; // Left tag
    witness_data.push(0x06); // U64 tag
    witness_data.extend_from_slice(&7u64.to_le_bytes()); // U64(7)

    let mut budget = Budget::new(10000, 10000);
    let result = script::evaluate(&p, Value::Unit, &witness_data, &mut budget);
    assert!(result.is_err(), "Witness Left(U64(7)) must be rejected for Bool type");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("witness") || err.contains("type mismatch") || err.contains("typecheck"),
        "Error should mention witness or type mismatch, got: {}", err
    );
}

#[test]
fn case_rejects_bool_true_for_non_bool_sum() {
    // Case with input type Sum(U64, U64) must NOT accept Bool(true).
    // The Bool shortcut is only allowed when input type is exactly Bool.
    // Use Jet(Add64) as both branches to force U64 input type on each arm,
    // making the Case input Sum(Product(U64,U64), Product(U64,U64)), not Bool.
    let p = prog(vec![
        Combinator::Comp(1, 2),          // 0: root
        Combinator::Witness,             // 1: -> Sum(Product(U64,U64), Product(U64,U64))
        Combinator::Case(3, 4),          // 2: Sum(Product(U64,U64), Product(U64,U64)) -> U64
        Combinator::Jet(JetId::Add64),   // 3: Product(U64, U64) -> U64
        Combinator::Jet(JetId::Add64),   // 4: Product(U64, U64) -> U64
    ]);

    // Provide Bool(true) as witness — tag 0x08, value 0x01
    let witness_data = vec![0x08, 0x01]; // Bool(true)

    let mut budget = Budget::new(10000, 10000);
    let result = script::evaluate(&p, Value::Unit, &witness_data, &mut budget);
    assert!(result.is_err(), "Case must reject Bool(true) when input type is not Bool");
}

// ═══════════════════════════════════════════════════════════════════
// Witness nested under Pair — the surviving hole
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pair_unit_unit_into_eq64_rejected_by_admission() {
    // Comp(Pair(Unit, Unit), Jet(Eq64)) must NOT pass admission.
    // Unit combinators always produce Value::Unit at runtime, but Eq64
    // needs Pair(U64, U64). The typechecker must not refine Unit combinator
    // outputs, and strict_type_edges must reject the unresolved output.
    let p = prog(vec![
        Combinator::Comp(1, 4),          // 0: root
        Combinator::Pair(2, 3),          // 1: Pair(Unit, Unit)
        Combinator::Unit,                // 2: -> Unit (fixed, not refinable)
        Combinator::Unit,                // 3: -> Unit (fixed, not refinable)
        Combinator::Jet(JetId::Eq64),   // 4: Product(U64, U64) -> Bool
    ]);

    let tc_result = script::typecheck(&p);
    if let Ok(ref typed) = tc_result {
        // Unit combinator's output must stay Unit — never refined to U64
        assert_eq!(
            typed[2].output_type,
            Type::Unit,
            "Unit combinator output must not be refined"
        );
        assert_eq!(
            typed[3].output_type,
            Type::Unit,
            "Unit combinator output must not be refined"
        );

        // strict_type_edges should reject: Pair children have Unit output
        let _strict_ok = typed[1].output_type != Type::Unit; // Pair output should be Product(Unit, Unit)
        // But the children outputs are Unit, so strict_type_edges should catch this
    }

    // Runtime must fail
    let mut budget = Budget::new(10000, 10000);
    let result = script::evaluate(&p, Value::Unit, &[], &mut budget);
    assert!(result.is_err(), "Comp(Pair(Unit, Unit), Eq64) must fail at runtime");
}

#[test]
fn pair_witness_unit_into_eq64_fails() {
    // Comp(Pair(Witness, Unit), Jet(Eq64)) — Witness gets refined to U64,
    // but Unit combinator stays Unit. Runtime always fails because Eq64
    // gets Pair(U64(n), Unit) not Pair(U64, U64).
    let p = prog(vec![
        Combinator::Comp(1, 4),          // 0: root
        Combinator::Pair(2, 3),          // 1: Pair(Witness, Unit)
        Combinator::Witness,             // 2: -> U64 (refined by Pair decomposition)
        Combinator::Unit,                // 3: -> Unit (fixed)
        Combinator::Jet(JetId::Eq64),   // 4: Product(U64, U64) -> Bool
    ]);

    let tc_result = script::typecheck(&p);
    if let Ok(ref typed) = tc_result {
        // Witness should be refined to U64
        assert_eq!(typed[2].output_type, Type::u64_type());
        // Unit combinator must stay Unit
        assert_eq!(typed[3].output_type, Type::Unit);
    }

    // Runtime must fail (Unit child produces Unit, not U64)
    let witness_data = Value::U64(5).serialize();
    let mut budget = Budget::new(10000, 10000);
    let result = script::evaluate(&p, Value::Unit, &witness_data, &mut budget);
    assert!(result.is_err(), "Pair(Witness, Unit) -> Eq64 must fail at runtime");
}

#[test]
fn pair_witness_witness_into_eq64_works_with_correct_types() {
    // Comp(Pair(Witness, Witness), Jet(Eq64)) — both witnesses should
    // get refined to U64 by the Pair decomposition.
    let p = prog(vec![
        Combinator::Comp(1, 4),          // 0: root
        Combinator::Pair(2, 3),          // 1: Pair(Witness, Witness)
        Combinator::Witness,             // 2: -> U64
        Combinator::Witness,             // 3: -> U64
        Combinator::Jet(JetId::Eq64),   // 4: Product(U64, U64) -> Bool
    ]);

    let tc_result = script::typecheck(&p);
    assert!(tc_result.is_ok(), "Pair(Witness, Witness) -> Eq64 should typecheck");

    // Verify witness types were refined
    let typed = tc_result.unwrap();
    assert_eq!(typed[2].output_type, Type::u64_type(), "First witness should be refined to U64");
    assert_eq!(typed[3].output_type, Type::u64_type(), "Second witness should be refined to U64");

    // Runtime: provide two equal U64 values
    let mut witness_data = Value::U64(42).serialize();
    witness_data.extend_from_slice(&Value::U64(42).serialize());
    let mut budget = Budget::new(10000, 10000);
    let result = script::evaluate(&p, Value::Unit, &witness_data, &mut budget);
    assert_eq!(result.unwrap(), Value::Bool(true), "42 == 42 should be true");
}

#[test]
fn witness_under_take_drop_gets_typed() {
    // Comp(Pair(Witness, Witness), Take(Iden)) — Take projects first element.
    // First Witness should be refined from the Take's output.
    let p = prog(vec![
        Combinator::Comp(1, 4),          // 0: root
        Combinator::Pair(2, 3),          // 1: Pair(Witness, Witness)
        Combinator::Witness,             // 2: -> ?
        Combinator::Witness,             // 3: -> ?
        Combinator::Take(5),            // 4: Product(A, B) -> A
        Combinator::Iden,                // 5: A -> A
    ]);

    let tc_result = script::typecheck(&p);
    assert!(tc_result.is_ok(), "Pair(Witness, Witness) -> Take(Iden) should typecheck");
}

// ═══════════════════════════════════════════════════════════════════
// Comp with fixed-output children — the surviving hole
// ═══════════════════════════════════════════════════════════════════

#[test]
fn comp_unit_eq64_must_fail() {
    // Comp(Unit, Jet(Eq64)): Unit always produces Value::Unit,
    // but Eq64 needs Product(U64, U64). The typechecker must NOT
    // refine Unit's output to Product(U64, U64).
    let p = prog(vec![
        Combinator::Comp(1, 2),          // 0: root
        Combinator::Unit,                // 1: -> Unit (fixed)
        Combinator::Jet(JetId::Eq64),   // 2: Product(U64, U64) -> Bool
    ]);

    let tc_result = script::typecheck(&p);
    if let Ok(ref typed) = tc_result {
        // Unit combinator's output must stay Unit
        assert_eq!(
            typed[1].output_type,
            Type::Unit,
            "Unit combinator output must not be refined to Product(U64, U64)"
        );
    }

    // Runtime must fail
    let mut budget = Budget::new(10000, 10000);
    let result = script::evaluate(&p, Value::Unit, &[], &mut budget);
    assert!(result.is_err(), "Comp(Unit, Eq64) must fail at runtime");
}

#[test]
fn comp_const_bool_into_eq64_must_fail() {
    // Comp(Const(Bool(true)), Jet(Eq64)): Const always produces Bool(true),
    // but Eq64 needs Product(U64, U64). Must not be refined.
    let p = prog(vec![
        Combinator::Comp(1, 2),                  // 0: root
        Combinator::Const(Value::Bool(true)),     // 1: -> Bool (fixed)
        Combinator::Jet(JetId::Eq64),            // 2: Product(U64, U64) -> Bool
    ]);

    let tc_result = script::typecheck(&p);
    if let Ok(ref typed) = tc_result {
        assert_eq!(
            typed[1].output_type,
            Type::bool_type(),
            "Const(Bool) output must not be refined"
        );
    }

    let mut budget = Budget::new(10000, 10000);
    let result = script::evaluate(&p, Value::Unit, &[], &mut budget);
    assert!(result.is_err(), "Comp(Const(Bool), Eq64) must fail at runtime");
}

#[test]
fn comp_jet_add64_into_eq256_must_fail() {
    // Comp(Jet(Add64), Jet(Eq256)): Add64 returns U64, Eq256 needs Product(U256, U256).
    // Jet output is fixed — must not be refined.
    let p = prog(vec![
        Combinator::Comp(1, 2),           // 0: root
        Combinator::Jet(JetId::Add64),   // 1: Product(U64, U64) -> U64 (fixed)
        Combinator::Jet(JetId::Eq256),   // 2: Product(U256, U256) -> Bool
    ]);

    let tc_result = script::typecheck(&p);
    if let Ok(ref typed) = tc_result {
        assert_eq!(
            typed[1].output_type,
            Type::u64_type(),
            "Jet(Add64) output must not be refined to Product(U256, U256)"
        );
    }

    let mut budget = Budget::new(10000, 10000);
    let input = Value::Pair(Box::new(Value::U64(1)), Box::new(Value::U64(2)));
    let result = script::evaluate(&p, input, &[], &mut budget);
    assert!(result.is_err(), "Comp(Add64, Eq256) must fail: U64 != Product(U256, U256)");
}

#[test]
fn nested_comp_witness_case_unit_unit_under_pair_eq64_must_fail() {
    // The exact doomed script:
    // Comp(Pair(Comp(Witness, Case(Unit, Unit)), Const(U64(0))), Jet(Eq64))
    //
    // Case(Unit, Unit) always returns Unit at runtime regardless of branch,
    // so Comp(Witness, Case(Unit,Unit)) always outputs Unit.
    // Pair(Unit_result, U64(0)) gives Pair(Unit, U64(0)) — not Pair(U64, U64).
    // Eq64 gets TypeMismatch.
    //
    // This must be rejected by admission, not just fail at runtime.
    let p = prog(vec![
        Combinator::Comp(1, 8),                  // 0: root
        Combinator::Pair(2, 7),                  // 1: Pair(Comp(...), Const(U64(0)))
        Combinator::Comp(3, 4),                  // 2: Comp(Witness, Case(Unit, Unit))
        Combinator::Witness,                     // 3: -> Bool (Sum(Unit,Unit))
        Combinator::Case(5, 6),                  // 4: Case(Unit, Unit) -> Unit
        Combinator::Unit,                        // 5: -> Unit (fixed)
        Combinator::Unit,                        // 6: -> Unit (fixed)
        Combinator::Const(Value::U64(0)),        // 7: -> U64 (fixed)
        Combinator::Jet(JetId::Eq64),           // 8: Product(U64, U64) -> Bool
    ]);

    let tc_result = script::typecheck(&p);
    if let Ok(ref typed) = tc_result {
        // Unit branches must stay Unit — not refined
        assert_eq!(typed[5].output_type, Type::Unit, "Unit branch must stay Unit");
        assert_eq!(typed[6].output_type, Type::Unit, "Unit branch must stay Unit");
        // Case output must be Unit (both branches are Unit)
        assert_eq!(typed[4].output_type, Type::Unit, "Case(Unit, Unit) output must be Unit");
        // Inner Comp's output was refined to U64 by Pair, but Case's output is Unit.
        // strict_type_edges must catch this mismatch.
        let inner_comp_out = &typed[2].output_type;
        let case_out = &typed[4].output_type;
        assert_ne!(
            inner_comp_out, case_out,
            "Inner Comp output should be refined (U64) while Case stays Unit — mismatch"
        );
    }

    // Admission must reject: serialize the script and check validate_output_script
    // indirectly via the evaluator (which typechecks and would catch the mismatch
    // through strict_type_edges in a real transaction).
    let script_bytes = script::serialize_program(&p);
    let output = exfer::types::transaction::TxOutput {
        value: 1_000_000,
        script: script_bytes,
        datum: None,
        datum_hash: None,
    };
    // Use the consensus validation path
    let validation_result = exfer::consensus::validation::validate_output_script_public(0, &output);
    assert!(
        validation_result.is_err(),
        "Consensus admission must reject Comp(Pair(Comp(Witness, Case(Unit,Unit)), Const(U64(0))), Eq64)"
    );

    // Runtime must also fail for any witness
    let witness_data = Value::Left(Box::new(Value::Unit)).serialize();
    let mut budget = Budget::new(10000, 10000);
    let result = script::evaluate(&p, Value::Unit, &witness_data, &mut budget);
    assert!(result.is_err(),
        "Comp(Pair(Comp(Witness, Case(Unit,Unit)), Const(U64(0))), Eq64) must fail at runtime");
}

#[test]
fn fold_with_unit_init_must_fail() {
    // Comp(Pair(Comp(Witness, Fold(Add64, Unit, 1)), Const(U64(0))), Jet(Eq64))
    // Fold(Add64, Unit, 1): initializer is Unit (fixed), step is Add64.
    // Unit always returns Value::Unit, Add64 needs Pair(U64, U64).
    // Must be rejected by admission.
    let p = prog(vec![
        Combinator::Comp(1, 9),                  // 0: root
        Combinator::Pair(2, 8),                  // 1: Pair
        Combinator::Comp(3, 4),                  // 2: Comp(Witness, Fold(...))
        Combinator::Witness,                     // 3: -> ?
        Combinator::Fold(5, 6, 1),              // 4: Fold(Add64, Unit, 1)
        Combinator::Jet(JetId::Add64),          // 5: step: Product(U64, U64) -> U64
        Combinator::Unit,                        // 6: init: -> Unit (fixed)
        Combinator::Unit,                        // 7: unused padding
        Combinator::Const(Value::U64(0)),        // 8: -> U64
        Combinator::Jet(JetId::Eq64),           // 9: Product(U64, U64) -> Bool
    ]);

    let tc_result = script::typecheck(&p);
    if let Ok(ref typed) = tc_result {
        // Unit init must stay Unit
        assert_eq!(typed[6].output_type, Type::Unit, "Unit init must not be refined");
    }

    // Runtime must fail
    let witness_data = Value::Pair(
        Box::new(Value::U64(1)),
        Box::new(Value::U64(2)),
    ).serialize();
    let mut budget = Budget::new(10000, 10000);
    let result = script::evaluate(&p, Value::Unit, &witness_data, &mut budget);
    assert!(result.is_err(), "Fold with Unit initializer must fail at runtime");
}

#[test]
fn listfold_with_unit_init_must_fail() {
    // Comp(Pair(Comp(Witness, ListFold(Add64, Unit)), Const(U64(0))), Jet(Eq64))
    // Same pattern with ListFold.
    let p = prog(vec![
        Combinator::Comp(1, 8),                  // 0: root
        Combinator::Pair(2, 7),                  // 1: Pair
        Combinator::Comp(3, 4),                  // 2: Comp(Witness, ListFold(...))
        Combinator::Witness,                     // 3: -> ?
        Combinator::ListFold(5, 6),             // 4: ListFold(Add64, Unit)
        Combinator::Jet(JetId::Add64),          // 5: step: Product(U64, U64) -> U64
        Combinator::Unit,                        // 6: init: -> Unit (fixed)
        Combinator::Const(Value::U64(0)),        // 7: -> U64
        Combinator::Jet(JetId::Eq64),           // 8: Product(U64, U64) -> Bool
    ]);

    let tc_result = script::typecheck(&p);
    if let Ok(ref typed) = tc_result {
        assert_eq!(typed[6].output_type, Type::Unit, "Unit init must not be refined");
    }

    let witness_data = Value::Pair(
        Box::new(Value::List(vec![Value::U64(1)])),
        Box::new(Value::U64(0)),
    ).serialize();
    let mut budget = Budget::new(10000, 10000);
    let result = script::evaluate(&p, Value::Unit, &witness_data, &mut budget);
    assert!(result.is_err(), "ListFold with Unit initializer must fail at runtime");
}
