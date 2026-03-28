//! Tests for Phase 2: Exfer Script core.
//!
//! Coverage: type checker, interpreter, cost analyzer, serialization.

use exfer::script::ast::{Combinator, Program};
use exfer::script::cost::{compute_cost, ListSizes, ScriptCost};
use exfer::script::eval::{evaluate, Budget, EvalError};
use exfer::script::serialize::{deserialize_program, merkle_hash, serialize_program};
use exfer::script::typecheck::{typecheck, TypeError};
use exfer::script::types::Type;
use exfer::script::value::Value;
use exfer::types::hash::Hash256;

// ============================================================
// Helper: build programs
// ============================================================

/// Build a program from a list of nodes. Node 0 is root.
fn prog(nodes: Vec<Combinator>) -> Program {
    Program { nodes, root: 0 }
}

// ============================================================
// Type Checker Tests
// ============================================================

#[test]
fn typecheck_iden() {
    let p = Program::single(Combinator::Iden);
    let typed = typecheck(&p).unwrap();
    assert_eq!(typed.len(), 1);
    assert_eq!(typed[0].input_type, typed[0].output_type);
}

#[test]
fn typecheck_unit() {
    let p = Program::single(Combinator::Unit);
    let typed = typecheck(&p).unwrap();
    assert_eq!(typed[0].output_type, Type::Unit);
}

#[test]
fn typecheck_comp() {
    // nodes[0] = Comp(1, 2), nodes[1] = Iden, nodes[2] = Unit
    let p = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    let typed = typecheck(&p).unwrap();
    // Comp(Iden, Unit): A -> Unit
    assert_eq!(typed[0].output_type, Type::Unit);
}

#[test]
fn typecheck_pair() {
    // Pair(Iden, Unit): A -> Product(A, Unit)
    let p = prog(vec![
        Combinator::Pair(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    let typed = typecheck(&p).unwrap();
    match &typed[0].output_type {
        Type::Product(_, b) => assert_eq!(**b, Type::Unit),
        other => panic!("expected Product, got {:?}", other),
    }
}

#[test]
fn typecheck_take() {
    // Take(Iden): Product(A, B) -> A
    let p = prog(vec![Combinator::Take(1), Combinator::Iden]);
    let typed = typecheck(&p).unwrap();
    match &typed[0].input_type {
        Type::Product(_, _) => {}
        other => panic!("expected Product input, got {:?}", other),
    }
}

#[test]
fn typecheck_drop() {
    // Drop(Iden): Product(A, B) -> B
    let p = prog(vec![Combinator::Drop(1), Combinator::Iden]);
    let typed = typecheck(&p).unwrap();
    match &typed[0].input_type {
        Type::Product(_, _) => {}
        other => panic!("expected Product input, got {:?}", other),
    }
}

#[test]
fn typecheck_injl() {
    // InjL(Iden): A -> Sum(A, Unit)
    let p = prog(vec![Combinator::InjL(1), Combinator::Iden]);
    let typed = typecheck(&p).unwrap();
    match &typed[0].output_type {
        Type::Sum(_, _) => {}
        other => panic!("expected Sum output, got {:?}", other),
    }
}

#[test]
fn typecheck_injr() {
    // InjR(Iden): A -> Sum(Unit, A)
    let p = prog(vec![Combinator::InjR(1), Combinator::Iden]);
    let typed = typecheck(&p).unwrap();
    match &typed[0].output_type {
        Type::Sum(_, _) => {}
        other => panic!("expected Sum output, got {:?}", other),
    }
}

#[test]
fn typecheck_case() {
    // Case(Iden, Iden): Sum(A, B) -> A/B (both branches Iden)
    let p = prog(vec![
        Combinator::Case(1, 2),
        Combinator::Iden,
        Combinator::Iden,
    ]);
    let typed = typecheck(&p).unwrap();
    match &typed[0].input_type {
        Type::Sum(_, _) => {}
        other => panic!("expected Sum input, got {:?}", other),
    }
}

#[test]
fn typecheck_case_branch_mismatch() {
    // Case(Const(U64(1)), Const(Bool(true))): output types differ
    let p = prog(vec![
        Combinator::Case(1, 2),
        Combinator::Const(Value::U64(1)),
        Combinator::Const(Value::Bool(true)),
    ]);
    let result = typecheck(&p);
    assert!(result.is_err());
    match result.unwrap_err() {
        TypeError::CaseBranchMismatch(_) => {}
        other => panic!("expected CaseBranchMismatch, got {:?}", other),
    }
}

#[test]
fn typecheck_const() {
    let p = Program::single(Combinator::Const(Value::U64(42)));
    let typed = typecheck(&p).unwrap();
    assert_eq!(typed[0].input_type, Type::Unit);
    assert_eq!(typed[0].output_type, Type::u64_type());
}

#[test]
fn typecheck_const_bool() {
    let p = Program::single(Combinator::Const(Value::Bool(true)));
    let typed = typecheck(&p).unwrap();
    assert_eq!(typed[0].output_type, Type::bool_type());
}

#[test]
fn typecheck_witness() {
    let p = Program::single(Combinator::Witness);
    let typed = typecheck(&p).unwrap();
    // Witness defaults to Unit -> Unit
    assert_eq!(typed[0].input_type, Type::Unit);
    assert_eq!(typed[0].output_type, Type::Unit);
}

#[test]
fn typecheck_fold() {
    // Fold(step, init, k=3)
    // init = Iden (A -> A), step = Take(Iden) (Product(A, B) -> A)
    let p = prog(vec![
        Combinator::Fold(1, 2, 3),
        Combinator::Take(3), // step: Product(A, B) -> A
        Combinator::Iden,    // init: A -> A
        Combinator::Iden,    // leaf
    ]);
    let typed = typecheck(&p).unwrap();
    match &typed[0].input_type {
        Type::Product(a, _) => {
            assert_eq!(**a, Type::Bound(3));
        }
        other => panic!("expected Product(Bound(3), _), got {:?}", other),
    }
}

#[test]
fn typecheck_listfold() {
    // ListFold(step, init)
    let p = prog(vec![
        Combinator::ListFold(1, 2),
        Combinator::Take(3), // step: Product(A, B) -> A
        Combinator::Iden,    // init: B -> B
        Combinator::Iden,    // leaf
    ]);
    let typed = typecheck(&p).unwrap();
    match &typed[0].input_type {
        Type::Product(a, _) => match a.as_ref() {
            Type::List(_) => {}
            other => panic!("expected List, got {:?}", other),
        },
        other => panic!("expected Product(List(_), _), got {:?}", other),
    }
}

#[test]
fn typecheck_comp_type_mismatch() {
    // Comp(Const(U64(1)), Const(Bool(true))): U64 output ≠ Unit input
    // Actually Const always takes Unit input, so any Comp(Const, Const) should work
    // since the type checker uses Unit as wildcard.
    // Let's test with explicitly typed nodes that conflict.
    // Const(U64(1)) -> u64_type output
    // Const(Bool(true)) -> bool_type output
    // Comp: first output must match second input — Const input is Unit, which is wildcard.
    // So this actually passes. Let's construct a real mismatch using jets.
    use exfer::script::jets::JetId;
    // Add64: Product(u64, u64) -> u64
    // Sha256: bytes -> hash256
    // Comp(Add64, Sha256): u64 output ≠ bytes input
    let p = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Jet(JetId::Add64),
        Combinator::Jet(JetId::Sha256),
    ]);
    let result = typecheck(&p);
    assert!(result.is_err());
    match result.unwrap_err() {
        TypeError::CompTypeMismatch { .. } => {}
        other => panic!("expected CompTypeMismatch, got {:?}", other),
    }
}

#[test]
fn typecheck_empty_program() {
    let p = Program {
        nodes: vec![],
        root: 0,
    };
    let result = typecheck(&p);
    assert!(result.is_err());
}

#[test]
fn typecheck_merkle_hidden() {
    let p = Program::single(Combinator::MerkleHidden(Hash256::ZERO));
    let typed = typecheck(&p).unwrap();
    // Hidden nodes get Unit types
    assert_eq!(typed[0].input_type, Type::Unit);
    assert_eq!(typed[0].output_type, Type::Unit);
}

// ============================================================
// Interpreter Tests
// ============================================================

#[test]
fn eval_iden() {
    let p = Program::single(Combinator::Iden);
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::U64(42), &[], &mut budget).unwrap();
    assert_eq!(result, Value::U64(42));
}

#[test]
fn eval_unit() {
    let p = Program::single(Combinator::Unit);
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::U64(42), &[], &mut budget).unwrap();
    assert_eq!(result, Value::Unit);
}

#[test]
fn eval_const() {
    let p = Program::single(Combinator::Const(Value::U64(99)));
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::Unit, &[], &mut budget).unwrap();
    assert_eq!(result, Value::U64(99));
}

#[test]
fn eval_comp_iden_unit() {
    // Comp(Iden, Unit): pass-through then discard
    let p = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::U64(42), &[], &mut budget).unwrap();
    assert_eq!(result, Value::Unit);
}

#[test]
fn eval_pair() {
    // Pair(Iden, Const(Bool(true))): input -> (input, true)
    let p = prog(vec![
        Combinator::Pair(1, 2),
        Combinator::Iden,
        Combinator::Const(Value::Bool(true)),
    ]);
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::U64(5), &[], &mut budget).unwrap();
    match result {
        Value::Pair(a, b) => {
            assert_eq!(*a, Value::U64(5));
            assert_eq!(*b, Value::Bool(true));
        }
        other => panic!("expected Pair, got {:?}", other),
    }
}

#[test]
fn eval_take() {
    // Take(Iden): Product(A, B) -> A
    let p = prog(vec![Combinator::Take(1), Combinator::Iden]);
    let mut budget = Budget::new(100, 100);
    let input = Value::Pair(Box::new(Value::U64(10)), Box::new(Value::U64(20)));
    let result = evaluate(&p, input, &[], &mut budget).unwrap();
    assert_eq!(result, Value::U64(10));
}

#[test]
fn eval_drop() {
    // Drop(Iden): Product(A, B) -> B
    let p = prog(vec![Combinator::Drop(1), Combinator::Iden]);
    let mut budget = Budget::new(100, 100);
    let input = Value::Pair(Box::new(Value::U64(10)), Box::new(Value::U64(20)));
    let result = evaluate(&p, input, &[], &mut budget).unwrap();
    assert_eq!(result, Value::U64(20));
}

#[test]
fn eval_take_non_pair_error() {
    let p = prog(vec![Combinator::Take(1), Combinator::Iden]);
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::U64(10), &[], &mut budget);
    assert!(result.is_err());
}

#[test]
fn eval_injl() {
    // InjL(Iden): A -> Left(A)
    let p = prog(vec![Combinator::InjL(1), Combinator::Iden]);
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::U64(7), &[], &mut budget).unwrap();
    assert_eq!(result, Value::Left(Box::new(Value::U64(7))));
}

#[test]
fn eval_injr() {
    // InjR(Iden): A -> Right(A)
    let p = prog(vec![Combinator::InjR(1), Combinator::Iden]);
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::U64(7), &[], &mut budget).unwrap();
    assert_eq!(result, Value::Right(Box::new(Value::U64(7))));
}

#[test]
fn eval_case_left() {
    // Case(Const(U64(1)), Const(U64(2)))
    // Left input -> branch f -> U64(1)
    let p = prog(vec![
        Combinator::Case(1, 2),
        Combinator::Const(Value::U64(1)),
        Combinator::Const(Value::U64(2)),
    ]);
    let mut budget = Budget::new(100, 100);
    let input = Value::Left(Box::new(Value::Unit));
    let result = evaluate(&p, input, &[], &mut budget).unwrap();
    assert_eq!(result, Value::U64(1));
}

#[test]
fn eval_case_right() {
    let p = prog(vec![
        Combinator::Case(1, 2),
        Combinator::Const(Value::U64(1)),
        Combinator::Const(Value::U64(2)),
    ]);
    let mut budget = Budget::new(100, 100);
    let input = Value::Right(Box::new(Value::Unit));
    let result = evaluate(&p, input, &[], &mut budget).unwrap();
    assert_eq!(result, Value::U64(2));
}

#[test]
fn eval_case_non_sum_error() {
    let p = prog(vec![
        Combinator::Case(1, 2),
        Combinator::Const(Value::U64(1)),
        Combinator::Const(Value::U64(2)),
    ]);
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::U64(42), &[], &mut budget);
    assert!(result.is_err());
}

#[test]
fn eval_fold_zero() {
    // Fold(step, init, k=0): should just return init(input.second)
    // init = Iden, step = Take(Iden)
    let p = prog(vec![
        Combinator::Fold(1, 2, 0),
        Combinator::Take(3), // step
        Combinator::Iden,    // init
        Combinator::Iden,    // leaf
    ]);
    let mut budget = Budget::new(1000, 1000);
    let input = Value::Pair(Box::new(Value::U64(0)), Box::new(Value::U64(99)));
    let result = evaluate(&p, input, &[], &mut budget).unwrap();
    assert_eq!(result, Value::U64(99)); // init(99) = 99
}

#[test]
fn eval_fold_iterations() {
    // Fold(step, init, k=3) where init = Const(U64(0)), step = Const(U64(1))
    // After k=3 iterations, acc = Const(1) regardless
    let p = prog(vec![
        Combinator::Fold(1, 2, 3),
        Combinator::Const(Value::U64(1)), // step: always returns 1
        Combinator::Const(Value::U64(0)), // init: returns 0
    ]);
    let mut budget = Budget::new(1000, 1000);
    let input = Value::Pair(Box::new(Value::U64(3)), Box::new(Value::Unit));
    let result = evaluate(&p, input, &[], &mut budget).unwrap();
    assert_eq!(result, Value::U64(1));
}

#[test]
fn eval_listfold_empty() {
    // ListFold(step, init) on empty list: returns init(input.second)
    let p = prog(vec![
        Combinator::ListFold(1, 2),
        Combinator::Const(Value::U64(1)), // step
        Combinator::Iden,                 // init
    ]);
    let mut budget = Budget::new(1000, 1000);
    let input = Value::Pair(Box::new(Value::List(vec![])), Box::new(Value::U64(42)));
    let result = evaluate(&p, input, &[], &mut budget).unwrap();
    assert_eq!(result, Value::U64(42));
}

#[test]
fn eval_listfold_elements() {
    // ListFold that counts elements by always returning Const(U64(N))
    // Actually let's just verify it iterates. Step = Const(U64(1)), init = Const(U64(0))
    // After processing 3 elements, acc = 1 (because step ignores input)
    let p = prog(vec![
        Combinator::ListFold(1, 2),
        Combinator::Const(Value::U64(1)), // step always returns 1
        Combinator::Const(Value::U64(0)), // init returns 0
    ]);
    let mut budget = Budget::new(1000, 1000);
    let input = Value::Pair(
        Box::new(Value::List(vec![Value::Unit, Value::Unit, Value::Unit])),
        Box::new(Value::Unit),
    );
    let result = evaluate(&p, input, &[], &mut budget).unwrap();
    assert_eq!(result, Value::U64(1));
}

#[test]
fn eval_witness() {
    // Witness reads from witness_data
    let p = Program::single(Combinator::Witness);
    let mut budget = Budget::new(100, 100);
    let witness_data = Value::U64(123).serialize();
    let result = evaluate(&p, Value::Unit, &witness_data, &mut budget).unwrap();
    assert_eq!(result, Value::U64(123));
}

#[test]
fn eval_witness_bool() {
    let p = Program::single(Combinator::Witness);
    let mut budget = Budget::new(100, 100);
    let witness_data = Value::Bool(true).serialize();
    let result = evaluate(&p, Value::Unit, &witness_data, &mut budget).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn eval_witness_empty_error() {
    let p = Program::single(Combinator::Witness);
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::Unit, &[], &mut budget);
    assert!(result.is_err());
}

#[test]
fn eval_merkle_hidden_error() {
    let p = Program::single(Combinator::MerkleHidden(Hash256::ZERO));
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::Unit, &[], &mut budget);
    assert!(result.is_err());
    match result.unwrap_err() {
        EvalError::HiddenNode => {}
        other => panic!("expected HiddenNode, got {:?}", other),
    }
}

#[test]
fn eval_budget_exceeded() {
    // Give only 1 step budget, run Comp which needs 2+ steps
    let p = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::Iden,
    ]);
    let mut budget = Budget::new(1, 100);
    let result = evaluate(&p, Value::Unit, &[], &mut budget);
    assert!(result.is_err());
    match result.unwrap_err() {
        EvalError::BudgetExceeded => {}
        other => panic!("expected BudgetExceeded, got {:?}", other),
    }
}

#[test]
fn eval_memory_exceeded() {
    // Create a budget with very low memory limit
    let p = Program::single(Combinator::Witness);
    let mut budget = Budget::new(100, 100);
    budget.memory_limit = 1; // 1 byte limit
    let witness_data = Value::Bytes(vec![0u8; 100]).serialize();
    let result = evaluate(&p, Value::Unit, &witness_data, &mut budget);
    assert!(result.is_err());
    match result.unwrap_err() {
        EvalError::MemoryExceeded => {}
        other => panic!("expected MemoryExceeded, got {:?}", other),
    }
}

// ============================================================
// Cost Analyzer Tests
// ============================================================

#[test]
fn cost_iden() {
    let p = Program::single(Combinator::Iden);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(cost, ScriptCost { cells: 0, steps: 1 });
}

#[test]
fn cost_unit() {
    let p = Program::single(Combinator::Unit);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(cost, ScriptCost { cells: 0, steps: 1 });
}

#[test]
fn cost_comp() {
    // Comp(Iden, Unit): cells = 0+0 = 0, steps = 1+1+1 = 3
    let p = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(cost, ScriptCost { cells: 0, steps: 3 });
}

#[test]
fn cost_pair() {
    // Pair(Iden, Unit): cells = 0+0+1 = 1, steps = 1+1+1 = 3
    let p = prog(vec![
        Combinator::Pair(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(cost, ScriptCost { cells: 1, steps: 3 });
}

#[test]
fn cost_take() {
    // Take(Iden): cells = 0, steps = 1+1 = 2
    let p = prog(vec![Combinator::Take(1), Combinator::Iden]);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(cost, ScriptCost { cells: 0, steps: 2 });
}

#[test]
fn cost_drop() {
    let p = prog(vec![Combinator::Drop(1), Combinator::Iden]);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(cost, ScriptCost { cells: 0, steps: 2 });
}

#[test]
fn cost_injl() {
    // InjL(Iden): cells = 0+1 = 1, steps = 1+1 = 2
    let p = prog(vec![Combinator::InjL(1), Combinator::Iden]);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(cost, ScriptCost { cells: 1, steps: 2 });
}

#[test]
fn cost_injr() {
    let p = prog(vec![Combinator::InjR(1), Combinator::Iden]);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(cost, ScriptCost { cells: 1, steps: 2 });
}

#[test]
fn cost_case() {
    // Const(U64(1)) serializes to 9 bytes → ceil_div(9,64)=1 → cells=2, steps=2
    // Case(Iden, Const(U64(1))): cells = max(0, 2)+1 = 3, steps = max(1, 2)+1 = 3
    let p = prog(vec![
        Combinator::Case(1, 2),
        Combinator::Iden,
        Combinator::Const(Value::U64(1)),
    ]);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(cost, ScriptCost { cells: 3, steps: 3 });
}

#[test]
fn cost_fold() {
    // Fold(step, init, k=5)
    // step = Iden (cells=0, steps=1), init = Iden (cells=0, steps=1)
    // cells = 0 + 5*0 = 0, steps = 1(top) + 1(init) + 5*(1+1) = 12
    let p = prog(vec![
        Combinator::Fold(1, 2, 5),
        Combinator::Iden,
        Combinator::Iden,
    ]);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(
        cost,
        ScriptCost {
            cells: 0,
            steps: 12
        }
    );
}

#[test]
fn cost_fold_zero() {
    // Fold with k=0: top-level step + init cost
    let p = prog(vec![
        Combinator::Fold(1, 2, 0),
        Combinator::Iden,
        Combinator::Iden,
    ]);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(cost, ScriptCost { cells: 0, steps: 2 });
}

#[test]
fn cost_listfold() {
    // ListFold(step, init) with list_size = 3
    // step = Iden (0, 1), init = Iden (0, 1)
    // cells = 0 + 3*0 = 0, steps = 1(top) + 1(init) + 3*(1+1) = 8
    let p = prog(vec![
        Combinator::ListFold(1, 2),
        Combinator::Iden,
        Combinator::Iden,
    ]);
    let sizes = ListSizes {
        input_count: 3,
        output_count: 2,
    };
    let cost = compute_cost(&p, &sizes).unwrap();
    assert_eq!(cost, ScriptCost { cells: 0, steps: 8 });
}

#[test]
fn cost_nested_fold() {
    // Nested fold: outer Fold(inner_fold, init, k=2)
    // inner_fold = Fold(Iden, Iden, k=3): cells=0, steps=1(top)+1+3*2=8
    // outer: cells = 0 + 2*0 = 0, steps = 1(top) + 1 + 2*(8+1) = 20
    let p = prog(vec![
        Combinator::Fold(1, 3, 2), // outer fold
        Combinator::Fold(2, 3, 3), // inner fold (step of outer)
        Combinator::Iden,          // step of inner
        Combinator::Iden,          // init for both
    ]);
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(
        cost,
        ScriptCost {
            cells: 0,
            steps: 20
        }
    );
}

#[test]
fn cost_jet() {
    use exfer::script::jets::JetId;
    let p = Program::single(Combinator::Jet(JetId::Add64));
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(
        cost,
        ScriptCost {
            cells: 1,
            steps: 10
        }
    );
}

#[test]
fn cost_jet_sha256() {
    use exfer::script::jets::JetId;
    let p = Program::single(Combinator::Jet(JetId::Sha256));
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert_eq!(
        cost,
        ScriptCost {
            cells: 1,
            steps: 1_000
        }
    );
}

#[test]
fn cost_empty_program() {
    let p = Program {
        nodes: vec![],
        root: 0,
    };
    let result = compute_cost(&p, &ListSizes::default());
    assert!(result.is_err());
}

// ============================================================
// Serialization Tests
// ============================================================

#[test]
fn serialize_roundtrip_iden() {
    let p = Program::single(Combinator::Iden);
    let bytes = serialize_program(&p);
    let p2 = deserialize_program(&bytes).unwrap();
    assert_eq!(p2.nodes.len(), 1);
    assert_eq!(p2.nodes[0], Combinator::Iden);
    assert_eq!(p2.root, 0);
}

#[test]
fn serialize_roundtrip_unit() {
    let p = Program::single(Combinator::Unit);
    let bytes = serialize_program(&p);
    let p2 = deserialize_program(&bytes).unwrap();
    assert_eq!(p2.nodes[0], Combinator::Unit);
}

#[test]
fn serialize_roundtrip_comp() {
    let p = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    let bytes = serialize_program(&p);
    let p2 = deserialize_program(&bytes).unwrap();
    assert_eq!(p2.nodes.len(), 3);
    assert_eq!(p2.nodes[0], Combinator::Comp(1, 2));
    assert_eq!(p2.nodes[1], Combinator::Iden);
    assert_eq!(p2.nodes[2], Combinator::Unit);
}

#[test]
fn serialize_roundtrip_all_combinators() {
    use exfer::script::jets::JetId;
    let p = prog(vec![
        Combinator::Comp(1, 2),                  // 0
        Combinator::Pair(3, 4),                  // 1
        Combinator::Case(5, 6),                  // 2
        Combinator::Take(7),                     // 3
        Combinator::Drop(8),                     // 4
        Combinator::InjL(9),                     // 5
        Combinator::InjR(10),                    // 6
        Combinator::Fold(11, 12, 100),           // 7
        Combinator::ListFold(13, 14),            // 8
        Combinator::Jet(JetId::Sha256),          // 9
        Combinator::Witness,                     // 10
        Combinator::Iden,                        // 11
        Combinator::Unit,                        // 12
        Combinator::MerkleHidden(Hash256::ZERO), // 13
        Combinator::Const(Value::U64(42)),       // 14
    ]);
    let bytes = serialize_program(&p);
    let p2 = deserialize_program(&bytes).unwrap();
    assert_eq!(p2.nodes.len(), p.nodes.len());
    for (i, (a, b)) in p.nodes.iter().zip(p2.nodes.iter()).enumerate() {
        assert_eq!(a, b, "node {} mismatch", i);
    }
}

#[test]
fn serialize_roundtrip_const_values() {
    // Test all Value types
    let values = vec![
        Value::Unit,
        Value::Bool(true),
        Value::Bool(false),
        Value::U64(0),
        Value::U64(u64::MAX),
        Value::Bytes(vec![1, 2, 3]),
        Value::Bytes(vec![]),
        Value::Left(Box::new(Value::U64(1))),
        Value::Right(Box::new(Value::Bool(true))),
        Value::Pair(Box::new(Value::U64(1)), Box::new(Value::U64(2))),
        Value::List(vec![Value::U64(1), Value::U64(2)]),
        Value::List(vec![]),
        Value::Hash(Hash256::ZERO),
        Value::U256([0xAB; 32]),
    ];
    for v in values {
        let p = Program::single(Combinator::Const(v.clone()));
        let bytes = serialize_program(&p);
        let p2 = deserialize_program(&bytes).unwrap();
        assert_eq!(p2.nodes[0], Combinator::Const(v));
    }
}

#[test]
fn serialize_invalid_tag() {
    let data = vec![
        1, 0, 0, 0, // node_count = 1
        0, 0, 0, 0,    // root = 0
        0xFF, // invalid tag
    ];
    let result = deserialize_program(&data);
    assert!(result.is_err());
}

#[test]
fn serialize_truncated() {
    let data = vec![0, 0]; // too short
    let result = deserialize_program(&data);
    assert!(result.is_err());
}

// ============================================================
// Merkle Hash Tests
// ============================================================

#[test]
fn merkle_hash_deterministic() {
    let p = Program::single(Combinator::Iden);
    let h1 = merkle_hash(&p);
    let h2 = merkle_hash(&p);
    assert_eq!(h1, h2);
}

#[test]
fn merkle_hash_different_programs() {
    let p1 = Program::single(Combinator::Iden);
    let p2 = Program::single(Combinator::Unit);
    assert_ne!(merkle_hash(&p1), merkle_hash(&p2));
}

#[test]
fn merkle_hash_hidden_passthrough() {
    // MerkleHidden(h) should hash to h itself
    let h = Hash256::sha256(b"test subtree");
    let p = Program::single(Combinator::MerkleHidden(h));
    assert_eq!(merkle_hash(&p), h);
}

#[test]
fn merkle_hash_pruning_equivalence() {
    // Build a program Comp(Iden, Unit)
    // Compute its Merkle hash
    // Replace the Unit child with MerkleHidden(hash_of_unit)
    // The root Merkle hash should be the same
    let full = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    let full_hash = merkle_hash(&full);

    // Get the hash of the Unit node
    let unit_hash = merkle_hash(&Program::single(Combinator::Unit));

    // Replace Unit with MerkleHidden
    let pruned = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::MerkleHidden(unit_hash),
    ]);
    let pruned_hash = merkle_hash(&pruned);

    assert_eq!(full_hash, pruned_hash);
}

#[test]
fn merkle_hash_const_different_values() {
    let p1 = Program::single(Combinator::Const(Value::U64(1)));
    let p2 = Program::single(Combinator::Const(Value::U64(2)));
    assert_ne!(merkle_hash(&p1), merkle_hash(&p2));
}

// ============================================================
// Value Serialization Tests
// ============================================================

#[test]
fn value_serialize_roundtrip() {
    let values = vec![
        Value::Unit,
        Value::Bool(true),
        Value::Bool(false),
        Value::U64(0),
        Value::U64(u64::MAX),
        Value::U256([0xFF; 32]),
        Value::Bytes(vec![1, 2, 3, 4, 5]),
        Value::Bytes(vec![]),
        Value::Hash(Hash256::ZERO),
        Value::Left(Box::new(Value::U64(42))),
        Value::Right(Box::new(Value::Bool(false))),
        Value::Pair(Box::new(Value::U64(1)), Box::new(Value::Bytes(vec![0xAA]))),
        Value::List(vec![Value::U64(1), Value::U64(2), Value::U64(3)]),
        Value::List(vec![]),
        Value::none(),
        Value::some(Value::U64(99)),
    ];
    for v in values {
        let bytes = v.serialize();
        let (decoded, consumed) = Value::deserialize(&bytes).unwrap();
        assert_eq!(decoded, v, "roundtrip failed for {:?}", v);
        assert_eq!(consumed, bytes.len());
    }
}

#[test]
fn value_infer_type() {
    assert_eq!(Value::Unit.infer_type(), Type::Unit);
    assert_eq!(Value::U64(0).infer_type(), Type::u64_type());
    assert_eq!(Value::Bool(true).infer_type(), Type::bool_type());
    assert_eq!(Value::Bytes(vec![]).infer_type(), Type::bytes());
    assert_eq!(Value::Hash(Hash256::ZERO).infer_type(), Type::hash256());

    match Value::Pair(Box::new(Value::U64(1)), Box::new(Value::U64(2))).infer_type() {
        Type::Product(a, b) => {
            assert_eq!(*a, Type::u64_type());
            assert_eq!(*b, Type::u64_type());
        }
        other => panic!("expected Product, got {:?}", other),
    }
}

#[test]
fn value_heap_size() {
    let val_size = std::mem::size_of::<Value>();
    // Inline variants have zero heap overhead
    assert_eq!(Value::Unit.heap_size(), 0);
    assert_eq!(Value::U64(42).heap_size(), 0);
    assert_eq!(Value::Bool(true).heap_size(), 0);
    assert_eq!(Value::U256([0u8; 32]).heap_size(), 0);
    assert_eq!(Value::Hash(Hash256::ZERO).heap_size(), 0);
    // Bytes: heap buffer = capacity
    let bytes_val = Value::Bytes(vec![0u8; 100]);
    assert_eq!(bytes_val.heap_size(), 100);
    // Box<Value> allocates size_of::<Value>() on heap
    let left = Value::Left(Box::new(Value::Unit));
    assert_eq!(left.heap_size(), val_size);
    let pair = Value::Pair(Box::new(Value::Unit), Box::new(Value::Unit));
    assert_eq!(pair.heap_size(), 2 * val_size);
    // List: capacity * size_of::<Value>() + recursive child heap
    let list = Value::List(vec![Value::U64(1), Value::U64(2)]);
    assert_eq!(list.heap_size(), 2 * val_size);
}

// ============================================================
// Program Structure Tests
// ============================================================

#[test]
fn program_validate_structure_valid() {
    let p = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    assert!(p.validate_structure().is_ok());
}

#[test]
fn program_validate_structure_child_before_parent() {
    // child index <= parent index violates DAG invariant
    let p = Program {
        nodes: vec![
            Combinator::Comp(0, 1), // child 0 == self, invalid
            Combinator::Iden,
        ],
        root: 0,
    };
    assert!(p.validate_structure().is_err());
}

#[test]
fn program_validate_structure_child_out_of_bounds() {
    let p = Program {
        nodes: vec![
            Combinator::Comp(1, 99), // 99 out of bounds
            Combinator::Iden,
        ],
        root: 0,
    };
    assert!(p.validate_structure().is_err());
}

#[test]
fn program_children() {
    let p = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    assert_eq!(p.children(0), vec![1, 2]);
    assert_eq!(p.children(1), Vec::<u32>::new());
    assert_eq!(p.children(2), Vec::<u32>::new());
}

// ============================================================
// Composition / Integration Tests
// ============================================================

#[test]
fn eval_identity_program() {
    // The identity program passes input through unchanged
    let p = Program::single(Combinator::Iden);
    let mut budget = Budget::new(100, 100);
    let input = Value::Pair(Box::new(Value::U64(1)), Box::new(Value::Bool(true)));
    let result = evaluate(&p, input.clone(), &[], &mut budget).unwrap();
    assert_eq!(result, input);
}

#[test]
fn eval_constant_program() {
    // A program that ignores input and returns a constant
    let p = Program::single(Combinator::Const(Value::Bool(true)));
    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p, Value::U64(999), &[], &mut budget).unwrap();
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn eval_pair_take_drop_roundtrip() {
    // Pair(Take(Iden), Drop(Iden)) on Product(A, B) should reconstruct the same pair
    let p = prog(vec![
        Combinator::Pair(1, 2),
        Combinator::Take(3),
        Combinator::Drop(4),
        Combinator::Iden,
        Combinator::Iden,
    ]);
    let mut budget = Budget::new(1000, 1000);
    let input = Value::Pair(Box::new(Value::U64(10)), Box::new(Value::U64(20)));
    let result = evaluate(&p, input.clone(), &[], &mut budget).unwrap();
    assert_eq!(result, input);
}

#[test]
fn full_typecheck_eval_cost() {
    // Verify a program passes type check, cost computation, and evaluation
    let p = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Pair(3, 4),
        Combinator::Take(5),
        Combinator::Iden,
        Combinator::Const(Value::Bool(true)),
        Combinator::Iden,
    ]);

    // Type check
    let typed = typecheck(&p).unwrap();
    assert_eq!(typed.len(), 6);

    // Cost
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    assert!(cost.steps > 0);

    // Evaluate
    let mut budget = Budget::new(cost.steps, cost.cells);
    let result = evaluate(&p, Value::Unit, &[], &mut budget).unwrap();
    // Comp(Pair(Iden, Const(true)), Take(Iden))
    // Pair(Iden, Const(true)) on Unit -> Pair(Unit, Bool(true))
    // Take(Iden) on Pair(Unit, Bool(true)) -> Unit
    assert_eq!(result, Value::Unit);
}

#[test]
fn serialize_deserialize_and_eval() {
    // Build, serialize, deserialize, then evaluate
    let p = prog(vec![
        Combinator::Pair(1, 2),
        Combinator::Iden,
        Combinator::Const(Value::U64(42)),
    ]);

    let bytes = serialize_program(&p);
    let p2 = deserialize_program(&bytes).unwrap();

    let mut budget = Budget::new(100, 100);
    let result = evaluate(&p2, Value::Bool(true), &[], &mut budget).unwrap();
    match result {
        Value::Pair(a, b) => {
            assert_eq!(*a, Value::Bool(true));
            assert_eq!(*b, Value::U64(42));
        }
        other => panic!("expected Pair, got {:?}", other),
    }
}

#[test]
fn merkle_hash_serialize_consistency() {
    // Two structurally identical programs must have the same Merkle hash
    let p1 = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    let p2 = prog(vec![
        Combinator::Comp(1, 2),
        Combinator::Iden,
        Combinator::Unit,
    ]);
    assert_eq!(merkle_hash(&p1), merkle_hash(&p2));
}
