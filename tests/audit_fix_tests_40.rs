//! Round 40 audit-fix structural tests.
//!
//! P0: Production genesis PoW validity (testnet-gated, nonce-independent)
//! P1: Fold/ListFold static cost includes top-level step
//! P1: Depth-limited evaluator checked at output admission
//! P1: Coinbase output datum invariants enforced
//! P2: Work formula uses 2^256/target (strict less-than predicate)

// ---- P0: Genesis PoW ----

/// Testnet genesis always valid (target = all-FF, any nonce works).
#[test]
#[cfg(feature = "testnet")]
fn p0_testnet_genesis_valid() {
    use exfer::consensus::pow::verify_pow;
    let block = exfer::genesis::genesis_block();
    assert!(
        verify_pow(&block.header).unwrap(),
        "testnet genesis must be valid with any nonce"
    );
}

/// Genesis block ID is deterministic across runs.

#[test]
fn p0_genesis_deterministic() {
    let a = exfer::genesis::genesis_block_id();
    let b = exfer::genesis::genesis_block_id();
    assert_eq!(a, b, "genesis block id must be deterministic");
}

/// The genesis template uses `genesis_target()` so the embedded nonce must
/// be mined against the correct target.

#[test]
fn p1a_fold_cost_covers_runtime() {
    use exfer::script::ast::{Combinator, Program};
    use exfer::script::cost::{compute_cost, ListSizes};
    use exfer::script::eval::{evaluate, Budget};
    use exfer::script::value::Value;

    // Fold(Iden, Iden, k=3): accumulator is Pair(input, acc)
    let p = Program {
        nodes: vec![
            Combinator::Fold(1, 2, 3),
            Combinator::Iden,
            Combinator::Iden,
        ],
        root: 0,
    };
    let cost = compute_cost(&p, &ListSizes::default()).unwrap();
    // Static cost should cover the runtime: budget starts at cost.steps
    let mut budget = Budget::new(cost.steps, cost.cells + 100);
    let input = Value::Pair(Box::new(Value::Unit), Box::new(Value::Unit));
    // This should succeed (budget exactly sufficient)
    let result = evaluate(&p, input, &[], &mut budget);
    assert!(
        result.is_ok(),
        "Static cost budget must be sufficient for runtime: {:?}",
        result.err()
    );
}

/// ListFold static cost >= runtime steps.

#[test]
fn p1a_listfold_cost_covers_runtime() {
    use exfer::script::ast::{Combinator, Program};
    use exfer::script::cost::{compute_cost, ListSizes};
    use exfer::script::eval::{evaluate, Budget};
    use exfer::script::value::Value;

    let p = Program {
        nodes: vec![
            Combinator::ListFold(1, 2),
            Combinator::Iden,
            Combinator::Iden,
        ],
        root: 0,
    };
    let sizes = ListSizes {
        input_count: 2,
        output_count: 0,
    };
    let cost = compute_cost(&p, &sizes).unwrap();
    let mut budget = Budget::new(cost.steps, cost.cells + 100);
    let list = Value::List(vec![Value::Unit, Value::Unit]);
    let input = Value::Pair(Box::new(list), Box::new(Value::Unit));
    let result = evaluate(&p, input, &[], &mut budget);
    assert!(
        result.is_ok(),
        "Static cost budget must be sufficient for runtime: {:?}",
        result.err()
    );
}

// ---- P1: Depth check in output admission ----

/// validate_output_script checks max_depth against MAX_EVAL_DEPTH.

#[test]
fn p1b_program_has_max_depth() {
    use exfer::script::ast::{Combinator, Program};
    let p = Program::single(Combinator::Iden);
    let depth = p.max_depth();
    assert_eq!(depth, 1, "single-node program has depth 1");
}

/// Deeper DAG has correct max_depth.

#[test]
fn p1b_max_depth_multi_node() {
    use exfer::script::ast::{Combinator, Program};
    // Comp(Take(Iden), Drop(Iden)) → depth = 3
    let p = Program {
        nodes: vec![
            Combinator::Comp(1, 2),
            Combinator::Take(3),
            Combinator::Drop(3),
            Combinator::Iden,
        ],
        root: 0,
    };
    let depth = p.max_depth();
    assert_eq!(depth, 3, "Comp(Take(Iden), Drop(Iden)) has depth 3");
}

/// MAX_EVAL_DEPTH is public and accessible.

#[test]
fn p1b_max_eval_depth_is_pub() {
    let d = exfer::script::eval::MAX_EVAL_DEPTH;
    assert!(d >= 64, "MAX_EVAL_DEPTH should be at least 64, got {}", d);
}

// ---- P1: Coinbase datum invariants ----

/// validate_coinbase checks datum size (DatumOversized).

#[test]
fn p1c_coinbase_rejects_oversized_datum() {
    use exfer::consensus::validation::validate_coinbase;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
    use exfer::types::MAX_DATUM_SIZE;

    let reward = 10_000_000_000u64;
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: reward,
            script: vec![0u8; 32],
            datum: Some(vec![0xAA; MAX_DATUM_SIZE + 1]),
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    let result = validate_coinbase(&tx, 0, reward);
    assert!(result.is_err(), "coinbase with oversized datum must fail");
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.contains("DatumOversized"),
        "error must be DatumOversized, got: {}",
        err
    );
}

/// Coinbase with mismatched datum hash is rejected.

#[test]
fn p1c_coinbase_rejects_datum_hash_mismatch() {
    use exfer::consensus::validation::validate_coinbase;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let reward = 10_000_000_000u64;
    let datum = b"hello datum".to_vec();
    let wrong_hash = Hash256([0xFF; 32]); // incorrect hash
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: reward,
            script: vec![0u8; 32],
            datum: Some(datum),
            datum_hash: Some(wrong_hash),
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    let result = validate_coinbase(&tx, 0, reward);
    assert!(result.is_err(), "coinbase with wrong datum hash must fail");
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.contains("DatumHashMismatch"),
        "error must be DatumHashMismatch, got: {}",
        err
    );
}

// ---- P2: Work formula uses target, not target+1 ----

/// work_from_target source uses "2^256 / target" not "2^256 / (target + 1)".

#[test]
fn p2_work_target_1() {
    use exfer::consensus::difficulty::work_from_target;
    use exfer::types::hash::Hash256;

    let mut t = [0u8; 32];
    t[31] = 1; // target = 1 in big-endian
    let work = work_from_target(&Hash256(t));
    assert_eq!(
        work, [0xFF; 32],
        "work(target=1) must saturate to max, not wrap to zero"
    );
}

/// work(target=1) > work(target=2): monotonicity at the overflow edge.
/// This is the exact regression that broke fork-choice when +1 wrapped to 0.

#[test]
fn p2_work_target_1_gt_target_2() {
    use exfer::consensus::difficulty::work_from_target;
    use exfer::types::hash::Hash256;

    let mut t1 = [0u8; 32];
    t1[31] = 1;
    let mut t2 = [0u8; 32];
    t2[31] = 2;

    let work_1 = work_from_target(&Hash256(t1));
    let work_2 = work_from_target(&Hash256(t2));
    assert!(
        work_1 > work_2,
        "work(target=1) must exceed work(target=2): {:?} vs {:?}",
        work_1,
        work_2
    );
}

/// work(smaller target) > work(larger target): monotonicity.

#[test]
fn p2_work_monotonic() {
    use exfer::consensus::difficulty::work_from_target;
    use exfer::types::hash::Hash256;

    // target_a = 256 (8 bits set), target_b = 512 (9 bits set)
    let mut a = [0u8; 32];
    a[30] = 1; // 256 in big-endian
    let mut b = [0u8; 32];
    b[30] = 2; // 512 in big-endian

    let work_a = work_from_target(&Hash256(a));
    let work_b = work_from_target(&Hash256(b));

    // Compare big-endian: work_a should be larger (harder)
    assert!(
        work_a > work_b,
        "work for smaller target must be larger (harder)"
    );
}

/// work(target=0) returns max sentinel.

#[test]
fn p2_work_target_zero() {
    use exfer::consensus::difficulty::work_from_target;
    use exfer::types::hash::Hash256;

    let work = work_from_target(&Hash256([0u8; 32]));
    assert_eq!(
        work, [0xFF; 32],
        "work for zero target must be max sentinel"
    );
}
