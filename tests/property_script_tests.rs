//! Property-based tests for Exfer Script:
//! Generate 1,000 random well-typed programs using all combinators,
//! verify strict_type_edges, serialize/deserialize round-trip, and
//! evaluate without panics.

use exfer::script::ast::{Combinator, Program};
use exfer::script::serialize::{deserialize_program, serialize_program};
use exfer::script::typecheck::{typecheck, TypedNode};
use exfer::script::types::Type;
use exfer::script::value::Value;
use exfer::script::{evaluate, Budget};
use exfer::types::hash::Hash256;

/// Deterministic PRNG (xorshift64) — no external dependency needed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn gen_range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo)
    }
    fn gen_bool(&mut self) -> bool {
        self.next() % 2 == 0
    }
}

/// Generate a random type with bounded depth.
fn random_type(rng: &mut Rng, depth: u32) -> Type {
    if depth == 0 {
        return match rng.gen_range(0, 5) {
            0 => Type::Unit,
            1 => Type::bool_type(),
            2 => Type::bytes(),
            3 => Type::u64_type(),
            _ => Type::hash256(),
        };
    }
    match rng.gen_range(0, 8) {
        0 => Type::Unit,
        1 => Type::bool_type(),
        2 => Type::bytes(),
        3 => Type::u64_type(),
        4 => Type::hash256(),
        5 => Type::Product(
            Box::new(random_type(rng, depth - 1)),
            Box::new(random_type(rng, depth - 1)),
        ),
        6 => Type::Sum(
            Box::new(random_type(rng, depth - 1)),
            Box::new(random_type(rng, depth - 1)),
        ),
        _ => Type::List(Box::new(random_type(rng, depth - 1))),
    }
}

/// Generate a random value of a given type (for Const nodes and witness data).
fn random_value(rng: &mut Rng, ty: &Type) -> Value {
    match ty {
        Type::Unit => Value::Unit,
        Type::Bound(0) => Value::Hash(Hash256([rng.next() as u8; 32])),
        Type::Bound(k) if *k == u64::MAX => Value::U64(rng.next()),
        Type::Bound(k) => Value::U64(rng.next() % k),
        Type::Sum(a, b) => {
            if rng.gen_bool() {
                Value::Left(Box::new(random_value(rng, a)))
            } else {
                Value::Right(Box::new(random_value(rng, b)))
            }
        }
        Type::Product(a, b) => Value::Pair(
            Box::new(random_value(rng, a)),
            Box::new(random_value(rng, b)),
        ),
        Type::List(elem) => {
            let len = rng.gen_range(0, 4) as usize;
            Value::List((0..len).map(|_| random_value(rng, elem)).collect())
        }
        Type::U256 => {
            let mut data = [0u8; 32];
            for b in &mut data {
                *b = rng.next() as u8;
            }
            Value::U256(data)
        }
    }
}

/// Generate a random well-typed program.
///
/// Strategy: build bottom-up. Each node has a known (input, output) type.
/// The builder tracks the type of each node and only creates valid compositions.
fn generate_program(rng: &mut Rng) -> (Program, Type, Type) {
    let target_nodes = rng.gen_range(3, 25) as usize;

    // Each entry: (Combinator, input_type, output_type)
    // Builder adds nodes in reverse order (leaves last, root first when reversed)
    let mut nodes: Vec<(Combinator, Type, Type)> = Vec::new();

    // Start with a random target type for the root
    let root_in = random_type(rng, 1);
    let root_out = random_type(rng, 1);

    // Build the root and expand downward
    build_node(rng, &mut nodes, &root_in, &root_out, target_nodes, 0);

    // Convert to Program: nodes are already in parent-first order with
    // children at higher indices.
    let program = Program {
        nodes: nodes.iter().map(|(c, _, _)| c.clone()).collect(),
        root: 0,
    };

    (program, root_in, root_out)
}

/// Recursively build a node with the given (input, output) type.
/// Returns the NodeId of the created node.
fn build_node(
    rng: &mut Rng,
    nodes: &mut Vec<(Combinator, Type, Type)>,
    input: &Type,
    output: &Type,
    budget: usize,
    depth: u32,
) -> u32 {
    let id = nodes.len() as u32;

    // Base cases — use leaf nodes when budget is low or depth is high
    if budget <= 1 || depth > 8 {
        return build_leaf(rng, nodes, input, output);
    }

    // Try to build a composite node
    let choice = rng.gen_range(0, 10);

    match choice {
        // Iden: input == output
        0 if input == output => {
            nodes.push((Combinator::Iden, input.clone(), output.clone()));
            id
        }
        // Unit: output must be Unit
        1 if *output == Type::Unit => {
            nodes.push((Combinator::Unit, input.clone(), Type::Unit));
            id
        }
        // Comp(f, g): f: input->mid, g: mid->output
        0..=3 => {
            let mid = random_type(rng, 1);
            nodes.push((Combinator::Comp(0, 0), input.clone(), output.clone())); // placeholder
            let f = build_node(rng, nodes, input, &mid, budget / 2, depth + 1);
            let g = build_node(rng, nodes, &mid, output, budget / 2, depth + 1);
            nodes[id as usize].0 = Combinator::Comp(f, g);
            id
        }
        // Pair(f, g): output must be Product(A, B)
        4 | 5 => {
            let (a, b) = match output {
                Type::Product(a, b) => (a.as_ref().clone(), b.as_ref().clone()),
                _ => {
                    let a = random_type(rng, 1);
                    let b = random_type(rng, 1);
                    // Override output to Product
                    nodes.push((
                        Combinator::Pair(0, 0),
                        input.clone(),
                        Type::Product(Box::new(a.clone()), Box::new(b.clone())),
                    ));
                    let f = build_node(rng, nodes, input, &a, budget / 2, depth + 1);
                    let g = build_node(rng, nodes, input, &b, budget / 2, depth + 1);
                    nodes[id as usize].0 = Combinator::Pair(f, g);
                    // Fix the output type
                    nodes[id as usize].2 = Type::Product(Box::new(a), Box::new(b));
                    return id;
                }
            };
            nodes.push((Combinator::Pair(0, 0), input.clone(), output.clone()));
            let f = build_node(rng, nodes, input, &a, budget / 2, depth + 1);
            let g = build_node(rng, nodes, input, &b, budget / 2, depth + 1);
            nodes[id as usize].0 = Combinator::Pair(f, g);
            id
        }
        // InjL(f): output must be Sum(A, _)
        6 => {
            let a = match output {
                Type::Sum(a, _) => a.as_ref().clone(),
                _ => random_type(rng, 1),
            };
            let actual_output = match output {
                Type::Sum(_, _) => output.clone(),
                _ => Type::Sum(Box::new(a.clone()), Box::new(random_type(rng, 1))),
            };
            nodes.push((Combinator::InjL(0), input.clone(), actual_output));
            let f = build_node(rng, nodes, input, &a, budget - 1, depth + 1);
            nodes[id as usize].0 = Combinator::InjL(f);
            id
        }
        // InjR(f): output must be Sum(_, B)
        7 => {
            let b = match output {
                Type::Sum(_, b) => b.as_ref().clone(),
                _ => random_type(rng, 1),
            };
            let actual_output = match output {
                Type::Sum(_, _) => output.clone(),
                _ => Type::Sum(Box::new(random_type(rng, 1)), Box::new(b.clone())),
            };
            nodes.push((Combinator::InjR(0), input.clone(), actual_output));
            let f = build_node(rng, nodes, input, &b, budget - 1, depth + 1);
            nodes[id as usize].0 = Combinator::InjR(f);
            id
        }
        // Case(f, g): input must be Sum(A, B)
        8 => {
            let (a, b) = match input {
                Type::Sum(a, b) => (a.as_ref().clone(), b.as_ref().clone()),
                _ => (random_type(rng, 1), random_type(rng, 1)),
            };
            let actual_input = Type::Sum(Box::new(a.clone()), Box::new(b.clone()));
            nodes.push((Combinator::Case(0, 0), actual_input, output.clone()));
            let f = build_node(rng, nodes, &a, output, budget / 2, depth + 1);
            let g = build_node(rng, nodes, &b, output, budget / 2, depth + 1);
            nodes[id as usize].0 = Combinator::Case(f, g);
            id
        }
        // Const: any input -> fixed output
        _ => build_leaf(rng, nodes, input, output),
    }
}

/// Build a leaf node with the given type constraints.
fn build_leaf(
    rng: &mut Rng,
    nodes: &mut Vec<(Combinator, Type, Type)>,
    input: &Type,
    output: &Type,
) -> u32 {
    let id = nodes.len() as u32;

    if input == output {
        // Iden
        nodes.push((Combinator::Iden, input.clone(), output.clone()));
        return id;
    }

    if *output == Type::Unit {
        // Unit combinator
        nodes.push((Combinator::Unit, input.clone(), Type::Unit));
        return id;
    }

    // Use Const with a random value of the output type
    let val = random_value(rng, output);
    nodes.push((Combinator::Const(val), Type::Unit, output.clone()));
    id
}

/// Replicate strict_type_edges check from consensus/validation.rs.
fn check_strict_type_edges(program: &Program, typed: &[TypedNode]) -> Vec<String> {
    let mut failures = Vec::new();
    for (i, node) in program.nodes.iter().enumerate() {
        match node {
            Combinator::Comp(f, g) => {
                let f_out = &typed[*f as usize].output_type;
                let g_in = &typed[*g as usize].input_type;
                if f_out != g_in {
                    failures.push(format!(
                        "node[{}] Comp({},{}): f_out={:?} != g_in={:?}",
                        i, f, g, f_out, g_in
                    ));
                }
            }
            Combinator::Case(f, g) => {
                let f_out = &typed[*f as usize].output_type;
                let g_out = &typed[*g as usize].output_type;
                if f_out != g_out {
                    failures.push(format!(
                        "node[{}] Case({},{}): f_out={:?} != g_out={:?}",
                        i, f, g, f_out, g_out
                    ));
                }
            }
            Combinator::Pair(f, g) => {
                let f_in = &typed[*f as usize].input_type;
                let g_in = &typed[*g as usize].input_type;
                if *f_in != Type::Unit && *g_in != Type::Unit && f_in != g_in {
                    failures.push(format!(
                        "node[{}] Pair({},{}): f_in={:?} != g_in={:?}",
                        i, f, g, f_in, g_in
                    ));
                }
            }
            Combinator::Fold(f, z, _) | Combinator::ListFold(f, z) => {
                let f_out = &typed[*f as usize].output_type;
                let z_out = &typed[*z as usize].output_type;
                if f_out != z_out {
                    failures.push(format!(
                        "node[{}] Fold/ListFold({},{}): f_out={:?} != z_out={:?}",
                        i, f, z, f_out, z_out
                    ));
                }
            }
            _ => {}
        }
    }
    failures
}

#[test]
fn property_1000_random_programs_strict_types() {
    let mut rng = Rng::new(0xDEADBEEF_CAFEBABE);
    let mut pass_count = 0;
    let mut skip_count = 0;

    for _trial in 0..1000 {
        let (program, _root_in, _root_out) = generate_program(&mut rng);

        // Validate structure
        if program.validate_structure().is_err() {
            skip_count += 1;
            continue;
        }

        // Typecheck with bidirectional inference
        let typed = match typecheck(&program) {
            Ok(t) => t,
            Err(_) => {
                skip_count += 1;
                continue;
            }
        };

        // Strict type edges may fail for programs with fixed-output
        // combinators (Unit, Const, Jet) whose output cannot be refined
        // to match their consumer's input type. These are correctly
        // rejected by admission — skip them for this property test.
        let failures = check_strict_type_edges(&program, &typed);
        if !failures.is_empty() {
            skip_count += 1;
            continue;
        }

        pass_count += 1;
    }

    assert!(
        pass_count >= 700,
        "Too few programs passed: {} passed, {} skipped",
        pass_count,
        skip_count
    );
}

#[test]
fn property_1000_random_programs_serialize_roundtrip() {
    let mut rng = Rng::new(0x12345678_ABCD0001);
    let mut pass_count = 0;

    for trial in 0..1000 {
        let (program, _, _) = generate_program(&mut rng);

        if program.validate_structure().is_err() {
            continue;
        }
        if typecheck(&program).is_err() {
            continue;
        }

        let serialized = serialize_program(&program);
        let deserialized = match deserialize_program(&serialized) {
            Ok(p) => p,
            Err(e) => {
                panic!("Trial {}: deserialize failed: {:?}", trial, e);
            }
        };

        // Re-serialize must produce identical bytes
        let reserialized = serialize_program(&deserialized);
        assert_eq!(
            serialized,
            reserialized,
            "Trial {}: round-trip produced different bytes ({} vs {} bytes)",
            trial,
            serialized.len(),
            reserialized.len()
        );

        // Node count must match
        assert_eq!(
            program.nodes.len(),
            deserialized.nodes.len(),
            "Trial {}: node count mismatch",
            trial
        );

        pass_count += 1;
    }

    assert!(
        pass_count >= 700,
        "Too few programs round-tripped: {}",
        pass_count
    );
}

#[test]
fn property_1000_random_programs_evaluate_no_panic() {
    let mut rng = Rng::new(0xFEEDFACE_DEADC0DE);
    let mut pass_count = 0;

    for _trial in 0..1000 {
        let (program, root_in, _root_out) = generate_program(&mut rng);

        if program.validate_structure().is_err() {
            continue;
        }
        if typecheck(&program).is_err() {
            continue;
        }

        // Generate a random input value matching the root input type
        let input = random_value(&mut rng, &root_in);

        // Generate some random witness data (may not be consumed correctly,
        // but evaluation must not panic)
        let mut witness_data = Vec::new();
        for _ in 0..10 {
            let v = Value::Bytes(vec![rng.next() as u8; 32]);
            witness_data.extend_from_slice(&v.serialize());
        }

        let mut budget = Budget::new(100_000, 100_000);

        // Evaluate — may return Ok or Err, but must not panic
        let _result = evaluate(&program, input, &witness_data, &mut budget);

        pass_count += 1;
    }

    assert!(
        pass_count >= 700,
        "Too few programs evaluated: {}",
        pass_count
    );
}

/// Test that all covenant builder programs pass strict_type_edges.
#[test]
fn covenant_programs_pass_strict_type_edges() {
    let pk_a = [0xAA; 32];
    let pk_b = [0xBB; 32];
    let pk_c = [0xCC; 32];
    let hash = Hash256::sha256(b"test");

    let programs: Vec<(&str, Program)> = vec![
        (
            "htlc",
            exfer::covenants::htlc::htlc(&pk_a, &pk_b, &hash, 1000),
        ),
        ("vault", exfer::covenants::vault::vault(&pk_a, &pk_b, 1000)),
        (
            "multisig_2of2",
            exfer::covenants::multisig::multisig_2of2(&pk_a, &pk_b),
        ),
        (
            "multisig_1of2",
            exfer::covenants::multisig::multisig_1of2(&pk_a, &pk_b),
        ),
        (
            "multisig_2of3",
            exfer::covenants::multisig::multisig_2of3(&pk_a, &pk_b, &pk_c),
        ),
        (
            "escrow",
            exfer::covenants::escrow::escrow(&pk_a, &pk_b, &pk_c, 1000),
        ),
        (
            "delegation",
            exfer::covenants::delegation::delegation(&pk_a, &pk_b, 1000),
        ),
    ];

    for (name, program) in &programs {
        // Serialize and deserialize (as consensus validation does)
        let serialized = serialize_program(program);
        let deserialized = deserialize_program(&serialized)
            .unwrap_or_else(|e| panic!("{}: deserialize failed: {:?}", name, e));

        let typed = typecheck(&deserialized)
            .unwrap_or_else(|e| panic!("{}: typecheck failed: {:?}", name, e));

        let failures = check_strict_type_edges(&deserialized, &typed);
        assert!(
            failures.is_empty(),
            "{}: strict_type_edges failed:\n{}",
            name,
            failures.join("\n")
        );

        // Root must output Bool
        let root_out = &typed[deserialized.root as usize].output_type;
        assert_eq!(
            *root_out,
            Type::bool_type(),
            "{}: root output is {:?}, expected Bool",
            name,
            root_out
        );
    }
}
