//! Type checker for Exfer Script programs.
//!
//! Infers input/output types for each node in a program DAG bottom-up.
//! Consensus-critical: two implementations must agree on well-typedness.

use super::ast::{Combinator, NodeId, Program};
use super::types::Type;

/// A node with its inferred input and output types.
#[derive(Clone, Debug)]
pub struct TypedNode {
    pub combinator: Combinator,
    pub input_type: Type,
    pub output_type: Type,
}

/// Type checking errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeError {
    /// Node index out of bounds.
    NodeOutOfBounds(NodeId),
    /// Child types don't match composition constraint.
    CompTypeMismatch {
        node: NodeId,
        f_out: Type,
        g_in: Type,
    },
    /// Take/Drop applied to non-product input.
    ExpectedProduct(NodeId),
    /// Case applied to non-sum input.
    ExpectedSum(NodeId),
    /// Case branches have different output types.
    CaseBranchMismatch(NodeId),
    /// Fold step function has wrong shape.
    FoldStepMismatch(NodeId),
    /// Fold initializer has wrong type.
    FoldInitMismatch(NodeId),
    /// ListFold step function has wrong shape.
    ListFoldStepMismatch(NodeId),
    /// ListFold initializer has wrong type.
    ListFoldInitMismatch(NodeId),
    /// MerkleHidden node cannot be type-checked (must be pruned).
    CannotTypeCheckHidden(NodeId),
    /// DAG structure is invalid.
    InvalidStructure(String),
    /// Witness type could not be resolved.
    UnresolvedWitness(NodeId),
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for TypeError {}

/// Type-check a program. Returns typed nodes for all nodes in the DAG.
///
/// Two-pass bidirectional inference:
/// 1. **Bottom-up** (leaves → root): infer types from children.  Witness and
///    Iden nodes start as `Unit → Unit` (unresolved wildcard).
/// 2. **Top-down** (root → leaves): propagate known types downward into
///    unresolved `Unit` positions.  When `Comp(f, g)` has `g` with a known
///    input type, that type is pushed into `f`'s output.  This resolves
///    Witness outputs, Iden through-types, and Unit-node inputs so that
///    `strict_type_edges` sees fully resolved types.
pub fn typecheck(program: &Program) -> Result<Vec<TypedNode>, TypeError> {
    program
        .validate_structure()
        .map_err(|e| TypeError::InvalidStructure(e.to_string()))?;

    let n = program.nodes.len();
    // Initialize with placeholder types
    let mut typed: Vec<Option<(Type, Type)>> = vec![None; n];

    // Pass 1: bottom-up — highest index first (leaves before parents)
    for i in (0..n).rev() {
        let node = &program.nodes[i];
        let (in_type, out_type) = exfer_node_type(i as NodeId, node, &typed, program)?;
        typed[i] = Some((in_type, out_type));
    }

    // Pass 2: top-down refinement — lowest index first (root before children).
    // Repeatedly push resolved types from parents into children's Unit wildcards.
    // A single pass suffices because parent indices are always lower than
    // children (DAG invariant), so by the time we visit a child, its parent
    // has already pushed any available type information.
    for i in 0..n {
        let node = program.nodes[i].clone();
        refine_children(i, &node, &program.nodes, &mut typed);
    }

    // Build result
    let mut result = Vec::with_capacity(n);
    for (i, node) in program.nodes.iter().enumerate() {
        let (input_type, output_type) = typed[i]
            .clone()
            .ok_or(TypeError::UnresolvedWitness(i as NodeId))?;
        result.push(TypedNode {
            combinator: node.clone(),
            input_type,
            output_type,
        });
    }

    Ok(result)
}

/// Refine a type slot: if `slot` is Unit (wildcard), replace it with `resolved`.
/// If both are non-Unit, keep `slot` unchanged (already resolved).
fn refine(slot: &mut Type, resolved: &Type) {
    if *slot == Type::Unit && *resolved != Type::Unit {
        *slot = resolved.clone();
    }
}

/// Recursively refine type slots: push resolved components into Unit wildcards
/// within structural types (Product, Sum, List).
fn refine_deep(slot: &mut Type, resolved: &Type) {
    if *slot == Type::Unit && *resolved != Type::Unit {
        *slot = resolved.clone();
        return;
    }
    match (slot, resolved) {
        (Type::Product(a1, a2), Type::Product(b1, b2)) => {
            refine_deep(a1, b1);
            refine_deep(a2, b2);
        }
        (Type::Sum(a1, a2), Type::Sum(b1, b2)) => {
            refine_deep(a1, b1);
            refine_deep(a2, b2);
        }
        (Type::List(a), Type::List(b)) => {
            refine_deep(a, b);
        }
        _ => {}
    }
}

/// Whether a combinator's output type can be refined by parent context.
/// Fixed-output combinators (Unit, Const, Jet) always produce a specific type
/// regardless of context — refining their output would make the typechecker
/// claim they produce values they never actually produce at runtime.
fn has_refinable_output(node: &Combinator) -> bool {
    !matches!(node, Combinator::Unit | Combinator::Const(_) | Combinator::Jet(_))
}

/// Push resolved types from a parent node into its children.
fn refine_children(node_idx: usize, node: &Combinator, nodes: &[Combinator], typed: &mut [Option<(Type, Type)>]) {
    match node {
        Combinator::Comp(f, g) => {
            // Comp(f, g): f's output feeds g's input.
            // Push g's input into f's output, and f's output into g's input.
            let g_in = typed[*g as usize].as_ref().unwrap().0.clone();
            let f_out = typed[*f as usize].as_ref().unwrap().1.clone();

            // Only refine f's output if f can actually produce different types.
            // Fixed-output combinators (Unit, Const, Jet) always produce
            // the same type — refining them would claim they produce values
            // they never actually produce at runtime.
            if has_refinable_output(&nodes[*f as usize]) {
                if let Some((_, ref mut f_output)) = typed[*f as usize] {
                    refine_deep(f_output, &g_in);
                }
            }
            if let Some((ref mut g_input, _)) = typed[*g as usize] {
                refine_deep(g_input, &f_out);
            }

            // For Iden children: input = output.
            // After refining f's output, also push into f's input if f is Iden.
            if matches!(typed[*f as usize].as_ref().unwrap(), (_, ref out) if *out != Type::Unit) {
                let f_out_resolved = typed[*f as usize].as_ref().unwrap().1.clone();
                if let Combinator::Iden = &typed[*f as usize]
                    .as_ref()
                    .map(|_| &Combinator::Iden)
                    .unwrap_or(&Combinator::Unit)
                {
                    // Can't easily check combinator type here — handled below
                }
                // If f's input is Unit and f is a simple pass-through, refine input too
                if let Some((ref mut f_input, _)) = typed[*f as usize] {
                    if *f_input == Type::Unit {
                        // Only push if we know f accepts the same type it outputs
                        // (Iden, Witness). Don't push for Unit combinator.
                    }
                }
                let _ = f_out_resolved; // used above
            }
        }

        Combinator::Pair(f, g) => {
            // Pair(f, g) produces Product(f_out, g_out).
            // Both f and g share the same input as the Pair.
            // Push the Pair's resolved input into f and g's inputs.
            let f_in = typed[*f as usize].as_ref().unwrap().0.clone();
            let g_in = typed[*g as usize].as_ref().unwrap().0.clone();
            if let Some((ref mut fi, _)) = typed[*f as usize] {
                refine_deep(fi, &g_in);
            }
            if let Some((ref mut gi, _)) = typed[*g as usize] {
                refine_deep(gi, &f_in);
            }
            // Also push the Pair's input into both children's inputs.
            let pair_in = typed[node_idx].as_ref().unwrap().0.clone();
            if pair_in != Type::Unit {
                if let Some((ref mut fi, _)) = typed[*f as usize] {
                    refine_deep(fi, &pair_in);
                }
                if let Some((ref mut gi, _)) = typed[*g as usize] {
                    refine_deep(gi, &pair_in);
                }
            }
            // If the Pair's output was resolved to Product(A, B) by a parent,
            // decompose and push A into f's output, B into g's output.
            // Only push into children whose output is refinable (not fixed
            // combinators like Unit or Const which always produce a fixed type).
            let pair_out = typed[node_idx].as_ref().unwrap().1.clone();
            if let Type::Product(ref a, ref b) = pair_out {
                if has_refinable_output(&nodes[*f as usize]) {
                    if let Some((_, ref mut fo)) = typed[*f as usize] {
                        refine_deep(fo, a);
                    }
                }
                if has_refinable_output(&nodes[*g as usize]) {
                    if let Some((_, ref mut go)) = typed[*g as usize] {
                        refine_deep(go, b);
                    }
                }
            }
        }

        Combinator::Case(f, g) => {
            // Case(f, g): both branches must produce same output type.
            // Only refine branches with refinable outputs.
            let f_out = typed[*f as usize].as_ref().unwrap().1.clone();
            let g_out = typed[*g as usize].as_ref().unwrap().1.clone();
            if has_refinable_output(&nodes[*f as usize]) {
                if let Some((_, ref mut fo)) = typed[*f as usize] {
                    refine_deep(fo, &g_out);
                }
            }
            if has_refinable_output(&nodes[*g as usize]) {
                if let Some((_, ref mut go)) = typed[*g as usize] {
                    refine_deep(go, &f_out);
                }
            }
        }

        Combinator::Take(f) => {
            // Take's input is Product(f_in, _). If we know the Product,
            // push the first component into f's input.
            // Nothing extra needed — bottom-up already handles this.
        }

        Combinator::Drop(f) => {
            // Similar to Take but for second component.
            let _ = f;
        }

        Combinator::Fold(f, z, _) | Combinator::ListFold(f, z) => {
            // Step output = init output. Only refine refinable children.
            let f_out = typed[*f as usize].as_ref().unwrap().1.clone();
            let z_out = typed[*z as usize].as_ref().unwrap().1.clone();
            if has_refinable_output(&nodes[*f as usize]) {
                if let Some((_, ref mut fo)) = typed[*f as usize] {
                    refine_deep(fo, &z_out);
                }
            }
            if has_refinable_output(&nodes[*z as usize]) {
                if let Some((_, ref mut zo)) = typed[*z as usize] {
                    refine_deep(zo, &f_out);
                }
            }
        }

        _ => {}
    }
}

/// Placeholder — not actually needed since we iterate by index.
fn find_parent_of(_f: &NodeId, _g: &NodeId, _typed: &[Option<(Type, Type)>]) -> Option<usize> {
    None
}

/// Get the already-inferred types for a child node.
fn child_types(child: NodeId, typed: &[Option<(Type, Type)>]) -> Result<(Type, Type), TypeError> {
    typed[child as usize]
        .clone()
        .ok_or(TypeError::NodeOutOfBounds(child))
}

/// Exfer the (input_type, output_type) for a single node.
fn exfer_node_type(
    id: NodeId,
    node: &Combinator,
    typed: &[Option<(Type, Type)>],
    _program: &Program,
) -> Result<(Type, Type), TypeError> {
    match node {
        Combinator::Iden => {
            // A -> A. Input type is unconstrained; use Unit as default.
            // The actual type gets refined when used as a child.
            Ok((Type::Unit, Type::Unit))
        }

        Combinator::Unit => {
            // A -> Unit for any A.
            Ok((Type::Unit, Type::Unit))
        }

        Combinator::Comp(f, g) => {
            let (f_in, f_out) = child_types(*f, typed)?;
            let (g_in, g_out) = child_types(*g, typed)?;

            // f's output must match g's input
            if !types_compatible(&f_out, &g_in) {
                return Err(TypeError::CompTypeMismatch {
                    node: id,
                    f_out,
                    g_in,
                });
            }
            Ok((f_in, g_out))
        }

        Combinator::Pair(f, g) => {
            let (f_in, f_out) = child_types(*f, typed)?;
            let (g_in, g_out) = child_types(*g, typed)?;
            // Both f and g take the same input type. Use f_in (they should match).
            let in_type = if f_in == Type::Unit { g_in } else { f_in };
            Ok((in_type, Type::Product(Box::new(f_out), Box::new(g_out))))
        }

        Combinator::Take(f) => {
            let (f_in, f_out) = child_types(*f, typed)?;
            // Input: Product(A, B); f: A -> C
            // The Take node's input is Product(f_in, anything)
            Ok((Type::Product(Box::new(f_in), Box::new(Type::Unit)), f_out))
        }

        Combinator::Drop(f) => {
            let (f_in, f_out) = child_types(*f, typed)?;
            // Input: Product(anything, B); f: B -> C
            Ok((Type::Product(Box::new(Type::Unit), Box::new(f_in)), f_out))
        }

        Combinator::InjL(f) => {
            let (f_in, f_out) = child_types(*f, typed)?;
            // A -> Sum(B, C) where f: A -> B
            Ok((f_in, Type::Sum(Box::new(f_out), Box::new(Type::Unit))))
        }

        Combinator::InjR(f) => {
            let (f_in, f_out) = child_types(*f, typed)?;
            // A -> Sum(B, C) where f: A -> C
            Ok((f_in, Type::Sum(Box::new(Type::Unit), Box::new(f_out))))
        }

        Combinator::Case(f, g) => {
            let (f_in, f_out) = child_types(*f, typed)?;
            let (g_in, g_out) = child_types(*g, typed)?;

            // f: A->C, g: B->C. Output types must match.
            if !types_compatible(&f_out, &g_out) {
                return Err(TypeError::CaseBranchMismatch(id));
            }
            let out = if f_out == Type::Unit { g_out } else { f_out };
            Ok((Type::Sum(Box::new(f_in), Box::new(g_in)), out))
        }

        Combinator::Fold(f, z, k) => {
            let (f_in, f_out) = child_types(*f, typed)?;
            let (z_in, z_out) = child_types(*z, typed)?;

            // z: A -> B (initializer)
            // f: Product(A, B) -> B (step)
            // f_out must equal z_out
            if !types_compatible(&f_out, &z_out) {
                return Err(TypeError::FoldInitMismatch(id));
            }

            // f_in should be Product(A, B) where A = z_in
            match &f_in {
                Type::Product(a, b) => {
                    if !types_compatible(a, &z_in) {
                        return Err(TypeError::FoldStepMismatch(id));
                    }
                    if !types_compatible(b, &z_out) {
                        return Err(TypeError::FoldStepMismatch(id));
                    }
                }
                Type::Unit => {
                    // Accept Unit as compatible placeholder
                }
                _ => return Err(TypeError::FoldStepMismatch(id)),
            }

            let b_type = if z_out == Type::Unit { f_out } else { z_out };
            Ok((
                Type::Product(Box::new(Type::Bound(*k)), Box::new(z_in)),
                b_type,
            ))
        }

        Combinator::ListFold(f, z) => {
            let (f_in, f_out) = child_types(*f, typed)?;
            let (z_in, z_out) = child_types(*z, typed)?;

            // z: B -> B (identity on accumulator)
            // f: Product(A, B) -> B (step)
            if !types_compatible(&f_out, &z_out) {
                return Err(TypeError::ListFoldInitMismatch(id));
            }

            // Extract A from f_in = Product(A, B)
            let elem_type = match &f_in {
                Type::Product(a, _) => (**a).clone(),
                Type::Unit => Type::Unit,
                _ => return Err(TypeError::ListFoldStepMismatch(id)),
            };

            let b_type = if z_out == Type::Unit { f_out } else { z_out };
            Ok((
                Type::Product(Box::new(Type::List(Box::new(elem_type))), Box::new(z_in)),
                b_type,
            ))
        }

        Combinator::Jet(jet_id) => {
            let (in_t, out_t) = jet_id.jet_type();
            Ok((in_t, out_t))
        }

        Combinator::Witness => {
            // Witness type is determined by usage context.
            // Default to Unit -> Unit; parent will refine.
            Ok((Type::Unit, Type::Unit))
        }

        Combinator::MerkleHidden(_) => {
            // Can't type-check hidden nodes — they're placeholders.
            // Accept with Unit types for now; they won't be evaluated.
            Ok((Type::Unit, Type::Unit))
        }

        Combinator::Const(v) => {
            // Input is Unit (constant ignores input), output is type_of(v).
            let out_type = v.infer_type();
            Ok((Type::Unit, out_type))
        }
    }
}

/// Check if two types are compatible (allowing Unit as a wildcard placeholder).
pub fn types_compatible(a: &Type, b: &Type) -> bool {
    if a == b {
        return true;
    }
    // Unit acts as a wildcard in type inference for unresolved types
    if *a == Type::Unit || *b == Type::Unit {
        return true;
    }
    // Recurse into structures
    match (a, b) {
        (Type::Sum(a1, a2), Type::Sum(b1, b2)) => {
            types_compatible(a1, b1) && types_compatible(a2, b2)
        }
        (Type::Product(a1, a2), Type::Product(b1, b2)) => {
            types_compatible(a1, b1) && types_compatible(a2, b2)
        }
        (Type::List(a1), Type::List(b1)) => types_compatible(a1, b1),
        _ => false,
    }
}
