//! Static cost computation for Exfer Script programs.
//!
//! Computes the worst-case (cells, steps) cost by walking the DAG bottom-up.
//! Consensus-critical: two implementations must agree on script cost.

use super::ast::{Combinator, NodeId, Program};

/// Cost of evaluating a script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptCost {
    pub cells: u64,
    pub steps: u64,
}

/// Information about list sizes for cost estimation.
#[derive(Clone, Debug, Default)]
pub struct ListSizes {
    pub input_count: usize,
    pub output_count: usize,
}

/// Cost computation errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CostError {
    /// Node index out of bounds.
    NodeOutOfBounds(NodeId),
    /// Cost overflow (program too expensive).
    Overflow,
    /// Invalid structure.
    InvalidStructure(String),
}

impl std::fmt::Display for CostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CostError {}

/// Compute the cost of a program.
///
/// Walks the DAG bottom-up (highest index to lowest), computing cost for each node.
/// The default list size for ListFold is `max(input_count, output_count)`.
pub fn compute_cost(program: &Program, list_sizes: &ListSizes) -> Result<ScriptCost, CostError> {
    program
        .validate_structure()
        .map_err(|e| CostError::InvalidStructure(e.to_string()))?;

    let n = program.nodes.len();
    let mut costs: Vec<Option<ScriptCost>> = vec![None; n];

    // Default list size for ListFold cost estimation
    let default_list_size = std::cmp::max(list_sizes.input_count, list_sizes.output_count) as u64;

    // Process bottom-up: highest index first (leaves before parents)
    for i in (0..n).rev() {
        let cost = node_cost(i as NodeId, &program.nodes[i], &costs, default_list_size)?;
        costs[i] = Some(cost);
    }

    costs[program.root as usize].ok_or(CostError::NodeOutOfBounds(program.root))
}

/// Get the cost of a child node.
fn child_cost(child: NodeId, costs: &[Option<ScriptCost>]) -> Result<ScriptCost, CostError> {
    costs[child as usize].ok_or(CostError::NodeOutOfBounds(child))
}

/// Compute cost for a single node.
fn node_cost(
    _id: NodeId,
    node: &Combinator,
    costs: &[Option<ScriptCost>],
    default_list_size: u64,
) -> Result<ScriptCost, CostError> {
    match node {
        Combinator::Iden => Ok(ScriptCost { cells: 0, steps: 1 }),

        Combinator::Unit => Ok(ScriptCost { cells: 0, steps: 1 }),

        Combinator::Comp(f, g) => {
            let fc = child_cost(*f, costs)?;
            let gc = child_cost(*g, costs)?;
            let cells = fc.cells.checked_add(gc.cells).ok_or(CostError::Overflow)?;
            let steps = fc
                .steps
                .checked_add(gc.steps)
                .and_then(|s| s.checked_add(1))
                .ok_or(CostError::Overflow)?;
            Ok(ScriptCost { cells, steps })
        }

        Combinator::Pair(f, g) => {
            let fc = child_cost(*f, costs)?;
            let gc = child_cost(*g, costs)?;
            let cells = fc
                .cells
                .checked_add(gc.cells)
                .and_then(|c| c.checked_add(1))
                .ok_or(CostError::Overflow)?;
            let steps = fc
                .steps
                .checked_add(gc.steps)
                .and_then(|s| s.checked_add(1))
                .ok_or(CostError::Overflow)?;
            Ok(ScriptCost { cells, steps })
        }

        Combinator::Take(f) => {
            let fc = child_cost(*f, costs)?;
            let steps = fc.steps.checked_add(1).ok_or(CostError::Overflow)?;
            Ok(ScriptCost {
                cells: fc.cells,
                steps,
            })
        }

        Combinator::Drop(f) => {
            let fc = child_cost(*f, costs)?;
            let steps = fc.steps.checked_add(1).ok_or(CostError::Overflow)?;
            Ok(ScriptCost {
                cells: fc.cells,
                steps,
            })
        }

        Combinator::InjL(f) => {
            let fc = child_cost(*f, costs)?;
            let cells = fc.cells.checked_add(1).ok_or(CostError::Overflow)?;
            let steps = fc.steps.checked_add(1).ok_or(CostError::Overflow)?;
            Ok(ScriptCost { cells, steps })
        }

        Combinator::InjR(f) => {
            let fc = child_cost(*f, costs)?;
            let cells = fc.cells.checked_add(1).ok_or(CostError::Overflow)?;
            let steps = fc.steps.checked_add(1).ok_or(CostError::Overflow)?;
            Ok(ScriptCost { cells, steps })
        }

        Combinator::Case(f, g) => {
            let fc = child_cost(*f, costs)?;
            let gc = child_cost(*g, costs)?;
            let cells = std::cmp::max(fc.cells, gc.cells)
                .checked_add(1)
                .ok_or(CostError::Overflow)?;
            let steps = std::cmp::max(fc.steps, gc.steps)
                .checked_add(1)
                .ok_or(CostError::Overflow)?;
            Ok(ScriptCost { cells, steps })
        }

        Combinator::Fold(f, z, k) => {
            let fc = child_cost(*f, costs)?;
            let zc = child_cost(*z, costs)?;
            // cells = cost(z).cells + k * cost(f).cells
            let f_cells_total = fc.cells.checked_mul(*k).ok_or(CostError::Overflow)?;
            let cells = zc
                .cells
                .checked_add(f_cells_total)
                .ok_or(CostError::Overflow)?;
            // steps = 1 (top-level) + cost(z).steps + k * (cost(f).steps + 1)
            // The evaluator calls budget.consume_step() at entry before
            // evaluating z and the k iterations.
            let f_steps_plus_1 = fc.steps.checked_add(1).ok_or(CostError::Overflow)?;
            let f_steps_total = f_steps_plus_1.checked_mul(*k).ok_or(CostError::Overflow)?;
            let steps = zc
                .steps
                .checked_add(f_steps_total)
                .ok_or(CostError::Overflow)?
                .checked_add(1) // top-level consume_step
                .ok_or(CostError::Overflow)?;
            Ok(ScriptCost { cells, steps })
        }

        Combinator::ListFold(f, z) => {
            let fc = child_cost(*f, costs)?;
            let zc = child_cost(*z, costs)?;
            let n = default_list_size;
            // cells = cost(z).cells + n * cost(f).cells
            let f_cells_total = fc.cells.checked_mul(n).ok_or(CostError::Overflow)?;
            let cells = zc
                .cells
                .checked_add(f_cells_total)
                .ok_or(CostError::Overflow)?;
            // steps = 1 (top-level) + cost(z).steps + n * (cost(f).steps + 1)
            let f_steps_plus_1 = fc.steps.checked_add(1).ok_or(CostError::Overflow)?;
            let f_steps_total = f_steps_plus_1.checked_mul(n).ok_or(CostError::Overflow)?;
            let steps = zc
                .steps
                .checked_add(f_steps_total)
                .ok_or(CostError::Overflow)?
                .checked_add(1) // top-level consume_step
                .ok_or(CostError::Overflow)?;
            Ok(ScriptCost { cells, steps })
        }

        Combinator::Jet(jet_id) => {
            let (steps, cells) = jet_id.jet_cost();
            Ok(ScriptCost { cells, steps })
        }

        Combinator::Witness => {
            // Witness: deserialization cost is O(witness_size) but fixed at 1 step for static analysis
            Ok(ScriptCost { cells: 0, steps: 1 })
        }

        Combinator::MerkleHidden(_) => {
            // Hidden nodes are never evaluated; cost is 0
            Ok(ScriptCost { cells: 0, steps: 0 })
        }

        Combinator::Const(v) => {
            // Loading a constant: cost is proportional to serialized size.
            // 1 + ceil_div(serialized_bytes, 64) steps and cells.
            // Runtime evaluator also charges track_memory(v.heap_size()).
            let serialized_bytes = v.serialize().len() as u64;
            let size_cost = serialized_bytes.div_ceil(64).max(1);
            let cells = 1u64.checked_add(size_cost).ok_or(CostError::Overflow)?;
            let steps = 1u64.checked_add(size_cost).ok_or(CostError::Overflow)?;
            Ok(ScriptCost { cells, steps })
        }
    }
}
