//! Interpreter for Exfer Script programs.
//!
//! Evaluates a program DAG on an input value, producing an output value.
//! Tracks resource consumption via a Budget. All errors map to `false` at
//! the validation layer.

use super::ast::{Combinator, NodeId, Program};
use super::jets::context::ScriptContext;
use super::value::Value;

/// Maximum script memory in bytes (16 MiB).
pub const MAX_SCRIPT_MEMORY: usize = 16 * 1024 * 1024;

/// Maximum recursion depth for the script evaluator.
/// Prevents stack overflow from deeply nested programs.
/// 128 is conservative: safe across all platforms and build profiles.
pub const MAX_EVAL_DEPTH: usize = 128;

/// Resource budget for script evaluation.
#[derive(Clone, Debug)]
pub struct Budget {
    pub steps_remaining: u64,
    pub cells_remaining: u64,
    pub memory_used: usize,
    pub memory_limit: usize,
}

impl Budget {
    /// Create a new budget with the given limits.
    pub fn new(steps: u64, cells: u64) -> Self {
        Budget {
            steps_remaining: steps,
            cells_remaining: cells,
            memory_used: 0,
            memory_limit: MAX_SCRIPT_MEMORY,
        }
    }

    /// Consume one step. Returns error if budget exceeded.
    fn consume_step(&mut self) -> Result<(), EvalError> {
        if self.steps_remaining == 0 {
            return Err(EvalError::BudgetExceeded);
        }
        self.steps_remaining -= 1;
        Ok(())
    }

    /// Consume n steps. Returns error if budget exceeded.
    fn consume_steps(&mut self, n: u64) -> Result<(), EvalError> {
        if self.steps_remaining < n {
            return Err(EvalError::BudgetExceeded);
        }
        self.steps_remaining -= n;
        Ok(())
    }

    /// Consume one cell. Returns error if budget exceeded.
    fn consume_cell(&mut self) -> Result<(), EvalError> {
        if self.cells_remaining == 0 {
            return Err(EvalError::BudgetExceeded);
        }
        self.cells_remaining -= 1;
        Ok(())
    }

    /// Track memory allocation. Returns error if limit exceeded.
    fn track_memory(&mut self, size: usize) -> Result<(), EvalError> {
        self.memory_used = self
            .memory_used
            .checked_add(size)
            .ok_or(EvalError::MemoryExceeded)?;
        if self.memory_used > self.memory_limit {
            return Err(EvalError::MemoryExceeded);
        }
        Ok(())
    }

    /// Release memory when an intermediate value goes out of scope.
    /// Tracks live heap, not cumulative allocations.
    fn release_memory(&mut self, size: usize) {
        self.memory_used = self.memory_used.saturating_sub(size);
    }
}

/// Evaluation errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalError {
    /// Step or cell budget exceeded.
    BudgetExceeded,
    /// Memory limit exceeded.
    MemoryExceeded,
    /// Runtime type mismatch (e.g., Take on non-Pair).
    TypeMismatch(String),
    /// Tried to evaluate a MerkleHidden node.
    HiddenNode,
    /// Witness deserialization failed.
    WitnessError(String),
    /// Node index out of bounds.
    NodeOutOfBounds(NodeId),
    /// Jet evaluation error.
    JetError(String),
    /// Recursion depth exceeded.
    RecursionDepthExceeded,
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for EvalError {}

/// State for tracking witness data consumption during evaluation.
struct WitnessReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WitnessReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        WitnessReader { data, pos: 0 }
    }

    fn read_value(&mut self) -> Result<Value, EvalError> {
        if self.pos >= self.data.len() {
            return Err(EvalError::WitnessError(
                "unexpected end of witness data".to_string(),
            ));
        }
        let (value, consumed) = Value::deserialize(&self.data[self.pos..])
            .map_err(|e| EvalError::WitnessError(e.to_string()))?;
        self.pos += consumed;
        Ok(value)
    }

    /// Deserialize a witness value and validate it against the expected type.
    /// Rejects non-canonical witness encodings before they can influence
    /// control flow (e.g. choosing the wrong Case branch).
    /// If the expected type is Unit (unresolved by the typechecker), accept
    /// any value — the typechecker's single-pass refinement may not fully
    /// resolve all witness types.
    fn read_typed_value(&mut self, expected: &super::Type) -> Result<Value, EvalError> {
        let value = self.read_value()?;
        if *expected != super::Type::Unit && !value.matches_type(expected) {
            return Err(EvalError::WitnessError(format!(
                "witness type mismatch: expected {:?}, got {:?}",
                expected,
                value.infer_type()
            )));
        }
        Ok(value)
    }
}

/// Evaluate a program on an input value (without script context).
///
/// Uses an empty ScriptContext. For scripts that don't use introspection jets.
pub fn evaluate(
    program: &Program,
    input: Value,
    witness_data: &[u8],
    budget: &mut Budget,
) -> Result<Value, EvalError> {
    evaluate_with_context(
        program,
        input,
        witness_data,
        budget,
        &ScriptContext::empty(),
    )
}

/// Evaluate a program on an input value with a script context.
///
/// Returns the output value, or an error if evaluation fails.
/// The caller maps any error to `false` for script validation.
pub fn evaluate_with_context(
    program: &Program,
    input: Value,
    witness_data: &[u8],
    budget: &mut Budget,
    context: &ScriptContext,
) -> Result<Value, EvalError> {
    // Typecheck to get expected witness types for runtime validation.
    let typed_nodes = super::typecheck(program)
        .map_err(|e| EvalError::TypeMismatch(format!("typecheck failed: {:?}", e)))?;
    let mut witness = WitnessReader::new(witness_data);
    let result = eval_node(
        program,
        program.root,
        &input,
        &mut witness,
        budget,
        context,
        &typed_nodes,
        0,
    )?;

    // Reject unconsumed witness bytes — prevents witness malleability.
    // Trailing bytes would not affect evaluation but create distinct
    // serializations for semantically identical transactions.
    if witness.pos < witness.data.len() {
        return Err(EvalError::WitnessError(format!(
            "unconsumed witness bytes: {} of {} consumed",
            witness.pos,
            witness.data.len()
        )));
    }

    Ok(result)
}

/// Evaluate a single node in the DAG.
fn eval_node(
    program: &Program,
    node_id: NodeId,
    input: &Value,
    witness: &mut WitnessReader<'_>,
    budget: &mut Budget,
    context: &ScriptContext,
    typed_nodes: &[super::TypedNode],
    depth: usize,
) -> Result<Value, EvalError> {
    if depth > MAX_EVAL_DEPTH {
        return Err(EvalError::RecursionDepthExceeded);
    }

    let node = program
        .get(node_id)
        .ok_or(EvalError::NodeOutOfBounds(node_id))?;

    match node.clone() {
        Combinator::Iden => {
            budget.consume_step()?;
            let result = input.clone();
            budget.track_memory(result.heap_size())?;
            Ok(result)
        }

        Combinator::Unit => {
            budget.consume_step()?;
            Ok(Value::Unit)
        }

        Combinator::Comp(f, g) => {
            budget.consume_step()?;
            let mid = eval_node(program, f, input, witness, budget, context, typed_nodes, depth + 1)?;
            let mid_heap = mid.heap_size();
            let result = eval_node(program, g, &mid, witness, budget, context, typed_nodes, depth + 1)?;
            budget.release_memory(mid_heap);
            Ok(result)
        }

        Combinator::Pair(f, g) => {
            budget.consume_step()?;
            budget.consume_cell()?;
            let left = eval_node(program, f, input, witness, budget, context, typed_nodes, depth + 1)?;
            let right = eval_node(program, g, input, witness, budget, context, typed_nodes, depth + 1)?;
            budget.track_memory(2 * std::mem::size_of::<Value>())?;
            Ok(Value::Pair(Box::new(left), Box::new(right)))
        }

        Combinator::Take(f) => {
            budget.consume_step()?;
            match input {
                Value::Pair(a, _) => eval_node(program, f, a, witness, budget, context, typed_nodes, depth + 1),
                _ => Err(EvalError::TypeMismatch(
                    "Take expects Pair input".to_string(),
                )),
            }
        }

        Combinator::Drop(f) => {
            budget.consume_step()?;
            match input {
                Value::Pair(_, b) => eval_node(program, f, b, witness, budget, context, typed_nodes, depth + 1),
                _ => Err(EvalError::TypeMismatch(
                    "Drop expects Pair input".to_string(),
                )),
            }
        }

        Combinator::InjL(f) => {
            budget.consume_step()?;
            budget.consume_cell()?;
            let result = eval_node(program, f, input, witness, budget, context, typed_nodes, depth + 1)?;
            budget.track_memory(std::mem::size_of::<Value>())?;
            Ok(Value::Left(Box::new(result)))
        }

        Combinator::InjR(f) => {
            budget.consume_step()?;
            budget.consume_cell()?;
            let result = eval_node(program, f, input, witness, budget, context, typed_nodes, depth + 1)?;
            budget.track_memory(std::mem::size_of::<Value>())?;
            Ok(Value::Right(Box::new(result)))
        }

        Combinator::Case(f, g) => {
            budget.consume_step()?;
            // Determine if the case input type is exactly Bool = Sum(Unit, Unit)
            let input_is_bool = typed_nodes.get(node_id as usize)
                .map(|tn| tn.input_type == super::Type::bool_type())
                .unwrap_or(false);
            match input {
                Value::Left(a) => {
                    // Validate payload matches the left branch's expected input type
                    if let Some(tn) = typed_nodes.get(f as usize) {
                        if !a.matches_type(&tn.input_type) {
                            return Err(EvalError::TypeMismatch(
                                format!("Case Left payload type mismatch: expected {:?}", tn.input_type),
                            ));
                        }
                    }
                    eval_node(program, f, a, witness, budget, context, typed_nodes, depth + 1)
                }
                Value::Right(b) => {
                    if let Some(tn) = typed_nodes.get(g as usize) {
                        if !b.matches_type(&tn.input_type) {
                            return Err(EvalError::TypeMismatch(
                                format!("Case Right payload type mismatch: expected {:?}", tn.input_type),
                            ));
                        }
                    }
                    eval_node(program, g, b, witness, budget, context, typed_nodes, depth + 1)
                }
                // Bool shortcut only allowed when input type is exactly Bool
                Value::Bool(false) if input_is_bool => {
                    eval_node(program, f, &Value::Unit, witness, budget, context, typed_nodes, depth + 1)
                }
                Value::Bool(true) if input_is_bool => {
                    eval_node(program, g, &Value::Unit, witness, budget, context, typed_nodes, depth + 1)
                }
                _ => Err(EvalError::TypeMismatch(
                    "Case expects Sum (Left/Right) or Bool input".to_string(),
                )),
            }
        }

        Combinator::Fold(f, z, k) => {
            budget.consume_step()?;
            let (_, init_input) = match input {
                Value::Pair(a, b) => (a.as_ref().clone(), b.as_ref().clone()),
                _ => {
                    return Err(EvalError::TypeMismatch(
                        "Fold expects Pair input".to_string(),
                    ))
                }
            };

            let mut acc = eval_node(program, z, &init_input, witness, budget, context, typed_nodes, depth + 1)?;

            let mut prev_step_heap = 0usize;
            for _ in 0..k {
                budget.consume_step()?;
                budget.release_memory(prev_step_heap);
                let clone_heap = init_input.heap_size();
                budget.track_memory(clone_heap + 2 * std::mem::size_of::<Value>())?;
                let step_input = Value::Pair(Box::new(init_input.clone()), Box::new(acc));
                prev_step_heap = step_input.heap_size();
                acc = eval_node(program, f, &step_input, witness, budget, context, typed_nodes, depth + 1)?;
            }
            budget.release_memory(prev_step_heap);

            Ok(acc)
        }

        Combinator::ListFold(f, z) => {
            budget.consume_step()?;
            let (list, init_input) = match input {
                Value::Pair(a, b) => {
                    let elements = match a.as_ref() {
                        Value::List(elems) => elems.clone(),
                        _ => {
                            return Err(EvalError::TypeMismatch(
                                "ListFold expects List as first element of Pair".to_string(),
                            ))
                        }
                    };
                    (elements, b.as_ref().clone())
                }
                _ => {
                    return Err(EvalError::TypeMismatch(
                        "ListFold expects Pair input".to_string(),
                    ))
                }
            };

            let mut acc = eval_node(program, z, &init_input, witness, budget, context, typed_nodes, depth + 1)?;

            let mut prev_step_heap = 0usize;
            for elem in &list {
                budget.consume_step()?;
                budget.release_memory(prev_step_heap);
                let clone_heap = elem.heap_size();
                budget.track_memory(clone_heap + 2 * std::mem::size_of::<Value>())?;
                let step_input = Value::Pair(Box::new(elem.clone()), Box::new(acc));
                prev_step_heap = step_input.heap_size();
                acc = eval_node(program, f, &step_input, witness, budget, context, typed_nodes, depth + 1)?;
            }
            budget.release_memory(prev_step_heap);

            Ok(acc)
        }

        Combinator::Jet(jet_id) => {
            // Charge data-proportional runtime cost from the budget.
            let cost = jet_id.runtime_cost(input, context);
            budget.consume_steps(cost)?;
            let result = jet_id
                .eval(input, context)
                .map_err(|e| EvalError::JetError(format!("{:?}", e)))?;
            budget.track_memory(result.heap_size())?;
            Ok(result)
        }

        Combinator::Witness => {
            budget.consume_step()?;
            let expected_type = &typed_nodes[node_id as usize].output_type;
            let value = witness.read_typed_value(expected_type)?;
            budget.track_memory(value.heap_size())?;
            Ok(value)
        }

        Combinator::MerkleHidden(_) => Err(EvalError::HiddenNode),

        Combinator::Const(v) => {
            budget.consume_step()?;
            budget.track_memory(v.heap_size())?;
            Ok(v.clone())
        }
    }
}
