//! Introspection jet implementations: access transaction data from ScriptContext.

use super::context::ScriptContext;
use super::JetError;
use crate::script::value::Value;
use crate::types::hash::Hash256;

/// Get list of transaction inputs as values.
/// Input: Unit -> List(Unit)
/// (Returns list of input indices for now; full input data via other jets)
pub fn jet_tx_inputs(context: &ScriptContext) -> Result<Value, JetError> {
    let inputs: Vec<Value> = context
        .tx_inputs
        .iter()
        .map(|info| {
            Value::Pair(
                Box::new(Value::Hash(info.prev_tx_id)),
                Box::new(Value::Pair(
                    Box::new(Value::U64(info.output_index as u64)),
                    Box::new(Value::Pair(
                        Box::new(Value::U64(info.value)),
                        Box::new(Value::Hash(info.script_hash)),
                    )),
                )),
            )
        })
        .collect();
    Ok(Value::List(inputs))
}

/// Get list of transaction outputs as values.
/// Input: Unit -> List(Unit)
pub fn jet_tx_outputs(context: &ScriptContext) -> Result<Value, JetError> {
    let outputs: Vec<Value> = context
        .tx_outputs
        .iter()
        .map(|info| {
            Value::Pair(
                Box::new(Value::U64(info.value)),
                Box::new(Value::Pair(
                    Box::new(Value::Hash(info.script_hash)),
                    Box::new(match &info.datum_hash {
                        Some(h) => Value::some(Value::Hash(*h)),
                        None => Value::none(),
                    }),
                )),
            )
        })
        .collect();
    Ok(Value::List(outputs))
}

/// Get value of input at given index.
/// Input: U64 (index) -> U64 (value)
pub fn jet_tx_value(input: &Value, context: &ScriptContext) -> Result<Value, JetError> {
    match input {
        Value::U64(idx) => {
            let idx = usize::try_from(*idx)
                .map_err(|_| JetError::OutOfBounds("tx_value index out of bounds".to_string()))?;
            if idx >= context.tx_inputs.len() {
                return Err(JetError::OutOfBounds(
                    "tx_value index out of bounds".to_string(),
                ));
            }
            Ok(Value::U64(context.tx_inputs[idx].value))
        }
        _ => Err(JetError::TypeMismatch("tx_value expects U64".to_string())),
    }
}

/// Get script hash of input at given index.
/// Input: U64 (index) -> Hash256
pub fn jet_tx_script_hash(input: &Value, context: &ScriptContext) -> Result<Value, JetError> {
    match input {
        Value::U64(idx) => {
            let idx = usize::try_from(*idx).map_err(|_| {
                JetError::OutOfBounds("tx_script_hash index out of bounds".to_string())
            })?;
            if idx >= context.tx_inputs.len() {
                return Err(JetError::OutOfBounds(
                    "tx_script_hash index out of bounds".to_string(),
                ));
            }
            Ok(Value::Hash(context.tx_inputs[idx].script_hash))
        }
        _ => Err(JetError::TypeMismatch(
            "tx_script_hash expects U64".to_string(),
        )),
    }
}

/// Get number of transaction inputs.
/// Input: Unit -> U64
pub fn jet_tx_input_count(context: &ScriptContext) -> Result<Value, JetError> {
    Ok(Value::U64(context.tx_inputs.len() as u64))
}

/// Get number of transaction outputs.
/// Input: Unit -> U64
pub fn jet_tx_output_count(context: &ScriptContext) -> Result<Value, JetError> {
    Ok(Value::U64(context.tx_outputs.len() as u64))
}

/// Get the index of the current input being evaluated.
/// Input: Unit -> U64
pub fn jet_self_index(context: &ScriptContext) -> Result<Value, JetError> {
    Ok(Value::U64(context.self_index as u64))
}

/// Get the current block height.
/// Input: Unit -> U64
pub fn jet_block_height(context: &ScriptContext) -> Result<Value, JetError> {
    Ok(Value::U64(context.block_height))
}

/// Get the transaction signing digest: "EXFER-SIG" || tx_header || tx_body.
/// Input: Unit -> Bytes
///
/// This is the message that Phase 1 signature validation signs/verifies.
/// Covenant scripts use this via `sig_check` to bind Ed25519 signatures
/// to the spending transaction, preventing replay/phishing-style misuse.
pub fn jet_tx_sig_hash(context: &ScriptContext) -> Result<Value, JetError> {
    Ok(Value::Bytes(context.sig_hash.to_vec()))
}

// Unused import suppression
const _: () = {
    fn _suppress(_: &Hash256) {}
};
