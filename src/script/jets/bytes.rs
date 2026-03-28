//! Byte operation jet implementations: cat, slice, len, eq_bytes.

use super::JetError;
use crate::script::value::Value;

/// Concatenate two byte sequences.
/// Input: Pair(Bytes, Bytes) -> Bytes
pub fn jet_cat(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::Pair(a, b) => match (a.as_ref(), b.as_ref()) {
            (Value::Bytes(x), Value::Bytes(y)) => {
                let mut result = x.clone();
                result.extend_from_slice(y);
                Ok(Value::Bytes(result))
            }
            _ => Err(JetError::TypeMismatch(
                "cat expects (Bytes, Bytes)".to_string(),
            )),
        },
        _ => Err(JetError::TypeMismatch("cat expects Pair".to_string())),
    }
}

/// Slice a byte sequence.
/// Input: Pair(Bytes, Pair(start_u64, len_u64)) -> Bytes
pub fn jet_slice(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::Pair(data, params) => match (data.as_ref(), params.as_ref()) {
            (Value::Bytes(bytes), Value::Pair(start_v, len_v)) => {
                match (start_v.as_ref(), len_v.as_ref()) {
                    (Value::U64(start), Value::U64(len)) => {
                        let start = usize::try_from(*start).unwrap_or(usize::MAX);
                        let len = usize::try_from(*len).unwrap_or(usize::MAX);
                        if start > bytes.len() {
                            return Ok(Value::Bytes(vec![]));
                        }
                        let end = std::cmp::min(start.saturating_add(len), bytes.len());
                        Ok(Value::Bytes(bytes[start..end].to_vec()))
                    }
                    _ => Err(JetError::TypeMismatch(
                        "slice expects (Bytes, (U64, U64))".to_string(),
                    )),
                }
            }
            _ => Err(JetError::TypeMismatch(
                "slice expects (Bytes, Pair)".to_string(),
            )),
        },
        _ => Err(JetError::TypeMismatch("slice expects Pair".to_string())),
    }
}

/// Length of a byte sequence.
/// Input: Bytes -> U64
pub fn jet_len(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::Bytes(data) => Ok(Value::U64(data.len() as u64)),
        _ => Err(JetError::TypeMismatch("len expects Bytes".to_string())),
    }
}

/// Compare two byte sequences for equality.
/// Input: Pair(Bytes|Hash, Bytes|Hash) -> Bool
/// Accepts both Bytes and Hash values (treats Hash as its 32-byte representation).
pub fn jet_eq_bytes(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::Pair(a, b) => {
            let lhs = to_byte_slice(a.as_ref())?;
            let rhs = to_byte_slice(b.as_ref())?;
            Ok(Value::Bool(lhs == rhs))
        }
        _ => Err(JetError::TypeMismatch("eq_bytes expects Pair".to_string())),
    }
}

/// Extract a byte slice from a Bytes or Hash value.
fn to_byte_slice(v: &Value) -> Result<&[u8], JetError> {
    match v {
        Value::Bytes(b) => Ok(b.as_slice()),
        Value::Hash(h) => Ok(h.0.as_slice()),
        _ => Err(JetError::TypeMismatch(
            "eq_bytes expects Bytes or Hash".to_string(),
        )),
    }
}
