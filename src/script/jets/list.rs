//! List operation jet implementations.

use super::JetError;
use crate::script::value::Value;

/// Get length of a list.
/// Input: List -> U64
pub fn jet_list_len(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::List(items) => Ok(Value::U64(items.len() as u64)),
        _ => Err(JetError::TypeMismatch("list_len expects List".to_string())),
    }
}

/// Get element at index from a list.
/// Input: Pair(List, U64) -> Option(element)
/// Returns None if out of bounds.
pub fn jet_list_at(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::Pair(list, idx) => match (list.as_ref(), idx.as_ref()) {
            (Value::List(items), Value::U64(i)) => {
                let i = usize::try_from(*i).unwrap_or(usize::MAX);
                if i < items.len() {
                    Ok(Value::some(items[i].clone()))
                } else {
                    Ok(Value::none())
                }
            }
            _ => Err(JetError::TypeMismatch(
                "list_at expects (List, U64)".to_string(),
            )),
        },
        _ => Err(JetError::TypeMismatch("list_at expects Pair".to_string())),
    }
}

/// Sum all U64 elements in a list.
/// Input: List(U64) -> U64
/// Empty list returns 0.
pub fn jet_list_sum(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::List(items) => {
            let mut sum: u64 = 0;
            for item in items {
                match item {
                    Value::U64(n) => {
                        sum = sum
                            .checked_add(*n)
                            .ok_or(JetError::Overflow("list_sum overflow".to_string()))?;
                    }
                    _ => {
                        return Err(JetError::TypeMismatch(
                            "list_sum expects List(U64)".to_string(),
                        ))
                    }
                }
            }
            Ok(Value::U64(sum))
        }
        _ => Err(JetError::TypeMismatch("list_sum expects List".to_string())),
    }
}

/// Check if all Bool elements in a list are true.
/// Input: List(Bool) -> Bool
/// Empty list returns true (vacuously true).
pub fn jet_list_all(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::List(items) => {
            for item in items {
                match item.as_bool() {
                    Some(b) => {
                        if !b {
                            return Ok(Value::Bool(false));
                        }
                    }
                    None => {
                        return Err(JetError::TypeMismatch(
                            "list_all expects List(Bool)".to_string(),
                        ))
                    }
                }
            }
            Ok(Value::Bool(true))
        }
        _ => Err(JetError::TypeMismatch("list_all expects List".to_string())),
    }
}

/// Check if any Bool element in a list is true.
/// Input: List(Bool) -> Bool
/// Empty list returns false.
pub fn jet_list_any(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::List(items) => {
            for item in items {
                match item.as_bool() {
                    Some(b) => {
                        if b {
                            return Ok(Value::Bool(true));
                        }
                    }
                    None => {
                        return Err(JetError::TypeMismatch(
                            "list_any expects List(Bool)".to_string(),
                        ))
                    }
                }
            }
            Ok(Value::Bool(false))
        }
        _ => Err(JetError::TypeMismatch("list_any expects List".to_string())),
    }
}

/// Find the index of the first true Bool in a list.
/// Input: List(Bool) -> Option(U64)
/// Returns None if no true element found or list is empty.
pub fn jet_list_find(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::List(items) => {
            for (i, item) in items.iter().enumerate() {
                match item.as_bool() {
                    Some(b) => {
                        if b {
                            return Ok(Value::some(Value::U64(i as u64)));
                        }
                    }
                    None => {
                        return Err(JetError::TypeMismatch(
                            "list_find expects List(Bool)".to_string(),
                        ))
                    }
                }
            }
            Ok(Value::none())
        }
        _ => Err(JetError::TypeMismatch("list_find expects List".to_string())),
    }
}
