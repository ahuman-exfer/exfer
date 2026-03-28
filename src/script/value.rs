//! Runtime values for Exfer Script evaluation.

use super::types::Type;
use crate::types::hash::Hash256;

/// A runtime value produced during script evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Unit value.
    Unit,
    /// Left tag of a Sum type.
    Left(Box<Value>),
    /// Right tag of a Sum type.
    Right(Box<Value>),
    /// Product (pair) of two values.
    Pair(Box<Value>, Box<Value>),
    /// Variable-length list.
    List(Vec<Value>),
    /// Raw byte sequence (for witness/datum data, byte ops).
    Bytes(Vec<u8>),
    /// 64-bit unsigned integer (for Bound(k) values and arithmetic).
    U64(u64),
    /// 256-bit value (for 256-bit arithmetic, stored big-endian).
    U256([u8; 32]),
    /// Boolean value.
    Bool(bool),
    /// Hash value (32 bytes).
    Hash(Hash256),
}

impl Value {
    /// Convenience: construct a None option value (Left(Unit)).
    pub fn none() -> Value {
        Value::Left(Box::new(Value::Unit))
    }

    /// Convenience: construct a Some option value (Right(v)).
    pub fn some(v: Value) -> Value {
        Value::Right(Box::new(v))
    }

    /// Estimate the heap size of this value in bytes (for memory tracking).
    ///
    /// Accounts for full allocated object size: each `Box<Value>` allocates
    /// `size_of::<Value>()` bytes on the heap, and each `Vec<Value>` element
    /// occupies `size_of::<Value>()` bytes in the Vec's heap buffer. Inline
    /// variants (U64, U256, Bool, Hash) have zero heap overhead — their data
    /// lives inside the enum's inline storage (covered by the parent Box/Vec
    /// allocation or the stack frame).
    pub fn heap_size(&self) -> usize {
        const VALUE_SIZE: usize = std::mem::size_of::<Value>();
        match self {
            Value::Unit | Value::U64(_) | Value::U256(_) | Value::Bool(_) | Value::Hash(_) => 0,
            Value::Left(v) => VALUE_SIZE + v.heap_size(),
            Value::Right(v) => VALUE_SIZE + v.heap_size(),
            Value::Pair(a, b) => 2 * VALUE_SIZE + a.heap_size() + b.heap_size(),
            Value::List(vs) => {
                let mut size = vs.capacity() * VALUE_SIZE;
                for v in vs {
                    size += v.heap_size();
                }
                size
            }
            Value::Bytes(bs) => bs.capacity(),
        }
    }

    /// Exfer the type of a value. Returns None for ambiguous Sum types
    /// where the "other" branch type is unknown.
    pub fn infer_type(&self) -> Type {
        match self {
            Value::Unit => Type::Unit,
            Value::Left(v) => Type::Sum(Box::new(v.infer_type()), Box::new(Type::Unit)),
            Value::Right(v) => Type::Sum(Box::new(Type::Unit), Box::new(v.infer_type())),
            Value::Pair(a, b) => Type::Product(Box::new(a.infer_type()), Box::new(b.infer_type())),
            Value::List(vs) => {
                let elem_type = if vs.is_empty() {
                    Type::Unit
                } else {
                    vs[0].infer_type()
                };
                Type::List(Box::new(elem_type))
            }
            Value::Bytes(_) => Type::bytes(),
            Value::U64(_) => Type::u64_type(),
            Value::U256(_) => Type::u256_type(),
            Value::Bool(_) => Type::bool_type(),
            Value::Hash(_) => Type::hash256(),
        }
    }

    /// Runtime type validation. Checks that a value matches an expected type.
    /// This is strict runtime checking, NOT type inference. Unit is literal,
    /// not a wildcard. Special-cases aliases: Bool, Bytes, Hash256, U256.
    pub fn matches_type(&self, ty: &Type) -> bool {
        use Type::*;
        // Bool alias: Sum(Unit, Unit)
        if *ty == Type::bool_type() {
            return match self {
                Value::Bool(_) => true,
                Value::Left(inner) if inner.as_ref() == &Value::Unit => true,
                Value::Right(inner) if inner.as_ref() == &Value::Unit => true,
                _ => false,
            };
        }
        // Bytes alias: List(Bound(256))
        if *ty == Type::bytes() {
            return matches!(self, Value::Bytes(_));
        }
        // Hash256 alias: Bound(0)
        if *ty == Type::hash256() {
            return matches!(self, Value::Hash(_));
        }
        // U256 nominal type
        if *ty == Type::U256 {
            return matches!(self, Value::U256(_));
        }
        match (self, ty) {
            (Value::Unit, Unit) => true,
            (Value::U64(n), Bound(k)) => *k == u64::MAX || *n < *k,
            (Value::Left(a), Sum(ta, _)) => a.matches_type(ta),
            (Value::Right(b), Sum(_, tb)) => b.matches_type(tb),
            (Value::Pair(a, b), Product(ta, tb)) => a.matches_type(ta) && b.matches_type(tb),
            (Value::List(elems), List(elem_ty)) => {
                elems.iter().all(|e| e.matches_type(elem_ty))
            }
            _ => false,
        }
    }

    /// Try to interpret this value as a boolean.
    /// Accepts `Bool(b)`, `Left(Unit)` (false), and `Right(Unit)` (true).
    /// Returns None if the value is not a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            Value::Left(inner) if **inner == Value::Unit => Some(false),
            Value::Right(inner) if **inner == Value::Unit => Some(true),
            _ => None,
        }
    }

    /// Try to interpret this value as a U256.
    /// Only accepts `Value::U256(data)`. U256 is a distinct type from
    /// Product(U64, U64) — no implicit conversion.
    pub fn as_u256(&self) -> Option<[u8; 32]> {
        match self {
            Value::U256(data) => Some(*data),
            _ => None,
        }
    }

    /// Check that all list constants in this value are homogeneous
    /// (every element has the same inferred type). Returns false if any
    /// nested list contains elements with mismatched types. Heterogeneous
    /// list constants pass type inference (which checks only the first
    /// element) but fail at runtime when list jets enforce per-element types.
    pub fn lists_are_homogeneous(&self) -> bool {
        match self {
            Value::List(vs) => {
                if vs.len() > 1 {
                    let expected = vs[0].infer_type();
                    for v in &vs[1..] {
                        if v.infer_type() != expected {
                            return false;
                        }
                    }
                }
                // Recurse into nested values
                vs.iter().all(|v| v.lists_are_homogeneous())
            }
            Value::Left(v) | Value::Right(v) => v.lists_are_homogeneous(),
            Value::Pair(a, b) => a.lists_are_homogeneous() && b.lists_are_homogeneous(),
            _ => true,
        }
    }

    /// Serialize a value to bytes (for Const embedding and witness deserialization).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize_into(&mut buf);
        buf
    }

    fn serialize_into(&self, buf: &mut Vec<u8>) {
        match self {
            Value::Unit => buf.push(0x00),
            Value::Left(v) => {
                buf.push(0x01);
                v.serialize_into(buf);
            }
            Value::Right(v) => {
                buf.push(0x02);
                v.serialize_into(buf);
            }
            Value::Pair(a, b) => {
                buf.push(0x03);
                a.serialize_into(buf);
                b.serialize_into(buf);
            }
            Value::List(vs) => {
                buf.push(0x04);
                buf.extend_from_slice(&(vs.len() as u32).to_le_bytes());
                for v in vs {
                    v.serialize_into(buf);
                }
            }
            Value::Bytes(bs) => {
                buf.push(0x05);
                buf.extend_from_slice(&(bs.len() as u32).to_le_bytes());
                buf.extend_from_slice(bs);
            }
            Value::U64(n) => {
                buf.push(0x06);
                buf.extend_from_slice(&n.to_le_bytes());
            }
            Value::U256(data) => {
                buf.push(0x07);
                buf.extend_from_slice(data);
            }
            Value::Bool(b) => {
                buf.push(0x08);
                buf.push(if *b { 1 } else { 0 });
            }
            Value::Hash(h) => {
                buf.push(0x09);
                buf.extend_from_slice(h.as_bytes());
            }
        }
    }

    /// Deserialize a value from bytes. Returns (value, bytes_consumed).
    pub fn deserialize(data: &[u8]) -> Result<(Value, usize), &'static str> {
        Self::deserialize_depth(data, 0)
    }

    fn deserialize_depth(data: &[u8], depth: usize) -> Result<(Value, usize), &'static str> {
        if depth > crate::types::MAX_VALUE_DEPTH {
            return Err("value nesting depth exceeded");
        }
        if data.is_empty() {
            return Err("unexpected end of value data");
        }
        let tag = data[0];
        let rest = &data[1..];
        match tag {
            0x00 => Ok((Value::Unit, 1)),
            0x01 => {
                let (v, consumed) = Value::deserialize_depth(rest, depth + 1)?;
                Ok((Value::Left(Box::new(v)), 1 + consumed))
            }
            0x02 => {
                let (v, consumed) = Value::deserialize_depth(rest, depth + 1)?;
                Ok((Value::Right(Box::new(v)), 1 + consumed))
            }
            0x03 => {
                let (a, ca) = Value::deserialize_depth(rest, depth + 1)?;
                let (b, cb) = Value::deserialize_depth(&rest[ca..], depth + 1)?;
                Ok((Value::Pair(Box::new(a), Box::new(b)), 1 + ca + cb))
            }
            0x04 => {
                if rest.len() < 4 {
                    return Err("unexpected end of list length");
                }
                let count = u32::from_le_bytes(rest[0..4].try_into().unwrap()) as usize;
                // P1-7: Cap allocation to prevent OOM on untrusted input
                if count > crate::types::MAX_LIST_LENGTH {
                    return Err("list length exceeds maximum");
                }
                let mut pos = 4;
                let mut vs = Vec::with_capacity(count);
                for _ in 0..count {
                    let (v, consumed) = Value::deserialize_depth(&rest[pos..], depth + 1)?;
                    vs.push(v);
                    pos += consumed;
                }
                Ok((Value::List(vs), 1 + pos))
            }
            0x05 => {
                if rest.len() < 4 {
                    return Err("unexpected end of bytes length");
                }
                let len = u32::from_le_bytes(rest[0..4].try_into().unwrap()) as usize;
                if rest.len() < 4 + len {
                    return Err("unexpected end of bytes data");
                }
                Ok((Value::Bytes(rest[4..4 + len].to_vec()), 1 + 4 + len))
            }
            0x06 => {
                if rest.len() < 8 {
                    return Err("unexpected end of u64 data");
                }
                let n = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                Ok((Value::U64(n), 1 + 8))
            }
            0x07 => {
                if rest.len() < 32 {
                    return Err("unexpected end of u256 data");
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&rest[0..32]);
                Ok((Value::U256(arr), 1 + 32))
            }
            0x08 => {
                if rest.is_empty() {
                    return Err("unexpected end of bool data");
                }
                match rest[0] {
                    0x00 => Ok((Value::Bool(false), 2)),
                    0x01 => Ok((Value::Bool(true), 2)),
                    _ => Err("non-canonical bool byte"),
                }
            }
            0x09 => {
                if rest.len() < 32 {
                    return Err("unexpected end of hash data");
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&rest[0..32]);
                Ok((Value::Hash(Hash256(arr)), 1 + 32))
            }
            _ => Err("unknown value tag"),
        }
    }
}
