//! Binary serialization and Merkle hashing for Exfer Script programs.
//!
//! Programs are serialized as Merkle trees for on-chain commitment.
//! The script commitment stored in an output is the Merkle hash of the root node.
//!
//! Consensus-critical: two implementations must produce identical byte sequences.

use super::ast::{Combinator, NodeId, Program};
use super::jets::JetId;
use super::value::Value;
use crate::types::hash::Hash256;

/// Domain separator for script Merkle hashes.
const SCRIPT_DOMAIN: &[u8] = b"EXFER-SCRIPT";

/// Tag bytes for each combinator type.
const TAG_IDEN: u8 = 0x00;
const TAG_COMP: u8 = 0x01;
const TAG_UNIT: u8 = 0x02;
const TAG_PAIR: u8 = 0x03;
const TAG_TAKE: u8 = 0x04;
const TAG_DROP: u8 = 0x05;
const TAG_INJL: u8 = 0x06;
const TAG_INJR: u8 = 0x07;
const TAG_CASE: u8 = 0x08;
const TAG_FOLD: u8 = 0x09;
const TAG_LISTFOLD: u8 = 0x0A;
const TAG_JET: u8 = 0x0B;
const TAG_WITNESS: u8 = 0x0C;
const TAG_HIDDEN: u8 = 0x0D;
const TAG_CONST: u8 = 0x0E;

/// Serialization errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SerializeError {
    /// Input data too short.
    UnexpectedEnd,
    /// Unknown tag byte.
    UnknownTag(u8),
    /// Invalid jet ID.
    InvalidJetId(u32),
    /// Value deserialization failed.
    ValueError(String),
    /// Node reference out of bounds.
    NodeOutOfBounds(NodeId),
    /// Invalid program structure.
    InvalidStructure(String),
}

impl std::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for SerializeError {}

/// Serialize a program to bytes.
///
/// Serializes as: [node_count: u32 LE] [node_0] [node_1] ... [node_n-1]
/// Each node is serialized with its tag byte and children as node indices (u32 LE).
pub fn serialize_program(program: &Program) -> Vec<u8> {
    let mut buf = Vec::new();

    // Node count
    buf.extend_from_slice(&(program.nodes.len() as u32).to_le_bytes());

    // Root index
    buf.extend_from_slice(&program.root.to_le_bytes());

    // Each node
    for node in &program.nodes {
        serialize_node(node, &mut buf);
    }

    buf
}

/// Serialize a single node to a buffer.
fn serialize_node(node: &Combinator, buf: &mut Vec<u8>) {
    match node {
        Combinator::Iden => {
            buf.push(TAG_IDEN);
        }
        Combinator::Comp(f, g) => {
            buf.push(TAG_COMP);
            buf.extend_from_slice(&f.to_le_bytes());
            buf.extend_from_slice(&g.to_le_bytes());
        }
        Combinator::Unit => {
            buf.push(TAG_UNIT);
        }
        Combinator::Pair(f, g) => {
            buf.push(TAG_PAIR);
            buf.extend_from_slice(&f.to_le_bytes());
            buf.extend_from_slice(&g.to_le_bytes());
        }
        Combinator::Take(f) => {
            buf.push(TAG_TAKE);
            buf.extend_from_slice(&f.to_le_bytes());
        }
        Combinator::Drop(f) => {
            buf.push(TAG_DROP);
            buf.extend_from_slice(&f.to_le_bytes());
        }
        Combinator::InjL(f) => {
            buf.push(TAG_INJL);
            buf.extend_from_slice(&f.to_le_bytes());
        }
        Combinator::InjR(f) => {
            buf.push(TAG_INJR);
            buf.extend_from_slice(&f.to_le_bytes());
        }
        Combinator::Case(f, g) => {
            buf.push(TAG_CASE);
            buf.extend_from_slice(&f.to_le_bytes());
            buf.extend_from_slice(&g.to_le_bytes());
        }
        Combinator::Fold(f, z, k) => {
            buf.push(TAG_FOLD);
            buf.extend_from_slice(&f.to_le_bytes());
            buf.extend_from_slice(&z.to_le_bytes());
            buf.extend_from_slice(&k.to_le_bytes());
        }
        Combinator::ListFold(f, z) => {
            buf.push(TAG_LISTFOLD);
            buf.extend_from_slice(&f.to_le_bytes());
            buf.extend_from_slice(&z.to_le_bytes());
        }
        Combinator::Jet(jet_id) => {
            buf.push(TAG_JET);
            buf.extend_from_slice(&(*jet_id as u32).to_le_bytes());
        }
        Combinator::Witness => {
            buf.push(TAG_WITNESS);
        }
        Combinator::MerkleHidden(hash) => {
            buf.push(TAG_HIDDEN);
            buf.extend_from_slice(hash.as_bytes());
        }
        Combinator::Const(v) => {
            buf.push(TAG_CONST);
            let value_bytes = v.serialize();
            buf.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&value_bytes);
        }
    }
}

/// Deserialize a program from bytes.
pub fn deserialize_program(data: &[u8]) -> Result<Program, SerializeError> {
    if data.len() < 8 {
        return Err(SerializeError::UnexpectedEnd);
    }

    let node_count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let root = u32::from_le_bytes(data[4..8].try_into().unwrap());

    // P1-7: Cap allocation to prevent OOM on untrusted input
    if node_count > crate::types::MAX_SCRIPT_NODES {
        return Err(SerializeError::InvalidStructure(format!(
            "node_count {} exceeds maximum {}",
            node_count,
            crate::types::MAX_SCRIPT_NODES
        )));
    }

    // Reject impossible node_count before allocating — each node needs
    // at least 1 byte (tag), so node_count cannot exceed remaining bytes.
    // Prevents allocation-amplification on short inputs (e.g. 32-byte
    // scripts in ambiguity checks claiming 65 535 nodes).
    let remaining_bytes = data.len().saturating_sub(8);
    if node_count > remaining_bytes {
        return Err(SerializeError::InvalidStructure(format!(
            "node_count {} exceeds available data ({} bytes)",
            node_count, remaining_bytes
        )));
    }

    let mut pos = 8;
    let mut nodes = Vec::with_capacity(node_count);

    for _ in 0..node_count {
        let (node, consumed) = deserialize_node(&data[pos..])?;
        nodes.push(node);
        pos += consumed;
    }

    if nodes.len() != node_count {
        return Err(SerializeError::InvalidStructure(
            "node count mismatch".to_string(),
        ));
    }

    if pos != data.len() {
        return Err(SerializeError::InvalidStructure(format!(
            "trailing bytes: consumed {} of {} bytes",
            pos,
            data.len()
        )));
    }

    let program = Program { nodes, root };
    program
        .validate_structure()
        .map_err(|e| SerializeError::InvalidStructure(e.to_string()))?;

    Ok(program)
}

/// Deserialize a single node from bytes. Returns (node, bytes_consumed).
fn deserialize_node(data: &[u8]) -> Result<(Combinator, usize), SerializeError> {
    if data.is_empty() {
        return Err(SerializeError::UnexpectedEnd);
    }

    let tag = data[0];
    let rest = &data[1..];

    match tag {
        TAG_IDEN => Ok((Combinator::Iden, 1)),

        TAG_COMP => {
            if rest.len() < 8 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let f = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            let g = u32::from_le_bytes(rest[4..8].try_into().unwrap());
            Ok((Combinator::Comp(f, g), 9))
        }

        TAG_UNIT => Ok((Combinator::Unit, 1)),

        TAG_PAIR => {
            if rest.len() < 8 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let f = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            let g = u32::from_le_bytes(rest[4..8].try_into().unwrap());
            Ok((Combinator::Pair(f, g), 9))
        }

        TAG_TAKE => {
            if rest.len() < 4 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let f = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            Ok((Combinator::Take(f), 5))
        }

        TAG_DROP => {
            if rest.len() < 4 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let f = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            Ok((Combinator::Drop(f), 5))
        }

        TAG_INJL => {
            if rest.len() < 4 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let f = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            Ok((Combinator::InjL(f), 5))
        }

        TAG_INJR => {
            if rest.len() < 4 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let f = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            Ok((Combinator::InjR(f), 5))
        }

        TAG_CASE => {
            if rest.len() < 8 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let f = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            let g = u32::from_le_bytes(rest[4..8].try_into().unwrap());
            Ok((Combinator::Case(f, g), 9))
        }

        TAG_FOLD => {
            if rest.len() < 16 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let f = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            let z = u32::from_le_bytes(rest[4..8].try_into().unwrap());
            let k = u64::from_le_bytes(rest[8..16].try_into().unwrap());
            Ok((Combinator::Fold(f, z, k), 17))
        }

        TAG_LISTFOLD => {
            if rest.len() < 8 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let f = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            let z = u32::from_le_bytes(rest[4..8].try_into().unwrap());
            Ok((Combinator::ListFold(f, z), 9))
        }

        TAG_JET => {
            if rest.len() < 4 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let id = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            let jet_id = JetId::from_u32(id).ok_or(SerializeError::InvalidJetId(id))?;
            Ok((Combinator::Jet(jet_id), 5))
        }

        TAG_WITNESS => Ok((Combinator::Witness, 1)),

        TAG_HIDDEN => {
            if rest.len() < 32 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&rest[0..32]);
            Ok((Combinator::MerkleHidden(Hash256(hash)), 33))
        }

        TAG_CONST => {
            if rest.len() < 4 {
                return Err(SerializeError::UnexpectedEnd);
            }
            let value_len = u32::from_le_bytes(rest[0..4].try_into().unwrap()) as usize;
            if rest.len() < 4 + value_len {
                return Err(SerializeError::UnexpectedEnd);
            }
            let (value, consumed) = Value::deserialize(&rest[4..4 + value_len])
                .map_err(|e| SerializeError::ValueError(e.to_string()))?;
            if consumed != value_len {
                return Err(SerializeError::ValueError(format!(
                    "TAG_CONST payload_size={} but value consumed {} bytes",
                    value_len, consumed
                )));
            }
            Ok((Combinator::Const(value), 5 + value_len))
        }

        _ => Err(SerializeError::UnknownTag(tag)),
    }
}

/// Compute the Merkle hash of a program's root node.
///
/// The Merkle hash of each node is:
///   SHA-256("EXFER-SCRIPT" || node_merkle_bytes)
///
/// For Merkle hashing, children are referenced by their Merkle hash (not NodeId).
pub fn merkle_hash(program: &Program) -> Hash256 {
    let n = program.nodes.len();
    let mut hashes: Vec<Hash256> = vec![Hash256::ZERO; n];

    // Bottom-up: highest index first
    for i in (0..n).rev() {
        hashes[i] = node_merkle_hash(&program.nodes[i], &hashes);
    }

    hashes[program.root as usize]
}

/// Compute Merkle hash for a single node, given child hashes.
fn node_merkle_hash(node: &Combinator, hashes: &[Hash256]) -> Hash256 {
    let mut buf = Vec::new();

    match node {
        Combinator::Iden => {
            buf.push(TAG_IDEN);
        }
        Combinator::Comp(f, g) => {
            buf.push(TAG_COMP);
            buf.extend_from_slice(hashes[*f as usize].as_bytes());
            buf.extend_from_slice(hashes[*g as usize].as_bytes());
        }
        Combinator::Unit => {
            buf.push(TAG_UNIT);
        }
        Combinator::Pair(f, g) => {
            buf.push(TAG_PAIR);
            buf.extend_from_slice(hashes[*f as usize].as_bytes());
            buf.extend_from_slice(hashes[*g as usize].as_bytes());
        }
        Combinator::Take(f) => {
            buf.push(TAG_TAKE);
            buf.extend_from_slice(hashes[*f as usize].as_bytes());
        }
        Combinator::Drop(f) => {
            buf.push(TAG_DROP);
            buf.extend_from_slice(hashes[*f as usize].as_bytes());
        }
        Combinator::InjL(f) => {
            buf.push(TAG_INJL);
            buf.extend_from_slice(hashes[*f as usize].as_bytes());
        }
        Combinator::InjR(f) => {
            buf.push(TAG_INJR);
            buf.extend_from_slice(hashes[*f as usize].as_bytes());
        }
        Combinator::Case(f, g) => {
            buf.push(TAG_CASE);
            buf.extend_from_slice(hashes[*f as usize].as_bytes());
            buf.extend_from_slice(hashes[*g as usize].as_bytes());
        }
        Combinator::Fold(f, z, k) => {
            buf.push(TAG_FOLD);
            buf.extend_from_slice(hashes[*f as usize].as_bytes());
            buf.extend_from_slice(hashes[*z as usize].as_bytes());
            buf.extend_from_slice(&k.to_le_bytes());
        }
        Combinator::ListFold(f, z) => {
            buf.push(TAG_LISTFOLD);
            buf.extend_from_slice(hashes[*f as usize].as_bytes());
            buf.extend_from_slice(hashes[*z as usize].as_bytes());
        }
        Combinator::Jet(jet_id) => {
            buf.push(TAG_JET);
            buf.extend_from_slice(&(*jet_id as u32).to_le_bytes());
        }
        Combinator::Witness => {
            buf.push(TAG_WITNESS);
        }
        Combinator::MerkleHidden(hash) => {
            // MerkleHidden nodes ARE their hash — the hash is the commitment
            // to the subtree they replaced.
            return *hash;
        }
        Combinator::Const(v) => {
            buf.push(TAG_CONST);
            let value_bytes = v.serialize();
            buf.extend_from_slice(&value_bytes);
        }
    }

    Hash256::domain_hash(SCRIPT_DOMAIN, &buf)
}
