//! Cryptographic jet implementations: SHA-256, Ed25519, Schnorr, Merkle verify.

use super::JetError;
use crate::script::value::Value;
use crate::types::hash::Hash256;

/// SHA-256 hash of byte input.
/// Input: Bytes -> Output: Hash
pub fn jet_sha256(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::Bytes(data) => {
            let hash = Hash256::sha256(data);
            Ok(Value::Hash(hash))
        }
        _ => Err(JetError::TypeMismatch("sha256 expects Bytes".to_string())),
    }
}

/// Ed25519 signature verification (ZIP-215 compatible).
/// Input: Pair(message_bytes, Pair(pubkey_bytes, sig_bytes)) -> Bool
pub fn jet_ed25519_verify(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::Pair(msg, rest) => match (msg.as_ref(), rest.as_ref()) {
            (Value::Bytes(message), Value::Pair(pk, sig)) => match (pk.as_ref(), sig.as_ref()) {
                (Value::Bytes(pubkey_bytes), Value::Bytes(sig_bytes)) => {
                    let result = ed25519_verify_zip215(message, pubkey_bytes, sig_bytes);
                    Ok(Value::Bool(result))
                }
                _ => Err(JetError::TypeMismatch(
                    "ed25519_verify expects (Bytes, (Bytes, Bytes))".to_string(),
                )),
            },
            _ => Err(JetError::TypeMismatch(
                "ed25519_verify expects (Bytes, (Bytes, Bytes))".to_string(),
            )),
        },
        _ => Err(JetError::TypeMismatch(
            "ed25519_verify expects Pair".to_string(),
        )),
    }
}

/// ZIP-215 compatible Ed25519 verification.
/// Uses `verify` (not `verify_strict`) to accept non-canonical encodings.
fn ed25519_verify_zip215(message: &[u8], pubkey_bytes: &[u8], sig_bytes: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};

    if pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
        return false;
    }

    let pubkey_arr: [u8; 32] = match pubkey_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };

    // Reject small-order (weak) keys — they can validate signatures across
    // unrelated messages, breaking transaction-message binding.
    if crate::types::is_weak_ed25519_key(&pubkey_arr) {
        return false;
    }

    let vk = match VerifyingKey::from_bytes(&pubkey_arr) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };

    let sig = Signature::from_bytes(&sig_arr);

    // Use verify (not verify_strict) for ZIP-215 compliance
    use ed25519_dalek::Verifier;
    vk.verify(message, &sig).is_ok()
}

/// Schnorr signature verification.
/// Input: Pair(message_bytes, Pair(pubkey_bytes, sig_bytes)) -> Bool
///
/// NOT YET IMPLEMENTED — jet ID 0x0003 is reserved for future Schnorr support.
/// Returns an error to prevent consensus-locking incorrect semantics.
pub fn jet_schnorr_verify(_input: &Value) -> Result<Value, JetError> {
    Err(JetError::NotImplemented(
        "schnorr_verify is reserved but not yet implemented".to_string(),
    ))
}

/// Merkle proof verification.
/// Input: Pair(root_hash, Pair(leaf_hash, proof_bytes)) -> Bool
pub fn jet_merkle_verify(input: &Value) -> Result<Value, JetError> {
    match input {
        Value::Pair(root, rest) => match (root.as_ref(), rest.as_ref()) {
            (Value::Hash(root_hash), Value::Pair(leaf, proof)) => {
                match (leaf.as_ref(), proof.as_ref()) {
                    (Value::Hash(leaf_hash), Value::Bytes(proof_bytes)) => {
                        let result = verify_merkle_proof(root_hash, leaf_hash, proof_bytes);
                        Ok(Value::Bool(result))
                    }
                    _ => Err(JetError::TypeMismatch(
                        "merkle_verify expects (Hash, (Hash, Bytes))".to_string(),
                    )),
                }
            }
            _ => Err(JetError::TypeMismatch(
                "merkle_verify expects (Hash, (Hash, Bytes))".to_string(),
            )),
        },
        _ => Err(JetError::TypeMismatch(
            "merkle_verify expects Pair".to_string(),
        )),
    }
}

/// Verify a Merkle proof: proof is a sequence of 33-byte steps [side: u8][sibling: 32 bytes].
/// side=0 → current is left child; side=1 → current is right child.
/// Each step: hash = SHA-256("EXFER-SCRIPT" || left || right)
fn verify_merkle_proof(root: &Hash256, leaf: &Hash256, proof: &[u8]) -> bool {
    if !proof.len().is_multiple_of(33) {
        return false;
    }

    let mut current = *leaf;

    for chunk in proof.chunks_exact(33) {
        let side = chunk[0];
        if side > 1 {
            return false;
        }
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&chunk[1..33]);
        let sibling_hash = Hash256(sibling);

        let mut combined = [0u8; 64];
        if side == 0 {
            // current is left child
            combined[..32].copy_from_slice(current.as_bytes());
            combined[32..].copy_from_slice(sibling_hash.as_bytes());
        } else {
            // current is right child
            combined[..32].copy_from_slice(sibling_hash.as_bytes());
            combined[32..].copy_from_slice(current.as_bytes());
        }
        current = Hash256::domain_hash(b"EXFER-MERKLE", &combined);
    }

    current == *root
}
