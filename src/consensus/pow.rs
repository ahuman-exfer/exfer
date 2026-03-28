use crate::types::block::BlockHeader;
use crate::types::hash::Hash256;
use crate::types::{
    ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_OUTPUT_LEN, ARGON2_PARALLELISM, DS_POW_P, DS_POW_S,
};
use argon2::{Algorithm, Argon2, Params, Version};
use std::fmt;

/// Error type for PoW computation failures.
#[derive(Debug)]
pub enum PowError {
    /// Argon2 parameter construction failed.
    Params(String),
    /// Argon2 hashing failed.
    Hash(String),
}

impl fmt::Display for PowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PowError::Params(e) => write!(f, "Argon2 param error: {e}"),
            PowError::Hash(e) => write!(f, "Argon2 hash error: {e}"),
        }
    }
}

impl std::error::Error for PowError {}

/// Compute the Argon2id proof-of-work hash for a block header.
///
/// 1. pw   = domain_hash("EXFER-POW-P", header_bytes)
/// 2. salt = domain_hash("EXFER-POW-S", header_bytes)
/// 3. pow  = Argon2id(password=pw, salt=salt, m=65536, t=2, p=1, output=32)
pub fn compute_pow(header: &BlockHeader) -> Result<Hash256, PowError> {
    let header_bytes = header.serialize();
    let pw = Hash256::domain_hash(DS_POW_P, &header_bytes);
    let salt = Hash256::domain_hash(DS_POW_S, &header_bytes);

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| PowError::Params(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(pw.as_bytes(), salt.as_bytes(), &mut output)
        .map_err(|e| PowError::Hash(e.to_string()))?;

    Ok(Hash256(output))
}

/// Verify that a block's PoW hash is strictly less than the difficulty_target.
/// Both pow and target are compared as 256-bit big-endian unsigned integers.
pub fn verify_pow(header: &BlockHeader) -> Result<bool, PowError> {
    let pow_hash = compute_pow(header)?;
    // Compare as 256-bit big-endian integers (raw byte comparison works because
    // Hash256 bytes are stored in big-endian order as SHA-256 output)
    Ok(pow_hash.as_bytes() < header.difficulty_target.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            height: 0,
            prev_block_id: Hash256::ZERO,
            timestamp: 1700000000,
            difficulty_target: Hash256::ZERO,
            nonce: 0,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        }
    }

    #[test]
    fn test_pow_deterministic() {
        let header = test_header();
        let pow1 = compute_pow(&header).unwrap();
        let pow2 = compute_pow(&header).unwrap();
        assert_eq!(pow1, pow2);
    }

    #[test]
    fn test_pow_changes_with_nonce() {
        let mut h1 = test_header();
        let pow1 = compute_pow(&h1).unwrap();
        h1.nonce = 1;
        let pow2 = compute_pow(&h1).unwrap();
        assert_ne!(pow1, pow2);
    }

    #[test]
    fn test_pow_uses_independent_domain_separators() {
        // Verify that pw and salt are different (since they use different domain seps)
        let header = test_header();
        let header_bytes = header.serialize();
        let pw = Hash256::domain_hash(DS_POW_P, &header_bytes);
        let salt = Hash256::domain_hash(DS_POW_S, &header_bytes);
        assert_ne!(pw, salt, "password and salt must differ");
    }

    #[test]
    fn test_verify_pow_max_target() {
        // With maximum target (all 0xFF), any PoW should be valid
        let mut header = test_header();
        header.difficulty_target = Hash256([0xFF; 32]);
        assert!(verify_pow(&header).unwrap());
    }

    #[test]
    fn test_verify_pow_min_target() {
        // With minimum target (all zeros), PoW should fail
        let mut header = test_header();
        header.difficulty_target = Hash256::ZERO;
        assert!(!verify_pow(&header).unwrap());
    }

    #[test]
    fn test_verify_pow_target_1() {
        // With target = 1, extremely unlikely to pass
        let mut header = test_header();
        let mut target = [0u8; 32];
        target[31] = 1;
        header.difficulty_target = Hash256(target);
        assert!(!verify_pow(&header).unwrap());
    }
}
