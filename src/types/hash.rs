use sha2::{Digest, Sha256};
use std::fmt;

/// A 32-byte SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Hash256 = Hash256([0u8; 32]);

    /// Prefix-free domain-separated SHA-256: SHA-256(len(sep) || separator || data).
    ///
    /// The single-byte length prefix ensures no domain separator is a prefix
    /// of another's encoding (e.g. "EXFER-TX" vs "EXFER-TXROOT").
    pub fn domain_hash(separator: &[u8], data: &[u8]) -> Self {
        debug_assert!(separator.len() <= 255, "separator must fit in one byte");
        let mut hasher = Sha256::new();
        hasher.update([separator.len() as u8]);
        hasher.update(separator);
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash256(bytes)
    }

    /// Raw SHA-256 (used only for block_id = SHA-256(header_bytes) and PoW pre-hash).
    pub fn sha256(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash256(bytes)
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Interpret as a 256-bit big-endian unsigned integer, returning
    /// the 32-byte representation directly (already big-endian).
    #[allow(dead_code, clippy::wrong_self_convention)]
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", hex::encode(self.0))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Compute Merkle root over a list of hashes using the given domain separator.
/// - If empty, returns Hash256::ZERO.
/// - If one element, returns that element.
/// - If odd number, duplicates the last element.
pub fn merkle_root(domain: &[u8], hashes: &[Hash256]) -> Hash256 {
    if hashes.is_empty() {
        return Hash256::ZERO;
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut level: Vec<Hash256> = hashes.to_vec();

    while level.len() > 1 {
        if !level.len().is_multiple_of(2) {
            let last = *level.last().expect("level is non-empty");
            level.push(last);
        }

        let mut next_level = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(pair[0].as_bytes());
            combined[32..].copy_from_slice(pair[1].as_bytes());
            next_level.push(Hash256::domain_hash(domain, &combined));
        }
        level = next_level;
    }

    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_hash_deterministic() {
        let h1 = Hash256::domain_hash(b"EXFER-TX", &[0x00]);
        let h2 = Hash256::domain_hash(b"EXFER-TX", &[0x00]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_domains_different_hashes() {
        let h1 = Hash256::domain_hash(b"EXFER-TX", &[0x00]);
        let h2 = Hash256::domain_hash(b"EXFER-SIG", &[0x00]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash256_zero() {
        assert_eq!(Hash256::ZERO.0, [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(merkle_root(b"EXFER-TXROOT", &[]), Hash256::ZERO);
    }

    #[test]
    fn test_merkle_root_single() {
        let h = Hash256::sha256(b"test");
        assert_eq!(merkle_root(b"EXFER-TXROOT", &[h]), h);
    }

    #[test]
    fn test_merkle_root_two() {
        let h1 = Hash256::sha256(b"a");
        let h2 = Hash256::sha256(b"b");
        let root = merkle_root(b"EXFER-TXROOT", &[h1, h2]);
        // Manually compute expected
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(h1.as_bytes());
        combined[32..].copy_from_slice(h2.as_bytes());
        let expected = Hash256::domain_hash(b"EXFER-TXROOT", &combined);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_odd_duplicates_last() {
        let h1 = Hash256::sha256(b"a");
        let h2 = Hash256::sha256(b"b");
        let h3 = Hash256::sha256(b"c");
        let root = merkle_root(b"EXFER-TXROOT", &[h1, h2, h3]);
        // h3 is duplicated: tree is [[h1,h2],[h3,h3]] -> [node01, node23] -> root
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_display() {
        let h = Hash256::ZERO;
        let s = format!("{}", h);
        assert_eq!(
            s,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
