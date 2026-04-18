use crate::chain::storage::ChainStorage;
use crate::types::block::BlockHeader;
use crate::types::hash::Hash256;
use crate::types::{MAX_RETARGET_FACTOR, RETARGET_WINDOW, TARGET_BLOCK_TIME_SECS};
use std::collections::HashMap;

/// Error from expected_difficulty when an ancestor header is missing.
#[derive(Debug)]
pub enum DifficultyError {
    /// An ancestor header required for the difficulty calculation was not found.
    /// Contains the hash of the specific missing block.
    AncestorNotFound(Hash256),
    /// Storage or other error.
    Other(String),
}

impl std::fmt::Display for DifficultyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DifficultyError::AncestorNotFound(h) => write!(f, "not found: {}", h),
            DifficultyError::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Genesis difficulty target.
/// Production: 2^248 (~256 expected Argon2id hashes).
/// Testnet: all 0xFF (any hash valid, nonce=0 works).
pub fn genesis_target() -> Hash256 {
    #[cfg(feature = "testnet")]
    {
        Hash256([0xFF; 32])
    }
    #[cfg(not(feature = "testnet"))]
    {
        let mut target = [0u8; 32];
        // 2^248: byte[0] = 0x01 in big-endian 256-bit representation
        target[0] = 0x01;
        Hash256(target)
    }
}

/// The production genesis target (2^248), always available regardless of feature flags.
/// Used for tests that need to verify the exact constant.
#[allow(dead_code)]
pub fn production_genesis_target() -> Hash256 {
    let mut target = [0u8; 32];
    target[0] = 0x01;
    Hash256(target)
}

/// Compute the expected difficulty target for a block by walking its own ancestry.
///
/// - If height == 0: genesis target
/// - If height % RETARGET_WINDOW != 0: same as parent's difficulty_target
/// - If height % RETARGET_WINDOW == 0: retarget using timestamps from this block's
///   own parent chain (not the canonical height index)
pub fn expected_difficulty(
    storage: &ChainStorage,
    prev_block_id: &Hash256,
    height: u64,
) -> Result<Hash256, DifficultyError> {
    if height == 0 {
        return Ok(genesis_target());
    }

    let parent = storage
        .get_header(prev_block_id)
        .map_err(|e| DifficultyError::Other(e.to_string()))?
        .ok_or(DifficultyError::AncestorNotFound(*prev_block_id))?;

    if !height.is_multiple_of(RETARGET_WINDOW) {
        // Not a retarget boundary: same as parent
        return Ok(parent.difficulty_target);
    }

    // Retarget boundary at height H.
    // Need: tip_timestamp = parent (height H-1), start_timestamp = block at height H-RETARGET_WINDOW.
    // This spans RETARGET_WINDOW-1 inter-block intervals.
    // Walk back from parent through RETARGET_WINDOW-1 prev_block_id links.
    let tip_timestamp = parent.timestamp;
    let mut current_id = *prev_block_id;

    // Walk RETARGET_WINDOW-1 steps back from parent (at H-1) to reach H-RETARGET_WINDOW
    for _ in 0..RETARGET_WINDOW - 1 {
        let hdr = storage
            .get_header(&current_id)
            .map_err(|e| DifficultyError::Other(e.to_string()))?
            .ok_or(DifficultyError::AncestorNotFound(current_id))?;
        current_id = hdr.prev_block_id;
    }

    let window_start = storage
        .get_header(&current_id)
        .map_err(|e| DifficultyError::Other(e.to_string()))?
        .ok_or(DifficultyError::AncestorNotFound(current_id))?;

    let actual_time = tip_timestamp.saturating_sub(window_start.timestamp);
    Ok(retarget(&parent.difficulty_target, actual_time))
}

// ── v1.5.0 Fix 2: in-memory header overlay for forward-chain validation ──

/// In-memory header overlay used during tip-validation.
///
/// During tip-confirmation of a peer's claimed chain above our local tip, the
/// forward headers being validated are not yet in storage. This overlay provides
/// a read path that checks an in-memory HashMap first and falls back to storage,
/// so the exact-forward retarget math in `expected_difficulty_overlay` can walk
/// forward-header ancestors that exist only in the overlay.
///
/// Invariant maintained by the caller: the overlay only contains headers that
/// have already passed structural + difficulty + PoW checks for their position.
/// An invalid header is never a retarget-lookback source.
///
/// Pre-checkpoint lookback (cold-bootstrap path 2b): headers below
/// `ASSUME_VALID_HEIGHT` that are not yet in storage can be inserted into the
/// overlay after strict SHA256 hash-chain authentication from the authenticated
/// checkpoint header (no Argon2 required — covered by checkpoint trust).
pub struct ForwardHeaderOverlay<'s> {
    storage: &'s ChainStorage,
    overlay: HashMap<Hash256, BlockHeader>,
}

impl<'s> ForwardHeaderOverlay<'s> {
    pub fn new(storage: &'s ChainStorage) -> Self {
        Self {
            storage,
            overlay: HashMap::new(),
        }
    }

    /// Insert a header keyed by its block_id. Callers must have validated the
    /// header before this call to preserve the no-invalid-headers invariant.
    pub fn insert(&mut self, header: BlockHeader) {
        let id = header.block_id();
        self.overlay.insert(id, header);
    }

    /// Read a header by block_id — overlay first, storage fallback.
    pub fn get_header(&self, id: &Hash256) -> Result<Option<BlockHeader>, DifficultyError> {
        if let Some(h) = self.overlay.get(id) {
            return Ok(Some(h.clone()));
        }
        self.storage
            .get_header(id)
            .map_err(|e| DifficultyError::Other(e.to_string()))
    }

    pub fn contains(&self, id: &Hash256) -> bool {
        self.overlay.contains_key(id)
    }

    pub fn overlay_len(&self) -> usize {
        self.overlay.len()
    }

    pub fn overlay_keys(&self) -> impl Iterator<Item = &Hash256> {
        self.overlay.keys()
    }
}

/// Like `expected_difficulty` but reads headers through a `ForwardHeaderOverlay`.
///
/// This is a byte-for-byte copy of the retarget algorithm in `expected_difficulty`
/// — only the header-source access path changes. That coupling is deliberate: the
/// spec requires that tip-validation use the same consensus difficulty as block
/// validation, exactly. Any algorithmic change here MUST be mirrored in
/// `expected_difficulty` (and vice-versa); out-of-date copies will cause
/// confirmation-time validation to disagree with block-time validation and break
/// IBD in subtle ways. A unit test in the consensus module asserts the two
/// functions produce identical results for any header whose ancestors are in
/// storage.
pub fn expected_difficulty_overlay(
    overlay: &ForwardHeaderOverlay,
    prev_block_id: &Hash256,
    height: u64,
) -> Result<Hash256, DifficultyError> {
    if height == 0 {
        return Ok(genesis_target());
    }
    let parent = overlay
        .get_header(prev_block_id)?
        .ok_or(DifficultyError::AncestorNotFound(*prev_block_id))?;
    if !height.is_multiple_of(RETARGET_WINDOW) {
        return Ok(parent.difficulty_target);
    }
    let tip_timestamp = parent.timestamp;
    let mut current_id = *prev_block_id;
    for _ in 0..RETARGET_WINDOW - 1 {
        let hdr = overlay
            .get_header(&current_id)?
            .ok_or(DifficultyError::AncestorNotFound(current_id))?;
        current_id = hdr.prev_block_id;
    }
    let window_start = overlay
        .get_header(&current_id)?
        .ok_or(DifficultyError::AncestorNotFound(current_id))?;
    let actual_time = tip_timestamp.saturating_sub(window_start.timestamp);
    Ok(retarget(&parent.difficulty_target, actual_time))
}

/// Compute the new difficulty target at a retarget boundary.
///
/// new_target = old_target * actual_time / expected_time
/// Clamped to [old_target / 4, old_target * 4].
/// Clamped to [1, 2^256 - 1].
///
/// `actual_time_secs`: elapsed time over the last RETARGET_WINDOW-1 intervals
/// (from block H-RETARGET_WINDOW to block H-1).
pub fn retarget(old_target: &Hash256, actual_time_secs: u64) -> Hash256 {
    // RETARGET_WINDOW blocks span RETARGET_WINDOW-1 inter-block intervals.
    // expected_difficulty() measures actual_time as timestamp(H-1) - timestamp(H-W),
    // which covers exactly W-1 gaps, so expected_time must match.
    let expected_time = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS; // 43,190

    // Edge case: treat 0 as 1
    let actual = if actual_time_secs == 0 {
        1
    } else {
        actual_time_secs
    };

    // Clamp actual_time to enforce max 4x adjustment
    let min_time = expected_time / MAX_RETARGET_FACTOR;
    let max_time = expected_time
        .checked_mul(MAX_RETARGET_FACTOR)
        .expect("no overflow");

    let clamped_time = actual.clamp(min_time, max_time);

    // new_target = old_target * clamped_time / expected_time
    let new_target_bytes = mul_div_256(old_target.as_bytes(), clamped_time, expected_time);

    // Clamp to minimum target of 1
    if new_target_bytes == [0u8; 32] {
        let mut min = [0u8; 32];
        min[31] = 1;
        return Hash256(min);
    }

    Hash256(new_target_bytes)
}

/// Multiply a 256-bit big-endian number by a u64 numerator, then divide by a u64 denominator.
/// Returns clamped to 256 bits (saturating at all 0xFF).
fn mul_div_256(value: &[u8; 32], numerator: u64, denominator: u64) -> [u8; 32] {
    assert!(denominator > 0, "division by zero");

    // Convert to array of u128 limbs from big-endian bytes (limb[0] is most significant)
    let mut limbs = [0u128; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let offset = i * 8;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&value[offset..offset + 8]);
        *limb = u64::from_be_bytes(bytes) as u128;
    }

    // Multiply by numerator, producing up to 320-bit result (5 limbs)
    let num = numerator as u128;
    let mut product = [0u128; 5];
    let mut carry = 0u128;
    for i in (0..4).rev() {
        let val = limbs[i] * num + carry;
        product[i + 1] = val & 0xFFFF_FFFF_FFFF_FFFF;
        carry = val >> 64;
    }
    product[0] = carry;

    // Divide by denominator
    let den = denominator as u128;
    let mut result_limbs = [0u64; 4];
    let mut remainder = 0u128;
    for i in 0..5 {
        let cur = (remainder << 64) | product[i];
        let q = cur / den;
        remainder = cur % den;
        if i == 0 {
            // If there's a nonzero quotient in the overflow limb, saturate
            if q > 0 {
                return [0xFF; 32];
            }
        } else {
            // Check for overflow (q must fit in u64)
            if q > u64::MAX as u128 {
                return [0xFF; 32];
            }
            result_limbs[i - 1] = q as u64;
        }
    }

    // Convert back to big-endian bytes
    let mut result = [0u8; 32];
    for (i, limb) in result_limbs.iter().enumerate() {
        let offset = i * 8;
        result[offset..offset + 8].copy_from_slice(&limb.to_be_bytes());
    }

    result
}

/// Compute work for a block: work = floor(2^256 / target).
///
/// PoW acceptance uses strict less-than: `pow_hash < target`.
/// The number of valid hashes is exactly `target` (from 0 to target-1),
/// so work = 2^256 / target, consistent with the acceptance predicate.
///
/// Both target and result are 32-byte big-endian.
pub fn work_from_target(target: &Hash256) -> [u8; 32] {
    let target_bytes = target.as_bytes();

    // target == 0 means no valid hash exists; return max work
    if *target_bytes == [0u8; 32] {
        return [0xFF; 32];
    }

    // floor(2^256 / target) using the identity:
    // floor(2^256 / d) = floor((2^256 - d) / d) + 1

    // Compute 2^256 - target via subtraction from 0 with implied borrow from 2^256
    let mut numerator = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = 0i16 - target_bytes[i] as i16 - borrow;
        if diff < 0 {
            numerator[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            numerator[i] = diff as u8;
            borrow = 0;
        }
    }

    // Divide numerator by target
    let quotient = div_256(&numerator, target_bytes);

    // quotient + 1, saturating at 2^256 - 1 to prevent overflow to zero
    let mut result = quotient;
    let mut carry = 1u16;
    for i in (0..32).rev() {
        let sum = result[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    if carry > 0 {
        // 2^256 / target >= 2^256 — saturate to max representable value
        result = [0xFF; 32];
    }

    result
}

/// Divide a 256-bit number a by a 256-bit number b (both big-endian).
/// Returns the quotient. b must not be zero.
fn div_256(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut remainder = [0u8; 32];
    let mut quotient = [0u8; 32];

    for bit_pos in 0..256 {
        // Shift remainder left by 1
        let mut carry = 0u8;
        for i in (0..32).rev() {
            let new_carry = remainder[i] >> 7;
            remainder[i] = (remainder[i] << 1) | carry;
            carry = new_carry;
        }

        // Bring in the next bit of a
        let byte_idx = bit_pos / 8;
        let bit_idx = 7 - (bit_pos % 8);
        let bit = (a[byte_idx] >> bit_idx) & 1;
        remainder[31] |= bit;

        // If remainder >= b, subtract and set quotient bit
        if ge_256(&remainder, b) {
            sub_256_inplace(&mut remainder, b);
            let q_byte = bit_pos / 8;
            let q_bit = 7 - (bit_pos % 8);
            quotient[q_byte] |= 1 << q_bit;
        }
    }

    quotient
}

/// Returns true if a >= b (256-bit big-endian).
fn ge_256(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true // equal
}

/// a -= b in-place (256-bit big-endian). Assumes a >= b.
fn sub_256_inplace(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            a[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            a[i] = diff as u8;
            borrow = 0;
        }
    }
}

/// Check if a retarget is needed at the given height.
#[allow(dead_code)]
pub fn needs_retarget(height: u64) -> bool {
    height > 0 && height.is_multiple_of(RETARGET_WINDOW)
}

/// Add two 256-bit work values (big-endian). Saturates at 2^256-1.
pub fn add_work(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    if carry > 0 {
        return [0xFF; 32];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_target() {
        // Verify genesis_target returns an appropriate value for the build config
        let target = genesis_target();
        #[cfg(feature = "testnet")]
        assert_eq!(
            target,
            Hash256([0xFF; 32]),
            "testnet target should be all 0xFF"
        );
        #[cfg(not(feature = "testnet"))]
        {
            assert_eq!(target.0[0], 0x01);
            for i in 1..32 {
                assert_eq!(target.0[i], 0x00, "byte {} should be 0", i);
            }
        }
    }

    #[test]
    fn test_production_genesis_target() {
        // Always verifies the 2^248 constant regardless of feature flags
        let target = production_genesis_target();
        assert_eq!(target.0[0], 0x01);
        for i in 1..32 {
            assert_eq!(target.0[i], 0x00, "byte {} should be 0", i);
        }
    }

    #[test]
    fn test_retarget_no_change() {
        let target = genesis_target();
        let expected_time = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
        let new_target = retarget(&target, expected_time);
        assert_eq!(target, new_target);
    }

    #[test]
    fn test_retarget_too_fast() {
        // Blocks came twice as fast → target should decrease (harder)
        let target = genesis_target();
        let expected = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
        let actual = expected / 2;
        let new_target = retarget(&target, actual);
        assert!(
            new_target.as_bytes() < target.as_bytes(),
            "target should decrease when blocks are fast"
        );
    }

    #[test]
    fn test_retarget_too_slow() {
        // Blocks came twice as slow → target should increase (easier)
        // Use production target (2^248) so there's room to increase
        let target = production_genesis_target();
        let expected = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
        let actual = expected * 2;
        let new_target = retarget(&target, actual);
        assert!(
            new_target.as_bytes() > target.as_bytes(),
            "target should increase when blocks are slow"
        );
    }

    #[test]
    fn test_retarget_clamp_max() {
        // Very slow blocks → should clamp to 4x
        let target = genesis_target();
        let expected = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
        let actual = expected * 100; // way too slow
        let new_target = retarget(&target, actual);
        let clamped = retarget(&target, expected * 4);
        assert_eq!(new_target, clamped);
    }

    #[test]
    fn test_retarget_clamp_min() {
        // Very fast blocks → should clamp to 1/4
        let target = genesis_target();
        let expected = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
        let actual = 1; // way too fast
        let new_target = retarget(&target, actual);
        let clamped = retarget(&target, expected / 4);
        assert_eq!(new_target, clamped);
    }

    #[test]
    fn test_retarget_zero_time() {
        // actual_time = 0 → treated as 1 → clamped to min_time
        let target = genesis_target();
        let new_target = retarget(&target, 0);
        let expected = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
        let clamped = retarget(&target, expected / 4);
        assert_eq!(new_target, clamped);
    }

    #[test]
    fn test_retarget_half_gives_half_target() {
        // Use production target (2^248) for exact byte-level assertion
        let target = production_genesis_target();
        let expected = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
        let actual = expected / 2;
        let new_target = retarget(&target, actual);
        // new_target should be target / 2
        // target = 2^248, so new_target = 2^247
        // 2^247: byte[1] = 0x80 (bit 247 = byte[1] bit 7)
        let mut expected_target = [0u8; 32];
        expected_target[1] = 0x80;
        assert_eq!(new_target, Hash256(expected_target));
    }

    #[test]
    fn test_needs_retarget() {
        assert!(!needs_retarget(0));
        assert!(!needs_retarget(1));
        assert!(!needs_retarget(4319));
        assert!(needs_retarget(4320));
        assert!(!needs_retarget(4321));
        assert!(needs_retarget(8640));
    }

    #[test]
    fn test_work_from_target() {
        // Higher target (easier) → less work
        let easy_target = Hash256([0xFF; 32]);
        let mut hard_target_bytes = [0u8; 32];
        hard_target_bytes[15] = 0x01; // 2^128
        let hard_target = Hash256(hard_target_bytes);
        let easy_work = work_from_target(&easy_target);
        let hard_work = work_from_target(&hard_target);
        assert!(hard_work > easy_work);
    }

    #[test]
    fn test_add_work() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 10;
        b[31] = 20;
        let sum = add_work(&a, &b);
        assert_eq!(sum[31], 30);
    }

    #[test]
    fn test_min_target_clamp() {
        // If retarget would push target below 1, it gets clamped to 1
        let mut tiny = [0u8; 32];
        tiny[31] = 1; // target = 1
        let target = Hash256(tiny);
        let expected = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
        // Blocks 4x faster → target / 4 = 0.25 → clamp to 1
        let new_target = retarget(&target, expected / 4);
        // target * (expected/4) / expected = target / 4 = 0 → clamped to 1
        assert_eq!(new_target.0[31], 1);
        // Ensure it's not all zeros
        assert_ne!(new_target, Hash256::ZERO);
    }
}
