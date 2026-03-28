//! Audit fix tests — round 51.
//!
//! Finding 2: Panic surface in PoW function.
//!   compute_pow used expect on Argon2 setup/hash — any unexpected backend
//!   error would panic in the consensus processing path.

// ── Finding 2: Structural — PoW returns Result, no panics ──

#[test]
fn compute_pow_returns_ok_on_valid_header() {
    use exfer::consensus::pow::compute_pow;
    use exfer::types::block::BlockHeader;
    use exfer::types::hash::Hash256;

    let header = BlockHeader {
        version: 1,
        height: 0,
        prev_block_id: Hash256::ZERO,
        timestamp: 1700000000,
        difficulty_target: Hash256::ZERO,
        nonce: 0,
        tx_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
    };
    assert!(
        compute_pow(&header).is_ok(),
        "compute_pow must return Ok for a valid header"
    );
}

#[test]
fn verify_pow_returns_ok_on_valid_header() {
    use exfer::consensus::pow::verify_pow;
    use exfer::types::block::BlockHeader;
    use exfer::types::hash::Hash256;

    let header = BlockHeader {
        version: 1,
        height: 0,
        prev_block_id: Hash256::ZERO,
        timestamp: 1700000000,
        difficulty_target: Hash256([0xFF; 32]),
        nonce: 0,
        tx_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
    };
    assert!(
        verify_pow(&header).unwrap(),
        "verify_pow must return Ok(true) for max target"
    );
}
