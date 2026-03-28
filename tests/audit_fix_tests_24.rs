//! Audit fix tests — round 24 (P0 + P1 + P2 + P3).
//! F1: block_reward panic before half-life boundary (ceiling division).
//! F2: IBD sync_from_peer chunks GetBlocks by MAX_GETBLOCKS_RESPONSE.
//! F3: Handshake uses read_hello (pre-auth allocation cap).
//! F4: Outbound response byte budget is strict (serialize before check).

// ── F1 (P0): block_reward doesn't panic near half-life boundary ──

#[test]
fn f1_reward_near_half_life_no_panic() {
    use exfer::consensus::reward::block_reward;
    use exfer::types::HALF_LIFE;

    // Height 6_303_744 previously triggered OOB via bucket index 4098
    let _ = block_reward(6_303_744);

    // HALF_LIFE - 1 is the maximum remainder, must not panic
    let _ = block_reward(HALF_LIFE - 1);

    // Also check a few more heights in the danger zone
    for h in (HALF_LIFE - 100)..HALF_LIFE {
        let _ = block_reward(h);
    }
}

#[test]
fn f1_reward_values_reasonable_near_half_life() {
    use exfer::consensus::reward::block_reward;
    use exfer::types::HALF_LIFE;

    // At HALF_LIFE - 1, reward should be close to (but slightly above) the
    // half-life value: BASE + DECAY/2 ≈ 5_050_000_000
    let r = block_reward(HALF_LIFE - 1);
    assert!(
        r > 5_000_000_000 && r < 5_100_000_000,
        "reward at HALF_LIFE - 1 should be ~5.05B, got {}",
        r
    );
}

// ── F2 (P1): sync_from_peer chunks GetBlocks ──
