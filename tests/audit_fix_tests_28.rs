// Round 28 audit fix tests — P1 (CPU/lock DoS via conflicting NewTx spam),
// P2 (global block-rate limiter exhausted by invalid-block spray),
// P3 (miner fee overflow self-DoS).

// ── P1: Mempool pre-check before expensive validation ─────────────────

#[test]
fn p3_build_coinbase_returns_none_on_fee_overflow() {
    // Runtime test: build_coinbase with fees that overflow u64 should return None
    use exfer::miner::miner::Miner;
    let miner = Miner::new([0x42; 32]);
    // block_reward(0) > 0, so adding u64::MAX must overflow
    assert!(
        miner.build_coinbase(0, u64::MAX).is_none(),
        "build_coinbase must return None when reward + fees overflows u64"
    );
}
