// Round 27 audit fix tests — P1 (fee/cost phase detection alignment),
// P2a (NewTx validation outside lock + strike counter), P2b (stale template cancellation),
// P3 (coinbase height checked cast).

// ── P1: Fee rule mismatch for 32-byte Phase-2 outputs ────────────────────

#[test]
fn p3_build_coinbase_rejects_overflow() {
    // Runtime test: build_coinbase with height > u32::MAX should return None
    use exfer::miner::miner::Miner;
    let miner = Miner::new([0x42; 32]);
    assert!(
        miner.build_coinbase(u64::from(u32::MAX) + 1, 0).is_none(),
        "build_coinbase must return None for height > u32::MAX"
    );
}
