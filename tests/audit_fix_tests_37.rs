//! Audit fix tests — round 37 (P1 + P2 + P3).
//!
//! P1: Emission consensus pinned with exact reward vectors.
//! P2: Phase-2 witness trailing bytes rejected (anti-malleability).
//! P3: Trivially invalid NewBlock messages are strike-counted.

// ── P1: Canonical reward vectors ──

#[test]
fn p1_canonical_vectors_exact() {
    use exfer::consensus::reward::block_reward;
    use exfer::types::HALF_LIFE;

    // Consensus-canonical vectors — EXACT equality, not tolerance
    let vectors: &[(u64, u64)] = &[
        (0, 10_000_000_000),
        (1, 9_999_998_912),
        (100, 9_999_891_228),
        (1_000, 9_998_912_280),
        (4_320, 9_995_301_790),
        (10_000, 9_989_127_892),
        (43_200, 9_953_117_900),
        (100_000, 9_891_814_300),
        (HALF_LIFE, 5_050_000_000),
        (2 * HALF_LIFE, 2_575_000_000),
        (3 * HALF_LIFE, 1_337_500_000),
        (10 * HALF_LIFE, 109_667_968),
        (630_720_000, 100_000_000),
    ];
    for &(h, expected) in vectors {
        assert_eq!(
            block_reward(h),
            expected,
            "CONSENSUS MISMATCH at height {}: got {}, expected {}",
            h,
            block_reward(h),
            expected
        );
    }
}

#[test]
fn p2_runtime_trailing_bytes_rejected() {
    // Runtime test: script that reads no witness data must fail with trailing bytes
    use exfer::script::ast::{Combinator, Program};
    use exfer::script::eval::{evaluate, Budget};
    use exfer::script::value::Value;

    // iden combinator: input → input (reads no witness data)
    let program = Program::single(Combinator::Iden);

    let mut budget = Budget::new(1000, 1000);
    let result = evaluate(&program, Value::Unit, &[0xFF], &mut budget);
    assert!(
        result.is_err(),
        "evaluation must fail when witness bytes remain unconsumed"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("unconsumed"),
        "error message must mention unconsumed: got {}",
        err_msg
    );
}

#[test]
fn p2_runtime_exact_consumption_ok() {
    // Script that reads exactly all witness data must succeed
    use exfer::script::ast::{Combinator, Program};
    use exfer::script::eval::{evaluate, Budget};
    use exfer::script::value::Value;

    // witness combinator: reads one value from witness
    let program = Program::single(Combinator::Witness);

    // Unit value serialized = 0x00 (1 byte)
    let mut budget = Budget::new(1000, 1000);
    let result = evaluate(&program, Value::Unit, &[0x00], &mut budget);
    assert!(
        result.is_ok(),
        "evaluation must succeed when all witness bytes consumed: {:?}",
        result
    );
}

// ── P3: Pre-validation failures are strike-counted ──
// (R49: pre_valid boolean split into separate height + difficulty checks;
//  tests now verify the difficulty check path has strike counting.)
//
// After the sync-manager refactor, the peer handler (handle_peer_messages)
// does only cheap pre-checks (trivial invalidity, global rate limit) and
// forwards to the sync manager.  The difficulty check now lives in
// process_block_event, which calls record_ip_strike on mismatch.
