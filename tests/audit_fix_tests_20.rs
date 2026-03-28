//! Audit fix tests — round 20 (findings P1×1, P2×1, P3×1).
//!
//! P1 (Ping/Pong during IBD): In the refactored architecture, block processing
//! runs in the sync manager task, NOT in the peer task. The peer task handles
//! Ping/Pong directly — socket I/O is never blocked by process_block. IBD recv
//! helpers (recv_ibd_headers, recv_ibd_block) process PeerEvents from a channel.

#[test]
fn p1_max_control_msgs_constant_exists() {
    assert_eq!(
        exfer::types::MAX_CONTROL_MSGS_DURING_IBD,
        50,
        "MAX_CONTROL_MSGS_DURING_IBD must be 50"
    );
}

#[test]
fn p2_retarget_identity_with_correct_intervals() {
    use exfer::consensus::difficulty::{genesis_target, retarget};
    use exfer::types::{RETARGET_WINDOW, TARGET_BLOCK_TIME_SECS};

    let target = genesis_target();
    // (RETARGET_WINDOW - 1) intervals at TARGET_BLOCK_TIME_SECS each = identity
    let identity_time = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
    let new_target = retarget(&target, identity_time);
    assert_eq!(
        target, new_target,
        "retarget with exactly (W-1)*T actual time must produce identical target"
    );
}

#[test]
fn p2_retarget_old_formula_would_differ() {
    use exfer::consensus::difficulty::{production_genesis_target, retarget};
    use exfer::types::{RETARGET_WINDOW, TARGET_BLOCK_TIME_SECS};

    // Passing RETARGET_WINDOW * T (the OLD wrong expected_time) as actual_time
    // should NOT be identity anymore — it should produce a slightly easier target
    let target = production_genesis_target();
    let old_wrong_time = RETARGET_WINDOW * TARGET_BLOCK_TIME_SECS;
    let new_target = retarget(&target, old_wrong_time);
    assert!(
        new_target.as_bytes() > target.as_bytes(),
        "W*T actual time should now be slightly above identity (proving the fix works)"
    );
}
