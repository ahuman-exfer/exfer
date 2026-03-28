//! Audit fix tests — round 52.
//!
//! Finding 1 (High): ScriptContext clone amplification in validation.
//!   validate_script_input cloned the full ScriptContext (large Vec fields +
//!   sig_hash bytes) per input. Fixed by using Arc for shared fields so
//!   per-input "cloning" is O(1) refcount bumps.
//!
//! Finding 2 (Low): IPv4 special-use ranges passing is_routable.
//!   Missing: TEST-NET doc ranges, IETF protocol, benchmarking, reserved.

use exfer::network::protocol::is_routable;

// ── Finding 1: Structural — ScriptContext uses Arc, not Vec ──

#[test]
fn script_context_with_self_index_shares_data() {
    use exfer::script::jets::context::{ScriptContext, TxInputInfo};
    use exfer::types::hash::Hash256;
    use std::sync::Arc;

    let inputs: Arc<[TxInputInfo]> = vec![TxInputInfo {
        prev_tx_id: Hash256::ZERO,
        output_index: 0,
        value: 1000,
        script_hash: Hash256::ZERO,
    }]
    .into();

    let ctx = ScriptContext {
        tx_inputs: inputs.clone(),
        tx_outputs: vec![].into(),
        self_index: 0,
        block_height: 100,
        sig_hash: vec![1, 2, 3].into(),
    };

    let ctx2 = ctx.with_self_index(5);

    // self_index changed
    assert_eq!(ctx2.self_index, 5);
    // block_height preserved
    assert_eq!(ctx2.block_height, 100);
    // Arc pointers are the same (shared, not copied)
    assert!(Arc::ptr_eq(&ctx.tx_inputs, &ctx2.tx_inputs));
    assert!(Arc::ptr_eq(&ctx.tx_outputs, &ctx2.tx_outputs));
    assert!(Arc::ptr_eq(&ctx.sig_hash, &ctx2.sig_hash));
}

#[test]
fn script_context_clone_is_shallow() {
    use exfer::script::jets::context::{ScriptContext, TxInputInfo};
    use exfer::types::hash::Hash256;
    use std::sync::Arc;

    let ctx = ScriptContext {
        tx_inputs: vec![
            TxInputInfo {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
                value: 1000,
                script_hash: Hash256::ZERO,
            };
            100
        ]
        .into(),
        tx_outputs: vec![].into(),
        self_index: 0,
        block_height: 0,
        sig_hash: vec![0u8; 1024].into(),
    };

    let ctx2 = ctx.clone();
    // Clone should share the same Arc allocations
    assert!(Arc::ptr_eq(&ctx.tx_inputs, &ctx2.tx_inputs));
    assert!(Arc::ptr_eq(&ctx.sig_hash, &ctx2.sig_hash));
}

// ── Finding 2: Behavioral — IPv4 special-use ranges ──

#[test]
fn ipv4_test_net_1_not_routable() {
    assert!(!is_routable(&"192.0.2.1:9333".parse().unwrap()));
}

#[test]
fn ipv4_test_net_2_not_routable() {
    assert!(!is_routable(&"198.51.100.1:9333".parse().unwrap()));
}

#[test]
fn ipv4_test_net_3_not_routable() {
    assert!(!is_routable(&"203.0.113.1:9333".parse().unwrap()));
}

#[test]
fn ipv4_ietf_protocol_not_routable() {
    assert!(!is_routable(&"192.0.0.1:9333".parse().unwrap()));
}

#[test]
fn ipv4_benchmarking_not_routable() {
    assert!(!is_routable(&"198.18.0.1:9333".parse().unwrap()));
    assert!(!is_routable(&"198.19.255.1:9333".parse().unwrap()));
}

#[test]
fn ipv4_reserved_not_routable() {
    assert!(!is_routable(&"240.0.0.1:9333".parse().unwrap()));
    assert!(!is_routable(&"250.0.0.1:9333".parse().unwrap()));
}

#[test]
fn ipv4_global_unicast_still_routable() {
    assert!(is_routable(&"1.1.1.1:9333".parse().unwrap()));
    assert!(is_routable(&"8.8.8.8:9333".parse().unwrap()));
    assert!(is_routable(&"193.0.0.1:9333".parse().unwrap()));
    assert!(is_routable(&"199.0.0.1:9333".parse().unwrap()));
}

// ── Finding 2: Structural — IPv4 special-use checks present ──
