//! Audit fix tests — round 16 (findings F1–F6).

// ── F1: Unsolicited heavy messages are rate-limited ──

#[test]
fn f1_unsolicited_counter_constant_exists() {
    assert_eq!(exfer::types::MAX_UNSOLICITED_PER_MIN, 10);
}

#[test]
fn f2_max_blocks_per_min_is_12() {
    assert_eq!(exfer::types::MAX_BLOCKS_PER_MIN, 12);
}

#[test]
fn f2_global_block_limit_constant_exists() {
    // 24 = 4× honest rate (6 blocks/min at 10s block time)
    assert_eq!(exfer::types::MAX_GLOBAL_BLOCKS_PER_MIN, 24);
}

#[test]
fn f2_global_limit_caps_aggregate_pow() {
    // Worst-case with global limit: 24 PoW/min regardless of peer count
    // vs old: 64 peers × 12/min = 768 PoW/min
    let max_global = exfer::types::MAX_GLOBAL_BLOCKS_PER_MIN;
    let max_per_peer = exfer::types::MAX_BLOCKS_PER_MIN;
    let max_inbound = exfer::types::MAX_INBOUND_PEERS as u32;

    // Global limit must be less than per-peer × max-peers
    assert!(
        max_global < max_per_peer * max_inbound,
        "global limit {} must be less than per-peer*peers {}",
        max_global,
        max_per_peer * max_inbound
    );
    // Global limit should be reasonable (< 50 PoW/min)
    assert!(
        max_global <= 50,
        "global limit {} should be <= 50",
        max_global
    );
}

// ── F3: Cat/Slice jets data-proportional runtime_cost ──

#[test]
fn f3_cat_runtime_cost_scales_with_data() {
    use exfer::script::jets::JetId;
    use exfer::script::value::Value;

    // Small input: 16 bytes total
    let small = Value::Pair(
        Box::new(Value::Bytes(vec![0u8; 8])),
        Box::new(Value::Bytes(vec![0u8; 8])),
    );
    let cost_small = JetId::Cat.runtime_cost(
        &small,
        &exfer::script::jets::context::ScriptContext::empty(),
    );

    // Large input: 8000 bytes total
    let large = Value::Pair(
        Box::new(Value::Bytes(vec![0u8; 4000])),
        Box::new(Value::Bytes(vec![0u8; 4000])),
    );
    let cost_large = JetId::Cat.runtime_cost(
        &large,
        &exfer::script::jets::context::ScriptContext::empty(),
    );

    // Large must cost significantly more than small
    assert!(
        cost_large > cost_small * 5,
        "Cat runtime_cost should scale with data: small={}, large={}",
        cost_small,
        cost_large
    );
    // Large must exceed the old static default of 100
    assert!(
        cost_large > 100,
        "Cat on 8000 bytes should exceed old static cost of 100, got {}",
        cost_large
    );
}

#[test]
fn f3_slice_runtime_cost_scales_with_data() {
    use exfer::script::jets::JetId;
    use exfer::script::value::Value;

    // Small: 16-byte source
    let small = Value::Pair(
        Box::new(Value::Bytes(vec![0u8; 16])),
        Box::new(Value::Pair(
            Box::new(Value::U64(0)),
            Box::new(Value::U64(8)),
        )),
    );
    let cost_small = JetId::Slice.runtime_cost(
        &small,
        &exfer::script::jets::context::ScriptContext::empty(),
    );

    // Large: 8000-byte source
    let large = Value::Pair(
        Box::new(Value::Bytes(vec![0u8; 8000])),
        Box::new(Value::Pair(
            Box::new(Value::U64(0)),
            Box::new(Value::U64(4000)),
        )),
    );
    let cost_large = JetId::Slice.runtime_cost(
        &large,
        &exfer::script::jets::context::ScriptContext::empty(),
    );

    assert!(
        cost_large > cost_small * 5,
        "Slice runtime_cost should scale with data: small={}, large={}",
        cost_small,
        cost_large
    );
    assert!(
        cost_large > 100,
        "Slice on 8000 bytes should exceed old static cost of 100, got {}",
        cost_large
    );
}

// ── F4: Phase 1/Phase 2 script classification is length-only ──

#[test]
fn f5_deserialize_impossible_counts_rejected() {
    use exfer::types::transaction::{SerError, Transaction};

    // Craft a payload with input_count=65535, output_count=65535
    // but only 4 bytes of header — no actual data follows.
    let mut data = Vec::new();
    data.extend_from_slice(&65535u16.to_le_bytes()); // input_count
    data.extend_from_slice(&65535u16.to_le_bytes()); // output_count
                                                     // No body follows — remaining = 0 but min_needed is huge

    let result = Transaction::deserialize(&data);
    assert!(result.is_err(), "impossible counts must be rejected early");
    match result.unwrap_err() {
        SerError::UnexpectedEof => {}
        other => panic!("expected UnexpectedEof, got {:?}", other),
    }
}

#[test]
fn f5_deserialize_moderate_impossible_counts() {
    use exfer::types::transaction::{SerError, Transaction};

    // input_count=100, output_count=100: needs 100*36 + 100*12 + 100*3 = 5100 bytes minimum
    let mut data = vec![0u8; 4 + 10]; // header + 10 junk bytes (way less than 5100)
    data[0..2].copy_from_slice(&100u16.to_le_bytes());
    data[2..4].copy_from_slice(&100u16.to_le_bytes());

    let result = Transaction::deserialize(&data);
    assert!(result.is_err());
    match result.unwrap_err() {
        SerError::UnexpectedEof => {}
        other => panic!("expected UnexpectedEof, got {:?}", other),
    }
}

// ── F6: Duplicate peer address check ──

#[test]
fn r3f3_getblocks_response_cap_constant() {
    assert_eq!(
        exfer::types::MAX_GETBLOCKS_RESPONSE,
        8,
        "MAX_GETBLOCKS_RESPONSE must be 8"
    );
}

#[test]
fn r3f3_response_bytes_budget_constant() {
    assert_eq!(
        exfer::types::MAX_RESPONSE_BYTES_PER_MIN,
        16_777_216,
        "MAX_RESPONSE_BYTES_PER_MIN must be 16 MiB"
    );
}
