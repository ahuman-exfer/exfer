//! Round 44 audit-fix structural tests.
//!
//! P0:  Eviction does NOT delete fork blocks from disk.
//! P1a: Fork-block tracking is durable across restart (FORK_BLOCKS_TABLE).
//! P1b: SPEC work formula matches implementation (floor(2^256 / target)).
//! P2:  SPEC coinbase output minimum matches implementation (DUST_THRESHOLD).

// ---- P0 (R44→R55→R113): Eviction uses evict_fork_block with full deletion ----

/// The old remove_fork_block (without _full) must not exist.

#[test]
fn p1_r67_orphan_cache_scaled() {
    use exfer::types::{MAX_BLOCK_SIZE, MAX_ORPHAN_BLOCKS, MAX_ORPHAN_CACHE_BYTES};
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            MAX_ORPHAN_CACHE_BYTES >= MAX_ORPHAN_BLOCKS * MAX_BLOCK_SIZE,
            "MAX_ORPHAN_CACHE_BYTES ({}) must be >= MAX_ORPHAN_BLOCKS * MAX_BLOCK_SIZE ({})",
            MAX_ORPHAN_CACHE_BYTES,
            MAX_ORPHAN_BLOCKS * MAX_BLOCK_SIZE
        );
    }
}

// ---- P1 (R67): Test window fix ----

/// Verify the p3_r66_rebuild_checks_state_root test window is large enough.

#[test]
fn p2_r71_impl_max_witness_is_65535() {
    assert_eq!(
        exfer::types::MAX_WITNESS_SIZE,
        65_535,
        "MAX_WITNESS_SIZE must be 65535 (u16 VarBytes wire limit)"
    );
}

// ── Round 72 ──

// ── P1: Bounded TCP write timeout ──

/// [P1 R72] Write path must use a write timeout to prevent slot pinning.
/// After the reader/writer split, the timeout lives in write_framed_message
/// (called by both Peer::send and the writer task).

#[test]
fn p1_r95_runtime_heterogeneous_list_detected() {
    use exfer::script::value::Value;
    // Homogeneous list should pass
    let homo = Value::List(vec![Value::U64(1), Value::U64(2), Value::U64(3)]);
    assert!(homo.lists_are_homogeneous(), "homogeneous list must pass");

    // Empty list should pass
    let empty = Value::List(vec![]);
    assert!(empty.lists_are_homogeneous(), "empty list must pass");

    // Single-element list should pass
    let single = Value::List(vec![Value::Bool(true)]);
    assert!(
        single.lists_are_homogeneous(),
        "single-element list must pass"
    );

    // Heterogeneous list must fail
    let hetero = Value::List(vec![Value::U64(1), Value::Bool(true)]);
    assert!(
        !hetero.lists_are_homogeneous(),
        "heterogeneous list must fail"
    );

    // Nested heterogeneous list must fail
    let nested = Value::Pair(
        Box::new(Value::Unit),
        Box::new(Value::List(vec![
            Value::U64(1),
            Value::Hash(exfer::types::hash::Hash256::ZERO),
        ])),
    );
    assert!(
        !nested.lists_are_homogeneous(),
        "nested heterogeneous list must fail"
    );
}

// ============================================================
// R95 P2: IBD ancestor recovery is multi-hop (bounded loop)
// ============================================================

/// [P2 R95] IBD ancestor recovery is a loop, not single-hop.

#[test]
fn p2_r97_control_msgs_limit_raised() {
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            exfer::types::MAX_CONTROL_MSGS_DURING_IBD >= 50,
            "MAX_CONTROL_MSGS_DURING_IBD must be >= 50 (was 10, too strict under relay chatter)"
        );
    }
}

/// [P2 R97 / R104] recv_headers relay arm counts toward ctrl_count.
/// R104 hardened: relay chatter is rate-limited to prevent IBD slowdown.

#[test]
fn p1_r98_max_script_steps_lowered() {
    assert_eq!(
        exfer::types::MAX_SCRIPT_STEPS,
        4_000_000,
        "MAX_SCRIPT_STEPS must be 4M (down from 10M)"
    );
}

/// [P1 R98] MAX_TX_SCRIPT_BUDGET lowered to 20M.

#[test]
fn p1_r98_max_tx_script_budget_lowered() {
    assert_eq!(
        exfer::types::MAX_TX_SCRIPT_BUDGET,
        20_000_000u128,
        "MAX_TX_SCRIPT_BUDGET must be 20M (down from 50M)"
    );
}

/// [P1 R98] MAX_TXS_PER_MIN lowered to 60.

#[test]
fn p1_r98_max_txs_per_min_lowered() {
    assert_eq!(
        exfer::types::MAX_TXS_PER_MIN,
        60,
        "MAX_TXS_PER_MIN must be 60 (down from 120)"
    );
}

/// [P1 R98] MAX_GLOBAL_TXS_PER_MIN lowered to 200.

#[test]
fn p1_r98_max_global_txs_per_min_lowered() {
    assert_eq!(
        exfer::types::MAX_GLOBAL_TXS_PER_MIN,
        200,
        "MAX_GLOBAL_TXS_PER_MIN must be 200 (down from 600)"
    );
}

/// [P1 R98] Budget still allows per-input to reach limit.

#[test]
fn p1_r98_budget_ge_per_input() {
    assert!(
        exfer::types::MAX_TX_SCRIPT_BUDGET >= exfer::types::MAX_SCRIPT_STEPS as u128,
        "per-tx budget must be >= per-input cap"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Round 98 — P2: Orphan cache hardening
// ═══════════════════════════════════════════════════════════════════

/// [P2 R98] Per-peer orphan cap removed — orphan handling is centralized
/// in the sync manager. Node-level orphan bounds (MAX_ORPHAN_BLOCKS,
/// MAX_ORPHAN_CACHE_BYTES) are sufficient.

#[test]
fn p2_r98_orphan_bounds_exist() {
    assert!(
        exfer::types::MAX_ORPHAN_BLOCKS > 0,
        "MAX_ORPHAN_BLOCKS must be positive"
    );
    assert!(
        exfer::types::MAX_ORPHAN_CACHE_BYTES > 0,
        "MAX_ORPHAN_CACHE_BYTES must be positive"
    );
}

/// [P2 R98→R102] genesis_target NOT imported — ceiling check removed
/// because retarget can legitimately exceed genesis target after slow windows.

#[test]
fn p1_r106_max_fork_blocks_increased() {
    use exfer::network::sync::MAX_FORK_BLOCKS;
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            MAX_FORK_BLOCKS == 128,
            "MAX_FORK_BLOCKS must be 128 (R117 disk-pressure bound): got {}",
            MAX_FORK_BLOCKS
        );
    }
}

/// [P1 R106] MAX_ANCESTOR_RECOVERY_DEPTH sized to RETARGET_WINDOW.

#[test]
fn p1_r111_evict_retains_work() {
    use exfer::chain::storage::ChainStorage;
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let tmpdir = tempfile::TempDir::new().unwrap();
    let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();

    let block = Block {
        header: BlockHeader {
            version: 1,
            height: 5,
            prev_block_id: Hash256::ZERO,
            timestamp: 1700000000,
            difficulty_target: Hash256([0xFF; 32]),
            nonce: 77,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput {
                value: 10_000_000_000,
                script: vec![0u8; 32],
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        }],
    };
    let block_id = block.header.block_id();
    let work = [0u8; 32];
    storage.store_fork_block_atomic(&block, &work).unwrap();
    storage.evict_fork_block(&block_id).unwrap();

    // Work must survive eviction (needed for difficulty ancestry walks)
    assert!(
        storage.get_cumulative_work(&block_id).unwrap().is_some(),
        "cumulative work must be retained after fork eviction"
    );
}

/// [P0 R113] evict_fork_block removes block body but retains header for difficulty ancestry.

#[test]
fn p0_r113_evict_retains_header_removes_body() {
    use exfer::chain::storage::ChainStorage;
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let tmpdir = tempfile::TempDir::new().unwrap();
    let storage = ChainStorage::open(&tmpdir.path().join("test.redb")).unwrap();

    let block = Block {
        header: BlockHeader {
            version: 1,
            height: 5,
            prev_block_id: Hash256::ZERO,
            timestamp: 1700000000,
            difficulty_target: Hash256([0xFF; 32]),
            nonce: 88,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput {
                value: 10_000_000_000,
                script: vec![0u8; 32],
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        }],
    };
    let block_id = block.header.block_id();
    let work = [0u8; 32];
    storage.store_fork_block_atomic(&block, &work).unwrap();
    storage.evict_fork_block(&block_id).unwrap();

    // Block body must be gone
    assert!(
        storage.get_block(&block_id).unwrap().is_none(),
        "block body must be removed after fork eviction"
    );
    // Header must survive (needed for difficulty ancestry walks)
    assert!(
        storage.get_header(&block_id).unwrap().is_some(),
        "header must be retained after fork eviction"
    );
}

/// [P1 R111] evict_fork_block has TOCTOU guard for canonical promotion.

#[test]
fn f1_r117_max_fork_blocks_capped() {
    use exfer::network::sync::MAX_FORK_BLOCKS;
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            MAX_FORK_BLOCKS <= 128,
            "MAX_FORK_BLOCKS must be <= 128 to bound disk pressure: got {}",
            MAX_FORK_BLOCKS
        );
    }
}
