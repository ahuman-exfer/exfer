//! Integration test for the read-only `get_node_info` JSON-RPC method
//! (node observability — direction #2). Builds a real `Node` and asserts:
//!   1. the full result schema + field types,
//!   2. chain identity is sourced from `node.genesis_id` (not tip-derived),
//!   3. the operational counters are surfaced live from `node.metrics` — after
//!      a reorg-class event the counters the RPC returns reflect it.
//!
//! The handler reads `node.metrics`, the same `Arc<NodeMetrics>` the production
//! increment sites in `network::sync` bump. A genuine multi-block PoW reorg is
//! not stand-up-able locally (fresh-chain mining is gated by the assume-valid
//! bootstrap anchor — see orphan_rate_fix_regression.rs), so this test drives
//! the reorg/orphan counters through the exact `crate::metrics` increment calls
//! the reorg path uses, then asserts the RPC reflects the change. The metric
//! accumulation logic itself is unit-tested in `src/metrics.rs`.

use exfer::chain::fork_choice::ChainTip;
use exfer::chain::state::UtxoSet;
use exfer::chain::storage::ChainStorage;
use exfer::genesis::genesis_block;
use exfer::mempool::Mempool;
use exfer::metrics::NodeMetrics;
use exfer::network::sync::Node;
use exfer::types::hash::Hash256;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::{Mutex, RwLock};

fn build_node(storage: Arc<ChainStorage>, gid: Hash256, utxo_set: UtxoSet, tip: ChainTip) -> Node {
    let (peer_events_tx, _rx) = tokio::sync::mpsc::channel(64);
    Node {
        storage,
        utxo_set: Arc::new(RwLock::new(utxo_set)),
        mempool: Arc::new(Mutex::new(Mempool::new())),
        tip: Arc::new(RwLock::new(tip)),
        genesis_id: gid,
        peers: Arc::new(Mutex::new(exfer::network::sync::PeerRegistry::new())),
        outbound_bootstraps: std::sync::Mutex::new(HashMap::new()),
        next_session_id: std::sync::atomic::AtomicU64::new(1),
        active_ibd_peer: std::sync::Mutex::new(None),
        global_block_limiter: std::sync::Mutex::new((std::time::Instant::now(), 0)),
        global_tx_limiter: std::sync::Mutex::new((std::time::Instant::now(), 0)),
        ip_abuse: std::sync::Mutex::new(HashMap::new()),
        fork_blocks: std::sync::Mutex::new(Vec::new()),
        orphan_blocks: std::sync::Mutex::new(Vec::new()),
        future_blocks: std::sync::Mutex::new(Vec::new()),
        difficulty_cache: std::sync::Mutex::new(HashMap::new()),
        shutdown: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        addr_book: std::sync::Mutex::new(HashMap::new()),
        pow_semaphore: tokio::sync::Semaphore::new(2),
        identity_key: ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]),
        identity_bans: std::sync::Mutex::new(HashMap::new()),
        global_response_limiter: std::sync::Mutex::new((std::time::Instant::now(), 0)),
        reorg_triggers: std::sync::Mutex::new(exfer::network::sync::ReorgTriggerState::new()),
        peer_events_tx,
        sync_state: std::sync::atomic::AtomicU8::new(0),
        best_peer_work: std::sync::Mutex::new([0u8; 32]),
        mining_cancel: std::sync::atomic::AtomicBool::new(false),
        assume_valid: false,
        assume_valid_verified: std::sync::atomic::AtomicBool::new(false),
        event_bus: exfer::events::EventBus::new(),
        ever_confirmed_peer: std::sync::atomic::AtomicBool::new(false),
        frame_budget: exfer::network::frame_budget::FrameBudget::new(),
        tip_validation_coord: Arc::new(
            exfer::network::tip_validation::TipValidationCoordinator::new(),
        ),
        assume_valid_cumulative_work_trusted: std::sync::atomic::AtomicBool::new(true),
        stage_a_authenticated_headers: tokio::sync::RwLock::new(None),
        devnet: false,
        metrics: std::sync::Arc::new(NodeMetrics::new()),
        started_at: std::time::Instant::now(),
    }
}

fn fresh_node() -> Arc<Node> {
    let tmpdir = Box::leak(Box::new(TempDir::new().unwrap()));
    let db_path = tmpdir.path().join("test.redb");
    let storage = Arc::new(ChainStorage::open(&db_path).unwrap());
    let genesis = genesis_block();
    let gid = genesis.header.block_id();
    storage.put_block(&genesis).unwrap();
    let mut utxo_set = UtxoSet::new();
    for tx in &genesis.transactions {
        let _ = utxo_set.apply_transaction(tx, 0);
    }
    let tip = ChainTip::genesis(gid, &genesis.header.difficulty_target);
    Arc::new(build_node(storage, gid, utxo_set, tip))
}

#[tokio::test]
async fn get_node_info_shape_and_identity() {
    let node = fresh_node();
    let info = exfer::rpc::node_info_json(&node).await;

    // Top-level shape: every documented field present with the right type.
    // version must be the real RELEASE_TAG, not the reserved "0.1.0"
    // CARGO_PKG_VERSION crates.io placeholder.
    assert_eq!(
        info.get("version").and_then(|v| v.as_str()),
        Some(exfer::types::RELEASE_TAG)
    );
    assert_ne!(
        info.get("version").and_then(|v| v.as_str()),
        Some(env!("CARGO_PKG_VERSION")),
        "get_node_info must surface RELEASE_TAG, not the Cargo placeholder"
    );
    let network = info.get("network").and_then(|v| v.as_str()).unwrap();
    assert!(
        matches!(network, "mainnet" | "testnet" | "devnet"),
        "unexpected network: {network}"
    );

    // Chain identity must equal node.genesis_id (hex), never tip-derived.
    let gid_hex = info
        .get("genesis_block_id")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(gid_hex, hex::encode(node.genesis_id.as_bytes()));

    // Genesis is the tip on a fresh node: tip height 0, tip id == genesis id.
    assert_eq!(info.get("tip_height").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(
        info.get("tip_block_id").and_then(|v| v.as_str()),
        Some(hex::encode(node.genesis_id.as_bytes()).as_str())
    );

    // tip_age_seconds is present (number) or null — never missing.
    assert!(info.get("tip_age_seconds").is_some());

    // Operational gauges.
    assert_eq!(info.get("peer_count").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(info.get("mempool_size").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(info.get("mempool_bytes").and_then(|v| v.as_u64()), Some(0));
    assert!(info
        .get("uptime_seconds")
        .and_then(|v| v.as_u64())
        .is_some());

    // Metrics object: every counter present and zero on a fresh node.
    let m = info.get("metrics").and_then(|v| v.as_object()).unwrap();
    for key in [
        "blocks_accepted",
        "blocks_orphaned",
        "reorgs_applied",
        "total_blocks_undone",
        "retrying_reorg_trigger",
        "reorg_recoverable_errors",
        "reorg_fatal_errors",
        "rate_cap_disconnects",
        "rate_cap_softdrops",
        "global_block_drops",
        "channel_send_drops",
    ] {
        assert_eq!(
            m.get(key).and_then(|v| v.as_u64()),
            Some(0),
            "metric {key} should be 0 on a fresh node"
        );
    }
}

#[tokio::test]
async fn get_node_info_reflects_metric_activity() {
    let node = fresh_node();

    // Drive the same counter increments the reorg path emits (sync.rs reorg
    // site: reorgs_applied + total_blocks_undone, demote loop: blocks_orphaned,
    // success log: blocks_accepted). The handler reads the live Arc, so the RPC
    // result must reflect these.
    NodeMetrics::incr(&node.metrics.reorgs_applied);
    NodeMetrics::add(&node.metrics.total_blocks_undone, 2);
    NodeMetrics::incr(&node.metrics.blocks_orphaned);
    NodeMetrics::incr(&node.metrics.blocks_orphaned);
    NodeMetrics::add(&node.metrics.blocks_accepted, 5);
    NodeMetrics::incr(&node.metrics.channel_send_drops);

    let info = exfer::rpc::node_info_json(&node).await;
    let m = info.get("metrics").and_then(|v| v.as_object()).unwrap();

    assert_eq!(m.get("reorgs_applied").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(
        m.get("total_blocks_undone").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(m.get("blocks_orphaned").and_then(|v| v.as_u64()), Some(2));
    assert_eq!(m.get("blocks_accepted").and_then(|v| v.as_u64()), Some(5));
    assert_eq!(
        m.get("channel_send_drops").and_then(|v| v.as_u64()),
        Some(1)
    );
    // Untouched counters stay zero.
    assert_eq!(
        m.get("reorg_fatal_errors").and_then(|v| v.as_u64()),
        Some(0)
    );
}
