//! Regression tests for two of the orphan-rate bug fixes whose logic is not
//! reachable from the existing suite and cannot be exercised by a local
//! multi-node network (fresh-chain mining is blocked by the assume-valid
//! bootstrap anchor). Both tests are constructed to FAIL on the pre-fix code
//! and PASS on the fix, so they have teeth as regression guards.
//!
//! - bug4: ReorgTriggerState.take() must purge the order-queue entry, or stale
//!   ghosts pin the global cap and evict still-live triggers under fork pressure.
//! - bug6: a re-fetched ancestor that a pending reorg is waiting for must be
//!   admitted past the fork-pool min-work eviction, or deep-fork recovery
//!   live-locks (the walk re-requests a body that is re-dropped forever).

// ── bug4: ReorgTriggerState order-queue desync ──

#[test]
fn reorg_trigger_take_purges_order_so_live_triggers_survive_cap_pressure() {
    use exfer::network::sync::{ReorgTriggerState, MAX_GLOBAL_TRIGGERS};
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;

    fn trigger_block(prev: Hash256, nonce: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                height: 1,
                prev_block_id: prev,
                timestamp: 1000,
                difficulty_target: Hash256([0xFF; 32]),
                nonce,
                tx_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
            },
            transactions: vec![],
        }
    }

    let mut rt = ReorgTriggerState::new();

    // X is a live trigger that is never taken. It is inserted FIRST, so it sits
    // at the front of the order queue.
    let x_anc = Hash256::sha256(b"live-ancestor-X");
    assert!(rt.insert(x_anc, trigger_block(x_anc, 0)));

    // Insert MAX_GLOBAL_TRIGGERS-1 further triggers and immediately take() each.
    // Pre-fix, take() leaves a ghost entry in the order queue, so after this loop
    // the queue is pinned at the cap (1 live X + MAX-1 ghosts) even though only X
    // is actually live. Post-fix, take() purges the order entry, so the queue
    // holds exactly [X] throughout.
    for i in 0..(MAX_GLOBAL_TRIGGERS - 1) {
        let anc = Hash256::sha256(format!("transient-{i}").as_bytes());
        assert!(rt.insert(anc, trigger_block(anc, i as u64 + 1)));
        assert!(rt.take(&anc).is_some(), "freshly inserted trigger must be takeable");
    }

    // One more live insert. Pre-fix the order queue is at the cap, so this insert
    // evicts order.pop_front() == X (a LIVE trigger) even though only ~2 triggers
    // are actually live. Post-fix the queue is [X], so no eviction occurs.
    let y_anc = Hash256::sha256(b"live-ancestor-Y");
    assert!(rt.insert(y_anc, trigger_block(y_anc, 9_999)));

    // The crux: X must still be retrievable. Fails pre-fix (X was wrongly
    // evicted -> None); passes post-fix (Some).
    assert!(
        rt.take(&x_anc).is_some(),
        "a long-lived reorg trigger was wrongly evicted by stale order-queue ghosts"
    );
}

// ── bug6: deep-fork re-admission live-lock ──
//
// NOT gated on a cargo feature: try_store_fork_block does no PoW, and the Node
// builder + genesis_block() work on the default build, so these fix-8 pins run
// under a plain `cargo test` (not only `--features testnet`).

mod deep_fork_readmission {
    use exfer::chain::fork_choice::ChainTip;
    use exfer::chain::state::UtxoSet;
    use exfer::consensus::difficulty::work_from_target;
    use exfer::chain::storage::ChainStorage;
    use exfer::genesis::genesis_block;
    use exfer::mempool::Mempool;
    use exfer::network::sync::{Node, MAX_FORK_BLOCKS};
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::{Mutex, RwLock};

    fn fork_block(nonce: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                height: 2,
                prev_block_id: Hash256::sha256(format!("parent-{nonce}").as_bytes()),
                timestamp: 1000 + nonce,
                difficulty_target: Hash256([0xFF; 32]),
                nonce,
                tx_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
            },
            transactions: vec![],
        }
    }

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
            metrics: std::sync::Arc::new(exfer::metrics::NodeMetrics::new()),
            started_at: std::time::Instant::now(),
        }
    }

    fn setup_full_pool() -> (Node, [u8; 32]) {
        let tmpdir = Box::leak(Box::new(TempDir::new().unwrap()));
        let db_path = tmpdir.path().join("test.redb");
        let storage = Arc::new(ChainStorage::open(&db_path).unwrap());
        let genesis = genesis_block();
        let gid = genesis.header.block_id();
        storage.put_block(&genesis).unwrap();
        let mut utxo_set = UtxoSet::new();
        for tx in &genesis.transactions {
            utxo_set.apply_transaction(tx, 0).unwrap();
        }
        let genesis_work = work_from_target(&genesis.header.difficulty_target);
        storage.put_cumulative_work(&gid, &genesis_work).unwrap();
        let tip = ChainTip::genesis(gid, &genesis.header.difficulty_target);
        let node = build_node(storage, gid, utxo_set, tip);

        // Fill the fork pool to capacity with maximally-strong entries.
        let high_work = [0xFFu8; 32];
        for nonce in 0..MAX_FORK_BLOCKS as u64 {
            let stored = node.try_store_fork_block(&fork_block(nonce), &high_work).unwrap();
            assert!(stored, "filler {nonce} should be stored while pool not yet full");
        }
        assert_eq!(
            node.fork_blocks.lock().unwrap().len() as u32,
            MAX_FORK_BLOCKS,
            "pool should be exactly full"
        );
        (node, high_work)
    }

    /// A weak block that NO pending reorg needs must still be dropped when the
    /// pool is full — proves the fix is not a general bypass of the fork-pool
    /// bound (anti-DoS / boundedness).
    #[tokio::test]
    async fn weak_unneeded_block_is_dropped_when_pool_full() {
        let (node, _high) = setup_full_pool();
        let weak = fork_block(900_001);
        let weak_id = weak.header.block_id();
        let low_work = {
            let mut w = [0u8; 32];
            w[31] = 1;
            w
        };
        let stored = node.try_store_fork_block(&weak, &low_work).unwrap();
        assert!(!stored, "a weak, non-reorg-needed block must be dropped when the pool is full");
        assert!(!node.storage.is_fork_block(&weak_id).unwrap());
        assert_eq!(node.fork_blocks.lock().unwrap().len() as u32, MAX_FORK_BLOCKS);
    }

    /// The same weak block, but now a pending reorg is waiting for it: it MUST
    /// be admitted (evicting a non-needed entry) so the reorg walk can read it
    /// and converge. Fails pre-fix (dropped -> live-lock), passes post-fix.
    #[tokio::test]
    async fn reorg_needed_block_is_admitted_when_pool_full() {
        let (node, _high) = setup_full_pool();
        let needed = fork_block(900_002);
        let needed_id = needed.header.block_id();
        let low_work = {
            let mut w = [0u8; 32];
            w[31] = 1;
            w
        };

        // Register a pending reorg trigger whose missing ancestor IS this block,
        // so it appears in the reorg-needed set the admission decision consults.
        {
            let mut rt = node.reorg_triggers.lock().unwrap();
            let waiter = fork_block(123_456); // some block waiting on `needed`
            assert!(rt.insert(needed_id, waiter));
        }

        let stored = node.try_store_fork_block(&needed, &low_work).unwrap();
        assert!(
            stored,
            "a reorg-needed ancestor must be admitted past min-work eviction (else deep-fork recovery live-locks)"
        );
        assert!(
            node.storage.is_fork_block(&needed_id).unwrap(),
            "the admitted reorg-needed block must be persisted as a fork block"
        );
        let pool = node.fork_blocks.lock().unwrap();
        assert!(pool.iter().any(|(id, _)| *id == needed_id), "needed block must be tracked in-memory");
        assert!(
            pool.len() as u32 <= MAX_FORK_BLOCKS,
            "pool must stay bounded (a non-needed entry was evicted to make room)"
        );
    }
}
