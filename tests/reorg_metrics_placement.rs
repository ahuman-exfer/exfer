//! Placement regression for the reorg metrics counters (PR #41 review).
//!
//! The reorg counters must count *committed* reorgs, not *attempts*. An earlier
//! cut incremented `reorgs_applied` / `total_blocks_undone` at the top of the
//! reorg branch (before the undo loop and the atomic commit, both of which can
//! roll the reorg back with the tip unchanged), so a higher-work fork that
//! reached the branch and then failed validation reported an applied reorg that
//! never happened. Symmetrically, the reorg error counters only fired on the
//! `retry_reorg_triggers` path, so a NewBlock-triggered reorg-apply failure
//! left `get_node_info` reading zero reorg errors.
//!
//! The existing metrics tests drive the counters directly, so they can't catch
//! placement-relative-to-commit. This test drives a REAL failing reorg through
//! `process_block` (a higher-work fork whose first block carries a corrupted
//! `state_root`, so the reorg apply rolls back) and asserts:
//!   - `reorgs_applied` / `total_blocks_undone` did NOT move (no false apply),
//!   - `reorg_recoverable_errors` DID move (the failure is counted on the
//!     NewBlock path, not only the retry path),
//!   - `reorg_fatal_errors` stayed 0 and the tip is unchanged.

#![cfg(feature = "testnet")]

use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::{Mutex, RwLock};

use ed25519_dalek::SigningKey;

use exfer::chain::fork_choice::ChainTip;
use exfer::chain::state::UtxoSet;
use exfer::chain::storage::ChainStorage;
use exfer::consensus::difficulty::{genesis_target, work_from_target};
use exfer::consensus::reward::block_reward;
use exfer::consensus::validation::compute_tx_root;
use exfer::events::EventBus;
use exfer::genesis::genesis_block;
use exfer::mempool::Mempool;
use exfer::network::sync::{Node, ProcessBlockOutcome};
use exfer::types::block::{Block, BlockHeader};
use exfer::types::hash::Hash256;
use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::TARGET_BLOCK_TIME_SECS;

/// Build a Node wired to the given storage / utxo set / tip. Mirrors the
/// production constructor's field set (kept in sync with `Node`).
fn make_node(
    storage: Arc<ChainStorage>,
    utxo_set: UtxoSet,
    tip: ChainTip,
    gid: Hash256,
) -> Arc<Node> {
    let (peer_events_tx, _peer_events_rx) = tokio::sync::mpsc::channel(64);
    Arc::new(Node {
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
        identity_key: SigningKey::from_bytes(&[0x42u8; 32]),
        identity_bans: std::sync::Mutex::new(HashMap::new()),
        global_response_limiter: std::sync::Mutex::new((std::time::Instant::now(), 0)),
        reorg_triggers: std::sync::Mutex::new(exfer::network::sync::ReorgTriggerState::new()),
        peer_events_tx,
        sync_state: std::sync::atomic::AtomicU8::new(0),
        best_peer_work: std::sync::Mutex::new([0u8; 32]),
        mining_cancel: std::sync::atomic::AtomicBool::new(false),
        assume_valid: false,
        assume_valid_verified: std::sync::atomic::AtomicBool::new(false),
        event_bus: EventBus::new(),
        devnet: false,
        ever_confirmed_peer: std::sync::atomic::AtomicBool::new(false),
        frame_budget: exfer::network::frame_budget::FrameBudget::new(),
        tip_validation_coord: Arc::new(
            exfer::network::tip_validation::TipValidationCoordinator::new(),
        ),
        assume_valid_cumulative_work_trusted: std::sync::atomic::AtomicBool::new(true),
        stage_a_authenticated_headers: tokio::sync::RwLock::new(None),
        metrics: std::sync::Arc::new(exfer::metrics::NodeMetrics::new()),
        started_at: std::time::Instant::now(),
    })
}

fn coinbase(height: u64, value: u64, pubkey: &[u8; 32]) -> Transaction {
    Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: height as u32,
        }],
        outputs: vec![TxOutput::new_p2pkh(value, pubkey)],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    }
}

/// Grind `header.nonce` until it satisfies the real testnet PoW target. With
/// the persistent-testnet difficulty (2^252) this is ~16 Argon2id attempts —
/// fast, but no longer free as it was under the old trivial 0xFF target where
/// nonce 0 always passed. Must be called AFTER every header field that feeds the
/// PoW hash is final (e.g. a deliberately-corrupted state_root).
fn mine(header: &mut BlockHeader) {
    while !exfer::consensus::pow::verify_pow(header).unwrap_or(false) {
        header.nonce = header.nonce.wrapping_add(1);
    }
}

/// Assemble a block, computing tx_root and the post-apply state_root by
/// replaying the txs (coinbase first) onto a clone of `base_utxo`, then mining a
/// valid nonce at the testnet genesis target.
fn build_block(
    prev: &BlockHeader,
    height: u64,
    txs: Vec<Transaction>,
    base_utxo: &UtxoSet,
) -> Block {
    let mut post = base_utxo.clone();
    for tx in &txs {
        post.apply_transaction(tx, height)
            .expect("apply for state_root");
    }
    let mut header = BlockHeader {
        version: 1,
        height,
        prev_block_id: prev.block_id(),
        timestamp: prev.timestamp + TARGET_BLOCK_TIME_SECS,
        difficulty_target: genesis_target(),
        nonce: 0,
        tx_root: compute_tx_root(&txs).expect("tx_root"),
        state_root: post.state_root(),
    };
    mine(&mut header);
    Block {
        header,
        transactions: txs,
    }
}

#[tokio::test]
async fn failed_reorg_does_not_count_as_applied_and_counts_the_error() {
    let db = TempDir::new().unwrap();
    let genesis = genesis_block();
    let gid = genesis.header.block_id();

    let storage = Arc::new(ChainStorage::open(&db.path().join("test.redb")).unwrap());
    storage.put_block(&genesis).unwrap();
    let mut utxo_set = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_set.apply_transaction(tx, 0).unwrap();
    }
    storage
        .put_cumulative_work(&gid, &work_from_target(&genesis.header.difficulty_target))
        .unwrap();
    let tip = ChainTip::genesis(gid, &genesis.header.difficulty_target);

    let node = make_node(storage, utxo_set.clone(), tip, gid);

    // Chain A: a single valid block — this is our canonical tip (height 1).
    let a1 = build_block(
        &genesis.header,
        1,
        vec![coinbase(1, block_reward(1), &[0xA1u8; 32])],
        &utxo_set,
    );
    let a1_id = a1.header.block_id();
    assert!(matches!(
        node.process_block(a1, None).await.expect("a1 accepted"),
        ProcessBlockOutcome::Accepted
    ));

    // Chain B: B1 forks genesis with a CORRUPTED state_root. It still passes
    // header validation (state_root is a UTXO commitment, checked only at reorg
    // apply) and is stored as an equal-work fork candidate.
    let mut b1 = build_block(
        &genesis.header,
        1,
        vec![coinbase(1, block_reward(1), &[0xB1u8; 32])],
        &utxo_set,
    );
    b1.header.state_root = Hash256::sha256(b"deliberately-wrong-state-root");
    // Re-mine: the corrupted state_root changed the PoW preimage, so the nonce
    // build_block found is stale. B1 must still pass header/PoW validation (it is
    // stored as a fork candidate); the state_root mismatch is only caught later,
    // at reorg-apply.
    mine(&mut b1.header);
    let b1_header = b1.header.clone();
    // After B1's coinbase (used only to shape B2's header; B2 is never reached
    // because the reorg fails on B1's state_root first).
    let mut after_b1 = utxo_set.clone();
    after_b1.apply_transaction(&b1.transactions[0], 1).unwrap();

    assert!(matches!(
        node.process_block(b1, None).await.expect("b1 stored"),
        ProcessBlockOutcome::Stored
    ));

    // B2 extends B1, so chain B (2 blocks) outweighs chain A (1 block) and a
    // reorg is triggered on this NewBlock path. The reorg undoes A1, then fails
    // applying B1 (state_root mismatch) and rolls back — the tip stays at A1.
    let b2 = build_block(
        &b1_header,
        2,
        vec![coinbase(2, block_reward(2), &[0xB2u8; 32])],
        &after_b1,
    );
    let res = node.process_block(b2, None).await;
    assert!(
        res.is_err(),
        "the reorg must fail on B1's corrupted state_root, not succeed"
    );

    // Tip is unchanged: the failed reorg did not advance the chain.
    {
        let tip = node.tip.read().await;
        assert_eq!(
            tip.height, 1,
            "tip height must stay at A1 after a failed reorg"
        );
        assert_eq!(
            tip.block_id, a1_id,
            "tip must still be A1 after a failed reorg"
        );
    }

    let m = node.metrics.snapshot();
    // The placement bug: an attempt that rolled back must NOT count as applied.
    assert_eq!(
        m.reorgs_applied, 0,
        "a reorg that failed after the attempt point must not count as applied"
    );
    assert_eq!(
        m.total_blocks_undone, 0,
        "no blocks were permanently undone by a rolled-back reorg"
    );
    // The error must be counted on the NewBlock path (not only via retries).
    assert_eq!(
        m.reorg_recoverable_errors, 1,
        "a recoverable reorg-apply failure on the NewBlock path must be counted"
    );
    assert_eq!(
        m.reorg_fatal_errors, 0,
        "a state_root mismatch is recoverable, not fatal"
    );
    // And no false orphan was recorded — the demote loop runs only post-commit.
    assert_eq!(
        m.blocks_orphaned, 0,
        "no block was demoted to fork storage by a rolled-back reorg"
    );
}

#[tokio::test]
async fn successful_reorg_counts_applied_and_undone_depth() {
    // The success-path companion to the failure test: a reorg that actually
    // commits must record exactly one applied reorg, the correct undo depth, and
    // one orphaned (demoted) block — and zero reorg errors.
    let db = TempDir::new().unwrap();
    let genesis = genesis_block();
    let gid = genesis.header.block_id();

    let storage = Arc::new(ChainStorage::open(&db.path().join("test.redb")).unwrap());
    storage.put_block(&genesis).unwrap();
    let mut utxo_set = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_set.apply_transaction(tx, 0).unwrap();
    }
    storage
        .put_cumulative_work(&gid, &work_from_target(&genesis.header.difficulty_target))
        .unwrap();
    let tip = ChainTip::genesis(gid, &genesis.header.difficulty_target);

    let node = make_node(storage, utxo_set.clone(), tip, gid);

    // Chain A: a single valid block — canonical tip at height 1.
    let a1 = build_block(
        &genesis.header,
        1,
        vec![coinbase(1, block_reward(1), &[0xA1u8; 32])],
        &utxo_set,
    );
    assert!(matches!(
        node.process_block(a1, None).await.expect("a1 accepted"),
        ProcessBlockOutcome::Accepted
    ));

    // Chain B: B1 forks genesis (valid), B2 extends B1 so B (2 blocks) outweighs
    // A (1 block) and triggers a reorg that commits, disconnecting A1.
    let b1 = build_block(
        &genesis.header,
        1,
        vec![coinbase(1, block_reward(1), &[0xB1u8; 32])],
        &utxo_set,
    );
    let b1_header = b1.header.clone();
    let mut after_b1 = utxo_set.clone();
    after_b1.apply_transaction(&b1.transactions[0], 1).unwrap();
    assert!(matches!(
        node.process_block(b1, None).await.expect("b1 stored"),
        ProcessBlockOutcome::Stored
    ));

    let b2 = build_block(
        &b1_header,
        2,
        vec![coinbase(2, block_reward(2), &[0xB2u8; 32])],
        &after_b1,
    );
    assert!(matches!(
        node.process_block(b2, None)
            .await
            .expect("b2 triggers reorg"),
        ProcessBlockOutcome::Accepted
    ));

    // Tip advanced to B2 (height 2): the reorg committed.
    {
        let tip = node.tip.read().await;
        assert_eq!(
            tip.height, 2,
            "tip must advance to B2 after a committed reorg"
        );
    }

    let m = node.metrics.snapshot();
    assert_eq!(m.reorgs_applied, 1, "exactly one reorg committed");
    assert_eq!(
        m.total_blocks_undone, 1,
        "one old-chain block (A1) was disconnected"
    );
    assert_eq!(m.blocks_orphaned, 1, "A1 was demoted to fork storage");
    assert_eq!(m.reorg_recoverable_errors, 0, "a clean reorg has no errors");
    assert_eq!(m.reorg_fatal_errors, 0, "a clean reorg has no errors");
}
