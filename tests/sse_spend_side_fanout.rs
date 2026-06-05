//! Regression test for the PR #25 spend-side SSE fanout fix.
//!
//! The block-commit fanout must nudge a subscriber watching a script whose
//! coins are SPENT (or whose output is removed by a reorg), not just one whose
//! coins are received. The originally-shipped code emitted output scripts only
//! and leaned on the (now opt-in) TipChanged for the spend side, so a confirmed
//! tx that never transited this node's mempool left a watched balance stale.
//!
//! No existing test drives `process_block` -> EventBus; the mempool-admit path
//! is explicitly NOT the bug. These two tests stand up a real Node and assert a
//! `ScriptChanged` reaches a subscriber for:
//!   1. a block-only spend of a watched UTXO (single-block-append spend side);
//!   2. a reorg that disconnects a block whose coinbase paid the watched script
//!      (old-chain removed-output side; coinbase is never reintroduced to the
//!      mempool, so the emit can only come from the disconnect fanout).

#![cfg(feature = "testnet")]

use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::{Mutex, RwLock};

use ed25519_dalek::{Signer, SigningKey};

use exfer::chain::fork_choice::ChainTip;
use exfer::chain::state::{UtxoEntry, UtxoSet};
use exfer::chain::storage::ChainStorage;
use exfer::consensus::difficulty::{genesis_target, work_from_target};
use exfer::consensus::reward::block_reward;
use exfer::consensus::validation::compute_tx_root;
use exfer::events::{ChainEvent, EventBus};
use exfer::genesis::genesis_block;
use exfer::mempool::Mempool;
use exfer::network::sync::{Node, ProcessBlockOutcome};
use exfer::types::block::{Block, BlockHeader};
use exfer::types::hash::Hash256;
use exfer::types::transaction::{OutPoint, Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::TARGET_BLOCK_TIME_SECS;

/// Build a Node wired to the given storage / utxo set / tip / bus. Mirrors the
/// production constructor's field set (kept in sync with `Node`).
fn make_node(
    storage: Arc<ChainStorage>,
    utxo_set: UtxoSet,
    tip: ChainTip,
    gid: Hash256,
    bus: Arc<EventBus>,
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
        event_bus: bus,
        devnet: false,
        ever_confirmed_peer: std::sync::atomic::AtomicBool::new(false),
        frame_budget: exfer::network::frame_budget::FrameBudget::new(),
        tip_validation_coord: Arc::new(exfer::network::tip_validation::TipValidationCoordinator::new()),
        assume_valid_cumulative_work_trusted: std::sync::atomic::AtomicBool::new(true),
        stage_a_authenticated_headers: tokio::sync::RwLock::new(None),
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

/// A signed P2PKH spend of `prev` (value `prev_value`, locked to `sk`'s key),
/// paying `prev_value - fee` to `recipient`; the `fee` is left for the block's
/// coinbase to claim (block tx validation enforces a minimum fee). Never
/// inserted into any mempool — this is a block-only tx.
fn signed_spend(
    prev: OutPoint,
    prev_value: u64,
    fee: u64,
    sk: &SigningKey,
    recipient: &[u8; 32],
) -> Transaction {
    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: prev.tx_id,
            output_index: prev.output_index,
        }],
        outputs: vec![TxOutput::new_p2pkh(prev_value - fee, recipient)],
        witnesses: vec![TxWitness {
            witness: vec![0u8; 96],
            redeemer: None,
        }],
    };
    let sig_msg = tx.sig_message().unwrap();
    let sig = sk.sign(&sig_msg);
    let mut witness = Vec::with_capacity(96);
    witness.extend_from_slice(&sk.verifying_key().to_bytes());
    witness.extend_from_slice(&sig.to_bytes());
    tx.witnesses[0].witness = witness;
    tx
}

/// Assemble a block, computing its tx_root and the post-apply state_root by
/// replaying the txs (coinbase first) onto a clone of `base_utxo`. Difficulty
/// is the trivial testnet genesis target, so nonce 0 satisfies PoW.
fn build_block(prev: &BlockHeader, height: u64, txs: Vec<Transaction>, base_utxo: &UtxoSet) -> Block {
    let mut post = base_utxo.clone();
    for tx in &txs {
        post.apply_transaction(tx, height).expect("apply for state_root");
    }
    Block {
        header: BlockHeader {
            version: 1,
            height,
            prev_block_id: prev.block_id(),
            timestamp: prev.timestamp + TARGET_BLOCK_TIME_SECS,
            difficulty_target: genesis_target(),
            nonce: 0,
            tx_root: compute_tx_root(&txs).expect("tx_root"),
            state_root: post.state_root(),
        },
        transactions: txs,
    }
}

/// Drain every event currently queued for a subscriber and report whether any
/// was a `ScriptChanged` for `script`.
fn drained_has_script(rx: &mut tokio::sync::mpsc::Receiver<ChainEvent>, script: &[u8]) -> bool {
    let mut hit = false;
    while let Ok(ev) = rx.try_recv() {
        if let ChainEvent::ScriptChanged(s) = ev {
            if s == script {
                hit = true;
            }
        }
    }
    hit
}

/// Genesis + a synthetic non-coinbase UTXO locked to `watched`, persisted so a
/// Node can be built on top. Returns (storage, in-memory utxo_set, tip, gid).
fn genesis_with_watched_utxo(
    db: &TempDir,
    watched_pubkey: &[u8; 32],
    watched_outpoint: OutPoint,
    watched_value: u64,
) -> (Arc<ChainStorage>, UtxoSet, ChainTip, Hash256) {
    let storage = Arc::new(ChainStorage::open(&db.path().join("test.redb")).unwrap());
    let genesis = genesis_block();
    let gid = genesis.header.block_id();
    storage.put_block(&genesis).unwrap();

    let mut utxo_set = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_set.apply_transaction(tx, 0).unwrap();
    }
    utxo_set
        .insert(
            watched_outpoint,
            UtxoEntry {
                output: TxOutput::new_p2pkh(watched_value, watched_pubkey),
                height: 0,
                is_coinbase: false,
            },
        )
        .expect("insert watched UTXO");

    storage
        .put_cumulative_work(&gid, &work_from_target(&genesis.header.difficulty_target))
        .unwrap();
    let tip = ChainTip::genesis(gid, &genesis.header.difficulty_target);
    (storage, utxo_set, tip, gid)
}

#[tokio::test]
async fn block_only_spend_emits_script_changed_for_spender() {
    let db = TempDir::new().unwrap();
    let genesis = genesis_block();

    // A coin locked to the watched key, spendable at height 1.
    let watched_sk = SigningKey::from_bytes(&[7u8; 32]);
    let watched_pk = watched_sk.verifying_key().to_bytes();
    let watched_script = TxOutput::new_p2pkh(0, &watched_pk).script;
    let watched_op = OutPoint::new(Hash256::sha256(b"watched-coin"), 0);
    let watched_value = 5_000_000_000u64;

    let (storage, utxo_set, tip, gid) =
        genesis_with_watched_utxo(&db, &watched_pk, watched_op, watched_value);

    let bus = EventBus::new();
    // Subscribe BEFORE the block so the nudge can't be missed.
    let (_sid, mut rx) = bus.subscribe(&[watched_script.clone()], false);

    let node = make_node(storage, utxo_set.clone(), tip, gid, bus);

    // Block 1: coinbase (pays a stranger) + a block-only spend of the watched
    // coin to a different stranger. The watched script is NOT paid back to, so
    // a receive-only fanout would never mention it.
    let fee = 100_000u64;
    let spend = signed_spend(watched_op, watched_value, fee, &watched_sk, &[0x33u8; 32]);
    let cb = coinbase(1, block_reward(1) + fee, &[0x99u8; 32]);
    let block = build_block(&genesis.header, 1, vec![cb, spend], &utxo_set);

    let outcome = node.process_block(block, None).await.expect("block accepted");
    assert!(matches!(outcome, ProcessBlockOutcome::Accepted));

    assert!(
        drained_has_script(&mut rx, &watched_script),
        "spending a watched UTXO in a block-only tx must emit script_changed for the spent script"
    );
}

#[tokio::test]
async fn reorg_disconnect_emits_script_changed_for_removed_output() {
    let db = TempDir::new().unwrap();
    let genesis = genesis_block();

    let watched_sk = SigningKey::from_bytes(&[9u8; 32]);
    let watched_pk = watched_sk.verifying_key().to_bytes();
    let watched_script = TxOutput::new_p2pkh(0, &watched_pk).script;

    // No pre-seeded watched UTXO here; the watched coin is created by A1's
    // coinbase and destroyed when A1 is reorged out.
    let storage = Arc::new(ChainStorage::open(&db.path().join("test.redb")).unwrap());
    let gid = genesis.header.block_id();
    storage.put_block(&genesis).unwrap();
    let mut utxo_set = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_set.apply_transaction(tx, 0).unwrap();
    }
    storage
        .put_cumulative_work(&gid, &work_from_target(&genesis.header.difficulty_target))
        .unwrap();
    let tip = ChainTip::genesis(gid, &genesis.header.difficulty_target);

    let bus = EventBus::new();
    let (_sid, mut rx) = bus.subscribe(&[watched_script.clone()], false);
    let node = make_node(storage, utxo_set.clone(), tip, gid, bus);

    // Chain A: single block whose coinbase pays the watched script.
    let a1 = build_block(
        &genesis.header,
        1,
        vec![coinbase(1, block_reward(1), &watched_pk)],
        &utxo_set,
    );
    assert!(matches!(
        node.process_block(a1, None).await.expect("a1"),
        ProcessBlockOutcome::Accepted
    ));
    // The connect emitted watched (coinbase output). Clear it so we only see
    // the reorg-disconnect emit below.
    let _ = drained_has_script(&mut rx, &watched_script);

    // Chain B: B1 forks genesis (coinbase to a stranger), B2 extends B1 so
    // B outweighs A and triggers a reorg that disconnects A1.
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
        node.process_block(b1, None).await.expect("b1"),
        ProcessBlockOutcome::Stored
    ));

    let b2 = build_block(
        &b1_header,
        2,
        vec![coinbase(2, block_reward(2), &[0xB2u8; 32])],
        &after_b1,
    );
    assert!(matches!(
        node.process_block(b2, None).await.expect("b2"),
        ProcessBlockOutcome::Accepted
    ));

    // A1's coinbase output (paying the watched script) is gone after the
    // disconnect. A coinbase is never reintroduced to the mempool, so the only
    // possible nudge is the old-chain removed-output fanout under test.
    assert!(
        drained_has_script(&mut rx, &watched_script),
        "reorg disconnecting a block whose coinbase paid the watched script must emit script_changed"
    );
}
