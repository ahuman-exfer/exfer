//! Integration tests for Phase 3a's [`open_chain`] (issue #6).
//!
//! Covers the three load-bearing boot paths that determine whether a node
//! starts cleanly, refuses to start, or transparently falls back to a full
//! replay:
//!
//!   1. Fast path on a populated snapshot — the happy case the PR exists to
//!      enable.
//!   2. Fallback when the snapshot marker is absent (typical pre-3a datadir
//!      first boot).
//!   3. Hard error when the snapshot marker is present and tip matches but
//!      `state_root` mismatches the tip header (the only condition that
//!      should refuse to start; everything else falls through).
//!
//! These tests are deliberately scoped to genesis-only chains because the
//! `open_chain` decision logic is shape-of-chain-independent — the loop
//! that walks blocks runs the same code regardless of chain length, and the
//! decision tree at the top (marker present? tip matches? state_root
//! matches?) is what we want to pin.

use std::sync::Arc;

use exfer::chain::open::open_chain;
use exfer::chain::state::UtxoSet;
use exfer::chain::storage::ChainStorage;
use exfer::genesis::genesis_block;
use exfer::types::hash::Hash256;
use exfer::types::transaction::{OutPoint, TxOutput};

use tempfile::TempDir;

fn fresh_storage(dir: &TempDir, name: &str) -> Arc<ChainStorage> {
    Arc::new(ChainStorage::open(&dir.path().join(name)).expect("open"))
}

#[test]
fn open_chain_fast_path_succeeds_on_populated_snapshot() {
    // 1. Open a fresh storage, run open_chain — empty DB → genesis bootstrap.
    let dir = TempDir::new().unwrap();
    let storage = fresh_storage(&dir, "test.redb");
    let genesis_id = genesis_block().header.block_id();
    let mut utxos = UtxoSet::new();
    let tip1 = open_chain(&storage, &mut utxos, &genesis_id, false, false)
        .expect("first open should bootstrap genesis");
    assert_eq!(tip1.block_id, genesis_id, "tip is genesis");
    let root1 = utxos.state_root();
    let utxo_count_1 = utxos.len();

    // 2. Finalize the snapshot so the marker is set for the next open.
    storage
        .finalize_utxo_snapshot(&utxos, &tip1.block_id)
        .expect("finalize snapshot");
    assert_eq!(
        storage.get_utxo_snapshot_tip().unwrap(),
        Some(tip1.block_id),
        "marker set to tip after finalize"
    );

    // 3. Drop the in-memory UtxoSet, re-open storage from disk, call
    //    open_chain again — must take the fast path and reconstruct an
    //    identical UtxoSet without re-running replay_chain.
    drop(storage);
    let storage2 = fresh_storage(&dir, "test.redb");
    let mut utxos2 = UtxoSet::new();
    let tip2 = open_chain(&storage2, &mut utxos2, &genesis_id, false, false)
        .expect("second open should take fast path");
    assert_eq!(tip2.block_id, tip1.block_id, "tip stable");
    assert_eq!(tip2.height, tip1.height, "height stable");
    assert_eq!(utxos2.len(), utxo_count_1, "utxo count round-trips");
    assert_eq!(
        utxos2.state_root(),
        root1,
        "state_root round-trips byte-identical (pins iter-order determinism)"
    );
}

#[test]
fn open_chain_falls_back_to_replay_when_marker_absent() {
    // Simulates a pre-Phase-3a (legacy) datadir: chain data is intact
    // but the snapshot markers don't exist. After the P1 fix, fresh
    // bootstraps seed the marker via `commit_genesis_atomic`, so we
    // explicitly clear the snapshot state to reach the legacy shape.
    let dir = TempDir::new().unwrap();
    let storage = fresh_storage(&dir, "test.redb");
    let genesis_id = genesis_block().header.block_id();
    let mut utxos = UtxoSet::new();
    let tip1 = open_chain(&storage, &mut utxos, &genesis_id, false, false).unwrap();
    let root1 = utxos.state_root();

    storage
        .clear_utxo_snapshot()
        .expect("simulate pre-3a datadir");
    assert!(
        storage.get_utxo_snapshot_tip().unwrap().is_none(),
        "marker cleared — simulating legacy datadir"
    );

    // Re-open: marker absent → open_chain logs "falling through" and
    // delegates to replay_chain via run_replay_and_maybe_migrate. With
    // auto_migrate=false the snapshot stays unmarked after replay,
    // matching the `--no-auto-migrate` operator preference.
    drop(storage);
    let storage2 = fresh_storage(&dir, "test.redb");
    let mut utxos2 = UtxoSet::new();
    let tip2 = open_chain(&storage2, &mut utxos2, &genesis_id, false, false)
        .expect("fallback to replay must succeed");
    assert_eq!(tip2.block_id, tip1.block_id);
    assert_eq!(utxos2.state_root(), root1, "replay-derived state_root matches");
    assert!(
        storage2.get_utxo_snapshot_tip().unwrap().is_none(),
        "auto_migrate=false leaves marker absent"
    );
}

#[test]
fn open_chain_auto_migrate_backfills_snapshot_on_fallback() {
    // Verifies the lazy-migration UX for a legacy pre-Phase-3a datadir:
    // chain data is intact but the snapshot markers don't exist. With
    // `auto_migrate=true`, the first open should fall through to replay
    // and finalize a fresh snapshot, so the second open hits the fast
    // path.
    let dir = TempDir::new().unwrap();
    let storage = fresh_storage(&dir, "test.redb");
    let genesis_id = genesis_block().header.block_id();
    let mut utxos = UtxoSet::new();
    let _tip = open_chain(&storage, &mut utxos, &genesis_id, false, true)
        .expect("first open bootstraps genesis");

    // Pretend this is a pre-Phase-3a datadir by clearing the snapshot
    // state (after the P1 fix, commit_genesis_atomic seeds the marker
    // automatically, which is the Phase-3a steady-state behavior).
    storage
        .clear_utxo_snapshot()
        .expect("simulate pre-3a datadir");
    assert!(
        storage.get_utxo_snapshot_tip().unwrap().is_none(),
        "marker cleared — legacy-datadir shape"
    );

    // Second open WITH auto_migrate: marker absent → fallback to replay
    // → finalize_utxo_snapshot writes the marker.
    drop(storage);
    let storage2 = fresh_storage(&dir, "test.redb");
    let mut utxos2 = UtxoSet::new();
    let _ = open_chain(&storage2, &mut utxos2, &genesis_id, false, true)
        .expect("second open with auto_migrate fallback");
    assert_eq!(
        storage2.get_utxo_snapshot_tip().unwrap(),
        Some(genesis_id),
        "auto_migrate finalized the snapshot during fallback"
    );

    // Third open should now hit the fast path (marker present, tip match).
    drop(storage2);
    let storage3 = fresh_storage(&dir, "test.redb");
    let mut utxos3 = UtxoSet::new();
    let _ = open_chain(&storage3, &mut utxos3, &genesis_id, false, true)
        .expect("third open is fast path");
    // Sanity: the in-memory UtxoSet must agree with the genesis state_root.
    let expected_root = {
        let mut set = UtxoSet::new();
        for tx in &genesis_block().transactions {
            set.apply_transaction(tx, 0).unwrap();
        }
        set.state_root()
    };
    assert_eq!(utxos3.state_root(), expected_root);
}

#[test]
fn rebuild_state_recovery_loop_clears_and_finalizes_in_one_boot() {
    // Mirrors the `--rebuild-state` CLI flow that the operator runs after
    // hitting the "snapshot is corrupt" error in `open_chain`:
    //
    //   storage.clear_utxo_snapshot()  ←  what --rebuild-state does first
    //   open_chain(..., auto_migrate=true)  ←  forces fallback → finalize
    //
    // The chain data is untouched; only the derived snapshot is rebuilt.
    let dir = TempDir::new().unwrap();
    let storage = fresh_storage(&dir, "test.redb");
    let genesis_id = genesis_block().header.block_id();
    let mut utxos = UtxoSet::new();
    let _ = open_chain(&storage, &mut utxos, &genesis_id, false, true).unwrap();
    let expected_root = utxos.state_root();

    // Operator's recovery step: clear the snapshot in place.
    storage
        .clear_utxo_snapshot()
        .expect("clear_utxo_snapshot should not touch chain data");
    assert!(storage.get_utxo_snapshot_tip().unwrap().is_none());

    // Reopen with auto_migrate=true (which --rebuild-state forces).
    // open_chain falls through to replay and finalize re-seeds the marker.
    drop(storage);
    let storage2 = fresh_storage(&dir, "test.redb");
    let mut utxos2 = UtxoSet::new();
    let _ = open_chain(&storage2, &mut utxos2, &genesis_id, false, true)
        .expect("rebuild recovery via fallback+finalize");
    assert_eq!(
        storage2.get_utxo_snapshot_tip().unwrap(),
        Some(genesis_id),
        "fresh snapshot finalized in the same boot"
    );
    assert_eq!(
        utxos2.state_root(),
        expected_root,
        "rebuilt UtxoSet matches the canonical state_root"
    );
}

#[test]
fn open_chain_rejects_when_marker_matches_but_state_root_mismatches() {
    // 1. Bootstrap genesis as usual.
    let dir = TempDir::new().unwrap();
    let storage = fresh_storage(&dir, "test.redb");
    let genesis_id = genesis_block().header.block_id();
    let mut utxos = UtxoSet::new();
    let tip = open_chain(&storage, &mut utxos, &genesis_id, false, false).unwrap();
    assert_eq!(tip.block_id, genesis_id);

    // 2. Inject an extra (non-canonical) UTXO into the in-memory set BEFORE
    //    finalizing. The on-disk snapshot will be a superset of the
    //    canonical state — its computed state_root will not match the
    //    genesis header's state_root.
    let fake_op = OutPoint::new(Hash256([0xab; 32]), 7);
    let fake_entry = exfer::chain::state::UtxoEntry {
        output: TxOutput::new_p2pkh(123_456, &[0xcd; 32]),
        height: 99_999,
        is_coinbase: false,
    };
    utxos.insert(fake_op, fake_entry).unwrap();
    storage
        .finalize_utxo_snapshot(&utxos, &tip.block_id)
        .expect("finalize accepts whatever UtxoSet we give it");

    // 3. Re-open: marker present, tip matches, but state_root mismatches.
    //    Must return Err pointing the operator at --rebuild-state. This is
    //    the only condition that should HARD FAIL — all other "snapshot is
    //    not trustworthy" cases fall through to replay.
    drop(storage);
    let storage2 = fresh_storage(&dir, "test.redb");
    let mut utxos2 = UtxoSet::new();
    let err = open_chain(&storage2, &mut utxos2, &genesis_id, false, false)
        .expect_err("must fail on state_root mismatch");
    assert!(
        err.contains("state_root"),
        "error message must mention state_root: {}",
        err
    );
    assert!(
        err.contains("--rebuild-state"),
        "error message must point at --rebuild-state recovery: {}",
        err
    );
}
