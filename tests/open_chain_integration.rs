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
    let tip1 = open_chain(&storage, &mut utxos, &genesis_id, false, false, true)
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
    let tip2 = open_chain(&storage2, &mut utxos2, &genesis_id, false, false, true)
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
    let tip1 = open_chain(&storage, &mut utxos, &genesis_id, false, false, true).unwrap();
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
    let tip2 = open_chain(&storage2, &mut utxos2, &genesis_id, false, false, true)
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
    let _tip = open_chain(&storage, &mut utxos, &genesis_id, false, true, true)
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
    let _ = open_chain(&storage2, &mut utxos2, &genesis_id, false, true, true)
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
    let _ = open_chain(&storage3, &mut utxos3, &genesis_id, false, true, true)
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
fn no_auto_migrate_replays_on_every_restart() {
    // Reviewer follow-up to P1: a legacy pre-Phase-3a datadir running
    // with `--no-auto-migrate` must fall back to replay on EVERY
    // restart, never the corruption error path. The pre-follow-up code
    // let the first `commit_block_atomic` after a fallback stamp the
    // partial UTXOS_TABLE state as complete, which trapped the next
    // reopen on the state_root mismatch. The fix splits the marker
    // helpers: `advance_snapshot_marker_in_txn` is a no-op while
    // `UTXO_SNAPSHOT_COMPLETE_KEY` is absent, so the markers stay
    // absent across any number of block commits and `open_chain`'s
    // marker check always selects the fallback branch.
    let dir = TempDir::new().unwrap();
    let storage = fresh_storage(&dir, "test.redb");
    let genesis_id = genesis_block().header.block_id();
    let mut utxos = UtxoSet::new();
    let _ = open_chain(&storage, &mut utxos, &genesis_id, false, true, true).unwrap();
    let canonical_root = utxos.state_root();

    // Pretend this is a pre-Phase-3a datadir.
    storage
        .clear_utxo_snapshot()
        .expect("simulate pre-3a datadir");

    // Three back-to-back restarts with --no-auto-migrate. Each must
    // fall back, never hit the fast path, never raise corruption.
    drop(storage);
    for restart in 1..=3 {
        let s = fresh_storage(&dir, "test.redb");
        let mut u = UtxoSet::new();
        let tip = open_chain(&s, &mut u, &genesis_id, false, false, true)
            .unwrap_or_else(|e| panic!("restart {restart}: open_chain must not error: {e}"));
        assert_eq!(tip.block_id, genesis_id, "restart {restart}: tip stable");
        assert_eq!(
            u.state_root(),
            canonical_root,
            "restart {restart}: replay-derived state_root matches canonical"
        );
        assert!(
            s.get_utxo_snapshot_tip().unwrap().is_none(),
            "restart {restart}: --no-auto-migrate leaves the markers absent"
        );
    }
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
    let _ = open_chain(&storage, &mut utxos, &genesis_id, false, true, true).unwrap();
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
    let _ = open_chain(&storage2, &mut utxos2, &genesis_id, false, true, true)
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
    let tip = open_chain(&storage, &mut utxos, &genesis_id, false, false, true).unwrap();
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
    let err = open_chain(&storage2, &mut utxos2, &genesis_id, false, false, true)
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

#[test]
fn open_chain_walk_checkpoint_skip_and_full_verify_parity() {
    // Track 1 (issue #6): once the walk marker equals the tip, open_chain
    // skips the structural walk and reads cumulative work O(1) from
    // WORK_TABLE. --full-verify (trust_walk_marker=false) forces the full
    // walk but must derive the identical result and re-stamp the marker so
    // the next boot is fast again.
    let dir = TempDir::new().unwrap();
    let storage = fresh_storage(&dir, "test.redb");
    let genesis_id = genesis_block().header.block_id();

    // First boot: empty DB → genesis bootstrap. commit_genesis_atomic stamps
    // the walk marker as a side effect.
    let mut utxos = UtxoSet::new();
    let tip1 = open_chain(&storage, &mut utxos, &genesis_id, false, true, true)
        .expect("genesis bootstrap");
    assert_eq!(
        storage.get_walk_verified_tip().unwrap(),
        Some(tip1.block_id),
        "genesis boot stamps the walk-verified marker"
    );

    // Second boot, trust_walk_marker=true → fast skip path. Cumulative work
    // must match the bootstrap value (read from WORK_TABLE, not re-walked).
    drop(storage);
    let storage2 = fresh_storage(&dir, "test.redb");
    let mut u2 = UtxoSet::new();
    let tip2 = open_chain(&storage2, &mut u2, &genesis_id, false, true, true)
        .expect("fast skip path");
    assert_eq!(tip2.block_id, tip1.block_id, "tip stable on skip path");
    assert_eq!(
        tip2.cumulative_work, tip1.cumulative_work,
        "skip path reads cumulative work from WORK_TABLE — parity with the walk"
    );
    assert_eq!(
        storage2.get_walk_verified_tip().unwrap(),
        Some(tip1.block_id),
        "skip path leaves the marker current"
    );

    // Third boot, trust_walk_marker=false (--full-verify) → forces the full
    // walk, derives the same result, and re-stamps the marker.
    drop(storage2);
    let storage3 = fresh_storage(&dir, "test.redb");
    let mut u3 = UtxoSet::new();
    let tip3 = open_chain(&storage3, &mut u3, &genesis_id, false, true, false)
        .expect("--full-verify forced walk");
    assert_eq!(tip3.block_id, tip1.block_id);
    assert_eq!(
        tip3.cumulative_work, tip1.cumulative_work,
        "--full-verify walk derives the same cumulative work as the skip path"
    );
    assert_eq!(
        storage3.get_walk_verified_tip().unwrap(),
        Some(tip1.block_id),
        "--full-verify re-stamps the marker so the next boot is fast again"
    );
}

// ---------------------------------------------------------------------------
// Issue #29: devnet is a separate chain (distinct genesis), so a devnet
// datadir cannot be reopened as a networked node and vice versa. open_chain
// must refuse the cross-open at the height-0 genesis-id check — on the FAST
// (snapshot) path too, which is where #29's per-tx-validation gap lived.
// ---------------------------------------------------------------------------

/// Seed `storage` with `genesis` as a committed, snapshot-finalized chain —
/// the shape a real datadir has after one boot. Forces the next open_chain
/// onto the fast path.
fn seed_genesis_datadir(storage: &Arc<ChainStorage>, genesis: &exfer::types::block::Block) {
    let mut u = UtxoSet::new();
    let muts = u
        .apply_transaction(&genesis.transactions[0], 0)
        .expect("apply genesis coinbase");
    storage
        .commit_genesis_atomic(genesis, &[0u8; 32], &muts)
        .expect("commit genesis");
    storage
        .finalize_utxo_snapshot(&u, &genesis.header.block_id())
        .expect("finalize snapshot (forces fast path on next open)");
}

#[test]
#[cfg(feature = "testnet")] // devnet genesis nonce=0 is PoW-valid only at trivial difficulty
fn devnet_datadir_refuses_to_open_as_networked_node() {
    let dir = TempDir::new().unwrap();
    let storage = fresh_storage(&dir, "devnet.redb");
    // What `exfer devnet` creates: a chain rooted at the devnet genesis.
    seed_genesis_datadir(&storage, &exfer::genesis::devnet_genesis_block());

    // What `exfer node` does: open with the CANONICAL genesis id. Must refuse
    // (fast path, since the snapshot is finalized) rather than load a chain
    // whose history was produced under devnet's 1-block coinbase maturity.
    let canonical_id = genesis_block().header.block_id();
    let mut u = UtxoSet::new();
    let res = open_chain(&storage, &mut u, &canonical_id, false, true, true);
    assert!(
        res.is_err(),
        "a devnet datadir must NOT open under the canonical genesis (issue #29)"
    );
}

#[test]
#[cfg(feature = "testnet")]
fn canonical_datadir_refuses_to_open_as_devnet() {
    let dir = TempDir::new().unwrap();
    let storage = fresh_storage(&dir, "main.redb");
    seed_genesis_datadir(&storage, &genesis_block());

    let devnet_id = exfer::genesis::devnet_genesis_block().header.block_id();
    let mut u = UtxoSet::new();
    let res = open_chain(&storage, &mut u, &devnet_id, false, true, true);
    assert!(
        res.is_err(),
        "a canonical datadir must NOT open under the devnet genesis"
    );
}
