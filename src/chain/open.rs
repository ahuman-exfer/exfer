//! Phase 3a (issue #6) boot paths.
//!
//! `open_chain` is the new default: try a fast read of the persisted UTXO
//! snapshot + cheap structural per-block walk; fall through to `replay_chain`
//! on any reason the snapshot isn't trustworthy.
//!
//! `replay_chain` is preserved unchanged from pre-3a as:
//!   - The fallback when the snapshot marker is missing / stale / mismatched.
//!   - The backbone of lazy migration (commit 6's `run_replay_and_maybe_migrate`).
//!   - The recovery mechanism for `--rebuild-state`.
//!
//! Lives in the library (not in `src/main.rs` as before) so integration tests
//! in `tests/` and the diagnostic bench in `src/bin/bench_phase3a.rs` can
//! exercise the same code path the production node runs.

use std::sync::Arc;

use tracing::info;

use crate::chain::fork_choice::ChainTip;
use crate::chain::state::{UtxoMutation, UtxoSet};
use crate::chain::storage::ChainStorage;
use crate::consensus::difficulty::{add_work, expected_difficulty, work_from_target};
use crate::consensus::validation::{
    apply_block_transactions_assume_valid, validate_and_apply_block_transactions_atomic,
    validate_block_header, validate_block_header_skip_pow,
};
use crate::genesis::genesis_block;
use crate::types::hash::Hash256;
use crate::types::{ASSUME_VALID_HASH, ASSUME_VALID_HEIGHT, MTP_WINDOW};

/// Phase 3a (issue #6) — fast boot path: cheap structural per-block walk
/// over canonical metadata + bulk-load of the persisted UTXO snapshot +
/// state-root cross-check. Falls through to [`replay_chain`] when the
/// snapshot is missing, stale, or fails the cross-check, so this function
/// is safe to make the default boot path.
///
/// What is preserved from `replay_chain`'s integrity checks:
///   - Tip metadata presence + consistency with height-index / blocks table
///   - Genesis hash match at h=0
///   - Per-height: height-index → block resolution, parent linkage, full
///     `validate_block_header_skip_pow` (covers version, height seq,
///     prev-id, difficulty target, MTP, timestamp gap, block size,
///     coinbase structure, tx-root, intra-block duplicate/double-spend).
///   - Final tip/walk consistency.
///
/// What is dropped (replaced by the state_root cross-check + persisted
/// UTXO snapshot):
///   - Per-tx signature / script validation
///   - UTXO state mutation during the walk
/// Track 1 (issue #6) — `trust_walk_marker` controls the structural walk:
/// when `true` (default), a `WALK_VERIFIED_TIP` marker equal to the current
/// tip lets the walk be skipped entirely (cumulative work read O(1) from
/// `WORK_TABLE`); a stale marker shrinks it to the unverified suffix. When
/// `false` (`--full-verify`), the marker is ignored and the full genesis→tip
/// walk runs, then the marker is re-stamped so subsequent boots are fast again.
pub fn open_chain(
    storage: &Arc<ChainStorage>,
    utxo_set: &mut UtxoSet,
    expected_genesis_id: &Hash256,
    assume_valid: bool,
    auto_migrate: bool,
    trust_walk_marker: bool,
) -> Result<ChainTip, String> {
    // Bootstrap-from-empty / tip-missing remains entirely handled by
    // replay_chain (genesis seeding lives in the caller path before us
    // anyway; this branch covers any leftover edge case).
    let tip_id = match storage
        .get_tip()
        .map_err(|e| format!("db error reading tip: {}", e))?
    {
        Some(id) => id,
        None => {
            return replay_chain(storage, utxo_set, expected_genesis_id, assume_valid);
        }
    };

    // Genesis-identity guard (issue #29). The stored chain's genesis MUST match
    // the genesis this node expects — on EVERY path, including the fast path
    // below, which (with a current walk marker) sets an empty walk range and so
    // never reaches the in-walk height-0 check. Without this guard a datadir
    // built under a different genesis — e.g. an `exfer devnet` chain (distinct
    // genesis, 1-block coinbase maturity) — would load into a networked node via
    // the fast path, which trusts the snapshot state_root and never re-validates
    // per-tx rules. One O(1) height-index lookup.
    //
    // Scope: this catches every NEW devnet datadir (distinct genesis) and any
    // cross-BUILD open (a testnet build's genesis differs from mainnet's, since
    // the difficulty target is part of block_id). It does NOT catch a PRE-fix
    // devnet datadir: shipped PR #27 devnet had no distinct genesis, so it
    // stored the canonical id at height 0, matches `expected_genesis_id` on a
    // same-build node, and loads its age-1 coinbase history via the fast path
    // (which never re-checks maturity). The network is NOT protected by this
    // guard for that case — the genesis handshake also passes a canonical-genesis
    // datadir — it is protected by peer-side re-validation: inbound blocks go
    // through validate_and_apply_block_transactions_atomic at
    // coinbase_maturity()=360 (sync.rs), so honest peers reject the age-1 spends
    // and the trivial-PoW tip loses fork choice. The residual is LOCAL: such a
    // datadir's own RPC reports age-1 coinbase as spendable. So wipe any pre-fix
    // devnet datadir; never reopen a devnet datadir as a networked node.
    // Out of scope by design: forcing a per-tx replay on every unmarked canonical
    // datadir would re-trigger the v1.10.2 mass-replay wedge for all legit
    // mainnet users, so it is not done here.
    match storage
        .get_block_id_by_height(0)
        .map_err(|e| format!("db error reading stored genesis id: {}", e))?
    {
        Some(stored) if stored == *expected_genesis_id => {}
        Some(stored) => {
            return Err(format!(
                "genesis mismatch: datadir genesis is {} but this node expects {} — \
                 refusing to load a chain from a different network (e.g. an `exfer devnet` \
                 datadir opened as a networked node)",
                stored, expected_genesis_id
            ));
        }
        None => {
            // Tip exists but no height-0 entry — corrupt index; let replay surface it.
            return run_replay_and_maybe_migrate(
                storage,
                utxo_set,
                expected_genesis_id,
                assume_valid,
                auto_migrate,
            );
        }
    }

    // Snapshot marker must (a) exist + complete and (b) point at the
    // current tip. Anything else → fall through to full replay, and
    // (when auto_migrate is on) backfill the snapshot atomically at the
    // end so the next boot takes the fast path.
    let snapshot_tip = storage
        .get_utxo_snapshot_tip()
        .map_err(|e| format!("db error reading utxo snapshot marker: {}", e))?;
    match snapshot_tip {
        Some(id) if id == tip_id => {}
        Some(stale) => {
            info!(
                "UTXO snapshot stale (snapshot_tip={} current_tip={}); falling through to full replay",
                stale, tip_id
            );
            return run_replay_and_maybe_migrate(
                storage,
                utxo_set,
                expected_genesis_id,
                assume_valid,
                auto_migrate,
            );
        }
        None => {
            info!("UTXO snapshot missing or incomplete; falling through to full replay");
            return run_replay_and_maybe_migrate(
                storage,
                utxo_set,
                expected_genesis_id,
                assume_valid,
                auto_migrate,
            );
        }
    }

    let tip_header = storage
        .get_header(&tip_id)
        .map_err(|e| format!("db error reading tip header: {}", e))?
        .ok_or_else(|| format!("tip block header {} not found", tip_id))?;
    let tip_height = tip_header.height;

    // Assume-valid: same policy as replay_chain — skip PoW iff the
    // checkpoint block is in storage at the expected hash.
    let assume_valid_proven = assume_valid
        && tip_height >= ASSUME_VALID_HEIGHT
        && storage
            .get_block_id_by_height(ASSUME_VALID_HEIGHT)
            .ok()
            .flatten()
            .map(|id| id == Hash256(ASSUME_VALID_HASH))
            .unwrap_or(false);

    // -------- Track 1: decide how much structural walk is needed --------
    //
    // TRUST-MODEL NOTE: skipping the walk relaxes corruption detection. The
    // walk re-checks header linkage, full-block structure (body present,
    // tx_root, intra-block double-spend, coinbase shape) and re-derives
    // cumulative work over already-canonical, already-validated blocks. With
    // the marker present, those checks are elided on boot, so corruption in
    // *old* canonical blocks becomes a latent runtime failure (surfaced when
    // that block is next read — e.g. a reorg back through it) instead of a
    // boot-time abort. This is acceptable for routine operation (old canonical
    // blocks are immutable and were validated when first received); the marker
    // is advanced atomically with the tip by every commit, and `--full-verify`
    // forces a one-shot full walk for operators who want defense-in-depth. The
    // persisted-UTXO `state_root` cross-check below is unaffected either way.
    let walk_marker = if trust_walk_marker {
        storage
            .get_walk_verified_tip()
            .map_err(|e| format!("db error reading walk-verified marker: {}", e))?
    } else {
        None // --full-verify: ignore the marker, force a full walk, re-stamp at end.
    };

    let mut prev_id = Hash256::ZERO;
    let mut cumulative_work = [0u8; 32];
    // Half-open lower bound of the walk: 0 = full walk, tip_height+1 = skip.
    let mut walk_from: u64 = 0;

    match walk_marker {
        Some(id) if id == tip_id => {
            // Fast path: the walk was already proven through the current tip.
            // Read cumulative work directly from WORK_TABLE (O(1)); fall back
            // to a full walk if it is somehow absent (defensive — every commit
            // persists it).
            match storage
                .get_cumulative_work(&tip_id)
                .map_err(|e| format!("db error reading cumulative work for tip: {}", e))?
            {
                Some(work) => {
                    cumulative_work = work;
                    prev_id = tip_id;
                    walk_from = tip_height + 1; // empty walk range
                    info!(
                        "Boot: walk checkpoint current (tip={} height={}); skipping structural walk",
                        tip_id, tip_height
                    );
                }
                None => {
                    info!(
                        "Boot: walk marker present but cumulative work missing for tip {}; \
                         running full structural walk",
                        tip_id
                    );
                }
            }
        }
        Some(ancestor) => {
            // Stale marker: walk only the suffix [marker_height+1 ..= tip].
            let marker_header = storage
                .get_header(&ancestor)
                .map_err(|e| format!("db error reading walk-marker header: {}", e))?;
            let marker_work = storage
                .get_cumulative_work(&ancestor)
                .map_err(|e| format!("db error reading walk-marker cumulative work: {}", e))?;
            match (marker_header, marker_work) {
                (Some(h), Some(work)) if h.height <= tip_height => {
                    prev_id = ancestor;
                    cumulative_work = work;
                    walk_from = h.height + 1;
                    info!(
                        "Boot: walk checkpoint stale (marker={} height={} current_tip={} height={}); \
                         walking suffix {}..={}",
                        ancestor, h.height, tip_id, tip_height, walk_from, tip_height
                    );
                }
                _ => {
                    info!(
                        "Boot: walk marker {} unusable (header/work missing or beyond tip); \
                         running full structural walk",
                        ancestor
                    );
                }
            }
        }
        None => {
            if trust_walk_marker {
                info!("Boot: no walk checkpoint; running full structural walk (will stamp marker)");
            } else {
                info!("Boot: --full-verify — running full structural walk regardless of marker");
            }
        }
    }
    let did_walk = walk_from <= tip_height;

    // -------- Cheap structural per-block walk (over [walk_from ..= tip]) --------
    for height in walk_from..=tip_height {
        let block_id = storage
            .get_block_id_by_height(height)
            .map_err(|e| format!("db error at height {}: {}", height, e))?
            .ok_or_else(|| {
                format!(
                    "height index missing entry at height {} during open_chain walk",
                    height
                )
            })?;
        if height == 0 && block_id != *expected_genesis_id {
            return Err(format!(
                "height 0 block {} does not match expected genesis {}; database belongs to a different chain",
                block_id, expected_genesis_id
            ));
        }
        let block = storage
            .get_block(&block_id)
            .map_err(|e| format!("db error reading block at height {}: {}", height, e))?
            .ok_or_else(|| {
                format!(
                    "canonical block {} at height {} missing during open_chain walk",
                    block_id, height
                )
            })?;
        if block.header.prev_block_id != prev_id {
            return Err(format!(
                "chain linkage broken at height {}: block prev_block_id {} != expected {}",
                height, block.header.prev_block_id, prev_id
            ));
        }
        if height > 0 {
            let parent_header = storage
                .get_header(&block.header.prev_block_id)
                .map_err(|e| format!("db error reading parent header at height {}: {}", height, e))?
                .ok_or_else(|| format!("parent header not found at height {}", height))?;
            let ancestors = storage
                .get_ancestor_timestamps(&block.header.prev_block_id, MTP_WINDOW)
                .map_err(|e| {
                    format!(
                        "db error reading ancestor timestamps at height {}: {}",
                        height, e
                    )
                })?;
            let target =
                expected_difficulty(storage, &block.header.prev_block_id, block.header.height)
                    .map_err(|e| format!("difficulty computation failed at height {}: {}", height, e))?;
            let skip_pow = assume_valid_proven && height <= ASSUME_VALID_HEIGHT;
            let result = if skip_pow {
                validate_block_header_skip_pow(
                    &block,
                    Some(&parent_header),
                    &ancestors,
                    &target,
                    None,
                )
            } else {
                validate_block_header(
                    &block,
                    Some(&parent_header),
                    &ancestors,
                    &target,
                    None,
                )
            };
            result.map_err(|e| {
                format!("block header validation failed at height {}: {:?}", height, e)
            })?;
        }
        let blk_work = work_from_target(&block.header.difficulty_target);
        cumulative_work = add_work(&cumulative_work, &blk_work);
        prev_id = block_id;
    }
    if prev_id != tip_id {
        return Err(format!(
            "open_chain/tip mismatch: last walked block {} != persisted tip {}; \
             height index and tip metadata are inconsistent",
            prev_id, tip_id
        ));
    }

    // -------- Load persisted UTXO snapshot + state_root cross-check --------
    let utxos = storage
        .iter_utxos()
        .map_err(|e| format!("failed to read UTXOS_TABLE: {}", e))?;
    let utxo_count = utxos.len();
    for (op, entry) in utxos {
        utxo_set
            .insert(op, entry)
            .map_err(|e| format!("failed to seed in-memory UtxoSet from snapshot: {:?}", e))?;
    }
    let computed_root = utxo_set.state_root();
    if computed_root != tip_header.state_root {
        return Err(format!(
            "UTXO snapshot state_root {} does not match tip header state_root {}; \
             on-disk snapshot is corrupt. Run with --rebuild-state to recover from \
             a full chain replay.",
            computed_root, tip_header.state_root
        ));
    }

    // Track 1: if we actually walked (full / partial / forced --full-verify),
    // the structural integrity of the chain through the tip is now proven and
    // the state_root cross-check passed — stamp the marker so the next boot
    // takes the fast path. The skip path left the marker already current.
    if did_walk {
        storage
            .set_walk_verified_tip(&tip_id)
            .map_err(|e| format!("failed to persist walk-verified marker: {}", e))?;
    }

    info!(
        "Opened chain from persisted UTXO snapshot: tip={} height={} utxos={}",
        tip_id, tip_height, utxo_count
    );

    Ok(ChainTip {
        block_id: tip_id,
        height: tip_height,
        cumulative_work,
    })
}

/// Phase 3a — invoke `replay_chain` and, on success with `auto_migrate`,
/// finalize the UTXO snapshot so the next boot uses the fast path.
///
/// Emits a single info line BEFORE replay_chain starts so operators see an
/// expected-duration band and don't interrupt a multi-second to multi-minute
/// backfill (per issue #6 review ask).
pub fn run_replay_and_maybe_migrate(
    storage: &Arc<ChainStorage>,
    utxo_set: &mut UtxoSet,
    expected_genesis_id: &Hash256,
    assume_valid: bool,
    auto_migrate: bool,
) -> Result<ChainTip, String> {
    if auto_migrate {
        info!(
            "Phase 3a migration: rebuilding UTXO snapshot via full chain replay. \
             Expected duration: seconds to minutes depending on chain size and CPU \
             (~30-60s on a ~500k block chain on commodity hardware). Do NOT interrupt — \
             a clean restart resumes from scratch; an interrupted backfill leaves no \
             on-disk inconsistency thanks to the atomic snapshot marker."
        );
    } else {
        info!(
            "Phase 3a migration disabled (--no-auto-migrate). Running full chain \
             replay; UTXO snapshot will NOT be backfilled. Next boot will repeat \
             this replay. Use --rebuild-state for a one-shot manual backfill."
        );
    }
    let tip = replay_chain(storage, utxo_set, expected_genesis_id, assume_valid)?;
    if auto_migrate {
        let start = std::time::Instant::now();
        let utxo_count = utxo_set.len();
        storage
            .finalize_utxo_snapshot(utxo_set, &tip.block_id)
            .map_err(|e| {
                format!(
                    "Phase 3a snapshot backfill failed: {}. Replay state is in memory \
                     this run, but the next restart will replay again. Restart with \
                     --no-auto-migrate to skip the backfill attempt, or investigate \
                     disk/space.",
                    e
                )
            })?;
        info!(
            "Phase 3a migration complete: {} UTXOs persisted in {:.2}s. Next boot will \
             use the fast open path.",
            utxo_count,
            start.elapsed().as_secs_f64()
        );
    }
    Ok(tip)
}

/// Replay the canonical chain from genesis to tip, rebuilding the UTXO set
/// and validating every block. Returns the chain tip on success.
///
/// All corruption/inconsistency conditions return `Err` instead of panicking,
/// so the caller can log cleanly and exit gracefully.
pub fn replay_chain(
    storage: &Arc<ChainStorage>,
    utxo_set: &mut UtxoSet,
    expected_genesis_id: &Hash256,
    assume_valid: bool,
) -> Result<ChainTip, String> {
    let tip_id = match storage
        .get_tip()
        .map_err(|e| format!("db error reading tip: {}", e))?
    {
        Some(id) => id,
        None => {
            // Fail-closed: if TIP is missing but HEIGHT_INDEX has entries,
            // the database is corrupt — do not silently normalize.
            if !storage
                .height_index_is_empty()
                .map_err(|e| format!("db error checking height index: {}", e))?
            {
                return Err(
                    "tip metadata missing but height index is not empty; database may be corrupt"
                        .to_string(),
                );
            }

            // Also check blocks table — only commit genesis into a truly empty database.
            if !storage
                .blocks_table_is_empty()
                .map_err(|e| format!("db error checking blocks table: {}", e))?
            {
                return Err(
                    "tip metadata missing but blocks table is not empty; database may be corrupt"
                        .to_string(),
                );
            }

            // First start: apply genesis atomically (block + header +
            // height index + work + tip + UTXOS in one write transaction).
            //
            // This bootstrap can only seed the CANONICAL genesis (it has the
            // expected id, not the block, so it can't reconstruct a foreign
            // one). If the caller expects a different genesis — e.g. an
            // `exfer devnet` process, which seeds its distinct genesis itself
            // before reaching here — refuse rather than silently seed the
            // wrong chain and return a tip that doesn't match expected.
            let genesis = genesis_block();
            let gid = genesis.header.block_id();
            if gid != *expected_genesis_id {
                return Err(format!(
                    "cannot bootstrap an empty datadir: only the canonical genesis {} is \
                     available here, but this node expects {} — the caller must seed its \
                     own genesis first (e.g. the devnet path)",
                    gid, expected_genesis_id
                ));
            }

            let mut genesis_mutations: Vec<UtxoMutation> = Vec::new();
            for tx in &genesis.transactions {
                let m = utxo_set
                    .apply_transaction(tx, 0)
                    .map_err(|e| format!("genesis transaction failed: {:?}", e))?;
                genesis_mutations.extend(m);
            }

            let genesis_work = work_from_target(&genesis.header.difficulty_target);
            storage
                .commit_genesis_atomic(&genesis, &genesis_work, &genesis_mutations)
                .map_err(|e| format!("failed to commit genesis: {}", e))?;

            return Ok(ChainTip::genesis(gid, &genesis.header.difficulty_target));
        }
    };

    // Get tip height for bounded forward walk
    let tip_header = storage
        .get_header(&tip_id)
        .map_err(|e| format!("db error reading tip header: {}", e))?
        .ok_or_else(|| format!("tip block header {} not found", tip_id))?;
    let tip_height = tip_header.height;

    // Check if assume-valid checkpoint is proven: chain must be at or past
    // checkpoint height AND the block at that height must match the hash.
    let assume_valid_proven = assume_valid && tip_height >= ASSUME_VALID_HEIGHT && {
        match storage
            .get_block_id_by_height(ASSUME_VALID_HEIGHT)
            .map_err(|e| format!("db error checking checkpoint: {}", e))?
        {
            Some(id) => id == Hash256(ASSUME_VALID_HASH),
            None => false,
        }
    };
    if assume_valid {
        if assume_valid_proven {
            info!(
                "Assume-valid checkpoint verified in storage at height {}",
                ASSUME_VALID_HEIGHT
            );
        } else {
            info!("Assume-valid checkpoint not yet proven — full PoW verification during replay");
        }
    }

    let mut cumulative_work = [0u8; 32];
    let mut block_count = 0u64;
    let mut prev_id = Hash256::ZERO; // genesis has prev = ZERO

    let replay_start = std::time::Instant::now();

    info!("Replaying {} blocks...", tip_height + 1);

    // Forward walk using height index — one block at a time, no Vec accumulation
    for height in 0..=tip_height {
        let block_id = storage
            .get_block_id_by_height(height)
            .map_err(|e| format!("db error at height {}: {}", height, e))?
            .ok_or_else(|| {
                format!(
                    "height index missing entry at height {} during replay",
                    height
                )
            })?;

        // Verify height 0 is our expected genesis
        if height == 0 && block_id != *expected_genesis_id {
            return Err(format!(
                "height 0 block {} does not match expected genesis {}; \
                 database belongs to a different chain",
                block_id, expected_genesis_id
            ));
        }

        let block = storage
            .get_block(&block_id)
            .map_err(|e| format!("db error reading block at height {}: {}", height, e))?
            .ok_or_else(|| {
                format!(
                    "block {} at height {} not found during replay",
                    block_id, height
                )
            })?;

        // Verify chain linkage (catches corrupt height index)
        if block.header.prev_block_id != prev_id {
            return Err(format!(
                "chain linkage broken at height {}: block prev_block_id {} != expected {}",
                height, block.header.prev_block_id, prev_id
            ));
        }

        // Full consensus validation (skip header for genesis — already PoW-checked)
        if block.header.height > 0 {
            let parent_header = storage
                .get_header(&block.header.prev_block_id)
                .map_err(|e| format!("db error reading parent header at height {}: {}", height, e))?
                .ok_or_else(|| {
                    format!("parent header not found at height {} during replay", height)
                })?;
            let ancestor_timestamps = storage
                .get_ancestor_timestamps(&block.header.prev_block_id, MTP_WINDOW)
                .map_err(|e| {
                    format!(
                        "db error reading ancestor timestamps at height {}: {}",
                        height, e
                    )
                })?;
            let expected_target =
                expected_difficulty(storage, &block.header.prev_block_id, block.header.height)
                    .map_err(|e| {
                        format!("difficulty computation failed at height {}: {}", height, e)
                    })?;

            // Assume-valid: skip PoW for blocks at/below checkpoint, but ONLY
            // if the checkpoint block is already in storage and matches.
            // If chain is shorter than checkpoint, verify full PoW.
            let skip_pow = assume_valid_proven && height <= ASSUME_VALID_HEIGHT;
            if !skip_pow {
                validate_block_header(
                    &block,
                    Some(&parent_header),
                    &ancestor_timestamps,
                    &expected_target,
                    None,
                )
            } else {
                validate_block_header_skip_pow(
                    &block,
                    Some(&parent_header),
                    &ancestor_timestamps,
                    &expected_target,
                    None,
                )
            }
            .map_err(|e| {
                format!(
                    "block header validation failed at height {}: {:?}",
                    block.header.height, e
                )
            })?;

            // Assume-valid checkpoint during replay (redundant if already proven,
            // but verifies integrity on every replay)
            if assume_valid_proven && height == ASSUME_VALID_HEIGHT {
                let expected = Hash256(ASSUME_VALID_HASH);
                let actual = block.header.block_id();
                if actual != expected {
                    return Err(format!(
                        "assume-valid checkpoint failed during replay at height {}: expected {}, got {}",
                        ASSUME_VALID_HEIGHT, expected, actual
                    ));
                }
            }
        }

        // Apply the block to the UTXO set. Two paths:
        //
        // - If the assume-valid checkpoint is proven AND this block is at or
        //   below `ASSUME_VALID_HEIGHT`, skip signature/script validation —
        //   the block was validated when first imported and the downstream
        //   per-block state-root check still detects mis-application.
        //
        // - Otherwise, full validation as before.
        let skip_tx_validation = assume_valid_proven && height <= ASSUME_VALID_HEIGHT;
        let apply_result = if skip_tx_validation {
            apply_block_transactions_assume_valid(&block, utxo_set)
        } else {
            validate_and_apply_block_transactions_atomic(&block, utxo_set)
        };
        let (_fees, _mutations) = apply_result.map_err(|e| {
            format!(
                "block transaction {} failed at height {}: {:?}",
                if skip_tx_validation { "apply" } else { "validation" },
                block.header.height,
                e
            )
        })?;

        // TX indexing during replay is deferred — commit_block_atomic and
        // commit_reorg_atomic index new blocks as they arrive. Doing per-block
        // index_tx writes during replay of 28K+ blocks causes OOM on
        // memory-constrained nodes (each write transaction buffers in redb).

        // Verify state integrity (O(1) with incremental SMT)
        let computed = utxo_set.state_root();
        if computed != block.header.state_root {
            return Err(format!(
                "state root mismatch at height {}: expected {}, got {}",
                block.header.height, block.header.state_root, computed
            ));
        }

        // NOTE: `store_spent_utxos` and `put_cumulative_work` were called
        // here per-block in earlier versions, but both are *already*
        // persisted atomically by `commit_block_atomic` /
        // `commit_reorg_atomic` (chain/storage.rs) when the block first
        // arrives. Re-writing them on every replay was duplicate I/O —
        // 2 extra redb write transactions per block, each with its own
        // fsync. At chain heights in the 100k+ range this dominated
        // replay wall time on slow / network-attached storage.
        //
        // Atomicity invariant: if `storage.get_block(&block_id)` succeeded
        // above, then the commit transaction that wrote the block also
        // wrote spent_utxos + cumulative_work, so they are present.
        let block_work = work_from_target(&block.header.difficulty_target);
        cumulative_work = add_work(&cumulative_work, &block_work);

        // Progress logging every 1000 blocks
        if (height + 1) % 1000 == 0 || height == tip_height {
            let elapsed = replay_start.elapsed().as_secs();
            let pct = (height + 1) as f64 / (tip_height + 1) as f64 * 100.0;
            info!(
                "Replay progress: {}/{} blocks ({:.1}%) in {}s",
                height + 1,
                tip_height + 1,
                pct,
                elapsed,
            );
        }

        prev_id = block_id;
        block_count += 1;
    }

    // Final consistency check: last replayed block must equal persisted tip
    if prev_id != tip_id {
        return Err(format!(
            "replay/tip mismatch: last replayed block {} != persisted tip {}; \
             height index and tip metadata are inconsistent",
            prev_id, tip_id
        ));
    }

    let (smt_nodes, smt_leaves) = utxo_set.smt_stats();
    info!(
        "Replayed {} blocks, UTXO set has {} entries, SMT: {} nodes + {} leaves",
        block_count,
        utxo_set.len(),
        smt_nodes,
        smt_leaves,
    );

    // Memory diagnostics: log RSS after replay
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") || line.starts_with("VmSize:") {
                    info!("Memory after replay: {}", line.trim());
                }
            }
        }
    }

    Ok(ChainTip {
        block_id: tip_id,
        height: tip_height,
        cumulative_work,
    })
}
