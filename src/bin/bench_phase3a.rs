//! Phase 3a design benchmark — diagnostic only, do not ship.
//!
//! Measures four things on an existing chain.redb:
//!   Exp1 — cheap canonical-metadata walk (header + linkage + skip_pow validation).
//!          This is the boot-time cost of the proposed open_chain integrity walk,
//!          assuming UTXO is persisted (so no per-tx work).
//!   Exp2 — full UTXO rebuild via the existing replay path (baseline today).
//!          Reports wall time + final utxo count + SMT stats + state root.
//!   Exp3 — SMT-rebuild-from-iter (proxy for Phase 3b's open-time SMT cost
//!          once UTXO is persisted but SMT is not).
//!   Exp4 — A/B comparison: finalize the snapshot then time the actual
//!          `open_chain` (Phase 3a fast path) on a fresh ChainStorage
//!          handle. Headline number for the PR: open_chain wall-time vs
//!          replay_chain wall-time (Exp2) on the same chain.
//!
//! Output is `tag=value` lines on stdout so the surrounding shell can grep
//! cheaply. Progress and free-form notes go to stderr.
//!
//! Run: bench_phase3a <datadir>      (default: /data)

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use exfer::chain::open::open_chain;
use exfer::chain::state::UtxoSet;
use exfer::chain::storage::ChainStorage;
use exfer::consensus::difficulty::expected_difficulty;
use exfer::consensus::validation::{
    apply_block_transactions_assume_valid, validate_block_header_skip_pow,
};
use exfer::genesis::genesis_block;
use exfer::types::hash::Hash256;
use exfer::types::{ASSUME_VALID_HASH, ASSUME_VALID_HEIGHT, MTP_WINDOW};

const BAND: u64 = 50_000;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let datadir = PathBuf::from(
        args.get(1)
            .cloned()
            .unwrap_or_else(|| "/data".to_string()),
    );
    let db_path = datadir.join("chain.redb");
    eprintln!("# opening {}", db_path.display());
    let storage = ChainStorage::open(&db_path).map_err(|e| e.to_string())?;

    let tip_id = storage
        .get_tip()
        .map_err(|e| e.to_string())?
        .ok_or("tip missing")?;
    let tip_header = storage
        .get_header(&tip_id)
        .map_err(|e| e.to_string())?
        .ok_or("tip header missing")?;
    let tip_height = tip_header.height;
    println!("tip_height={}", tip_height);
    println!("tip_id={}", tip_id);

    let av_proven = tip_height >= ASSUME_VALID_HEIGHT
        && storage
            .get_block_id_by_height(ASSUME_VALID_HEIGHT)
            .map_err(|e| e.to_string())?
            .map(|id| id == Hash256(ASSUME_VALID_HASH))
            .unwrap_or(false);
    println!("assume_valid_proven={}", av_proven);
    println!("assume_valid_height={}", ASSUME_VALID_HEIGHT);

    let genesis_id = genesis_block().header.block_id();

    // ===== Experiment 1: cheap canonical-metadata walk =====
    eprintln!("# Exp1: cheap canonical-metadata walk");
    let mut prev_id = Hash256::ZERO;
    let exp1_start = Instant::now();
    let mut last_band_t = exp1_start;
    for height in 0..=tip_height {
        let block_id = storage
            .get_block_id_by_height(height)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("height {} missing", height))?;
        if height == 0 && block_id != genesis_id {
            return Err("genesis mismatch".into());
        }
        // Load full block (header-only validation still needs body for size + tx_root + coinbase checks).
        let block = storage
            .get_block(&block_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("block {} missing", block_id))?;
        if block.header.prev_block_id != prev_id {
            return Err(format!("chain linkage broken at {}", height));
        }
        if height > 0 {
            let parent = storage
                .get_header(&block.header.prev_block_id)
                .map_err(|e| e.to_string())?
                .ok_or("parent header missing")?;
            let ancestors = storage
                .get_ancestor_timestamps(&block.header.prev_block_id, MTP_WINDOW)
                .map_err(|e| e.to_string())?;
            let target = expected_difficulty(&storage, &block.header.prev_block_id, block.header.height)
                .map_err(|e| format!("{:?}", e))?;
            validate_block_header_skip_pow(&block, Some(&parent), &ancestors, &target, None)
                .map_err(|e| format!("header invalid at {}: {:?}", height, e))?;
        }
        prev_id = block_id;
        if height > 0 && height % BAND == 0 {
            let now = Instant::now();
            let band = now.duration_since(last_band_t).as_secs_f64();
            println!(
                "exp1_band[{}..{}]_secs={:.2} rate_bps={:.0}",
                height - BAND,
                height,
                band,
                BAND as f64 / band.max(1e-9)
            );
            last_band_t = now;
        }
    }
    if prev_id != tip_id {
        return Err("tip mismatch in exp1".into());
    }
    let exp1_elapsed = exp1_start.elapsed().as_secs_f64();
    println!("exp1_total_secs={:.2}", exp1_elapsed);
    println!(
        "exp1_avg_blocks_per_sec={:.0}",
        (tip_height as f64) / exp1_elapsed.max(1e-9)
    );

    // ===== Experiment 2: full UTXO rebuild =====
    eprintln!("# Exp2: full UTXO rebuild (current cost of art)");
    let mut utxo_set = UtxoSet::new();
    let exp2_start = Instant::now();
    let mut total_outputs_created: u64 = 0;
    let mut total_inputs_spent: u64 = 0;
    for tx in &genesis_block().transactions {
        utxo_set
            .apply_transaction(tx, 0)
            .map_err(|e| format!("genesis apply failed: {:?}", e))?;
        total_outputs_created += tx.outputs.len() as u64;
    }
    let mut prev_id = Hash256::ZERO;
    let mut last_band_t = exp2_start;
    for height in 0..=tip_height {
        let block_id = storage
            .get_block_id_by_height(height)
            .map_err(|e| e.to_string())?
            .ok_or("h")?;
        let block = storage
            .get_block(&block_id)
            .map_err(|e| e.to_string())?
            .ok_or("b")?;
        if height > 0 {
            // ALWAYS use the assume-valid-fast path here, regardless of
            // whether the snapshot's tip is past ASSUME_VALID_HEIGHT.
            //
            // Rationale: this bench's purpose is to model "today's open
            // cost when the production node is restarting on a chain that
            // is past the checkpoint" — i.e. the steady-state restart cost
            // operators see in practice. When the snapshot's tip happens
            // to be BELOW the new checkpoint (e.g. mid-rollout right after
            // the checkpoint bump), the production replay would fall back
            // to full Argon2id PoW + sig validation per block, taking
            // hours. Measuring THAT cost here would produce a misleading
            // Exp2 number that scales with the rollout-vs-checkpoint
            // race, not with chain shape. The assume-valid fast path is
            // the realistic restart cost across most of the chain's
            // lifetime, so we measure that. Mutations are discarded.
            let _mutations = apply_block_transactions_assume_valid(&block, &mut utxo_set)
                .map_err(|e| format!("apply-av {} failed: {:?}", height, e))?
                .1;
            // Note: total_inputs_spent / total_outputs_created tallies are
            // computed from the block body (deterministic, independent of
            // the apply path) to keep the bench's emit fields stable.
            for tx in &block.transactions {
                total_outputs_created += tx.outputs.len() as u64;
                if !tx.is_coinbase() {
                    total_inputs_spent += tx.inputs.len() as u64;
                }
            }
        }
        prev_id = block_id;
        if height > 0 && height % BAND == 0 {
            let now = Instant::now();
            let band = now.duration_since(last_band_t).as_secs_f64();
            println!(
                "exp2_band[{}..{}]_secs={:.2} utxos_so_far={}",
                height - BAND,
                height,
                band,
                utxo_set.len()
            );
            last_band_t = now;
        }
    }
    if prev_id != tip_id {
        return Err("tip mismatch in exp2".into());
    }
    let exp2_elapsed = exp2_start.elapsed().as_secs_f64();
    let final_root = utxo_set.state_root();
    let (smt_nodes, smt_leaves) = utxo_set.smt_stats();
    println!("exp2_total_secs={:.2}", exp2_elapsed);
    println!("utxo_count={}", utxo_set.len());
    println!("smt_nodes={}", smt_nodes);
    println!("smt_leaves={}", smt_leaves);
    println!("total_outputs_created={}", total_outputs_created);
    println!("total_inputs_spent={}", total_inputs_spent);
    println!("final_state_root={}", final_root);

    // ===== Experiment 3: SMT rebuild from a fully-populated UTXO set =====
    // Models Phase 3b's open-time cost: if we persist UTXO but not SMT, how
    // long does the boot-time SMT rebuild take per UTXO?
    eprintln!("# Exp3: SMT rebuild from existing UTXO set");
    let utxos: Vec<_> = utxo_set
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut fresh = UtxoSet::new();
    let exp3_start = Instant::now();
    for (outpoint, entry) in &utxos {
        fresh
            .insert(outpoint.clone(), entry.clone())
            .map_err(|e| format!("insert failed: {:?}", e))?;
    }
    let exp3_elapsed = exp3_start.elapsed().as_secs_f64();
    let fresh_root = fresh.state_root();
    println!("exp3_total_secs={:.6}", exp3_elapsed);
    println!(
        "exp3_utxos_per_sec={:.0}",
        utxos.len() as f64 / exp3_elapsed.max(1e-9)
    );
    println!("exp3_root_matches_full_rebuild={}", fresh_root == final_root);

    // ===== Experiment 4: end-to-end A/B vs Exp2 =====
    //
    // Naively timing open_chain on this snapshot would NOT produce a useful
    // baseline number: this snapshot's tip is below ASSUME_VALID_HEIGHT, so
    // `assume_valid_proven` is false, and open_chain's cheap walk falls back
    // to validate_block_header (with full Argon2id PoW) for every block —
    // hours per run. That's a property of the snapshot chosen for the bench,
    // not of Phase 3a; once the production chain crosses the checkpoint, the
    // walk uses skip_pow (Exp1 cost ≈ 12s on this hardware).
    //
    // To still produce a meaningful A/B number on whatever snapshot the
    // operator has on hand, measure the open_chain components that DON'T
    // depend on the assume-valid state and model the missing piece from
    // Exp1:
    //
    //   exp4_finalize_secs              : finalize_utxo_snapshot (one-time
    //                                     migration cost, not paid every boot)
    //   exp4_read_side_secs             : drop storage → re-open → iter_utxos
    //                                     → bulk-insert into fresh UtxoSet
    //                                     (rebuilds SMT incrementally) →
    //                                     state_root cross-check. This is
    //                                     everything open_chain does AFTER
    //                                     the cheap walk.
    //   exp4_modeled_open_chain_secs    : exp1_total_secs + exp4_read_side_secs
    //                                     — the per-boot Phase 3a steady-state
    //                                     cost on a chain past the checkpoint.
    //   exp4_speedup_vs_exp2_modeled    : exp2_total / modeled. The headline.
    eprintln!("# Exp4: finalize + read-side measurement (open_chain components)");

    let exp4_finalize_start = Instant::now();
    storage
        .finalize_utxo_snapshot(&utxo_set, &tip_id)
        .map_err(|e| format!("finalize_utxo_snapshot failed: {}", e))?;
    let exp4_finalize_secs = exp4_finalize_start.elapsed().as_secs_f64();
    println!("exp4_finalize_secs={:.4}", exp4_finalize_secs);

    // Drop the in-memory UtxoSet AND the storage handle so the re-open
    // measurement is honest (cold redb file handle, no warm page cache from
    // the test process's prior reads).
    drop(utxo_set);
    drop(storage);

    let storage2 = Arc::new(ChainStorage::open(&db_path).map_err(|e| e.to_string())?);
    let exp4_read_start = Instant::now();
    let utxos_from_disk = storage2
        .iter_utxos()
        .map_err(|e| format!("iter_utxos failed: {}", e))?;
    let mut utxo_set2 = UtxoSet::new();
    for (op, entry) in utxos_from_disk {
        utxo_set2
            .insert(op, entry)
            .map_err(|e| format!("insert failed: {:?}", e))?;
    }
    let read_state_root = utxo_set2.state_root();
    if read_state_root != final_root {
        return Err(format!(
            "exp4 read-side state_root mismatch: got {} expected {}",
            read_state_root, final_root
        ));
    }
    let exp4_read_side_secs = exp4_read_start.elapsed().as_secs_f64();
    println!("exp4_read_side_secs={:.4}", exp4_read_side_secs);
    println!("exp4_read_side_utxo_count={}", utxo_set2.len());
    println!(
        "exp4_read_side_state_root_matches_exp2={}",
        read_state_root == final_root
    );

    // Modeled steady-state open_chain (post-checkpoint chain): cheap walk
    // (exp1) + read side (exp4). Compare to today's replay (exp2). Suppress
    // open_chain itself running here because it would PoW-verify every block
    // on this below-checkpoint snapshot, see the comment block at the top
    // of Exp4.
    let exp4_modeled = exp1_elapsed + exp4_read_side_secs;
    println!("exp4_modeled_open_chain_secs={:.4}", exp4_modeled);
    println!(
        "exp4_speedup_vs_exp2_modeled={:.2}x",
        exp2_elapsed / exp4_modeled.max(1e-9)
    );

    // ===== Experiment 5 (Track 1, issue #6): walk-checkpoint A/B =====
    //
    // Exp4 finalized the snapshot, which also stamps WALK_VERIFIED_TIP at the
    // tip. So open_chain with trust_walk_marker=true takes the skip path (no
    // structural walk, cumulative work read O(1) from WORK_TABLE), while
    // trust_walk_marker=false (--full-verify) forces the full genesis→tip walk
    // — the effective per-boot cost before Track 1. Headline:
    //   exp5_forced_walk_open_secs  : --full-verify / pre-Track-1 boot walk cost
    //   exp5_skip_open_secs         : Track 1 steady-state boot (walk skipped)
    //   exp5_walk_eliminated_secs   : the part Track 1 removes every boot
    // NOTE: on a chain BELOW ASSUME_VALID_HEIGHT the forced walk PoW-verifies
    // every block (slow but correct); on a real chain past the checkpoint it
    // uses skip_pow, matching Exp1.
    eprintln!("# Exp5: walk-checkpoint A/B (forced walk vs skip)");

    let storage_fv = Arc::new(ChainStorage::open(&db_path).map_err(|e| e.to_string())?);
    let mut uset_fv = UtxoSet::new();
    let exp5_walk_start = Instant::now();
    let fv_tip = open_chain(&storage_fv, &mut uset_fv, &genesis_id, true, false, false)
        .map_err(|e| format!("open_chain(--full-verify) failed: {}", e))?;
    let exp5_forced_walk_secs = exp5_walk_start.elapsed().as_secs_f64();
    println!("exp5_forced_walk_open_secs={:.4}", exp5_forced_walk_secs);
    drop(uset_fv);
    drop(storage_fv);

    let storage_skip = Arc::new(ChainStorage::open(&db_path).map_err(|e| e.to_string())?);
    let mut uset_skip = UtxoSet::new();
    let exp5_skip_start = Instant::now();
    let skip_tip = open_chain(&storage_skip, &mut uset_skip, &genesis_id, true, false, true)
        .map_err(|e| format!("open_chain(skip) failed: {}", e))?;
    let exp5_skip_secs = exp5_skip_start.elapsed().as_secs_f64();
    println!("exp5_skip_open_secs={:.4}", exp5_skip_secs);
    println!(
        "exp5_walk_eliminated_secs={:.4}",
        (exp5_forced_walk_secs - exp5_skip_secs).max(0.0)
    );
    println!(
        "exp5_speedup={:.2}x",
        exp5_forced_walk_secs / exp5_skip_secs.max(1e-9)
    );
    println!(
        "exp5_tips_match={}",
        fv_tip.block_id == skip_tip.block_id && skip_tip.block_id == tip_id
    );
    println!(
        "exp5_cumulative_work_match={}",
        fv_tip.cumulative_work == skip_tip.cumulative_work
    );

    eprintln!("# DONE");
    Ok(())
}
