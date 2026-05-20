//! Phase 3a design benchmark — diagnostic only, do not ship.
//!
//! Measures three things on an existing chain.redb:
//!   Exp1 — cheap canonical-metadata walk (header + linkage + skip_pow validation).
//!          This is the boot-time cost of the proposed open_chain integrity walk,
//!          assuming UTXO is persisted (so no per-tx work).
//!   Exp2 — full UTXO rebuild via the existing replay path (baseline today).
//!          Reports wall time + final utxo count + SMT stats + state root.
//!   Exp3 — SMT-rebuild-from-iter (proxy for Phase 3b's open-time SMT cost
//!          once UTXO is persisted but SMT is not).
//!
//! Output is `tag=value` lines on stdout so the surrounding shell can grep
//! cheaply. Progress and free-form notes go to stderr.
//!
//! Run: bench_phase3a <datadir>      (default: /data)

use std::path::PathBuf;
use std::time::Instant;

use exfer::chain::state::UtxoSet;
use exfer::chain::storage::ChainStorage;
use exfer::consensus::difficulty::expected_difficulty;
use exfer::consensus::validation::{
    apply_block_transactions_assume_valid, validate_and_apply_block_transactions_atomic,
    validate_block_header_skip_pow,
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
            // Use whichever path the production replay would take at this
            // height: skip tx validation when av-checkpoint is proven and
            // we're at/below it, otherwise full validation.
            let skip_tx = av_proven && height <= ASSUME_VALID_HEIGHT;
            let (_fees, spent) = if skip_tx {
                apply_block_transactions_assume_valid(&block, &mut utxo_set)
                    .map_err(|e| format!("apply-av {} failed: {:?}", height, e))?
            } else {
                validate_and_apply_block_transactions_atomic(&block, &mut utxo_set)
                    .map_err(|e| format!("apply {} failed: {:?}", height, e))?
            };
            total_inputs_spent += spent.len() as u64;
            for tx in &block.transactions {
                total_outputs_created += tx.outputs.len() as u64;
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

    eprintln!("# DONE");
    Ok(())
}
