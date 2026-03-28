use crate::chain::state::UtxoSet;
use crate::consensus::pow::compute_pow;
use crate::consensus::reward::block_reward;
use crate::consensus::validation::compute_tx_root;
use crate::mempool::Mempool;
use crate::types::block::{Block, BlockHeader};
use crate::types::hash::Hash256;
use crate::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use crate::types::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Block miner.
#[derive(Clone)]
pub struct Miner {
    /// Miner's public key for coinbase rewards.
    pub pubkey: [u8; 32],
}

impl Miner {
    pub fn new(pubkey: [u8; 32]) -> Self {
        Miner { pubkey }
    }

    /// Build a coinbase transaction for the given height and fees.
    ///
    /// Returns `None` if height exceeds `u32::MAX` (coinbase output_index
    /// must encode height as u32 per consensus rules).
    pub fn build_coinbase(&self, height: u64, total_fees: u64) -> Option<Transaction> {
        let output_index = u32::try_from(height).ok()?;
        let reward = block_reward(height).checked_add(total_fees)?;

        Some(Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index,
            }],
            outputs: vec![TxOutput::new_p2pkh(reward, &self.pubkey)],
            witnesses: vec![TxWitness {
                witness: vec![], // coinbase witness is empty
                redeemer: None,
            }],
        })
    }

    /// Build a block template from mempool transactions.
    ///
    /// Returns `(block, skipped_tx_ids)` or `None` if height exceeds `u32::MAX`.
    /// `skipped_tx_ids` contains tx_ids that failed validation or application
    /// during template assembly — the caller should purge these from mempool
    /// to prevent pinning (stale txs holding spent_outpoints, blocking
    /// replacement spends as DoubleSpend).
    #[allow(dead_code)]
    pub fn build_template(
        &self,
        height: u64,
        prev_block_id: Hash256,
        difficulty_target: Hash256,
        timestamp: u64,
        mempool: &Mempool,
        utxo_set: &UtxoSet,
    ) -> Option<(Block, Vec<Hash256>)> {
        let max_tx_space = MAX_BLOCK_SIZE.saturating_sub(400);
        let (txs, _total_fees) = mempool.select_transactions(max_tx_space);
        self.build_template_from_txs(
            height,
            prev_block_id,
            difficulty_target,
            timestamp,
            &txs,
            utxo_set,
        )
    }

    /// Build a block template from pre-selected transactions.
    /// Used by the mining loop which clones candidates under the mempool lock
    /// and then releases it before calling this method.
    pub fn build_template_from_txs(
        &self,
        height: u64,
        prev_block_id: Hash256,
        difficulty_target: Hash256,
        timestamp: u64,
        txs: &[Transaction],
        utxo_set: &UtxoSet,
    ) -> Option<(Block, Vec<Hash256>)> {
        // Trial-apply non-coinbase txs to detect any that fail (e.g. inputs
        // spent by a concurrent block between mempool validation and template
        // build). Silently ignoring failures would produce a wrong state root.
        //
        // Snapshot before each apply: apply_transaction mutates state before
        // returning Err (partial input removal), so a failed tx would poison
        // the trial UTXO set for subsequent txs. Clone-before-try ensures
        // failed txs are cleanly skipped without side effects.
        let mut utxo_trial = utxo_set.clone();
        let mut applied_txs: Vec<Transaction> = Vec::with_capacity(txs.len());
        let mut skipped_ids: Vec<Hash256> = Vec::new();
        let mut _dropped = false;
        let mut applied_fees: u128 = 0;
        for tx in txs {
            // Full consensus validation (scripts, fees, dust, size) against
            // the trial UTXO set at the target height. This catches
            // height-dependent scripts (e.g. block_height introspection jets)
            // that became invalid since mempool admission, preventing wasted
            // PoW on blocks that would be rejected by process_block.
            if let Err(e) =
                crate::consensus::validation::validate_transaction(tx, &utxo_trial, height)
            {
                tracing::warn!("miner: skipping tx that failed validation: {:?}", e);
                if let Ok(tx_id) = tx.tx_id() {
                    skipped_ids.push(tx_id);
                }
                _dropped = true;
                continue;
            }

            let snapshot = utxo_trial.clone();
            // Compute fee from trial UTXO (has intra-block outputs available)
            let mut tx_in: u128 = 0;
            for input in &tx.inputs {
                let op =
                    crate::types::transaction::OutPoint::new(input.prev_tx_id, input.output_index);
                if let Some(entry) = utxo_trial.get(&op) {
                    tx_in += entry.output.value as u128;
                }
            }
            match utxo_trial.apply_transaction(tx, height) {
                Ok(()) => {
                    let tx_out: u128 = tx.outputs.iter().map(|o| o.value as u128).sum();
                    applied_fees += tx_in.saturating_sub(tx_out);
                    applied_txs.push(tx.clone());
                }
                Err(e) => {
                    tracing::warn!("miner: skipping tx that failed to apply: {}", e);
                    if let Ok(tx_id) = tx.tx_id() {
                        skipped_ids.push(tx_id);
                    }
                    utxo_trial = snapshot;
                    _dropped = true;
                }
            }
        }

        let actual_fees = applied_fees.min(u64::MAX as u128) as u64;

        // Build coinbase with correct fees
        let coinbase = match self.build_coinbase(height, actual_fees) {
            Some(cb) => cb,
            None => {
                tracing::error!("miner: build_coinbase returned None at height {}", height);
                return None;
            }
        };

        // Build final UTXO copy: coinbase first, then applied txs
        let mut utxo_copy = utxo_set.clone();
        if let Err(e) = utxo_copy.apply_transaction(&coinbase, height) {
            tracing::error!("miner: coinbase apply failed at height {}: {}", height, e);
            return None;
        }
        for tx in &applied_txs {
            if let Err(e) = utxo_copy.apply_transaction(tx, height) {
                tracing::warn!("miner: tx failed on rebuild: {}", e);
                return None;
            }
        }

        // Construct transaction list: coinbase first
        let mut transactions = Vec::with_capacity(1 + applied_txs.len());
        transactions.push(coinbase);
        transactions.extend(applied_txs);

        // Compute roots
        let tx_root = compute_tx_root(&transactions)
            .expect("miner-constructed transactions must be serializable");
        let state_root = utxo_copy.state_root();

        Some((
            Block {
                header: BlockHeader {
                    version: VERSION,
                    height,
                    prev_block_id,
                    timestamp,
                    difficulty_target,
                    nonce: 0,
                    tx_root,
                    state_root,
                },
                transactions,
            },
            skipped_ids,
        ))
    }

    /// Mine a block: grind nonces until PoW is found or cancellation.
    /// Returns the mined block, or None if cancelled or the timestamp
    /// exceeds `max_timestamp` (gap limit) during nonce-exhaustion refresh.
    pub fn mine(
        &self,
        mut block: Block,
        cancel: Arc<AtomicBool>,
        pause: Arc<AtomicBool>,
        min_timestamp: u64,
        max_timestamp: u64,
    ) -> Option<Block> {
        loop {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }

            // Yield CPU while block verification is in progress.
            // Spin-wait with sleep to avoid busy-looping.
            while pause.load(Ordering::Relaxed) {
                if cancel.load(Ordering::Relaxed) {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            let pow_hash = match compute_pow(&block.header) {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Compare as big-endian 256-bit integers
            if pow_hash.as_bytes() < block.header.difficulty_target.as_bytes() {
                return Some(block);
            }

            block.header.nonce = match block.header.nonce.checked_add(1) {
                Some(n) => n,
                None => {
                    // Exhausted nonce space — update timestamp and reset.
                    // Clamp to [min_timestamp, max_timestamp] to satisfy
                    // consensus rules (MTP and gap limit).
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(block.header.timestamp);
                    if now > max_timestamp {
                        // Clock exceeded gap limit — stop mining this template.
                        return None;
                    }
                    block.header.timestamp = now.max(min_timestamp);
                    block.header.nonce = 0;
                    continue;
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_coinbase() {
        let miner = Miner::new([0x42; 32]);
        let cb = miner.build_coinbase(0, 0).unwrap();

        assert!(cb.is_coinbase());
        assert_eq!(cb.inputs[0].output_index, 0);
        assert_eq!(cb.outputs[0].value, block_reward(0));
    }

    #[test]
    fn test_build_coinbase_with_fees() {
        let miner = Miner::new([0x42; 32]);
        let fees = 500_000;
        let cb = miner.build_coinbase(100, fees).unwrap();
        assert_eq!(cb.outputs[0].value, block_reward(100) + fees);
    }

    #[test]
    fn test_build_template() {
        let miner = Miner::new([0x42; 32]);
        let mempool = Mempool::new();
        let utxo_set = UtxoSet::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (block, skipped) = miner
            .build_template(
                0,
                Hash256::ZERO,
                Hash256([0xFF; 32]),
                now,
                &mempool,
                &utxo_set,
            )
            .unwrap();

        assert_eq!(block.header.version, VERSION);
        assert_eq!(block.header.height, 0);
        assert_eq!(block.transactions.len(), 1); // just coinbase
        assert!(block.transactions[0].is_coinbase());
        assert!(skipped.is_empty());
    }

    #[test]
    fn test_mine_with_easy_target() {
        let miner = Miner::new([0x42; 32]);
        let mempool = Mempool::new();
        let utxo_set = UtxoSet::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (block, _skipped) = miner
            .build_template(
                0,
                Hash256::ZERO,
                Hash256([0xFF; 32]), // maximum target (easiest)
                now,
                &mempool,
                &utxo_set,
            )
            .unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let pause = Arc::new(AtomicBool::new(false));
        let mined = miner.mine(block, cancel, pause, now, now + MAX_TIMESTAMP_GAP);

        assert!(mined.is_some());
        let mined = mined.unwrap();
        assert!(crate::consensus::pow::verify_pow(&mined.header).unwrap());
    }
}
