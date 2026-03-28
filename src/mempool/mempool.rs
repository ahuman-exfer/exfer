use crate::chain::state::UtxoSet;
use crate::consensus::cost;
use crate::consensus::validation::{validate_transaction, ValidationError};
use crate::types::hash::Hash256;
use crate::types::transaction::{OutPoint, Transaction};
use crate::types::{COINBASE_MATURITY, MEMPOOL_CAPACITY};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Maximum total serialized bytes allowed in the mempool (256 MiB).
const MAX_MEMPOOL_BYTES: usize = 256 * 1024 * 1024;

/// A transaction in the mempool, with cached metadata.
#[derive(Clone, Debug)]
struct MempoolEntry {
    tx: Transaction,
    tx_id: Hash256,
    fee: u64,
    /// Transaction cost (7-component formula).
    _tx_cost: u64,
    /// Fee density = fee / tx_cost (scaled by 1_000_000 for integer precision).
    fee_density: u64,
}

/// Transaction memory pool.
///
/// Holds unconfirmed transactions that have been validated against the current
/// UTXO set. Maximum capacity: 8,192 transactions.
/// Eviction is based on fee density (fee / tx_cost), lowest first.
pub struct Mempool {
    /// Transactions indexed by tx_id.
    entries: HashMap<Hash256, MempoolEntry>,
    /// Ordered by fee density (lowest first) for eviction.
    /// Key: (fee_density, tx_id) for unique ordering.
    by_fee_density: BTreeMap<(u64, Hash256), Hash256>,
    /// Track which outpoints are spent by mempool transactions.
    spent_outpoints: HashSet<OutPoint>,
    /// Total serialized bytes of all transactions currently in the mempool.
    total_bytes: usize,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            entries: HashMap::new(),
            by_fee_density: BTreeMap::new(),
            spent_outpoints: HashSet::new(),
            total_bytes: 0,
        }
    }

    /// Number of transactions in the mempool.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Cheap pre-screen: returns Err if tx is already known or conflicts with
    /// an existing mempool entry. Does NOT modify state.
    ///
    /// Call this under the mempool lock *before* expensive UTXO/script validation
    /// to avoid CPU-wasting attacks via conflicting-tx spam.
    pub fn pre_check(&self, tx: &Transaction) -> Result<(), MempoolError> {
        let tx_id = tx.tx_id().map_err(|_| {
            MempoolError::ValidationFailed(
                crate::consensus::validation::ValidationError::TxTooLarge { size: 0 },
            )
        })?;
        if self.entries.contains_key(&tx_id) {
            return Err(MempoolError::AlreadyInMempool);
        }
        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseNotAllowed);
        }
        for input in &tx.inputs {
            let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
            if self.spent_outpoints.contains(&outpoint) {
                return Err(MempoolError::DoubleSpend(outpoint));
            }
        }
        Ok(())
    }

    /// Add a transaction to the mempool after validating it.
    #[allow(dead_code)]
    pub fn add(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u64,
    ) -> Result<Hash256, MempoolError> {
        let tx_id = tx.tx_id().map_err(|_| {
            MempoolError::ValidationFailed(
                crate::consensus::validation::ValidationError::TxTooLarge { size: 0 },
            )
        })?;

        // Reject if already in mempool
        if self.entries.contains_key(&tx_id) {
            return Err(MempoolError::AlreadyInMempool);
        }

        // Reject coinbase
        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseNotAllowed);
        }

        // Check for double-spends with existing mempool transactions
        for input in &tx.inputs {
            let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
            if self.spent_outpoints.contains(&outpoint) {
                return Err(MempoolError::DoubleSpend(outpoint));
            }
        }

        // Validate against UTXO set (returns fee, script eval cost, and script validation cost)
        let (fee, script_cost, script_validation_cost) =
            validate_transaction(&tx, utxo_set, current_height)
                .map_err(MempoolError::ValidationFailed)?;

        // Use actual script cost for fee-density ranking (not Phase1-only tx_cost)
        let tx_cost = cost::tx_cost_with_script_cost(&tx, script_cost, script_validation_cost)
            .ok_or(MempoolError::CostOverflow)?;
        let fee_density = if tx_cost > 0 {
            fee.saturating_mul(1_000_000) / tx_cost
        } else {
            0
        };

        let entry = MempoolEntry {
            tx: tx.clone(),
            tx_id,
            fee,
            _tx_cost: tx_cost,
            fee_density,
        };

        let tx_bytes = tx.serialized_size().unwrap_or(0);

        // Evict if at item or byte capacity
        if self.entries.len() >= MEMPOOL_CAPACITY || self.total_bytes + tx_bytes > MAX_MEMPOOL_BYTES
        {
            if let Some((&(worst_density, _), _)) = self.by_fee_density.first_key_value() {
                if fee_density <= worst_density {
                    return Err(MempoolError::FeeTooLow);
                }
                while self.entries.len() >= MEMPOOL_CAPACITY
                    || self.total_bytes + tx_bytes > MAX_MEMPOOL_BYTES
                {
                    if self.entries.is_empty() {
                        break;
                    }
                    self.evict_lowest();
                }
            }
        }

        // Track spent outpoints
        for input in &tx.inputs {
            let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
            self.spent_outpoints.insert(outpoint);
        }

        self.by_fee_density.insert((fee_density, tx_id), tx_id);
        self.total_bytes += tx_bytes;
        self.entries.insert(tx_id, entry);

        Ok(tx_id)
    }

    /// Add a pre-validated transaction to the mempool.
    ///
    /// Skips UTXO validation (caller already did it outside the lock).
    /// `fee` and `script_cost` come from the caller's `validate_transaction` result.
    /// Still performs mempool-local checks (duplicate, double-spend, capacity).
    pub fn add_validated(
        &mut self,
        tx: Transaction,
        fee: u64,
        script_cost: u128,
        script_validation_cost: u128,
        _current_height: u64,
    ) -> Result<Hash256, MempoolError> {
        let tx_id = tx
            .tx_id()
            .map_err(|_| MempoolError::ValidationFailed(ValidationError::TxTooLarge { size: 0 }))?;

        if self.entries.contains_key(&tx_id) {
            return Err(MempoolError::AlreadyInMempool);
        }

        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseNotAllowed);
        }

        for input in &tx.inputs {
            let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
            if self.spent_outpoints.contains(&outpoint) {
                return Err(MempoolError::DoubleSpend(outpoint));
            }
        }

        let tx_cost_val = cost::tx_cost_with_script_cost(&tx, script_cost, script_validation_cost)
            .ok_or(MempoolError::CostOverflow)?;
        let fee_density = if tx_cost_val > 0 {
            fee.saturating_mul(1_000_000) / tx_cost_val
        } else {
            0
        };

        let entry = MempoolEntry {
            tx: tx.clone(),
            tx_id,
            fee,
            _tx_cost: tx_cost_val,
            fee_density,
        };

        let tx_bytes = tx.serialized_size().unwrap_or(0);

        if self.entries.len() >= MEMPOOL_CAPACITY || self.total_bytes + tx_bytes > MAX_MEMPOOL_BYTES
        {
            if let Some((&(worst_density, _), _)) = self.by_fee_density.first_key_value() {
                if fee_density <= worst_density {
                    return Err(MempoolError::FeeTooLow);
                }
                while self.entries.len() >= MEMPOOL_CAPACITY
                    || self.total_bytes + tx_bytes > MAX_MEMPOOL_BYTES
                {
                    if self.entries.is_empty() {
                        break;
                    }
                    self.evict_lowest();
                }
            }
        }

        for input in &tx.inputs {
            let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
            self.spent_outpoints.insert(outpoint);
        }

        self.by_fee_density.insert((fee_density, tx_id), tx_id);
        self.total_bytes += tx_bytes;
        self.entries.insert(tx_id, entry);

        Ok(tx_id)
    }

    /// Remove a transaction from the mempool (e.g., after it's been mined).
    pub fn remove(&mut self, tx_id: &Hash256) -> Option<Transaction> {
        if let Some(entry) = self.entries.remove(tx_id) {
            self.by_fee_density
                .remove(&(entry.fee_density, entry.tx_id));
            for input in &entry.tx.inputs {
                let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
                self.spent_outpoints.remove(&outpoint);
            }
            self.total_bytes = self
                .total_bytes
                .saturating_sub(entry.tx.serialized_size().unwrap_or(0));
            Some(entry.tx)
        } else {
            None
        }
    }

    /// Evict the lowest fee-density transaction.
    fn evict_lowest(&mut self) {
        if let Some((&key, &tx_id)) = self.by_fee_density.first_key_value() {
            self.by_fee_density.remove(&key);
            if let Some(entry) = self.entries.remove(&tx_id) {
                for input in &entry.tx.inputs {
                    let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
                    self.spent_outpoints.remove(&outpoint);
                }
                self.total_bytes = self
                    .total_bytes
                    .saturating_sub(entry.tx.serialized_size().unwrap_or(0));
            }
        }
    }

    /// Get a transaction by its ID.
    #[allow(dead_code)]
    pub fn get(&self, tx_id: &Hash256) -> Option<&Transaction> {
        self.entries.get(tx_id).map(|e| &e.tx)
    }

    /// Select transactions for a block template, ordered by fee density (highest first).
    /// Returns (transactions, total_fees).
    pub fn select_transactions(&self, max_block_size: usize) -> (Vec<Transaction>, u64) {
        let mut selected = Vec::new();
        let mut total_fees = 0u64;
        let mut total_size = 0usize;

        // Iterate from highest fee density to lowest
        for (_, tx_id) in self.by_fee_density.iter().rev() {
            if let Some(entry) = self.entries.get(tx_id) {
                let size = entry.tx.serialized_size().unwrap_or(usize::MAX);
                if total_size + size <= max_block_size {
                    // Stop adding transactions if fees would overflow u64
                    if let Some(new_fees) = total_fees.checked_add(entry.fee) {
                        selected.push(entry.tx.clone());
                        total_fees = new_fees;
                        total_size += size;
                    }
                }
            }
        }

        (selected, total_fees)
    }

    /// Remove transactions that conflict with a newly confirmed block.
    pub fn remove_confirmed(&mut self, transactions: &[Transaction]) {
        // First pass: remove transactions by ID (exact matches)
        // Confirmed block transactions have already passed validation,
        // so tx_id() cannot fail (fields are within wire limits).
        for tx in transactions {
            if let Ok(tx_id) = tx.tx_id() {
                self.remove(&tx_id);
            }
        }

        // Build set of all outpoints spent by confirmed transactions
        let mut confirmed_outpoints: HashSet<OutPoint> = HashSet::new();
        for tx in transactions {
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.inputs {
                confirmed_outpoints.insert(OutPoint::new(input.prev_tx_id, input.output_index));
            }
        }

        // Single pass: remove any mempool tx spending a confirmed outpoint
        let mut to_remove = Vec::new();
        for (tx_id, entry) in &self.entries {
            for inp in &entry.tx.inputs {
                if confirmed_outpoints.contains(&OutPoint::new(inp.prev_tx_id, inp.output_index)) {
                    to_remove.push(*tx_id);
                    break;
                }
            }
        }

        for tx_id in to_remove {
            self.remove(&tx_id);
        }
    }

    /// Collect all input outpoints referenced by mempool transactions.
    /// Used to build a UTXO snapshot outside the mempool lock scope.
    pub fn referenced_outpoints(&self) -> Vec<OutPoint> {
        let mut outpoints = Vec::new();
        for entry in self.entries.values() {
            for input in &entry.tx.inputs {
                outpoints.push(OutPoint::new(input.prev_tx_id, input.output_index));
            }
        }
        outpoints
    }

    /// Remove mempool entries that are no longer valid after a tip change.
    /// Called after a normal block or reorg.
    ///
    /// Two-phase check:
    /// 1. UTXO existence + coinbase maturity (cheap — catches spent inputs)
    /// 2. Full validate_transaction including script re-evaluation (catches
    ///    height-dependent scripts that became invalid at the new tip)
    ///
    /// The caller should pass a UTXO snapshot (from `snapshot_for_outpoints`)
    /// rather than the full UTXO set, so the UTXO read lock is not held during
    /// the entire mempool iteration.
    pub fn revalidate(&mut self, utxo_set: &UtxoSet, current_height: u64) {
        let tx_ids: Vec<Hash256> = self.entries.keys().copied().collect();
        for tx_id in tx_ids {
            let should_remove = if let Some(entry) = self.entries.get(&tx_id) {
                // Phase 1: cheap UTXO existence + maturity check
                let utxo_invalid = entry.tx.inputs.iter().any(|input| {
                    let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
                    match utxo_set.get(&outpoint) {
                        None => true, // input no longer exists
                        Some(utxo) => {
                            // Coinbase maturity may have changed after reorg
                            utxo.is_coinbase
                                && current_height.saturating_sub(utxo.height) < COINBASE_MATURITY
                        }
                    }
                });
                if utxo_invalid {
                    true
                } else {
                    // Phase 2: full validation (scripts, fees, dust, size)
                    // at the new height. Catches height-dependent scripts
                    // that became invalid after a tip change.
                    crate::consensus::validation::validate_transaction(
                        &entry.tx,
                        utxo_set,
                        current_height,
                    )
                    .is_err()
                }
            } else {
                false
            };
            if should_remove {
                self.remove(&tx_id);
            }
        }
    }

    /// Check if an outpoint is spent by a mempool transaction.
    #[allow(dead_code)]
    pub fn is_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_outpoints.contains(outpoint)
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum MempoolError {
    AlreadyInMempool,
    CoinbaseNotAllowed,
    DoubleSpend(OutPoint),
    ValidationFailed(ValidationError),
    FeeTooLow,
    CostOverflow,
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::AlreadyInMempool => write!(f, "transaction already in mempool"),
            MempoolError::CoinbaseNotAllowed => write!(f, "coinbase transactions not allowed"),
            MempoolError::DoubleSpend(op) => write!(f, "double-spend of {:?}", op),
            MempoolError::ValidationFailed(e) => write!(f, "validation failed: {}", e),
            MempoolError::FeeTooLow => write!(f, "fee density too low for mempool"),
            MempoolError::CostOverflow => write!(f, "transaction cost overflow"),
        }
    }
}

impl std::error::Error for MempoolError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::state::UtxoEntry;
    use crate::types::transaction::{TxInput, TxOutput, TxWitness};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn setup_utxo_and_tx() -> (UtxoSet, Transaction) {
        let mut utxo_set = UtxoSet::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();

        // Create a UTXO with enough value to cover dust + fee
        let prev_tx_id = Hash256::sha256(b"prev_tx");
        let outpoint = OutPoint::new(prev_tx_id, 0);
        utxo_set
            .insert(
                outpoint,
                UtxoEntry {
                    output: TxOutput::new_p2pkh(1_000_000_000, &pubkey),
                    height: 0,
                    is_coinbase: false,
                },
            )
            .expect("insert test UTXO");

        // Build a transaction spending it
        let mut tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(900_000_000, &[2u8; 32])],
            witnesses: vec![TxWitness {
                witness: vec![0u8; 96], // placeholder
                redeemer: None,
            }],
        };

        // Build proper witness: pubkey(32) + signature(64)
        let sig_msg = tx.sig_message().unwrap();
        let signature = signing_key.sign(&sig_msg);
        let mut witness_data = Vec::with_capacity(96);
        witness_data.extend_from_slice(&pubkey);
        witness_data.extend_from_slice(&signature.to_bytes());
        tx.witnesses[0].witness = witness_data;

        (utxo_set, tx)
    }

    #[test]
    fn test_add_and_get() {
        let (utxo_set, tx) = setup_utxo_and_tx();
        let mut mempool = Mempool::new();
        let tx_id = mempool.add(tx.clone(), &utxo_set, 100).unwrap();
        assert_eq!(mempool.len(), 1);
        assert_eq!(mempool.get(&tx_id).unwrap(), &tx);
    }

    #[test]
    fn test_reject_duplicate() {
        let (utxo_set, tx) = setup_utxo_and_tx();
        let mut mempool = Mempool::new();
        mempool.add(tx.clone(), &utxo_set, 100).unwrap();
        match mempool.add(tx, &utxo_set, 100) {
            Err(MempoolError::AlreadyInMempool) => {}
            other => panic!("expected AlreadyInMempool, got {:?}", other),
        }
    }

    #[test]
    fn test_reject_coinbase() {
        let utxo_set = UtxoSet::new();
        let coinbase = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(10_000_000_000, &[1u8; 32])],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        let mut mempool = Mempool::new();
        match mempool.add(coinbase, &utxo_set, 0) {
            Err(MempoolError::CoinbaseNotAllowed) => {}
            other => panic!("expected CoinbaseNotAllowed, got {:?}", other),
        }
    }

    #[test]
    fn test_remove() {
        let (utxo_set, tx) = setup_utxo_and_tx();
        let mut mempool = Mempool::new();
        let tx_id = mempool.add(tx.clone(), &utxo_set, 100).unwrap();
        assert_eq!(mempool.len(), 1);
        let removed = mempool.remove(&tx_id).unwrap();
        assert_eq!(removed, tx);
        assert_eq!(mempool.len(), 0);
    }
}
