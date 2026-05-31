use crate::chain::state::UtxoSet;
use crate::consensus::cost;
use crate::consensus::validation::{validate_transaction, ValidationError};
use crate::events::EventBus;
use crate::types::hash::Hash256;
use crate::types::transaction::{OutPoint, Transaction};
use crate::types::{COINBASE_MATURITY, MEMPOOL_CAPACITY};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

/// Maximum total serialized bytes allowed in the mempool (256 MiB).
const MAX_MEMPOOL_BYTES: usize = 256 * 1024 * 1024;

/// A resolved spent input: the outpoint a mempool tx consumes plus the script
/// (32-byte address) and value of the UTXO it spent.
///
/// Captured at admission from the validation UTXO snapshot (which is already in
/// hand at every `add_validated` call site) and consumed at removal so the
/// spend-side `by_script` rows can be de-indexed without re-resolving against a
/// UTXO set that has since changed. The `value` also feeds the outgoing amounts
/// reported by `address_mempool`.
#[derive(Clone, Debug)]
struct SpentInput {
    outpoint: OutPoint,
    script: Vec<u8>,
    value: u64,
}

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
    /// Resolved UTXOs this tx spends — kept so the spend-side `by_script` index
    /// can be maintained at removal without re-resolving inputs.
    spent_inputs: Vec<SpentInput>,
}

/// Address-scoped view of one unconfirmed transaction, returned by
/// `Mempool::address_mempool`. Carries the outputs paying the queried address
/// (`received`) and the outpoints this tx spent that were locked to the queried
/// address (`spent`), each with amounts — enough for a wallet to render a
/// receiver-side pending delta without a follow-up per-tx lookup.
#[derive(Clone, Debug)]
pub struct MempoolAddressTx {
    pub tx_id: Hash256,
    /// (output_index, value) for outputs of this tx paying the queried address.
    pub received: Vec<(u32, u64)>,
    /// (spent_outpoint, value) for inputs of this tx that consumed a UTXO
    /// locked to the queried address.
    pub spent: Vec<(OutPoint, u64)>,
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
    /// Secondary index: script bytes (32-byte address) → the set of mempool
    /// tx_ids touching that script, either by paying an output to it OR by
    /// spending a UTXO locked to it. Mirrors `UtxoSet::by_script`. Bounded by
    /// the mempool cap, so always tiny. `BTreeSet` for deterministic iteration.
    by_script: BTreeMap<Vec<u8>, BTreeSet<Hash256>>,
    /// Total serialized bytes of all transactions currently in the mempool.
    total_bytes: usize,
    /// Optional Phase 2 SSE event bus. Emitted to from `index_entry` /
    /// `deindex_entry` so every mempool admission, removal, eviction,
    /// confirmation drop, and revalidation drop nudges any subscriber
    /// watching a touched script. `None` keeps the mempool standalone
    /// (e.g. in unit tests).
    event_bus: Option<Arc<EventBus>>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            entries: HashMap::new(),
            by_fee_density: BTreeMap::new(),
            spent_outpoints: HashSet::new(),
            by_script: BTreeMap::new(),
            total_bytes: 0,
            event_bus: None,
        }
    }

    /// Install the Phase 2 SSE event bus. Must be called once at startup,
    /// before any txs are admitted. After this point every script-touching
    /// mempool mutation (admit / remove / evict / revalidate / confirm)
    /// will nudge interested SSE subscribers.
    pub fn set_event_bus(&mut self, bus: Arc<EventBus>) {
        self.event_bus = Some(bus);
    }

    fn emit_script_changed(&self, script: &[u8]) {
        if let Some(bus) = &self.event_bus {
            bus.emit_script_changed(script);
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

    /// Resolve a tx's inputs against a UTXO snapshot into `SpentInput`s.
    ///
    /// Callers already hold a snapshot covering exactly these outpoints (the
    /// validation snapshot built via `UtxoSet::snapshot_for_outpoints`). Inputs
    /// not present in the snapshot are skipped — for a tx that passed validation
    /// against this snapshot that cannot happen, but skipping keeps the index
    /// maintenance total rather than panicking on an unexpected gap.
    fn resolve_spent_inputs(tx: &Transaction, resolved: &UtxoSet) -> Vec<SpentInput> {
        let mut spent = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
            if let Some(utxo) = resolved.get(&outpoint) {
                spent.push(SpentInput {
                    outpoint,
                    script: utxo.output.script.clone(),
                    value: utxo.output.value,
                });
            }
        }
        spent
    }

    /// Add this entry's tx_id to the `by_script` index under every script it
    /// touches — output scripts (incoming) and resolved spent-input scripts
    /// (outgoing).
    fn index_entry(&mut self, entry: &MempoolEntry) {
        for output in &entry.tx.outputs {
            self.by_script
                .entry(output.script.clone())
                .or_default()
                .insert(entry.tx_id);
            self.emit_script_changed(&output.script);
        }
        for spent in &entry.spent_inputs {
            self.by_script
                .entry(spent.script.clone())
                .or_default()
                .insert(entry.tx_id);
            self.emit_script_changed(&spent.script);
        }
    }

    /// Remove this entry's tx_id from the `by_script` index, pruning any script
    /// whose set becomes empty (mirrors `UtxoSet::remove`).
    fn deindex_entry(&mut self, entry: &MempoolEntry) {
        // Collect scripts first so we can emit AFTER the index update — the
        // semantic is "the new state is visible, go re-pull". A subscriber
        // that reacts faster than this method returns would still see the
        // stale set; doing it after is one less surprising race.
        let scripts: Vec<&Vec<u8>> = entry
            .tx
            .outputs
            .iter()
            .map(|o| &o.script)
            .chain(entry.spent_inputs.iter().map(|s| &s.script))
            .collect();
        for script in &scripts {
            if let Some(set) = self.by_script.get_mut(*script) {
                set.remove(&entry.tx_id);
                if set.is_empty() {
                    self.by_script.remove(*script);
                }
            }
        }
        for script in scripts {
            self.emit_script_changed(script);
        }
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
            spent_inputs: Self::resolve_spent_inputs(&tx, utxo_set),
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
        self.index_entry(&entry);
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
        resolved_inputs: &UtxoSet,
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
            spent_inputs: Self::resolve_spent_inputs(&tx, resolved_inputs),
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
        self.index_entry(&entry);
        self.entries.insert(tx_id, entry);

        Ok(tx_id)
    }

    /// Remove a transaction from the mempool (e.g., after it's been mined).
    pub fn remove(&mut self, tx_id: &Hash256) -> Option<Transaction> {
        if let Some(entry) = self.entries.remove(tx_id) {
            self.by_fee_density
                .remove(&(entry.fee_density, entry.tx_id));
            self.deindex_entry(&entry);
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
                self.deindex_entry(&entry);
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

    /// Return the unconfirmed transactions touching `script` (a 32-byte
    /// address), with the per-tx amounts a wallet needs to render a pending
    /// receiver-side balance. O(k) via the `by_script` index, where k = txs
    /// touching the script.
    ///
    /// For each touching tx: `received` lists the outputs paying `script`
    /// (index + value), and `spent` lists the outpoints this tx consumed that
    /// were locked to `script` (outpoint + value). A tx that both pays and
    /// spends `script` appears once with both populated.
    pub fn address_mempool(&self, script: &[u8]) -> Vec<MempoolAddressTx> {
        let tx_ids = match self.by_script.get(script) {
            Some(set) => set,
            None => return Vec::new(),
        };
        let mut out = Vec::with_capacity(tx_ids.len());
        for tx_id in tx_ids {
            let entry = match self.entries.get(tx_id) {
                Some(e) => e,
                None => continue,
            };
            let received: Vec<(u32, u64)> = entry
                .tx
                .outputs
                .iter()
                .enumerate()
                .filter(|(_, o)| o.script.as_slice() == script)
                .map(|(idx, o)| (idx as u32, o.value))
                .collect();
            let spent: Vec<(OutPoint, u64)> = entry
                .spent_inputs
                .iter()
                .filter(|s| s.script.as_slice() == script)
                .map(|s| (s.outpoint, s.value))
                .collect();
            out.push(MempoolAddressTx {
                tx_id: *tx_id,
                received,
                spent,
            });
        }
        out
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

    // ── by_script index (issue #15 Tier 1) ──

    fn script_of(pubkey: &[u8; 32]) -> Vec<u8> {
        TxOutput::pubkey_hash_from_key(pubkey).0.to_vec()
    }

    /// Build (utxo_set, signed tx, sender_script, recipient_script): the tx
    /// spends a fresh 1 EXFER UTXO locked to a random key and pays `recipient`.
    /// Distinct `seed` ⇒ distinct outpoint/txid.
    fn signed_spend(recipient: &[u8; 32], seed: &[u8]) -> (UtxoSet, Transaction, Vec<u8>, Vec<u8>) {
        let mut utxo_set = UtxoSet::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();
        let prev_tx_id = Hash256::sha256(seed);
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
        let mut tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(900_000_000, recipient)],
            witnesses: vec![TxWitness {
                witness: vec![0u8; 96],
                redeemer: None,
            }],
        };
        let sig_msg = tx.sig_message().unwrap();
        let signature = signing_key.sign(&sig_msg);
        let mut wd = Vec::with_capacity(96);
        wd.extend_from_slice(&pubkey);
        wd.extend_from_slice(&signature.to_bytes());
        tx.witnesses[0].witness = wd;
        (utxo_set, tx, script_of(&pubkey), script_of(recipient))
    }

    /// Admit via the production `add_validated` path: build the resolving
    /// snapshot the real call sites pass, validate for the costs, then admit.
    fn add_validated_with_snapshot(
        mempool: &mut Mempool,
        utxo_set: &UtxoSet,
        tx: Transaction,
        height: u64,
    ) -> Hash256 {
        let outpoints: Vec<OutPoint> = tx
            .inputs
            .iter()
            .map(|i| OutPoint::new(i.prev_tx_id, i.output_index))
            .collect();
        let snap = utxo_set.snapshot_for_outpoints(&outpoints);
        let (fee, sc, svc) = validate_transaction(&tx, utxo_set, height).expect("valid tx");
        mempool
            .add_validated(tx, fee, sc, svc, height, &snap)
            .expect("admit")
    }

    #[tokio::test]
    async fn add_validated_emits_script_changed_for_recipient_and_sender() {
        // Phase 2 SSE smoke: admitting a tx into the mempool should nudge
        // any subscriber watching either the recipient (incoming) script
        // or the sender (outgoing / spend-side) script.
        let recipient = [10u8; 32];
        let (utxo_set, tx, sender_script, recipient_script) = signed_spend(&recipient, b"E");
        let bus = crate::events::EventBus::new();
        let (_recv_id, mut recv_rx) = bus.subscribe(&[recipient_script.clone()]);
        let (_send_id, mut send_rx) = bus.subscribe(&[sender_script.clone()]);
        let mut mempool = Mempool::new();
        mempool.set_event_bus(bus);
        add_validated_with_snapshot(&mut mempool, &utxo_set, tx, 100);

        // Recipient subscriber must see its script in the nudge.
        match recv_rx.try_recv() {
            Ok(crate::events::ChainEvent::ScriptChanged(s)) => assert_eq!(s, recipient_script),
            other => panic!("recipient subscriber: expected ScriptChanged, got {:?}", other),
        }
        // Sender subscriber must see its (spent-input) script in the nudge.
        match send_rx.try_recv() {
            Ok(crate::events::ChainEvent::ScriptChanged(s)) => assert_eq!(s, sender_script),
            other => panic!("sender subscriber: expected ScriptChanged, got {:?}", other),
        }
    }

    #[test]
    fn add_validated_indexes_incoming_and_outgoing() {
        let recipient = [7u8; 32];
        let (utxo_set, tx, sender_script, recipient_script) = signed_spend(&recipient, b"A");
        let mut mempool = Mempool::new();
        let tx_id = add_validated_with_snapshot(&mut mempool, &utxo_set, tx, 100);
        assert!(
            mempool
                .by_script
                .get(&recipient_script)
                .unwrap()
                .contains(&tx_id),
            "output (incoming) script must be indexed"
        );
        assert!(
            mempool
                .by_script
                .get(&sender_script)
                .unwrap()
                .contains(&tx_id),
            "spent-input (outgoing) script must be indexed"
        );
    }

    #[test]
    fn remove_deindexes_both_sides() {
        let recipient = [8u8; 32];
        let (utxo_set, tx, sender_script, recipient_script) = signed_spend(&recipient, b"B");
        let mut mempool = Mempool::new();
        let tx_id = add_validated_with_snapshot(&mut mempool, &utxo_set, tx, 100);
        mempool.remove(&tx_id).unwrap();
        assert!(mempool.by_script.get(&recipient_script).is_none());
        assert!(mempool.by_script.get(&sender_script).is_none());
        assert!(mempool.by_script.is_empty(), "empty sets must be pruned");
    }

    #[test]
    fn evict_lowest_deindexes() {
        let recipient = [9u8; 32];
        let (utxo_set, tx, sender_script, recipient_script) = signed_spend(&recipient, b"C");
        let mut mempool = Mempool::new();
        add_validated_with_snapshot(&mut mempool, &utxo_set, tx, 100);
        mempool.evict_lowest();
        assert!(mempool.by_script.get(&recipient_script).is_none());
        assert!(mempool.by_script.get(&sender_script).is_none());
    }

    #[test]
    fn two_txs_same_recipient_coexist() {
        let recipient = [11u8; 32];
        let (us1, tx1, _s1, recipient_script) = signed_spend(&recipient, b"D1");
        let (us2, tx2, _s2, _r2) = signed_spend(&recipient, b"D2");
        let mut mempool = Mempool::new();
        let id1 = add_validated_with_snapshot(&mut mempool, &us1, tx1, 100);
        let id2 = add_validated_with_snapshot(&mut mempool, &us2, tx2, 100);
        let set = mempool.by_script.get(&recipient_script).unwrap();
        assert!(set.contains(&id1) && set.contains(&id2));
        mempool.remove(&id1).unwrap();
        let set = mempool.by_script.get(&recipient_script).unwrap();
        assert!(
            !set.contains(&id1) && set.contains(&id2),
            "removing one leaves the other indexed"
        );
    }

    #[test]
    fn address_mempool_reports_amounts() {
        let recipient = [12u8; 32];
        let (utxo_set, tx, sender_script, recipient_script) = signed_spend(&recipient, b"E");
        let mut mempool = Mempool::new();
        let tx_id = add_validated_with_snapshot(&mut mempool, &utxo_set, tx, 100);

        // Recipient side: one received output of 900_000_000, nothing spent.
        let recv = mempool.address_mempool(&recipient_script);
        assert_eq!(recv.len(), 1);
        assert_eq!(recv[0].tx_id, tx_id);
        assert_eq!(recv[0].received, vec![(0u32, 900_000_000)]);
        assert!(recv[0].spent.is_empty());

        // Sender side: one spent input of 1_000_000_000, nothing received.
        let sent = mempool.address_mempool(&sender_script);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].tx_id, tx_id);
        assert!(sent[0].received.is_empty());
        assert_eq!(sent[0].spent.len(), 1);
        assert_eq!(sent[0].spent[0].1, 1_000_000_000);
    }

    #[test]
    fn remove_confirmed_clears_by_script() {
        // Confirm path: a tx touching X in mempool, then its block confirms it.
        let recipient = [13u8; 32];
        let (utxo_set, tx, sender_script, recipient_script) = signed_spend(&recipient, b"F");
        let mut mempool = Mempool::new();
        add_validated_with_snapshot(&mut mempool, &utxo_set, tx.clone(), 100);
        assert!(mempool.by_script.contains_key(&recipient_script));
        mempool.remove_confirmed(&[tx]);
        assert!(mempool.by_script.get(&recipient_script).is_none());
        assert!(mempool.by_script.get(&sender_script).is_none());
        assert!(mempool.by_script.is_empty());
    }

    #[test]
    fn reorg_reintroduction_repopulates_by_script() {
        // Correction A (inverse): a tx in mempool is confirmed away, then a
        // reorg reintroduces it via add_validated — index rows must come back.
        let recipient = [14u8; 32];
        let (utxo_set, tx, sender_script, recipient_script) = signed_spend(&recipient, b"G");
        let mut mempool = Mempool::new();
        let id1 = add_validated_with_snapshot(&mut mempool, &utxo_set, tx.clone(), 100);
        mempool.remove_confirmed(&[tx.clone()]);
        assert!(mempool.by_script.is_empty(), "confirmed away");
        // Reorg orphans that block; the tx is re-validated against its snapshot
        // and re-admitted (the sync.rs:3052 reintroduction path).
        let id2 = add_validated_with_snapshot(&mut mempool, &utxo_set, tx, 100);
        assert_eq!(id1, id2, "same tx ⇒ same id");
        assert!(
            mempool
                .by_script
                .get(&recipient_script)
                .unwrap()
                .contains(&id2)
        );
        assert!(
            mempool
                .by_script
                .get(&sender_script)
                .unwrap()
                .contains(&id2)
        );
    }
}
