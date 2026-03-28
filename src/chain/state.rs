use crate::chain::smt::{self, SparseMerkleTree};
use crate::types::hash::Hash256;
use crate::types::transaction::{OutPoint, SerError, Transaction, TxOutput};
use std::collections::BTreeMap;

/// Errors from UTXO state mutations (apply/undo).
#[derive(Debug, Clone)]
pub enum StateError {
    /// An input references a UTXO that doesn't exist in the set.
    InputNotFound(OutPoint),
    /// An output to be undone doesn't exist in the set.
    OutputNotFound(OutPoint),
    /// A spent UTXO being restored already exists (duplicate restore).
    DuplicateRestore(OutPoint),
    /// An outpoint already exists during forward insertion (invariant violation).
    DuplicateOutpoint(OutPoint),
    /// Serialization failure (e.g. oversized fields).
    Serialization(String),
    /// Undo received fewer spent UTXOs than the transaction has inputs.
    IncompleteUndo { expected: usize, got: usize },
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::InputNotFound(op) => write!(f, "input UTXO not found: {:?}", op),
            StateError::OutputNotFound(op) => write!(f, "output to undo not found: {:?}", op),
            StateError::DuplicateRestore(op) => write!(f, "duplicate UTXO restore: {:?}", op),
            StateError::DuplicateOutpoint(op) => {
                write!(f, "duplicate outpoint insertion: {:?}", op)
            }
            StateError::Serialization(msg) => write!(f, "serialization error: {}", msg),
            StateError::IncompleteUndo { expected, got } => write!(
                f,
                "incomplete undo: expected {} spent UTXOs, got {}",
                expected, got
            ),
        }
    }
}

impl From<SerError> for StateError {
    fn from(e: SerError) -> Self {
        StateError::Serialization(format!("{:?}", e))
    }
}

/// Information about a UTXO stored in the set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    pub output: TxOutput,
    /// Block height at which this UTXO was created.
    pub height: u64,
    /// Whether this UTXO came from a coinbase transaction.
    pub is_coinbase: bool,
}

/// The UTXO set: maps OutPoint → UtxoEntry.
/// Uses BTreeMap internally for deterministic ordering.
/// Uses a Sparse Merkle Tree for state_root computation.
/// Maintains a secondary script→outpoints index for O(1) address lookups.
#[derive(Clone, Debug)]
pub struct UtxoSet {
    utxos: BTreeMap<OutPoint, UtxoEntry>,
    smt: SparseMerkleTree,
    /// Secondary index: script bytes → set of OutPoints with that script.
    /// Kept in sync with utxos on every insert/remove.
    by_script: BTreeMap<Vec<u8>, std::collections::BTreeSet<OutPoint>>,
}

impl UtxoSet {
    pub fn new() -> Self {
        UtxoSet {
            utxos: BTreeMap::new(),
            smt: SparseMerkleTree::new(),
            by_script: BTreeMap::new(),
        }
    }

    /// Look up a UTXO by outpoint.
    pub fn get(&self, outpoint: &OutPoint) -> Option<&UtxoEntry> {
        self.utxos.get(outpoint)
    }

    /// Create a lightweight snapshot containing only the UTXOs referenced by
    /// the given outpoints. Used for transaction validation outside the main
    /// UTXO read lock — the snapshot is a point-in-time copy that does not
    /// block writers.  The SMT is left empty (not needed for validation reads).
    pub fn snapshot_for_outpoints(&self, outpoints: &[OutPoint]) -> UtxoSet {
        let mut utxos = BTreeMap::new();
        for op in outpoints {
            if let Some(entry) = self.utxos.get(op) {
                utxos.insert(*op, entry.clone());
            }
        }
        UtxoSet {
            utxos,
            smt: SparseMerkleTree::new(),
            by_script: BTreeMap::new(), // Not needed for validation snapshots
        }
    }

    /// Check if a UTXO exists.
    #[allow(dead_code)]
    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.utxos.contains_key(outpoint)
    }

    /// Add a UTXO to the set.
    /// Returns Err if the outpoint already exists (invariant violation)
    /// or the output cannot be serialized (oversized fields).
    pub fn insert(&mut self, outpoint: OutPoint, entry: UtxoEntry) -> Result<(), StateError> {
        if self.utxos.contains_key(&outpoint) {
            return Err(StateError::DuplicateOutpoint(outpoint));
        }
        // Compute SMT leaf key and value
        let key = smt::leaf_key(&outpoint.tx_id, outpoint.output_index);
        let value = smt::leaf_value(&entry.output.serialize()?, entry.height, entry.is_coinbase);
        self.smt.insert(key, value);
        let script = entry.output.script.clone();
        self.utxos.insert(outpoint, entry);
        self.by_script.entry(script).or_default().insert(outpoint);
        Ok(())
    }

    /// Remove a UTXO from the set. Returns the entry if it existed.
    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        if let Some(entry) = self.utxos.remove(outpoint) {
            let key = smt::leaf_key(&outpoint.tx_id, outpoint.output_index);
            self.smt.remove(&key);
            // Maintain secondary index
            if let Some(set) = self.by_script.get_mut(&entry.output.script) {
                set.remove(outpoint);
                if set.is_empty() {
                    self.by_script.remove(&entry.output.script);
                }
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Number of UTXOs in the set.
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Return SMT node and leaf counts for memory diagnostics.
    pub fn smt_stats(&self) -> (usize, usize) {
        (self.smt.node_count(), self.smt.leaf_count())
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// Apply a transaction to the UTXO set.
    /// Removes spent inputs and adds new outputs.
    /// Returns Err if any input UTXO is missing or serialization fails.
    pub fn apply_transaction(&mut self, tx: &Transaction, height: u64) -> Result<(), StateError> {
        let tx_id = tx.tx_id()?;
        let is_coinbase = tx.is_coinbase();

        // Remove spent inputs (skip for coinbase)
        if !is_coinbase {
            for input in &tx.inputs {
                let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
                if self.remove(&outpoint).is_none() {
                    return Err(StateError::InputNotFound(outpoint));
                }
            }
        }

        // Add new outputs
        for (idx, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint::new(tx_id, idx as u32);
            self.insert(
                outpoint,
                UtxoEntry {
                    output: output.clone(),
                    height,
                    is_coinbase,
                },
            )?;
        }
        Ok(())
    }

    /// Undo a transaction (for reorgs). Inverse of apply_transaction.
    /// `prev_utxos` provides the UTXOs that were spent by this transaction
    /// (needed to restore them).
    /// Returns Err if any output to undo is missing or a restore would duplicate.
    pub fn undo_transaction(
        &mut self,
        tx: &Transaction,
        prev_utxos: &[(OutPoint, UtxoEntry)],
    ) -> Result<(), StateError> {
        // Non-coinbase txs must have exactly as many spent UTXOs as inputs.
        // Coinbase txs have no real inputs (prev_tx_id = ZERO) — 0 is correct.
        if !tx.is_coinbase() && prev_utxos.len() != tx.inputs.len() {
            return Err(StateError::IncompleteUndo {
                expected: tx.inputs.len(),
                got: prev_utxos.len(),
            });
        }

        let tx_id = tx.tx_id()?;

        // Remove outputs added by this transaction
        for idx in 0..tx.outputs.len() {
            let outpoint = OutPoint::new(tx_id, idx as u32);
            if self.remove(&outpoint).is_none() {
                return Err(StateError::OutputNotFound(outpoint));
            }
        }

        // Restore spent inputs
        for (outpoint, entry) in prev_utxos {
            if self.contains(outpoint) {
                return Err(StateError::DuplicateRestore(*outpoint));
            }
            self.insert(*outpoint, entry.clone())?;
        }
        Ok(())
    }

    /// Undo a potentially partially-applied transaction.
    ///
    /// Unlike `undo_transaction`, this tolerates missing outputs and
    /// already-present inputs — it handles the case where
    /// `apply_transaction` failed mid-way through removing inputs or
    /// inserting outputs.
    ///
    /// `prev_utxos` provides snapshots of the UTXOs that the transaction
    /// *would* have consumed.  Any that are already present in the set
    /// (i.e. were never actually removed) are skipped.
    pub fn undo_partial_transaction(
        &mut self,
        tx: &Transaction,
        prev_utxos: &[(OutPoint, UtxoEntry)],
    ) -> Result<(), StateError> {
        let tx_id = tx.tx_id()?;

        // Remove any outputs that were inserted (ignore missing).
        for idx in 0..tx.outputs.len() {
            let outpoint = OutPoint::new(tx_id, idx as u32);
            let _ = self.remove(&outpoint);
        }

        // Restore any inputs that were removed (skip already-present).
        if !tx.is_coinbase() {
            for (outpoint, entry) in prev_utxos {
                if !self.contains(outpoint) {
                    self.insert(*outpoint, entry.clone())?;
                }
            }
        }
        Ok(())
    }

    /// Compute the state root (UTXO set commitment) via Sparse Merkle Tree.
    pub fn state_root(&self) -> Hash256 {
        self.smt.root()
    }

    /// Iterate over all UTXOs.
    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &UtxoEntry)> {
        self.utxos.iter()
    }

    /// Collect balance for a script. O(k) where k = UTXOs for this script,
    /// not O(n) over the entire UTXO set. Uses the by_script secondary index.
    pub fn balance_for_script(&self, script: &[u8], current_height: u64) -> u64 {
        let outpoints = match self.by_script.get(script) {
            Some(set) => set,
            None => return 0,
        };
        let mut total = 0u64;
        for op in outpoints {
            if let Some(entry) = self.utxos.get(op) {
                if entry.is_coinbase
                    && current_height.saturating_sub(entry.height) < super::super::types::COINBASE_MATURITY
                {
                    continue;
                }
                total = total.saturating_add(entry.output.value);
            }
        }
        total
    }

    /// Collect UTXOs matching a script into a Vec snapshot. O(k) where k = UTXOs
    /// for this script. Returns at most `limit` mature entries.
    pub fn utxos_for_script(
        &self,
        script: &[u8],
        current_height: u64,
        limit: usize,
    ) -> Vec<(OutPoint, u64, u64, bool)> {
        let outpoints = match self.by_script.get(script) {
            Some(set) => set,
            None => return Vec::new(),
        };
        let mut results = Vec::new();
        for op in outpoints {
            if let Some(entry) = self.utxos.get(op) {
                let mature = if entry.is_coinbase {
                    current_height.saturating_sub(entry.height) >= super::super::types::COINBASE_MATURITY
                } else {
                    true
                };
                if mature {
                    results.push((*op, entry.output.value, entry.height, entry.is_coinbase));
                    if results.len() >= limit {
                        break;
                    }
                }
            }
        }
        results
    }
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::transaction::{TxInput, TxOutput, TxWitness};

    fn make_coinbase(height: u64, value: u64) -> Transaction {
        let pubkey = [1u8; 32];
        Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: height as u32,
            }],
            outputs: vec![TxOutput::new_p2pkh(value, &pubkey)],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        }
    }

    #[test]
    fn test_apply_coinbase() {
        let mut utxo_set = UtxoSet::new();
        let cb = make_coinbase(0, 10_000_000_000);
        let tx_id = cb.tx_id().unwrap();
        utxo_set.apply_transaction(&cb, 0).unwrap();

        assert_eq!(utxo_set.len(), 1);
        let outpoint = OutPoint::new(tx_id, 0);
        let entry = utxo_set.get(&outpoint).unwrap();
        assert_eq!(entry.output.value, 10_000_000_000);
        assert!(entry.is_coinbase);
        assert_eq!(entry.height, 0);
    }

    #[test]
    fn test_apply_and_undo() {
        let mut utxo_set = UtxoSet::new();
        let cb = make_coinbase(0, 10_000_000_000);
        let cb_tx_id = cb.tx_id().unwrap();
        utxo_set.apply_transaction(&cb, 0).unwrap();

        // Spend the coinbase output
        let spend_tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: cb_tx_id,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(9_000_000_000, &[2u8; 32])],
            witnesses: vec![TxWitness {
                witness: vec![0u8; 96],
                redeemer: None,
            }],
        };

        // Save the UTXO being spent for undo
        let outpoint = OutPoint::new(cb_tx_id, 0);
        let prev_entry = utxo_set.get(&outpoint).unwrap().clone();

        utxo_set.apply_transaction(&spend_tx, 1).unwrap();
        assert_eq!(utxo_set.len(), 1);
        assert!(!utxo_set.contains(&outpoint));

        // Undo the spend
        utxo_set
            .undo_transaction(&spend_tx, &[(outpoint, prev_entry)])
            .unwrap();
        assert_eq!(utxo_set.len(), 1);
        assert!(utxo_set.contains(&outpoint));
    }

    #[test]
    fn test_state_root_deterministic() {
        let mut utxo_set = UtxoSet::new();
        let cb = make_coinbase(0, 10_000_000_000);
        utxo_set.apply_transaction(&cb, 0).unwrap();

        let root1 = utxo_set.state_root();
        let root2 = utxo_set.state_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_state_root_changes() {
        let mut utxo_set = UtxoSet::new();
        let cb1 = make_coinbase(0, 10_000_000_000);
        utxo_set.apply_transaction(&cb1, 0).unwrap();
        let root1 = utxo_set.state_root();

        let cb2 = make_coinbase(1, 10_000_000_000);
        utxo_set.apply_transaction(&cb2, 1).unwrap();
        let root2 = utxo_set.state_root();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_empty_state_root() {
        let utxo_set = UtxoSet::new();
        let root = utxo_set.state_root();
        assert_eq!(root, crate::chain::smt::empty_root());
    }

    #[test]
    fn test_state_root_after_undo_matches_before() {
        let mut utxo_set = UtxoSet::new();
        let cb = make_coinbase(0, 10_000_000_000);
        let cb_tx_id = cb.tx_id().unwrap();
        utxo_set.apply_transaction(&cb, 0).unwrap();
        let root_before = utxo_set.state_root();

        let spend_tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: cb_tx_id,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(9_000_000_000, &[2u8; 32])],
            witnesses: vec![TxWitness {
                witness: vec![0u8; 96],
                redeemer: None,
            }],
        };

        let outpoint = OutPoint::new(cb_tx_id, 0);
        let prev_entry = utxo_set.get(&outpoint).unwrap().clone();

        utxo_set.apply_transaction(&spend_tx, 1).unwrap();
        assert_ne!(utxo_set.state_root(), root_before);

        utxo_set
            .undo_transaction(&spend_tx, &[(outpoint, prev_entry)])
            .unwrap();
        assert_eq!(utxo_set.state_root(), root_before);
    }
}
