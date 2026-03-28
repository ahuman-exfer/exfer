//! Transaction context for introspection jets.
//!
//! Built once before script evaluation and shared across all inputs.
//! Uses `Arc` for the large fields (tx_inputs, tx_outputs, sig_hash) so
//! per-input clones are cheap refcount bumps, not deep copies.

use crate::types::hash::Hash256;
use std::sync::Arc;

/// Information about a transaction input for introspection.
#[derive(Clone, Debug)]
pub struct TxInputInfo {
    pub prev_tx_id: Hash256,
    pub output_index: u32,
    pub value: u64,
    pub script_hash: Hash256,
}

/// Information about a transaction output for introspection.
#[derive(Clone, Debug)]
pub struct TxOutputInfo {
    pub value: u64,
    pub script_hash: Hash256,
    pub datum_hash: Option<Hash256>,
}

/// Script evaluation context — provides transaction data to introspection jets.
///
/// Large fields use `Arc` so cloning for each input is O(1) (refcount bump)
/// rather than O(n) (deep copy of all vectors). Only `self_index` changes
/// per input.
#[derive(Clone, Debug)]
pub struct ScriptContext {
    pub tx_inputs: Arc<[TxInputInfo]>,
    pub tx_outputs: Arc<[TxOutputInfo]>,
    pub self_index: u32,
    pub block_height: u64,
    /// Domain-separated signing digest:
    /// `"EXFER-SIG" || genesis_block_id(32) || tx_header || tx_body`.
    /// Includes the genesis block ID to prevent cross-chain replay.
    /// Used by TxSigHash jet so covenant signatures bind to this transaction.
    pub sig_hash: Arc<[u8]>,
}

impl ScriptContext {
    /// Create an empty context (for testing or non-introspection scripts).
    pub fn empty() -> Self {
        ScriptContext {
            tx_inputs: Arc::from([]),
            tx_outputs: Arc::from([]),
            self_index: 0,
            block_height: 0,
            sig_hash: Arc::from([]),
        }
    }

    /// Create a context with the given self_index, sharing all other fields.
    /// This is O(1) — only bumps Arc refcounts and copies two scalars.
    pub fn with_self_index(&self, idx: u32) -> Self {
        ScriptContext {
            self_index: idx,
            block_height: self.block_height,
            tx_inputs: Arc::clone(&self.tx_inputs),
            tx_outputs: Arc::clone(&self.tx_outputs),
            sig_hash: Arc::clone(&self.sig_hash),
        }
    }
}
