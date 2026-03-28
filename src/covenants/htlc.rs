//! Hash Time-Locked Contract (HTLC) for atomic swaps.
//!
//! Two spending paths:
//! 1. **Hash path**: receiver reveals preimage + signs (before timeout)
//! 2. **Timeout path**: sender reclaims after block height exceeds timeout

use super::builder::ScriptBuilder;
use crate::script::ast::Program;
use crate::types::hash::Hash256;

/// Create an HTLC script.
///
/// **Hash path** witness: `[Left(Unit)][preimage_bytes][msg][sig_receiver]`
/// **Timeout path** witness: `[Right(Unit)][msg][sig_sender]`
pub fn htlc(
    sender_key: &[u8; 32],
    receiver_key: &[u8; 32],
    hash_lock: &Hash256,
    timeout_height: u64,
) -> Program {
    let mut b = ScriptBuilder::new();

    // Hash path: hash_eq(lock) AND sig_check(receiver)
    let hash_check = b.hash_eq(hash_lock);
    let receiver_check = b.sig_check(receiver_key);
    let hash_path = b.and(hash_check, receiver_check);

    // Timeout path: height_gt(timeout) AND sig_check(sender)
    let timeout_check = b.height_gt(timeout_height);
    let sender_check = b.sig_check(sender_key);
    let timeout_path = b.and(timeout_check, sender_check);

    // Dispatch based on witness selector
    let selector = b.witness();
    let case_node = b.case(hash_path, timeout_path);
    let _root = b.comp(selector, case_node);
    b.build()
}
