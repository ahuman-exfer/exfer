//! Escrow covenant: three-path spending (mutual, arbiter, timeout).
//!
//! 1. **Mutual**: both parties sign to release funds
//! 2. **Arbiter**: trusted third-party decides the outcome
//! 3. **Timeout**: after expiry, party_a can reclaim (refund)

use super::builder::ScriptBuilder;
use crate::script::ast::Program;

/// Create an escrow script.
///
/// **Mutual** witness: `[Left(Left(Unit))][msg_a][sig_a][msg_b][sig_b]`
/// **Arbiter** witness: `[Left(Right(Unit))][msg_arb][sig_arb]`
/// **Timeout** witness: `[Right(Unit)][msg_a][sig_a]`
pub fn escrow(
    party_a: &[u8; 32],
    party_b: &[u8; 32],
    arbiter: &[u8; 32],
    timeout_height: u64,
) -> Program {
    let mut b = ScriptBuilder::new();

    // Mutual close: both parties sign
    let check_a = b.sig_check(party_a);
    let check_b = b.sig_check(party_b);
    let mutual = b.and(check_a, check_b);

    // Arbiter decision
    let arbiter_check = b.sig_check(arbiter);

    // Timeout refund to party_a
    let timeout = b.height_gt(timeout_height);
    let refund_check = b.sig_check(party_a);
    let timeout_path = b.and(timeout, refund_check);

    // Inner case: Left(Unit) -> mutual, Right(Unit) -> arbiter
    let inner_case = b.case(mutual, arbiter_check);

    // Outer case: Left(x) -> inner dispatch, Right(Unit) -> timeout
    let outer_case = b.case(inner_case, timeout_path);

    // Read selector from witness and dispatch
    let selector = b.witness();
    let _root = b.comp(selector, outer_case);
    b.build()
}
