//! Multisig covenant templates: N-of-M threshold signature schemes.

use super::builder::ScriptBuilder;
use crate::script::ast::Program;

/// 2-of-2 multisig: both parties must sign.
///
/// Witness data (in order):
/// 1. `Bytes(msg_a)`, `Bytes(sig_a)` for key A
/// 2. `Bytes(msg_b)`, `Bytes(sig_b)` for key B
pub fn multisig_2of2(pk_a: &[u8; 32], pk_b: &[u8; 32]) -> Program {
    let mut b = ScriptBuilder::new();
    let check_a = b.sig_check(pk_a);
    let check_b = b.sig_check(pk_b);
    let _root = b.and(check_a, check_b);
    b.build()
}

/// 1-of-2 multisig: either party can sign.
///
/// Witness data:
/// 1. Selector: `Left(Unit)` for key A, `Right(Unit)` for key B
/// 2. `Bytes(msg)`, `Bytes(sig)` for the chosen key
pub fn multisig_1of2(pk_a: &[u8; 32], pk_b: &[u8; 32]) -> Program {
    let mut b = ScriptBuilder::new();
    let check_a = b.sig_check(pk_a);
    let check_b = b.sig_check(pk_b);
    let selector = b.witness();
    let case_node = b.case(check_a, check_b);
    let _root = b.comp(selector, case_node);
    b.build()
}

/// 2-of-3 multisig: any two of three parties must sign.
///
/// Uses Case-based dispatch. The spender selects which pair of keys to use.
///
/// Witness data:
/// 1. Selector: `Left(Left(Unit))` for A+B, `Left(Right(Unit))` for A+C,
///    `Right(Unit)` for B+C
/// 2. `Bytes(msg_1)`, `Bytes(sig_1)`, `Bytes(msg_2)`, `Bytes(sig_2)` for
///    the chosen pair
pub fn multisig_2of3(pk_a: &[u8; 32], pk_b: &[u8; 32], pk_c: &[u8; 32]) -> Program {
    let mut b = ScriptBuilder::new();

    // Combination A+B
    let check_a1 = b.sig_check(pk_a);
    let check_b1 = b.sig_check(pk_b);
    let combo_ab = b.and(check_a1, check_b1);

    // Combination A+C
    let check_a2 = b.sig_check(pk_a);
    let check_c1 = b.sig_check(pk_c);
    let combo_ac = b.and(check_a2, check_c1);

    // Combination B+C
    let check_b2 = b.sig_check(pk_b);
    let check_c2 = b.sig_check(pk_c);
    let combo_bc = b.and(check_b2, check_c2);

    // Inner case: Left(Unit) -> A+B, Right(Unit) -> A+C
    let inner_case = b.case(combo_ab, combo_ac);

    // Outer case: Left(x) -> inner dispatch, Right(Unit) -> B+C
    let outer_case = b.case(inner_case, combo_bc);

    // Read selector from witness and dispatch
    let selector = b.witness();
    let _root = b.comp(selector, outer_case);
    b.build()
}
