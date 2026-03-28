//! Delegation covenant: owner or time-limited delegate.
//!
//! Two spending paths:
//! 1. **Owner**: owner key can spend at any time
//! 2. **Delegate**: delegate key can spend only before expiry height

use super::builder::ScriptBuilder;
use crate::script::ast::Program;

/// Create a delegation script.
///
/// **Owner** witness: `[Left(Unit)][msg][sig_owner]`
/// **Delegate** witness: `[Right(Unit)][msg][sig_delegate]`
pub fn delegation(owner_key: &[u8; 32], delegate_key: &[u8; 32], expiry_height: u64) -> Program {
    let mut b = ScriptBuilder::new();

    // Owner path: just sig_check
    let owner_check = b.sig_check(owner_key);

    // Delegate path: sig_check AND height < expiry
    let delegate_check = b.sig_check(delegate_key);
    let time_check = b.height_lt(expiry_height);
    let delegate_path = b.and(delegate_check, time_check);

    // Dispatch based on witness selector
    let selector = b.witness();
    let case_node = b.case(owner_check, delegate_path);
    let _root = b.comp(selector, case_node);
    b.build()
}
