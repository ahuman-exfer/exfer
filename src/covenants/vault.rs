//! Vault covenant: timelock + recovery key.
//!
//! Two spending paths:
//! 1. **Normal**: primary key signs after locktime expires
//! 2. **Recovery**: recovery key can spend at any time (emergency)

use super::builder::ScriptBuilder;
use crate::script::ast::Program;

/// Create a vault script.
///
/// **Normal** witness: `[Left(Unit)][msg][sig_primary]`
/// **Recovery** witness: `[Right(Unit)][msg][sig_recovery]`
pub fn vault(primary_key: &[u8; 32], recovery_key: &[u8; 32], locktime: u64) -> Program {
    let mut b = ScriptBuilder::new();

    // Normal path: height_gt(locktime) AND sig_check(primary)
    let time_check = b.height_gt(locktime);
    let primary_check = b.sig_check(primary_key);
    let normal_path = b.and(time_check, primary_check);

    // Recovery path: just sig_check(recovery)
    let recovery_check = b.sig_check(recovery_key);

    // Dispatch based on witness selector
    let selector = b.witness();
    let case_node = b.case(normal_path, recovery_check);
    let _root = b.comp(selector, case_node);
    b.build()
}
