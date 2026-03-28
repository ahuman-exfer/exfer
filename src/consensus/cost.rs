use crate::consensus::validation::is_phase1_script;
use crate::types::transaction::Transaction;
use crate::types::{
    MIN_FEE_DIVISOR, OUTPUT_TYPECHECK_COST, PHASE1_SCRIPT_EVAL_COST, SMT_DELETE_COST,
    SMT_INSERT_COST, UTXO_CREATE_COST, UTXO_LOOKUP_COST,
};

/// Compute ceil_div(a, b) using u128 intermediates to prevent overflow.
/// Returns None if result > u64::MAX.
pub fn ceil_div_u128(a: u64, b: u64) -> Option<u64> {
    let a = a as u128;
    let b = b as u128;
    let result = a.div_ceil(b);
    if result > u64::MAX as u128 {
        None
    } else {
        Some(result as u64)
    }
}

/// Compute the total cost of a transaction.
///
/// tx_cost = script_eval_cost
///         + output_typecheck_cost
///         + witness_deser_cost
///         + datum_deser_cost
///         + tx_deser_cost
///         + utxo_io_cost
///         + smt_cost
///         + script_validation_cost
///
/// Returns None if the total overflows u64.
/// For Phase 1 (pubkey-hash) inputs, script_validation_cost is 0.
pub fn tx_cost(tx: &Transaction) -> Option<u64> {
    let input_count = tx.inputs.len() as u64;
    let output_count = tx.outputs.len() as u64;

    // 1. script_eval_cost: Phase 1 = 5000 + ceil_div(sig_message_bytes, 64) × 8 per input
    let sig_message_bytes = tx.sig_message().ok()?.len() as u64;
    let per_input_cost =
        (PHASE1_SCRIPT_EVAL_COST as u128) + (sig_message_bytes.div_ceil(64) as u128) * 8;
    let script_eval_cost = (input_count as u128) * per_input_cost;

    // 2. output_typecheck_cost: OUTPUT_TYPECHECK_COST per non-Phase-1 output
    let mut output_typecheck_cost: u128 = 0;
    for output in &tx.outputs {
        if !is_phase1_script(&output.script) {
            // Non-Phase-1 script: deserialization + typecheck + strict edges + jet scan
            output_typecheck_cost += OUTPUT_TYPECHECK_COST as u128;
        }
    }

    // 3. witness_deser_cost: sum of ceil_div(witness_bytes, 64) per input
    let mut witness_deser_cost: u128 = 0;
    for witness in &tx.witnesses {
        let witness_bytes = witness.witness.len() as u64;
        if witness_bytes > 0 {
            let cost = ceil_div_u128(witness_bytes, 64)?;
            witness_deser_cost += cost as u128;
        }
        // redeemer bytes also count
        if let Some(ref redeemer) = witness.redeemer {
            let redeemer_bytes = redeemer.len() as u64;
            if redeemer_bytes > 0 {
                let cost = ceil_div_u128(redeemer_bytes, 64)?;
                witness_deser_cost += cost as u128;
            }
        }
    }

    // 4. datum_deser_cost: sum of ceil_div(datum_bytes, 64) per output
    //    (In Phase 1, datums are always None, so this is 0)
    let mut datum_deser_cost: u128 = 0;
    for output in &tx.outputs {
        if let Some(ref datum) = output.datum {
            let datum_bytes = datum.len() as u64;
            if datum_bytes > 0 {
                let cost = ceil_div_u128(datum_bytes, 64)?;
                datum_deser_cost += cost as u128;
            }
        }
    }

    // 5. tx_deser_cost: ceil_div(total_tx_bytes, 64)
    let total_tx_bytes = tx.serialize().ok()?.len() as u64;
    let tx_deser_cost = ceil_div_u128(total_tx_bytes, 64)? as u128;

    // 6. utxo_io_cost: input_count × UTXO_LOOKUP_COST + output_count × UTXO_CREATE_COST
    let utxo_io_cost = (input_count as u128) * (UTXO_LOOKUP_COST as u128)
        + (output_count as u128) * (UTXO_CREATE_COST as u128);

    // 7. smt_cost: input_count × SMT_DELETE_COST + output_count × SMT_INSERT_COST
    let smt_cost = (input_count as u128) * (SMT_DELETE_COST as u128)
        + (output_count as u128) * (SMT_INSERT_COST as u128);

    // 8. script_validation_cost: ceil_div(script_bytes, 64) × 10 per script-locked input
    //    Phase 1 inputs are not script-locked, so this is 0 for tx_cost.
    let script_validation_cost: u128 = 0;

    // Sum all components
    let total = script_eval_cost
        + output_typecheck_cost
        + witness_deser_cost
        + datum_deser_cost
        + tx_deser_cost
        + utxo_io_cost
        + smt_cost
        + script_validation_cost;

    if total > u64::MAX as u128 {
        None
    } else {
        Some(total as u64)
    }
}

/// Compute the minimum fee for a transaction.
/// min_fee = ceil_div(tx_cost, MIN_FEE_DIVISOR)
/// Returns None if tx_cost overflows or min_fee overflows u64.
pub fn min_fee(tx: &Transaction) -> Option<u64> {
    let cost = tx_cost(tx)?;
    ceil_div_u128(cost, MIN_FEE_DIVISOR)
}

/// Compute tx_cost using actual script evaluation cost (for Phase 2+ scripts).
///
/// Same as `tx_cost` but substitutes the script_eval_cost component with
/// the caller-provided actual cost instead of using PHASE1_SCRIPT_EVAL_COST.
/// `script_validation_cost` covers deserialization, canonicalization,
/// type-checking, and cost analysis of spent script-locked outputs.
pub fn tx_cost_with_script_cost(
    tx: &Transaction,
    script_eval_cost: u128,
    script_validation_cost: u128,
) -> Option<u64> {
    let input_count = tx.inputs.len() as u64;
    let output_count = tx.outputs.len() as u64;

    // 1. script_eval_cost: provided by caller (actual cost)
    // (already in script_eval_cost parameter)

    // 2. output_typecheck_cost: OUTPUT_TYPECHECK_COST per non-Phase-1 output
    let mut output_typecheck_cost: u128 = 0;
    for output in &tx.outputs {
        if !is_phase1_script(&output.script) {
            output_typecheck_cost += OUTPUT_TYPECHECK_COST as u128;
        }
    }

    // 3. witness_deser_cost
    let mut witness_deser_cost: u128 = 0;
    for witness in &tx.witnesses {
        let witness_bytes = witness.witness.len() as u64;
        if witness_bytes > 0 {
            let cost = ceil_div_u128(witness_bytes, 64)?;
            witness_deser_cost += cost as u128;
        }
        if let Some(ref redeemer) = witness.redeemer {
            let redeemer_bytes = redeemer.len() as u64;
            if redeemer_bytes > 0 {
                let cost = ceil_div_u128(redeemer_bytes, 64)?;
                witness_deser_cost += cost as u128;
            }
        }
    }

    // 4. datum_deser_cost
    let mut datum_deser_cost: u128 = 0;
    for output in &tx.outputs {
        if let Some(ref datum) = output.datum {
            let datum_bytes = datum.len() as u64;
            if datum_bytes > 0 {
                let cost = ceil_div_u128(datum_bytes, 64)?;
                datum_deser_cost += cost as u128;
            }
        }
    }

    // 5. tx_deser_cost
    let total_tx_bytes = tx.serialize().ok()?.len() as u64;
    let tx_deser_cost = ceil_div_u128(total_tx_bytes, 64)? as u128;

    // 6. utxo_io_cost
    let utxo_io_cost = (input_count as u128) * (UTXO_LOOKUP_COST as u128)
        + (output_count as u128) * (UTXO_CREATE_COST as u128);

    // 7. smt_cost
    let smt_cost = (input_count as u128) * (SMT_DELETE_COST as u128)
        + (output_count as u128) * (SMT_INSERT_COST as u128);

    // 8. script_validation_cost: provided by caller
    // (deserialization + canonicalization + typecheck + cost analysis of script-locked inputs)

    let total = script_eval_cost
        + output_typecheck_cost
        + witness_deser_cost
        + datum_deser_cost
        + tx_deser_cost
        + utxo_io_cost
        + smt_cost
        + script_validation_cost;

    if total > u64::MAX as u128 {
        None
    } else {
        Some(total as u64)
    }
}

/// Compute min_fee using actual script evaluation cost.
pub fn min_fee_with_script_cost(
    tx: &Transaction,
    script_eval_cost: u128,
    script_validation_cost: u128,
) -> Option<u64> {
    let cost = tx_cost_with_script_cost(tx, script_eval_cost, script_validation_cost)?;
    ceil_div_u128(cost, MIN_FEE_DIVISOR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::hash::Hash256;
    use crate::types::transaction::{TxInput, TxOutput, TxWitness};

    fn make_simple_tx() -> Transaction {
        let pubkey = [1u8; 32];
        Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::sha256(b"prev"),
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(1000, &pubkey)],
            witnesses: vec![TxWitness {
                witness: vec![0u8; 96], // pubkey(32) + sig(64)
                redeemer: None,
            }],
        }
    }

    #[test]
    fn test_ceil_div_basic() {
        assert_eq!(ceil_div_u128(10, 3), Some(4));
        assert_eq!(ceil_div_u128(9, 3), Some(3));
        assert_eq!(ceil_div_u128(1, 1), Some(1));
        assert_eq!(ceil_div_u128(0, 1), Some(0));
        assert_eq!(ceil_div_u128(100, 64), Some(2));
        assert_eq!(ceil_div_u128(64, 64), Some(1));
        assert_eq!(ceil_div_u128(65, 64), Some(2));
    }

    #[test]
    fn test_tx_cost_basic() {
        let tx = make_simple_tx();
        let cost = tx_cost(&tx).unwrap();

        // 1 input, 1 output:
        // script_eval_cost = 1 × (5000 + ceil(sig_msg_bytes/64) × 8)
        // output_typecheck_cost = 0
        // witness_deser_cost = ceil(96/64) = 2
        // datum_deser_cost = 0
        // tx_deser_cost = ceil(tx_bytes/64)
        // utxo_io_cost = 1 × 100 + 1 × 100 = 200
        // smt_cost = 1 × 500 + 1 × 500 = 1000
        // script_validation_cost = 0 (Phase 1 inputs)

        let sig_msg_bytes = tx.sig_message().unwrap().len() as u64;
        let sig_msg_cost = sig_msg_bytes.div_ceil(64) * 8;
        let tx_bytes = tx.serialize().unwrap().len() as u64;
        let expected_deser = ceil_div_u128(tx_bytes, 64).unwrap();
        #[allow(clippy::identity_op)]
        let expected = (5000 + sig_msg_cost) + 0 + 2 + 0 + expected_deser + 200 + 1000;
        assert_eq!(cost, expected);
    }

    #[test]
    fn test_min_fee_basic() {
        let tx = make_simple_tx();
        let cost = tx_cost(&tx).unwrap();
        let fee = min_fee(&tx).unwrap();
        let expected = ceil_div_u128(cost, 100).unwrap();
        assert_eq!(fee, expected);
    }

    #[test]
    fn test_min_fee_positive() {
        // Any non-trivial transaction should have min_fee > 0
        let tx = make_simple_tx();
        let fee = min_fee(&tx).unwrap();
        assert!(fee > 0, "min_fee should be > 0 for any real transaction");
    }

    #[test]
    fn test_tx_cost_multiple_inputs_outputs() {
        let pubkey = [1u8; 32];
        let tx = Transaction {
            inputs: vec![
                TxInput {
                    prev_tx_id: Hash256::sha256(b"prev1"),
                    output_index: 0,
                },
                TxInput {
                    prev_tx_id: Hash256::sha256(b"prev2"),
                    output_index: 1,
                },
            ],
            outputs: vec![
                TxOutput::new_p2pkh(500, &pubkey),
                TxOutput::new_p2pkh(300, &pubkey),
                TxOutput::new_p2pkh(200, &pubkey),
            ],
            witnesses: vec![
                TxWitness {
                    witness: vec![0u8; 96],
                    redeemer: None,
                },
                TxWitness {
                    witness: vec![0u8; 96],
                    redeemer: None,
                },
            ],
        };
        let cost = tx_cost(&tx).unwrap();

        // 2 inputs, 3 outputs:
        // script_eval_cost = 2 × (5000 + ceil(sig_msg_bytes/64) × 8)
        // witness_deser_cost = 2 × ceil(96/64) = 2 × 2 = 4
        // utxo_io_cost = 2 × 100 + 3 × 100 = 500
        // smt_cost = 2 × 500 + 3 × 500 = 2500

        let sig_msg_bytes = tx.sig_message().unwrap().len() as u64;
        let per_input = 5000 + sig_msg_bytes.div_ceil(64) * 8;
        let tx_bytes = tx.serialize().unwrap().len() as u64;
        let expected_deser = ceil_div_u128(tx_bytes, 64).unwrap();
        #[allow(clippy::identity_op)]
        let expected = 2 * per_input + 0 + 4 + 0 + expected_deser + 500 + 2500;
        assert_eq!(cost, expected);
    }

    #[test]
    fn test_coinbase_cost() {
        // Coinbase has empty witness, so witness_deser_cost = 0
        let pubkey = [1u8; 32];
        let tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(10_000_000_000, &pubkey)],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        let cost = tx_cost(&tx).unwrap();
        assert!(cost > 0);
    }
}
