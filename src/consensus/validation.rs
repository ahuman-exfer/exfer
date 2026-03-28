use crate::chain::state::{UtxoEntry, UtxoSet};
use crate::consensus::cost;
use crate::script::jets::context::{ScriptContext, TxInputInfo, TxOutputInfo};
use crate::script::{self, Combinator};
use crate::types::block::{Block, BlockHeader};
use crate::types::hash::{merkle_root, Hash256};
use crate::types::transaction::{OutPoint, SerError, Transaction, TxOutput};
use crate::types::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashSet;

/// Validation error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    // Block errors
    InvalidVersion(u32),
    InvalidHeight {
        expected: u64,
        got: u64,
    },
    InvalidPrevBlockId,
    PowFailed,
    InvalidDifficulty,
    TimestampBelowMtp {
        mtp: u64,
        timestamp: u64,
    },
    TimestampTooFarAhead {
        max: u64,
        timestamp: u64,
    },
    TimestampGapTooLarge {
        parent: u64,
        timestamp: u64,
    },
    InvalidTxRoot,
    #[allow(dead_code)]
    InvalidStateRoot,
    NoCoinbase,
    NoTransactions,
    BlockTooLarge {
        size: usize,
    },
    DuplicateTransaction(Hash256),
    DoubleSpend(OutPoint),
    NonCoinbaseSentinel {
        tx_index: usize,
    },

    // Transaction errors
    NoInputs,
    NoOutputs,
    UtxoNotFound(OutPoint),
    DuplicateInput(OutPoint),
    PubkeyHashMismatch {
        input_index: usize,
    },
    SignatureInvalid {
        input_index: usize,
    },
    WitnessInvalid {
        input_index: usize,
        reason: String,
    },
    OutputBelowDust {
        output_index: usize,
        value: u64,
    },
    ValueOverflow,
    InsufficientInputValue,
    FeeBelowMinimum {
        fee: u64,
        min_fee: u64,
    },
    CoinbaseImmature {
        outpoint: OutPoint,
        age: u64,
    },
    TxTooLarge {
        size: usize,
    },
    CostOverflow,
    WitnessCountMismatch {
        inputs: usize,
        witnesses: usize,
    },
    IllTypedScript(usize),
    AmbiguousScript(usize),
    ScriptEvalFailed {
        input_index: usize,
        reason: String,
    },
    DatumHashMismatch(usize),
    WitnessOversized {
        input_index: usize,
        size: usize,
    },
    DatumOversized {
        output_index: usize,
        size: usize,
    },
    RedeemerOversized {
        input_index: usize,
        size: usize,
    },
    Phase1HasRedeemer {
        input_index: usize,
    },
    RewardOverflow,
    ArithmeticOverflow,
    /// Rollback failed — UTXO state is inconsistent, node must restart.
    StateCorrupted(String),

    // Coinbase errors
    CoinbaseBadInputCount(usize),
    CoinbaseBadOutputIndex {
        expected: u32,
        got: u32,
    },
    CoinbaseHeightOverflow(u64),
    CoinbaseWrongReward {
        expected: u64,
        got: u64,
    },
    #[allow(dead_code)]
    CoinbaseZeroOutput {
        index: usize,
    },
    CoinbaseWitnessNotEmpty,
    CoinbaseHasRedeemer,
    CoinbaseWitnessCountMismatch {
        expected: usize,
        got: usize,
    },

    /// Script context build failed because an input's UTXO was not found.
    InputMissing {
        index: usize,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ValidationError {}

/// Information about a UTXO needed for validation.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct UtxoInfo {
    pub output: TxOutput,
    /// The height at which this UTXO was created.
    pub height: u64,
    /// Whether this UTXO came from a coinbase transaction.
    pub is_coinbase: bool,
}

/// Lightweight, UTXO-independent structural validation for all transactions
/// in a block. Catches format/size/dust/duplicate errors cheaply before
/// committing to full semantic validation or disk storage.
///
/// Called on fork blocks before `try_store_fork_block()` to prevent storing
/// blocks that will inevitably fail semantic validation during reorg,
/// avoiding expensive undo/reapply cycles.
pub fn validate_block_structure(block: &Block) -> Result<(), ValidationError> {
    if block.transactions.is_empty() {
        return Err(ValidationError::NoTransactions);
    }
    // Coinbase structural checks (UTXO-independent subset).
    // These catch semantically-doomed fork blocks before they consume
    // scarce fork storage slots and churn eviction during reorg pressure.
    let coinbase = &block.transactions[0];
    if coinbase.inputs.len() != 1 {
        return Err(ValidationError::CoinbaseBadInputCount(
            coinbase.inputs.len(),
        ));
    }
    if coinbase.inputs[0].prev_tx_id != Hash256::ZERO {
        return Err(ValidationError::CoinbaseBadInputCount(0));
    }
    // output_index must encode height (Rule 2, Section 4.5)
    let expected_idx = u32::try_from(block.header.height)
        .map_err(|_| ValidationError::CoinbaseHeightOverflow(block.header.height))?;
    if coinbase.inputs[0].output_index != expected_idx {
        return Err(ValidationError::CoinbaseBadOutputIndex {
            expected: expected_idx,
            got: coinbase.inputs[0].output_index,
        });
    }
    // Coinbase must have exactly 1 witness, no redeemer.
    // Witness data must be empty for all blocks except genesis (height 0),
    // which carries the NIST Beacon attestation message.
    if coinbase.witnesses.len() != 1 {
        return Err(ValidationError::CoinbaseWitnessCountMismatch {
            expected: 1,
            got: coinbase.witnesses.len(),
        });
    }
    if block.header.height != 0 && !coinbase.witnesses[0].witness.is_empty() {
        return Err(ValidationError::CoinbaseWitnessNotEmpty);
    }
    if coinbase.witnesses[0].redeemer.is_some() {
        return Err(ValidationError::CoinbaseHasRedeemer);
    }
    // Coinbase outputs: dust threshold + datum size limits + datum hash consistency + script admissibility
    for (idx, output) in coinbase.outputs.iter().enumerate() {
        if output.value < DUST_THRESHOLD {
            return Err(ValidationError::OutputBelowDust {
                output_index: idx,
                value: output.value,
            });
        }
        if let Some(ref datum) = output.datum {
            if datum.len() > MAX_DATUM_SIZE {
                return Err(ValidationError::DatumOversized {
                    output_index: idx,
                    size: datum.len(),
                });
            }
        }
        // Datum hash consistency (UTXO-independent)
        if let (Some(datum), Some(hash)) = (&output.datum, &output.datum_hash) {
            let computed = Hash256::sha256(datum);
            if computed != *hash {
                return Err(ValidationError::DatumHashMismatch(idx));
            }
        }
        // Script admissibility (UTXO-independent)
        check_script_admissible(idx, output)?;
    }
    // Non-coinbase structural checks
    for tx in block.transactions.iter().skip(1) {
        if tx.inputs.is_empty() {
            return Err(ValidationError::NoInputs);
        }
        if tx.outputs.is_empty() {
            return Err(ValidationError::NoOutputs);
        }
        if tx.witnesses.len() != tx.inputs.len() {
            return Err(ValidationError::WitnessCountMismatch {
                inputs: tx.inputs.len(),
                witnesses: tx.witnesses.len(),
            });
        }
        // Size limits on witness/datum/redeemer fields
        for (idx, witness) in tx.witnesses.iter().enumerate() {
            if witness.witness.len() > MAX_WITNESS_SIZE {
                return Err(ValidationError::WitnessOversized {
                    input_index: idx,
                    size: witness.witness.len(),
                });
            }
            if let Some(ref redeemer) = witness.redeemer {
                if redeemer.len() > MAX_REDEEMER_SIZE {
                    return Err(ValidationError::RedeemerOversized {
                        input_index: idx,
                        size: redeemer.len(),
                    });
                }
            }
        }
        for (idx, output) in tx.outputs.iter().enumerate() {
            if let Some(ref datum) = output.datum {
                if datum.len() > MAX_DATUM_SIZE {
                    return Err(ValidationError::DatumOversized {
                        output_index: idx,
                        size: datum.len(),
                    });
                }
            }
            // Datum hash consistency (UTXO-independent)
            if let (Some(datum), Some(hash)) = (&output.datum, &output.datum_hash) {
                let computed = Hash256::sha256(datum);
                if computed != *hash {
                    return Err(ValidationError::DatumHashMismatch(idx));
                }
            }
            // Script admissibility (UTXO-independent)
            check_script_admissible(idx, output)?;
        }
        // TX size limit
        let serialized = tx
            .serialize()
            .map_err(|_| ValidationError::TxTooLarge { size: 0 })?;
        if serialized.len() > MAX_TX_SIZE {
            return Err(ValidationError::TxTooLarge {
                size: serialized.len(),
            });
        }
        // No duplicate inputs
        let mut seen = HashSet::new();
        for input in &tx.inputs {
            let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
            if !seen.insert(outpoint) {
                return Err(ValidationError::DuplicateInput(outpoint));
            }
        }
        // Dust threshold
        for (idx, output) in tx.outputs.iter().enumerate() {
            if output.value < DUST_THRESHOLD {
                return Err(ValidationError::OutputBelowDust {
                    output_index: idx,
                    value: output.value,
                });
            }
        }
    }
    Ok(())
}

/// Validate a non-coinbase transaction against the UTXO set.
/// Returns (fee, total_script_cost) where fee = sum_inputs - sum_outputs
/// and total_script_cost is the actual script evaluation cost (for accurate fee-density ranking).
/// UTXO-independent script admissibility check for `validate_block_structure`.
///
/// Phase 1 (32-byte) scripts must not also deserialize as valid Phase 2 programs
/// (ambiguity guard). Phase 2 scripts must type-check and pass all structural
/// constraints (output type, depth, cost, etc.) via `validate_output_script`.
///
/// This catches doomed outputs before consuming fork cache or UTXO storage,
/// since script admissibility depends only on the script bytes — not on any UTXO.
fn check_script_admissible(idx: usize, output: &TxOutput) -> Result<(), ValidationError> {
    if output.script.is_empty() {
        return Err(ValidationError::IllTypedScript(idx));
    }
    if is_phase1_script(&output.script) {
        // Ambiguity guard: reject 32-byte scripts that also deserialize as
        // valid Phase 2 programs.
        if script::deserialize_program(&output.script).is_ok() {
            return Err(ValidationError::AmbiguousScript(idx));
        }
    } else {
        validate_output_script(idx, output)?;
    }
    Ok(())
}

///
/// Implements all 13 transaction validation rules from SPEC Section 8.
pub fn validate_transaction(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    current_height: u64,
) -> Result<(u64, u128, u128), ValidationError> {
    // Rule 1: at least one input
    if tx.inputs.is_empty() {
        return Err(ValidationError::NoInputs);
    }

    // Rule 2: at least one output
    if tx.outputs.is_empty() {
        return Err(ValidationError::NoOutputs);
    }

    // Witness count must match input count
    if tx.witnesses.len() != tx.inputs.len() {
        return Err(ValidationError::WitnessCountMismatch {
            inputs: tx.inputs.len(),
            witnesses: tx.witnesses.len(),
        });
    }

    // Consensus size limits on witness, datum, and redeemer fields.
    // These mirror the limits enforced at deserialization (transaction.rs) but
    // must also be checked here: internal/block-construction paths that bypass
    // wire decoding could otherwise accept oversized objects.
    for (idx, witness) in tx.witnesses.iter().enumerate() {
        if witness.witness.len() > MAX_WITNESS_SIZE {
            return Err(ValidationError::WitnessOversized {
                input_index: idx,
                size: witness.witness.len(),
            });
        }
        if let Some(ref redeemer) = witness.redeemer {
            if redeemer.len() > MAX_REDEEMER_SIZE {
                return Err(ValidationError::RedeemerOversized {
                    input_index: idx,
                    size: redeemer.len(),
                });
            }
        }
    }
    for (idx, output) in tx.outputs.iter().enumerate() {
        if let Some(ref datum) = output.datum {
            if datum.len() > MAX_DATUM_SIZE {
                return Err(ValidationError::DatumOversized {
                    output_index: idx,
                    size: datum.len(),
                });
            }
        }
    }

    // Rule 11: size limit
    let serialized = tx
        .serialize()
        .map_err(|_| ValidationError::TxTooLarge { size: 0 })?;
    if serialized.len() > MAX_TX_SIZE {
        return Err(ValidationError::TxTooLarge {
            size: serialized.len(),
        });
    }

    // Rule 4: no duplicate inputs
    let mut seen_outpoints = HashSet::new();
    for input in &tx.inputs {
        let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
        if !seen_outpoints.insert(outpoint) {
            return Err(ValidationError::DuplicateInput(outpoint));
        }
    }

    // Rule 6: every output value > 0
    // Rule 9: every output value >= dust_threshold
    for (idx, output) in tx.outputs.iter().enumerate() {
        if output.value < DUST_THRESHOLD {
            return Err(ValidationError::OutputBelowDust {
                output_index: idx,
                value: output.value,
            });
        }
        // Datum consistency: if both datum and datum_hash are present,
        // the hash must match the inline datum. Prevents ambiguous outputs.
        if let (Some(datum), Some(hash)) = (&output.datum, &output.datum_hash) {
            let computed = Hash256::sha256(datum);
            if computed != *hash {
                return Err(ValidationError::DatumHashMismatch(idx));
            }
        }
    }

    // --- Pass 1: Cheap checks (UTXO existence, maturity, value accumulation) ---
    // All UTXO lookups and maturity checks run before any expensive crypto work.
    // This prevents CPU-amplification attacks where a missing input placed late
    // forces the node to verify all earlier signatures before failing.
    let mut total_input: u128 = 0;
    let mut input_utxos: Vec<&UtxoEntry> = Vec::with_capacity(tx.inputs.len());

    for input in &tx.inputs {
        let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);

        // Rule 3: UTXO must exist
        let utxo_entry = utxo_set
            .get(&outpoint)
            .ok_or(ValidationError::UtxoNotFound(outpoint))?;

        // Rule 10: coinbase maturity
        if utxo_entry.is_coinbase {
            let age = current_height.saturating_sub(utxo_entry.height);
            if age < COINBASE_MATURITY {
                return Err(ValidationError::CoinbaseImmature { outpoint, age });
            }
        }

        total_input += utxo_entry.output.value as u128;
        input_utxos.push(utxo_entry);
    }

    // Rule 7: sum(inputs) >= sum(outputs), both as u128 — checked before expensive work
    let mut total_output: u128 = 0;
    for output in &tx.outputs {
        total_output += output.value as u128;
    }

    if total_input > u128::from(u64::MAX) || total_output > u128::from(u64::MAX) {
        return Err(ValidationError::ValueOverflow);
    }

    if total_input < total_output {
        return Err(ValidationError::InsufficientInputValue);
    }

    // Rule 12: Output script type-checking — every output script must be well-typed.
    // Checked BEFORE expensive input validation to prevent CPU-DoS via txs that
    // are guaranteed-invalid at output stage but force signature/script work first.
    for (idx, output) in tx.outputs.iter().enumerate() {
        if is_phase1_script(&output.script) {
            // Ambiguity guard: reject 32-byte scripts that also deserialize as
            // valid Phase 2 programs. Without this, a script author could create
            // an output whose spending semantics depend on which phase the
            // spender invokes, leading to silent fund-lock or wrong authorization.
            if script::deserialize_program(&output.script).is_ok() {
                return Err(ValidationError::AmbiguousScript(idx));
            }
        } else {
            validate_output_script(idx, output)?;
        }
    }

    // Build sig_message for Phase 1 signature verification
    let sig_message = tx
        .sig_message()
        .map_err(|_| ValidationError::TxTooLarge { size: 0 })?;

    // Build script context for Phase 2+ introspection jets
    let script_context = build_script_context(tx, utxo_set, current_height)?;

    // --- Pass 2: Expensive checks (signature verification, script evaluation) ---
    let mut total_script_cost: u128 = 0;
    let mut total_script_validation_cost: u128 = 0;

    for (idx, input_utxo) in input_utxos.iter().enumerate() {
        let witness = &tx.witnesses[idx];

        // Rule 5: Script validation — Phase 1 backward compat or Phase 2+ script eval
        if is_phase1_script(&input_utxo.output.script) {
            // Phase 1: 32-byte pubkey hash — validate with old signature method
            validate_phase1_input(idx, witness, &input_utxo.output, &sig_message)?;
            // Data-proportional cost: base + ceil_div(sig_message_bytes, 64) × 8
            let sig_msg_cost = (sig_message.len() as u64).div_ceil(64) * 8;
            total_script_cost += PHASE1_SCRIPT_EVAL_COST as u128 + sig_msg_cost as u128;
        } else {
            // Phase 2+: full script evaluation (returns actual cost)
            let script_cost =
                validate_script_input(idx, witness, &input_utxo.output, &script_context)?;
            total_script_cost += script_cost as u128;
            // Script validation cost: deserialization + canonicalization + typecheck + cost analysis
            let script_bytes = input_utxo.output.script.len() as u64;
            total_script_validation_cost += (script_bytes.div_ceil(64) * 10) as u128;
        }
    }

    // Rule 13: Per-transaction script budget cap
    if total_script_cost > MAX_TX_SCRIPT_BUDGET {
        return Err(ValidationError::ScriptEvalFailed {
            input_index: tx.inputs.len().saturating_sub(1),
            reason: format!(
                "total script cost {} exceeds per-transaction budget {}",
                total_script_cost, MAX_TX_SCRIPT_BUDGET
            ),
        });
    }

    let fee = (total_input - total_output) as u64;

    // Rule 8: fee >= min_fee (P1-8: use actual script cost, not Phase 1 constant)
    let min_fee =
        cost::min_fee_with_script_cost(tx, total_script_cost, total_script_validation_cost)
            .ok_or(ValidationError::CostOverflow)?;
    if fee < min_fee {
        return Err(ValidationError::FeeBelowMinimum { fee, min_fee });
    }

    Ok((fee, total_script_cost, total_script_validation_cost))
}

/// Check if a script is a Phase 1 pubkey hash.
///
/// Phase 1 scripts are raw 32-byte pubkey hashes (SHA-256("EXFER-ADDR" || pk)).
/// Phase 2+ scripts are serialized DAGs with combinator tag bytes, and are
/// always longer than 32 bytes for any non-trivial program. The distinction
/// is purely by length: exactly 32 bytes = Phase 1 pubkey hash.
///
/// This is deterministic and future-proof: Phase 2 script commitments that
/// happen to be exactly 32 bytes are not supported (authors must pad to 33+).
/// Relying on deserialization success/failure was fragile because changes to
/// the deserializer could alter classification of edge-case byte sequences.
pub fn is_phase1_script(script_bytes: &[u8]) -> bool {
    script_bytes.len() == 32
}

/// Phase 1 signature validation: pubkey(32) + signature(64) in witness.
fn validate_phase1_input(
    idx: usize,
    witness: &crate::types::transaction::TxWitness,
    utxo_output: &TxOutput,
    sig_message: &[u8],
) -> Result<(), ValidationError> {
    if witness.witness.len() != 96 {
        return Err(ValidationError::WitnessInvalid {
            input_index: idx,
            reason: format!("witness length {} != 96", witness.witness.len()),
        });
    }

    // SPEC §4.4: Phase 1 inputs must have has_redeemer = 0
    if witness.redeemer.is_some() {
        return Err(ValidationError::Phase1HasRedeemer { input_index: idx });
    }

    let pubkey_bytes: [u8; 32] = witness.witness[0..32]
        .try_into()
        .expect("slice is 32 bytes");
    let sig_bytes: [u8; 64] = witness.witness[32..96]
        .try_into()
        .expect("slice is 64 bytes");

    let expected_hash = TxOutput::pubkey_hash_from_key(&pubkey_bytes);
    if expected_hash.as_bytes() != utxo_output.script.as_slice() {
        return Err(ValidationError::PubkeyHashMismatch { input_index: idx });
    }

    // Reject small-order (weak) keys — they can validate signatures across
    // unrelated messages, breaking transaction-message binding.
    if is_weak_ed25519_key(&pubkey_bytes) {
        return Err(ValidationError::SignatureInvalid { input_index: idx });
    }
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| ValidationError::SignatureInvalid { input_index: idx })?;
    let signature = Signature::from_bytes(&sig_bytes);
    // Use verify (not verify_strict) for ZIP-215 compliance — accepts non-canonical
    // encodings, matching the jet path and ensuring consensus determinism.
    verifying_key
        .verify(sig_message, &signature)
        .map_err(|_| ValidationError::SignatureInvalid { input_index: idx })?;

    Ok(())
}

/// Phase 2+ script validation: deserialize, type-check, compute cost, evaluate.
/// Returns the script's step cost on success (for fee calculation).
fn validate_script_input(
    idx: usize,
    witness: &crate::types::transaction::TxWitness,
    utxo_output: &TxOutput,
    context: &ScriptContext,
) -> Result<u64, ValidationError> {
    // 1. Deserialize script
    let program = script::deserialize_program(&utxo_output.script).map_err(|e| {
        ValidationError::ScriptEvalFailed {
            input_index: idx,
            reason: format!("script deserialization failed: {}", e),
        }
    })?;

    // 2. Canonical serialization check: re-serializing the deserialized program
    //    must produce the exact original bytes. This catches non-canonical
    //    encodings that parse but differ from the committed script.
    //    (When partial Merkle revelation ships, this step will instead verify
    //    merkle_hash(revealed_program) == the output's script commitment.)
    let reserialized = script::serialize_program(&program);
    if reserialized != utxo_output.script {
        return Err(ValidationError::ScriptEvalFailed {
            input_index: idx,
            reason: "script serialization is non-canonical".to_string(),
        });
    }

    // 3. Type-check
    if script::typecheck(&program).is_err() {
        return Err(ValidationError::ScriptEvalFailed {
            input_index: idx,
            reason: "script type-check failed".to_string(),
        });
    }

    // 4. Build input value from witness/redeemer/datum
    let datum =
        resolve_datum(utxo_output, witness).map_err(|e| ValidationError::ScriptEvalFailed {
            input_index: idx,
            reason: format!("datum resolution failed: {}", e),
        })?;
    let input_value = build_script_input(
        &witness.witness,
        witness.redeemer.as_deref(),
        datum.as_deref(),
    );

    // 5. Compute cost
    let list_sizes = script::ListSizes {
        input_count: context.tx_inputs.len(),
        output_count: context.tx_outputs.len(),
    };
    let cost = script::compute_cost(&program, &list_sizes).map_err(|e| {
        ValidationError::ScriptEvalFailed {
            input_index: idx,
            reason: format!("cost computation failed: {}", e),
        }
    })?;

    // Consensus cap: reject scripts exceeding MAX_SCRIPT_STEPS
    if cost.steps > MAX_SCRIPT_STEPS {
        return Err(ValidationError::ScriptEvalFailed {
            input_index: idx,
            reason: format!(
                "script cost {} steps exceeds consensus cap {}",
                cost.steps, MAX_SCRIPT_STEPS
            ),
        });
    }

    // 6. Evaluate
    // Budget uses the full consensus cap (MAX_SCRIPT_STEPS), not the
    // static cost estimate. Static jet_cost values are typical-case
    // estimates for admissibility, but runtime_cost can be higher for
    // data-proportional jets (SHA256, MerkleVerify, list ops) with
    // larger inputs. Using the consensus cap as budget prevents scripts
    // that pass admissibility from becoming unspendable at runtime.
    let mut budget = script::Budget::new(MAX_SCRIPT_STEPS, cost.cells);
    let context_with_self = context.with_self_index(idx as u32);
    let result = script::evaluate_with_context(
        &program,
        input_value,
        &witness.witness,
        &mut budget,
        &context_with_self,
    );

    // Actual runtime cost = budget consumed during evaluation.
    // This reflects data-proportional jet costs (SHA256, MerkleVerify, etc.)
    // and is used for min_fee computation to prevent underpricing heavy scripts.
    let actual_steps = MAX_SCRIPT_STEPS - budget.steps_remaining;

    match result {
        Ok(ref v) if v.as_bool() == Some(true) => Ok(actual_steps),
        Ok(other) => Err(ValidationError::ScriptEvalFailed {
            input_index: idx,
            reason: format!("script returned {:?} (expected Bool(true) or Right(Unit))", other),
        }),
        Err(e) => Err(ValidationError::ScriptEvalFailed {
            input_index: idx,
            reason: format!("script evaluation failed: {}", e),
        }),
    }
}

/// The input type that the runtime provides to every script via `build_script_input`:
/// `Product(Bytes, Product(Option(Bytes), Product(Option(Bytes), Unit)))`
/// where Bytes = List(Bound(256)) and Option(X) = Sum(Unit, X).
fn script_input_type() -> script::Type {
    use script::Type;
    Type::Product(
        Box::new(Type::bytes()), // witness
        Box::new(Type::Product(
            Box::new(Type::option(Type::bytes())), // redeemer
            Box::new(Type::Product(
                Box::new(Type::option(Type::bytes())), // datum
                Box::new(Type::Unit),                  // context (via jets)
            )),
        )),
    )
}

/// Validate an output script is well-typed and spendable (prevents UTXO set pollution).
/// Test-only wrapper for output admission validation.
#[allow(dead_code)]
pub fn validate_output_script_public(idx: usize, output: &TxOutput) -> Result<(), ValidationError> {
    validate_output_script(idx, output)
}

fn validate_output_script(idx: usize, output: &TxOutput) -> Result<(), ValidationError> {
    let program = script::deserialize_program(&output.script)
        .map_err(|_| ValidationError::IllTypedScript(idx))?;
    let typed_nodes =
        script::typecheck(&program).map_err(|_| ValidationError::IllTypedScript(idx))?;
    // Root must output Bool — scripts returning non-Bool are unspendable
    // because the evaluator requires Ok(Bool(true)) for a valid spend.
    let root_output_type = &typed_nodes[program.root as usize].output_type;
    if *root_output_type != script::Type::bool_type() {
        return Err(ValidationError::IllTypedScript(idx));
    }
    // Strict type edge check: verify all composition edges have exact type
    // matches (no Unit-as-wildcard). The typechecker uses Unit as a placeholder
    // for unresolved types, but output scripts must be fully type-consistent
    // to be spendable at runtime.
    if !strict_type_edges(&program, &typed_nodes) {
        return Err(ValidationError::IllTypedScript(idx));
    }
    // Reject scripts containing unimplemented jets, hidden nodes, or
    // heterogeneous list constants. List type inference uses only the
    // first element's type, so a Const([U64(1), Bool(true)]) would
    // pass type checking but fail at runtime when list jets enforce
    // per-element type homogeneity — permanently locking funds.
    for node in &program.nodes {
        match node {
            Combinator::Jet(jet_id) if !jet_id.is_implemented() => {
                return Err(ValidationError::IllTypedScript(idx));
            }
            Combinator::MerkleHidden(_) => {
                return Err(ValidationError::IllTypedScript(idx));
            }
            Combinator::Const(v) if !v.lists_are_homogeneous() => {
                return Err(ValidationError::IllTypedScript(idx));
            }
            _ => {}
        }
    }
    // Root input type must be compatible with the runtime input shape.
    // A script with root input Sum(Bytes, Bytes) would pass all other checks
    // but fail at every spend attempt (evaluator provides a Product).
    // Use one-directional wildcard: script's Unit = "don't care", but
    // runtime's Unit is literal Unit (prevents Drop-chain bypass).
    let root_input_type = &typed_nodes[program.root as usize].input_type;
    let expected = script_input_type();
    if !script_input_accepts(root_input_type, &expected) {
        return Err(ValidationError::IllTypedScript(idx));
    }
    // Reject scripts whose DAG depth exceeds the evaluator's recursion limit.
    // The evaluator enforces MAX_EVAL_DEPTH at runtime; scripts deeper than
    // that would always fail with RecursionDepthExceeded, locking funds.
    if program.max_depth() > script::eval::MAX_EVAL_DEPTH {
        return Err(ValidationError::IllTypedScript(idx));
    }
    // Reject scripts that provably exceed the step cap even with minimum
    // list sizes. Any spending tx has ≥1 input and ≥1 output, so {1,1}
    // is a sound lower bound. If the minimum-case cost exceeds the cap,
    // the script is provably unspendable.
    let min_list_sizes = script::ListSizes {
        input_count: 1,
        output_count: 1,
    };
    match script::compute_cost(&program, &min_list_sizes) {
        Ok(cost) if cost.steps > MAX_SCRIPT_STEPS => {
            return Err(ValidationError::IllTypedScript(idx));
        }
        Err(_) => {
            // Cost computation overflow → provably unspendable
            return Err(ValidationError::IllTypedScript(idx));
        }
        Ok(_) => {} // passes minimum-case check
    }
    Ok(())
}

/// One-directional type compatibility for output-script validation.
///
/// The script's `Unit` acts as a wildcard ("don't care" — e.g. via Drop),
/// but the runtime's `Unit` is literal Unit. This prevents Drop-chain
/// scripts (like `Drop(Drop(Drop(Jet(Eq64))))`) from passing validation:
/// the script's inner node expects Product(u64,u64) but its root sees
/// all-Unit from the Drop chain — the script side is Unit (wildcard, ok),
/// but the runtime side is never Unit at those positions, so it passes.
/// The key difference from `types_compatible`: runtime Unit is NOT a wildcard.
fn script_input_accepts(script_type: &script::Type, runtime_type: &script::Type) -> bool {
    use script::Type;
    if script_type == runtime_type {
        return true;
    }
    // Script's Unit means "don't care" — accepts anything
    if *script_type == Type::Unit {
        return true;
    }
    // Runtime's Unit is literal Unit — script must also be Unit (handled above)
    match (script_type, runtime_type) {
        (Type::Product(a1, a2), Type::Product(b1, b2)) => {
            script_input_accepts(a1, b1) && script_input_accepts(a2, b2)
        }
        (Type::Sum(a1, a2), Type::Sum(b1, b2)) => {
            script_input_accepts(a1, b1) && script_input_accepts(a2, b2)
        }
        (Type::List(a1), Type::List(b1)) => script_input_accepts(a1, b1),
        _ => false,
    }
}

/// Check that all internal type edges in the program are strict (exact equality).
///
/// The typechecker uses `Unit` as a wildcard placeholder for unresolved types.
/// This allows ill-typed compositions (e.g. `Comp(Iden, Jet(Ed25519Verify))`)
/// to pass typecheck. At runtime these would always fail, locking funds.
/// This function rejects programs with any wildcard-dependent type connections.
fn strict_type_edges(program: &script::Program, typed: &[script::TypedNode]) -> bool {
    for node in &program.nodes {
        match node {
            Combinator::Comp(f, g) => {
                // f's output must exactly equal g's input — no Unit wildcard
                if typed[*f as usize].output_type != typed[*g as usize].input_type {
                    return false;
                }
            }
            Combinator::Case(f, g) => {
                // Both branches must produce exactly the same output type
                if typed[*f as usize].output_type != typed[*g as usize].output_type {
                    return false;
                }
            }
            Combinator::Pair(f, g) => {
                // Both children receive the same input — if both have non-Unit
                // input types, they must agree (prevents conflicting expectations
                // like one expecting Bytes and the other u64).
                let f_in = &typed[*f as usize].input_type;
                let g_in = &typed[*g as usize].input_type;
                if *f_in != script::Type::Unit && *g_in != script::Type::Unit && f_in != g_in {
                    return false;
                }
                // Children's output types must not be Unit (unresolved).
                // A Pair with an unresolved child output produces an
                // ill-typed Product that can pass admission but fail at
                // runtime (e.g. Pair(Witness, Unit) -> Eq64 is doomed).
                let f_out = &typed[*f as usize].output_type;
                let g_out = &typed[*g as usize].output_type;
                if *f_out == script::Type::Unit || *g_out == script::Type::Unit {
                    return false;
                }
            }
            Combinator::Fold(f, z, _) => {
                // Step output must exactly equal init output, and neither can be Unit
                let f_out = &typed[*f as usize].output_type;
                let z_out = &typed[*z as usize].output_type;
                if f_out != z_out || *f_out == script::Type::Unit || *z_out == script::Type::Unit {
                    return false;
                }
            }
            Combinator::ListFold(f, z) => {
                let f_out = &typed[*f as usize].output_type;
                let z_out = &typed[*z as usize].output_type;
                if f_out != z_out || *f_out == script::Type::Unit || *z_out == script::Type::Unit {
                    return false;
                }
            }
            _ => {}
        }
    }
    // Final pass: verify every node's output is consistent with its
    // children's actual outputs. The refinement pass can push types into
    // a node's output slot that its children can never actually produce.
    for (i, node) in program.nodes.iter().enumerate() {
        let node_out = &typed[i].output_type;
        if *node_out == script::Type::Unit {
            continue; // Unresolved — will be caught by other checks if needed
        }
        match node {
            Combinator::Comp(_, g) => {
                // Comp output = g's output. If they disagree, the refinement
                // pushed an unreachable type into the Comp's output slot.
                let g_out = &typed[*g as usize].output_type;
                if node_out != g_out {
                    return false;
                }
            }
            Combinator::Case(f, g) => {
                // Case output = either branch. Both must be non-Unit and equal.
                let f_out = &typed[*f as usize].output_type;
                let g_out = &typed[*g as usize].output_type;
                if *f_out == script::Type::Unit || *g_out == script::Type::Unit {
                    return false;
                }
                if node_out != f_out || node_out != g_out {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Resolve datum from UTXO (inline) or witness (hash-committed).
///
/// P2-9: If datum_hash is set, the spender MUST provide a matching datum.
/// Returning Ok(None) when datum_hash is set would make the commitment meaningless.
fn resolve_datum(
    utxo: &TxOutput,
    witness: &crate::types::transaction::TxWitness,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(datum) = &utxo.datum {
        // If datum_hash is also present, verify consistency.
        // Prevents ambiguous outputs where inline datum doesn't match the hash.
        if let Some(hash) = &utxo.datum_hash {
            let computed = Hash256::sha256(datum);
            if computed != *hash {
                return Err("datum_hash does not match inline datum".to_string());
            }
        }
        Ok(Some(datum.clone()))
    } else if let Some(hash) = &utxo.datum_hash {
        // Spender MUST provide datum in redeemer when datum_hash is set
        match &witness.redeemer {
            Some(provided) => {
                if provided.len() > crate::types::MAX_DATUM_SIZE {
                    return Err(format!(
                        "hash-committed datum exceeds MAX_DATUM_SIZE ({} > {})",
                        provided.len(),
                        crate::types::MAX_DATUM_SIZE
                    ));
                }
                let computed = Hash256::sha256(provided);
                if computed == *hash {
                    Ok(Some(provided.clone()))
                } else {
                    Err("datum hash mismatch".to_string())
                }
            }
            None => Err("datum required: output has datum_hash but no datum provided".to_string()),
        }
    } else {
        Ok(None)
    }
}

/// Build the input value for script evaluation from witness/redeemer/datum.
fn build_script_input(
    witness: &[u8],
    redeemer: Option<&[u8]>,
    datum: Option<&[u8]>,
) -> script::Value {
    script::Value::Pair(
        Box::new(script::Value::Bytes(witness.to_vec())),
        Box::new(script::Value::Pair(
            Box::new(match redeemer {
                Some(r) => script::Value::Right(Box::new(script::Value::Bytes(r.to_vec()))),
                None => script::Value::Left(Box::new(script::Value::Unit)),
            }),
            Box::new(script::Value::Pair(
                Box::new(match datum {
                    Some(d) => script::Value::Right(Box::new(script::Value::Bytes(d.to_vec()))),
                    None => script::Value::Left(Box::new(script::Value::Unit)),
                }),
                Box::new(script::Value::Unit),
            )),
        )),
    )
}

/// Build a ScriptContext from a transaction and UTXO set.
fn build_script_context(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    block_height: u64,
) -> Result<ScriptContext, ValidationError> {
    let tx_inputs: Vec<TxInputInfo> = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
            let utxo = utxo_set
                .get(&outpoint)
                .ok_or(ValidationError::InputMissing { index: i })?;
            Ok(TxInputInfo {
                prev_tx_id: input.prev_tx_id,
                output_index: input.output_index,
                value: utxo.output.value,
                script_hash: Hash256::sha256(&utxo.output.script),
            })
        })
        .collect::<Result<Vec<_>, ValidationError>>()?;

    let tx_outputs: Vec<TxOutputInfo> = tx
        .outputs
        .iter()
        .map(|output| TxOutputInfo {
            value: output.value,
            script_hash: Hash256::sha256(&output.script),
            datum_hash: output.datum_hash,
        })
        .collect();

    // Pre-compute the signing digest so covenant scripts can bind
    // signatures to this transaction via the TxSigHash jet.
    // Propagate serialization errors instead of silently falling back to
    // an all-zeros digest, which could mask bugs in future call paths.
    let sig_hash = tx
        .sig_message()
        .map_err(|_| ValidationError::TxTooLarge { size: 0 })?;

    Ok(ScriptContext {
        tx_inputs: tx_inputs.into(),
        tx_outputs: tx_outputs.into(),
        self_index: 0, // Will be overridden per-input via with_self_index()
        block_height,
        sig_hash: sig_hash.into(),
    })
}

/// Validate a coinbase transaction (Section 8.1).
pub fn validate_coinbase(
    tx: &Transaction,
    height: u64,
    expected_reward: u64,
) -> Result<(), ValidationError> {
    // Rule 1: exactly one input with sentinel outpoint
    if tx.inputs.len() != 1 {
        return Err(ValidationError::CoinbaseBadInputCount(tx.inputs.len()));
    }

    if tx.inputs[0].prev_tx_id != Hash256::ZERO {
        return Err(ValidationError::CoinbaseBadInputCount(0));
    }

    // Rule 11 (applied uniformly): size limit
    let serialized = tx
        .serialize()
        .map_err(|_| ValidationError::TxTooLarge { size: 0 })?;
    if serialized.len() > MAX_TX_SIZE {
        return Err(ValidationError::TxTooLarge {
            size: serialized.len(),
        });
    }

    // Rule 2: output_index == height (as u32, checked)
    let expected_idx =
        u32::try_from(height).map_err(|_| ValidationError::CoinbaseHeightOverflow(height))?;
    if tx.inputs[0].output_index != expected_idx {
        return Err(ValidationError::CoinbaseBadOutputIndex {
            expected: expected_idx,
            got: tx.inputs[0].output_index,
        });
    }

    // Witness constraints (per Section 13 rule 5):
    // - exactly 1 witness (matching 1 input)
    // - witnesses[0].witness must be empty (except genesis, which carries
    //   the NIST Beacon attestation message)
    // - witnesses[0] must have no redeemer
    if tx.witnesses.len() != 1 {
        return Err(ValidationError::CoinbaseWitnessCountMismatch {
            expected: 1,
            got: tx.witnesses.len(),
        });
    }
    if height != 0 && !tx.witnesses[0].witness.is_empty() {
        return Err(ValidationError::CoinbaseWitnessNotEmpty);
    }
    if tx.witnesses[0].redeemer.is_some() {
        return Err(ValidationError::CoinbaseHasRedeemer);
    }

    // Rule 4: all output values >= DUST_THRESHOLD (subsumes > 0)
    for (idx, output) in tx.outputs.iter().enumerate() {
        if output.value < DUST_THRESHOLD {
            return Err(ValidationError::OutputBelowDust {
                output_index: idx,
                value: output.value,
            });
        }
        // Datum size limit (same as regular tx)
        if let Some(ref datum) = output.datum {
            if datum.len() > MAX_DATUM_SIZE {
                return Err(ValidationError::DatumOversized {
                    output_index: idx,
                    size: datum.len(),
                });
            }
        }
        // Datum hash consistency (same as regular tx)
        if let (Some(datum), Some(hash)) = (&output.datum, &output.datum_hash) {
            let computed = Hash256::sha256(datum);
            if computed != *hash {
                return Err(ValidationError::DatumHashMismatch(idx));
            }
        }
    }

    // Coinbase outputs must also pass script-validity checks — an invalid
    // or unspendable output script would permanently lock the reward,
    // and a miner could use trivially small / ill-typed outputs to bloat
    // the UTXO set at negligible cost.
    for (idx, output) in tx.outputs.iter().enumerate() {
        if is_phase1_script(&output.script) {
            // Same ambiguity guard as regular tx outputs: reject 32-byte
            // scripts that also parse as Phase 2 programs.
            if script::deserialize_program(&output.script).is_ok() {
                return Err(ValidationError::AmbiguousScript(idx));
            }
        } else {
            validate_output_script(idx, output)?;
        }
    }

    // Rule 3: sum(outputs) == expected_reward (exact, no rounding)
    let mut total_output: u128 = 0;
    for output in &tx.outputs {
        total_output += output.value as u128;
    }

    if total_output > u128::from(u64::MAX) {
        return Err(ValidationError::CoinbaseWrongReward {
            expected: expected_reward,
            got: u64::MAX,
        });
    }

    let total = total_output as u64;
    if total != expected_reward {
        return Err(ValidationError::CoinbaseWrongReward {
            expected: expected_reward,
            got: total,
        });
    }

    Ok(())
}

/// Compute the transaction Merkle root.
///
/// Uses witness-committed hashes (wtx_id) so that the block header
/// transitively commits to all witness data, preventing block malleability.
/// Returns Err if any transaction cannot be serialized (oversized fields).
pub fn compute_tx_root(transactions: &[Transaction]) -> Result<Hash256, SerError> {
    let mut wtx_ids = Vec::with_capacity(transactions.len());
    for tx in transactions {
        wtx_ids.push(tx.wtx_id()?);
    }
    Ok(merkle_root(DS_TXROOT, &wtx_ids))
}

/// Header-only block validation (no UTXO state required).
/// Validates: version, height, prev_block_id, difficulty, PoW, timestamps, block size,
/// coinbase presence, no extra coinbases, tx_root, no duplicate txs, no intra-block double-spends.
pub fn validate_block_header(
    block: &Block,
    parent: Option<&BlockHeader>,
    ancestor_timestamps: &[u64],
    expected_target: &Hash256,
    wall_clock: Option<u64>,
) -> Result<(), ValidationError> {
    validate_block_header_inner(
        block,
        parent,
        ancestor_timestamps,
        expected_target,
        wall_clock,
        false,
    )
}

/// Like `validate_block_header` but can skip PoW verification when the
/// caller has already verified difficulty + PoW (e.g. NewBlock/BlockResponse
/// pre-checks). Avoids redundant Argon2id computation (R110 P2 fix).
pub fn validate_block_header_skip_pow(
    block: &Block,
    parent: Option<&BlockHeader>,
    ancestor_timestamps: &[u64],
    expected_target: &Hash256,
    wall_clock: Option<u64>,
) -> Result<(), ValidationError> {
    validate_block_header_inner(
        block,
        parent,
        ancestor_timestamps,
        expected_target,
        wall_clock,
        true,
    )
}

fn validate_block_header_inner(
    block: &Block,
    parent: Option<&BlockHeader>,
    ancestor_timestamps: &[u64],
    expected_target: &Hash256,
    wall_clock: Option<u64>,
    skip_pow: bool,
) -> Result<(), ValidationError> {
    let header = &block.header;

    // Rule 2: version
    if header.version != VERSION {
        return Err(ValidationError::InvalidVersion(header.version));
    }

    // Rule 3: height
    match parent {
        Some(p) => {
            let expected_height = p
                .height
                .checked_add(1)
                .ok_or(ValidationError::ArithmeticOverflow)?;
            if header.height != expected_height {
                return Err(ValidationError::InvalidHeight {
                    expected: expected_height,
                    got: header.height,
                });
            }
        }
        None => {
            if header.height != 0 {
                return Err(ValidationError::InvalidHeight {
                    expected: 0,
                    got: header.height,
                });
            }
        }
    }

    // Rule 4: prev_block_id
    match parent {
        Some(p) => {
            if header.prev_block_id != p.block_id() {
                return Err(ValidationError::InvalidPrevBlockId);
            }
        }
        None => {
            if header.prev_block_id != Hash256::ZERO {
                return Err(ValidationError::InvalidPrevBlockId);
            }
        }
    }

    // Rule 6: difficulty target
    if header.difficulty_target != *expected_target {
        return Err(ValidationError::InvalidDifficulty);
    }

    // Rule 5: PoW (skippable if caller already verified)
    if !skip_pow {
        match super::pow::verify_pow(header) {
            Ok(true) => {}
            Ok(false) | Err(_) => return Err(ValidationError::PowFailed),
        }
    }

    // Rule 7: timestamp > MTP
    if !ancestor_timestamps.is_empty() {
        let mtp = median_time_past(ancestor_timestamps);
        if header.timestamp <= mtp {
            return Err(ValidationError::TimestampBelowMtp {
                mtp,
                timestamp: header.timestamp,
            });
        }
    }

    // Rule 8: timestamp not too far in the future (policy check, skipped during IBD)
    if let Some(wc) = wall_clock {
        let max_future = wc
            .checked_add(MAX_TIMESTAMP_DRIFT)
            .ok_or(ValidationError::ArithmeticOverflow)?;
        if header.timestamp > max_future {
            return Err(ValidationError::TimestampTooFarAhead {
                max: max_future,
                timestamp: header.timestamp,
            });
        }
    }

    // Rule 9: timestamp gap
    if let Some(p) = parent {
        let max_gap = p
            .timestamp
            .checked_add(MAX_TIMESTAMP_GAP)
            .ok_or(ValidationError::ArithmeticOverflow)?;
        if header.timestamp > max_gap {
            return Err(ValidationError::TimestampGapTooLarge {
                parent: p.timestamp,
                timestamp: header.timestamp,
            });
        }
    }

    // Rule 16: block size
    let block_bytes = block
        .serialize()
        .map_err(|_| ValidationError::TxTooLarge { size: 0 })?;
    if block_bytes.len() > MAX_BLOCK_SIZE {
        return Err(ValidationError::BlockTooLarge {
            size: block_bytes.len(),
        });
    }

    // Rule 12: first transaction must be coinbase
    if block.transactions.is_empty() {
        return Err(ValidationError::NoCoinbase);
    }
    if !block.transactions[0].is_coinbase() {
        return Err(ValidationError::NoCoinbase);
    }

    // Rule 12: no other transaction may have sentinel outpoint
    for (i, tx) in block.transactions.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(ValidationError::NonCoinbaseSentinel { tx_index: i });
        }
    }

    // Rule 14: no duplicate transactions
    let mut seen_tx_ids = HashSet::new();
    for tx in &block.transactions {
        let tx_id = tx
            .tx_id()
            .map_err(|_| ValidationError::TxTooLarge { size: 0 })?;
        if !seen_tx_ids.insert(tx_id) {
            return Err(ValidationError::DuplicateTransaction(tx_id));
        }
    }

    // Rule 15: no double-spends within the block
    let mut spent_in_block = HashSet::new();
    for tx in block.transactions.iter().skip(1) {
        for input in &tx.inputs {
            let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
            if !spent_in_block.insert(outpoint) {
                return Err(ValidationError::DoubleSpend(outpoint));
            }
        }
    }

    // Rule 10: tx_root
    let computed_tx_root = compute_tx_root(&block.transactions)
        .map_err(|_| ValidationError::TxTooLarge { size: 0 })?;
    if header.tx_root != computed_tx_root {
        return Err(ValidationError::InvalidTxRoot);
    }

    Ok(())
}

/// Transaction-level block validation (requires UTXO state).
/// Validates: each non-coinbase tx against UTXO set, coinbase reward.
/// Call this only when the UTXO state matches the block's parent.
///
/// This is a convenience wrapper that clones the UTXO set internally.
/// For callers that already have a mutable staged set (e.g. process_block),
/// use `validate_and_apply_block_transactions` to avoid the extra clone
/// and redundant transaction replay.
#[allow(dead_code)]
pub fn validate_block_transactions(
    block: &Block,
    utxo_set: &UtxoSet,
) -> Result<u64, ValidationError> {
    let mut staged = utxo_set.clone();
    validate_and_apply_block_transactions(block, &mut staged)
}

/// Validate block transactions AND apply them to `utxo_set` in a single pass.
///
/// On success, `utxo_set` reflects all block transactions applied and the
/// function returns total fees. On failure, `utxo_set` is in a partially-applied
/// state (caller should discard it).
///
/// Per SPEC Section 8.2, tx at position `i` may spend outputs from
/// transactions at positions `0..i-1` in the same block (intra-block
/// dependency spending). The UTXO set accumulates each transaction's
/// outputs after validation.
#[allow(dead_code)]
pub fn validate_and_apply_block_transactions(
    block: &Block,
    utxo_set: &mut UtxoSet,
) -> Result<u64, ValidationError> {
    let header = &block.header;

    // Apply coinbase outputs first so non-coinbase txs could reference them
    // (subject to maturity — which will naturally fail at COINBASE_MATURITY check).
    utxo_set
        .apply_transaction(&block.transactions[0], header.height)
        .map_err(|e| ValidationError::StateCorrupted(format!("coinbase apply: {}", e)))?;

    // Validate each non-coinbase transaction and compute total fees
    let mut total_fees: u128 = 0;
    for tx in block.transactions.iter().skip(1) {
        let (fee, _script_cost, _script_validation_cost) =
            validate_transaction(tx, utxo_set, header.height)?;
        total_fees += fee as u128;
        // Apply this tx's effects so subsequent txs can spend its outputs
        utxo_set
            .apply_transaction(tx, header.height)
            .map_err(|e| ValidationError::StateCorrupted(format!("tx apply: {}", e)))?;
    }

    if total_fees > u64::MAX as u128 {
        return Err(ValidationError::ValueOverflow);
    }
    let total_fees = total_fees as u64;

    // Validate coinbase
    let expected_reward = super::reward::block_reward(header.height)
        .checked_add(total_fees)
        .ok_or(ValidationError::RewardOverflow)?;
    validate_coinbase(&block.transactions[0], header.height, expected_reward)?;

    Ok(total_fees)
}

/// Validate and apply block transactions with automatic rollback on failure.
///
/// On success: `utxo_set` has all block transactions applied, returns
/// `(total_fees, spent_utxos)`. The `spent_utxos` list is collected
/// incrementally during application and includes intra-block spends
/// (outputs created and consumed within the same block).
///
/// On failure: `utxo_set` is rolled back to its pre-call state, returns error.
pub fn validate_and_apply_block_transactions_atomic(
    block: &Block,
    utxo_set: &mut UtxoSet,
) -> Result<(u64, Vec<(OutPoint, UtxoEntry)>), ValidationError> {
    let header = &block.header;

    // Collect spent UTXOs incrementally as we apply. This captures both
    // pre-block UTXOs and intra-block outputs (created by an earlier tx
    // in this block and spent by a later one). Without incremental
    // collection, undo would fail on intra-block dependency spends.
    let mut spent_utxos: Vec<(OutPoint, UtxoEntry)> = Vec::new();
    // Track serialized undo-metadata bytes to prevent amplification DoS:
    // block inputs are small (~36 bytes each) but the UTXOs they reference
    // can carry large scripts/datums. Without a budget, an attacker can
    // pre-create large UTXOs across many blocks then spend them in one
    // block, forcing disproportionate RAM/disk for undo metadata.
    let mut spent_utxos_bytes: usize = 0;

    // Apply coinbase outputs first (same as non-atomic path)
    if let Err(e) = utxo_set.apply_transaction(&block.transactions[0], header.height) {
        // Coinbase apply failed — may have partially inserted outputs.
        // Best-effort rollback: undo_transaction removes any outputs that
        // were inserted. If undo also fails, report both errors so the
        // caller knows the severity of the state corruption.
        if let Err(undo_err) = utxo_set.undo_transaction(&block.transactions[0], &[]) {
            return Err(ValidationError::StateCorrupted(format!(
                "coinbase apply: {}; rollback also failed: {}",
                e, undo_err
            )));
        }
        return Err(ValidationError::StateCorrupted(format!(
            "coinbase apply: {}",
            e
        )));
    }
    let mut applied_count: usize = 1;

    // Validate and apply each non-coinbase transaction
    let mut total_fees: u128 = 0;
    for tx in block.transactions.iter().skip(1) {
        match validate_transaction(tx, utxo_set, header.height) {
            Ok((fee, _script_cost, _script_validation_cost)) => {
                total_fees += fee as u128;
                // Snapshot each input's UTXO *before* apply_transaction removes it.
                // This captures intra-block outputs that exist in utxo_set now
                // (added by an earlier tx in this block) but didn't exist pre-block.
                for input in &tx.inputs {
                    let outpoint = OutPoint::new(input.prev_tx_id, input.output_index);
                    if let Some(entry) = utxo_set.get(&outpoint) {
                        // 53 bytes fixed overhead + serialized output size.
                        // Fixed: tx_id(32) + output_index(4) + len_prefix(4) + height(8) + coinbase(1) + count_amortized(4).
                        let entry_bytes =
                            53 + entry.output.serialize().map(|b| b.len()).unwrap_or(0);
                        spent_utxos_bytes = spent_utxos_bytes.saturating_add(entry_bytes);
                        if spent_utxos_bytes > MAX_SPENT_UTXOS_SIZE {
                            if let Err(undo_err) = undo_applied_transactions(
                                block,
                                utxo_set,
                                applied_count,
                                &spent_utxos,
                            ) {
                                return Err(ValidationError::StateCorrupted(format!(
                                    "undo metadata overflow: rollback failed: {}",
                                    undo_err
                                )));
                            }
                            return Err(ValidationError::BlockTooLarge {
                                size: spent_utxos_bytes,
                            });
                        }
                        spent_utxos.push((outpoint, entry.clone()));
                    }
                }
                if let Err(e) = utxo_set.apply_transaction(tx, header.height) {
                    // apply_transaction may have partially mutated state
                    // (some inputs removed, some outputs inserted before
                    // the error).  First undo the partial current tx, then
                    // roll back all previously applied transactions.
                    let tx_spent: Vec<_> = spent_utxos
                        .iter()
                        .filter(|(op, _)| {
                            tx.inputs.iter().any(|i| {
                                i.prev_tx_id == op.tx_id && i.output_index == op.output_index
                            })
                        })
                        .cloned()
                        .collect();
                    if let Err(partial_err) = utxo_set.undo_partial_transaction(tx, &tx_spent) {
                        return Err(ValidationError::StateCorrupted(format!(
                            "tx apply: {}: partial undo failed: {}",
                            e, partial_err
                        )));
                    }
                    if let Err(undo_err) =
                        undo_applied_transactions(block, utxo_set, applied_count, &spent_utxos)
                    {
                        return Err(ValidationError::StateCorrupted(format!(
                            "tx apply: {}: rollback failed: {}",
                            e, undo_err
                        )));
                    }
                    return Err(ValidationError::StateCorrupted(format!("tx apply: {}", e)));
                }
                applied_count += 1;
            }
            Err(e) => {
                if let Err(undo_err) =
                    undo_applied_transactions(block, utxo_set, applied_count, &spent_utxos)
                {
                    return Err(ValidationError::StateCorrupted(format!(
                        "{}: rollback failed: {}",
                        e, undo_err
                    )));
                }
                return Err(e);
            }
        }
    }

    if total_fees > u64::MAX as u128 {
        if let Err(undo_err) =
            undo_applied_transactions(block, utxo_set, applied_count, &spent_utxos)
        {
            return Err(ValidationError::StateCorrupted(format!(
                "ValueOverflow: rollback failed: {}",
                undo_err
            )));
        }
        return Err(ValidationError::ValueOverflow);
    }
    let total_fees = total_fees as u64;

    // Validate coinbase reward
    let expected_reward = match super::reward::block_reward(header.height).checked_add(total_fees) {
        Some(r) => r,
        None => {
            if let Err(undo_err) =
                undo_applied_transactions(block, utxo_set, applied_count, &spent_utxos)
            {
                return Err(ValidationError::StateCorrupted(format!(
                    "RewardOverflow: rollback failed: {}",
                    undo_err
                )));
            }
            return Err(ValidationError::RewardOverflow);
        }
    };

    if let Err(e) = validate_coinbase(&block.transactions[0], header.height, expected_reward) {
        if let Err(undo_err) =
            undo_applied_transactions(block, utxo_set, applied_count, &spent_utxos)
        {
            return Err(ValidationError::StateCorrupted(format!(
                "{}: rollback failed: {}",
                e, undo_err
            )));
        }
        return Err(e);
    }

    Ok((total_fees, spent_utxos))
}

/// Undo `applied_count` transactions from the front of `block.transactions`
/// in reverse order. Restores spent UTXOs from `spent_utxos`.
///
/// Returns `Err` on first failure — caller must treat UTXO state as
/// inconsistent (fail closed).
fn undo_applied_transactions(
    block: &Block,
    utxo_set: &mut UtxoSet,
    applied_count: usize,
    spent_utxos: &[(OutPoint, UtxoEntry)],
) -> Result<(), String> {
    for tx in block.transactions[..applied_count].iter().rev() {
        let tx_spent: Vec<_> = spent_utxos
            .iter()
            .filter(|(op, _)| {
                tx.inputs
                    .iter()
                    .any(|i| i.prev_tx_id == op.tx_id && i.output_index == op.output_index)
            })
            .cloned()
            .collect();
        utxo_set
            .undo_transaction(tx, &tx_spent)
            .map_err(|e| format!("undo_applied_transactions failed: {}", e))?;
    }
    Ok(())
}

/// Undo all transactions in a block (reverse order). Convenience wrapper
/// over `undo_applied_transactions` for state_root mismatch rollback.
///
/// Returns `Err` if any undo fails — UTXO state is inconsistent.
pub fn undo_block_transactions(
    block: &Block,
    utxo_set: &mut UtxoSet,
    spent_utxos: &[(OutPoint, UtxoEntry)],
) -> Result<(), String> {
    undo_applied_transactions(block, utxo_set, block.transactions.len(), spent_utxos)
}

/// Compute the Median Time Past from ancestor timestamps.
/// `timestamps` should be ordered most-recent-first, up to 11 entries.
pub fn median_time_past(timestamps: &[u64]) -> u64 {
    let mut sorted: Vec<u64> = timestamps.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_median_time_past_odd() {
        let timestamps = vec![100, 90, 95, 80, 85, 70, 75, 60, 65, 50, 55];
        let mtp = median_time_past(&timestamps);
        // sorted: [50,55,60,65,70,75,80,85,90,95,100]
        // median at index 5 = 75
        assert_eq!(mtp, 75);
    }

    #[test]
    fn test_median_time_past_few() {
        let timestamps = vec![100, 90, 95];
        let mtp = median_time_past(&timestamps);
        // sorted: [90, 95, 100], median at index 1 = 95
        assert_eq!(mtp, 95);
    }

    #[test]
    fn test_compute_tx_root_single() {
        use crate::types::transaction::{TxInput, TxOutput, TxWitness};
        let tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(100, &[0u8; 32])],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        let root = compute_tx_root(std::slice::from_ref(&tx)).unwrap();
        // Single tx: root = wtx_id (witness-committed hash)
        assert_eq!(root, tx.wtx_id().unwrap());
    }
}
