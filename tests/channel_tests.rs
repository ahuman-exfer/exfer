//! Integration tests for the payment channel lifecycle.
//!
//! Requires `--features channels` to compile.

#![cfg(feature = "channels")]

use exfer::covenants::channel::{ChannelState, PaymentChannel};
use exfer::script::eval::{evaluate_with_context, Budget};
use exfer::script::jets::context::ScriptContext;
use exfer::script::serialize::{deserialize_program, serialize_program};
use exfer::script::typecheck::typecheck;
use exfer::script::value::Value;
use exfer::types::transaction::TxOutput;

use ed25519_dalek::{Signer, SigningKey};

// ── Helpers ──

fn make_keypair(seed: u8) -> (SigningKey, [u8; 32]) {
    let secret = [seed; 32];
    let sk = SigningKey::from_bytes(&secret);
    let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    (sk, pk_bytes)
}

fn sign(sk: &SigningKey, message: &[u8]) -> Vec<u8> {
    sk.sign(message).to_bytes().to_vec()
}

#[allow(dead_code)]
fn witness_values(values: &[Value]) -> Vec<u8> {
    let mut data = Vec::new();
    for v in values {
        data.extend_from_slice(&v.serialize());
    }
    data
}

fn context_with_sig_hash(height: u64, sig_hash: Vec<u8>) -> ScriptContext {
    ScriptContext {
        tx_inputs: vec![].into(),
        tx_outputs: vec![].into(),
        self_index: 0,
        block_height: height,
        sig_hash: sig_hash.into(),
    }
}

fn eval_ok(program: &exfer::script::ast::Program, witness: &[u8], ctx: &ScriptContext) -> Value {
    let mut budget = Budget::new(500_000, 500_000);
    evaluate_with_context(program, Value::Unit, witness, &mut budget, ctx).unwrap()
}

fn eval_result(
    program: &exfer::script::ast::Program,
    witness: &[u8],
    ctx: &ScriptContext,
) -> Result<Value, exfer::script::eval::EvalError> {
    let mut budget = Budget::new(500_000, 500_000);
    evaluate_with_context(program, Value::Unit, witness, &mut budget, ctx)
}

// ═══════════════════════════════════════════════════════════════════
// Channel state unit tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn channel_state_initial() {
    let state = ChannelState::initial(5_000_000, 3_000_000);
    assert_eq!(state.sequence, 0);
    assert_eq!(state.balance_a, 5_000_000);
    assert_eq!(state.balance_b, 3_000_000);
    assert_eq!(state.total(), 8_000_000);
}

#[test]
fn channel_state_update() {
    let s0 = ChannelState::initial(5_000_000, 3_000_000);
    let s1 = s0.update(4_000_000, 4_000_000);
    assert_eq!(s1.sequence, 1);
    assert_eq!(s1.balance_a, 4_000_000);
    assert_eq!(s1.balance_b, 4_000_000);
    assert_eq!(s1.total(), 8_000_000);
}

#[test]
fn channel_state_newer_than() {
    let s0 = ChannelState::initial(5_000_000, 3_000_000);
    let s1 = s0.update(4_000_000, 4_000_000);
    let s2 = s1.update(3_000_000, 5_000_000);

    assert!(s1.is_newer_than(&s0));
    assert!(s2.is_newer_than(&s1));
    assert!(s2.is_newer_than(&s0));
    assert!(!s0.is_newer_than(&s1));
}

#[test]
fn channel_state_multiple_updates() {
    let mut state = ChannelState::initial(10_000_000, 0);
    for i in 1..=100 {
        state = state.update(10_000_000 - i * 100_000, i * 100_000);
    }
    assert_eq!(state.sequence, 100);
    assert_eq!(state.total(), 10_000_000);
}

// ═══════════════════════════════════════════════════════════════════
// 1. Two-party open
// ═══════════════════════════════════════════════════════════════════

#[test]
fn open_funding_output_value_and_script() {
    let (_, pk_a) = make_keypair(50);
    let (_, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let state = ChannelState::initial(5_000_000, 3_000_000);

    let output = channel.funding_output(&state);
    assert_eq!(output.value, 8_000_000, "funding value = total capacity");
    assert!(output.datum.is_none());
    assert!(output.datum_hash.is_none());

    // Script bytes match serialized funding_script
    let expected_script = serialize_program(&channel.funding_script());
    assert_eq!(output.script, expected_script);
}

#[test]
fn open_funding_script_accepts_both_sigs() {
    let (sk_a, pk_a) = make_keypair(50);
    let (sk_b, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let program = channel.funding_script();
    assert!(program.validate_structure().is_ok());
    assert!(typecheck(&program).is_ok());

    let msg = b"funding tx";
    let sig_a = sign(&sk_a, msg);
    let sig_b = sign(&sk_b, msg);

    let witness = PaymentChannel::multisig_witness(&sig_a, &sig_b);
    let ctx = context_with_sig_hash(0, msg.to_vec());
    assert_eq!(eval_ok(&program, &witness, &ctx), Value::Bool(true));
}

#[test]
fn open_funding_script_rejects_single_sig() {
    let (sk_a, pk_a) = make_keypair(50);
    let (_, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let program = channel.funding_script();

    let msg = b"funding tx";
    let sig_a = sign(&sk_a, msg);
    let bad_sig = vec![0u8; 64];

    let witness = PaymentChannel::multisig_witness(&sig_a, &bad_sig);
    let ctx = context_with_sig_hash(0, msg.to_vec());
    assert_eq!(eval_ok(&program, &witness, &ctx), Value::Bool(false));
}

// ═══════════════════════════════════════════════════════════════════
// 2. Cooperative close with both signatures
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cooperative_close_outputs_reflect_final_state() {
    let (_, pk_a) = make_keypair(50);
    let (_, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let state = ChannelState::initial(5_000_000, 3_000_000)
        .update(4_000_000, 4_000_000)
        .update(3_500_000, 4_500_000);

    let outputs = channel.cooperative_close_outputs(&state);
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].value, 3_500_000, "party A balance");
    assert_eq!(outputs[1].value, 4_500_000, "party B balance");

    // Both are P2PKH (32-byte script = pubkey hash)
    assert_eq!(outputs[0].script.len(), 32);
    assert_eq!(outputs[1].script.len(), 32);

    // Addresses match each party
    let addr_a = TxOutput::pubkey_hash_from_key(&pk_a);
    let addr_b = TxOutput::pubkey_hash_from_key(&pk_b);
    assert_eq!(outputs[0].script, addr_a.0.to_vec());
    assert_eq!(outputs[1].script, addr_b.0.to_vec());
}

#[test]
fn cooperative_close_both_sign_funding() {
    let (sk_a, pk_a) = make_keypair(50);
    let (sk_b, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let program = channel.funding_script();

    // Both sign the cooperative close tx
    let msg = b"cooperative-close";
    let sig_a = sign(&sk_a, msg);
    let sig_b = sign(&sk_b, msg);

    let witness = PaymentChannel::multisig_witness(&sig_a, &sig_b);
    let ctx = context_with_sig_hash(500, msg.to_vec());
    assert_eq!(eval_ok(&program, &witness, &ctx), Value::Bool(true));
}

#[test]
fn cooperative_close_skips_zero_balance() {
    let (_, pk_a) = make_keypair(50);
    let (_, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let state = ChannelState::initial(8_000_000, 0);

    let outputs = channel.cooperative_close_outputs(&state);
    assert_eq!(outputs.len(), 1, "zero-balance output skipped");
    assert_eq!(outputs[0].value, 8_000_000);
}

// ═══════════════════════════════════════════════════════════════════
// 3. Unilateral close with timeout
// ═══════════════════════════════════════════════════════════════════

#[test]
fn unilateral_close_output_structure() {
    let (_, pk_a) = make_keypair(50);
    let (_, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let state = ChannelState::initial(6_000_000, 2_000_000);
    let close_height = 1000;

    // Party A publishes unilateral close
    let outputs = channel.commitment_outputs(&state, &pk_a, close_height);
    assert_eq!(outputs.len(), 2);

    // Output 0: counterparty (B) gets immediate P2PKH
    assert_eq!(outputs[0].value, 2_000_000);
    let addr_b = TxOutput::pubkey_hash_from_key(&pk_b);
    assert_eq!(outputs[0].script, addr_b.0.to_vec());

    // Output 1: publisher (A) gets close_script (not P2PKH)
    assert_eq!(outputs[1].value, 6_000_000);
    assert!(
        outputs[1].script.len() > 32,
        "close_script is a full program"
    );
}

#[test]
fn unilateral_close_finalize_after_timeout() {
    let (sk_a, pk_a) = make_keypair(50);
    let (_, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let close_height = 1000;
    let close_program = channel.close_script(close_height, &pk_a);

    // After dispute window: height > 1000 + 144 = 1144
    let msg = b"finalize-tx";
    let sig_a = sign(&sk_a, msg);
    let witness = PaymentChannel::close_finalize_witness(&sig_a);

    let ctx = context_with_sig_hash(1200, msg.to_vec());
    assert_eq!(
        eval_ok(&close_program, &witness, &ctx),
        Value::Bool(true),
        "publisher can finalize after timeout"
    );
}

#[test]
fn unilateral_close_finalize_before_timeout_fails() {
    let (sk_a, pk_a) = make_keypair(50);
    let (_, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let close_height = 1000;
    let close_program = channel.close_script(close_height, &pk_a);

    // Before dispute window expires: 1050 < 1144
    let msg = b"too-early";
    let sig_a = sign(&sk_a, msg);
    let witness = PaymentChannel::close_finalize_witness(&sig_a);

    let ctx = context_with_sig_hash(1050, msg.to_vec());
    match eval_result(&close_program, &witness, &ctx) {
        Ok(Value::Bool(false)) => {}
        Err(_) => {}
        other => panic!("expected failure before timeout, got {:?}", other),
    }
}

#[test]
fn unilateral_close_wrong_publisher_cannot_finalize() {
    let (_, pk_a) = make_keypair(50);
    let (sk_b, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let close_height = 1000;
    // Script expects party A as publisher
    let close_program = channel.close_script(close_height, &pk_a);

    // Party B tries to finalize (wrong key)
    let msg = b"hijack";
    let sig_b = sign(&sk_b, msg);
    let witness = PaymentChannel::close_finalize_witness(&sig_b);

    let ctx = context_with_sig_hash(1200, msg.to_vec());
    assert_eq!(
        eval_ok(&close_program, &witness, &ctx),
        Value::Bool(false),
        "wrong publisher rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 4. Dispute: replace stale state with newer state
// ═══════════════════════════════════════════════════════════════════

/// Full dispute scenario:
///
/// State 0: A=7M, B=1M (initial)
/// State 1: A=4M, B=4M (after off-chain update)
///
/// Party A publishes stale state 0 (claiming 7M).
/// Party B disputes within the window using the pre-signed dispute tx,
/// spending A's close_script output via the cooperative (Left) path.
/// The dispute tx creates outputs reflecting the correct state 1.
#[test]
fn dispute_replaces_stale_state_with_newer() {
    let (sk_a, pk_a) = make_keypair(50);
    let (sk_b, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let close_height = 1000;

    // --- Off-chain state progression ---
    let state_0 = ChannelState::initial(7_000_000, 1_000_000);
    let state_1 = state_0.update(4_000_000, 4_000_000);
    assert!(state_1.is_newer_than(&state_0));

    // --- A publishes stale state 0 ---
    let stale_outputs = channel.commitment_outputs(&state_0, &pk_a, close_height);
    assert_eq!(stale_outputs[1].value, 7_000_000, "A's stale claim");

    // The close_script on A's output:
    let close_program = channel.close_script(close_height, &pk_a);

    // --- B disputes using cooperative path (pre-signed by both) ---
    // During state 0->1 update, both parties pre-signed a dispute tx
    // that spends close_script's cooperative path.
    let dispute_msg = b"dispute-tx-corrects-to-state1";
    let sig_a = sign(&sk_a, dispute_msg);
    let sig_b = sign(&sk_b, dispute_msg);

    let witness = PaymentChannel::close_cooperative_witness(&sig_a, &sig_b);

    // Dispute within window: 1050 < 1000 + 144 = 1144
    let ctx = context_with_sig_hash(1050, dispute_msg.to_vec());
    assert_eq!(
        eval_ok(&close_program, &witness, &ctx),
        Value::Bool(true),
        "dispute succeeds with both pre-signed sigs"
    );

    // --- Dispute tx outputs reflect the correct (newer) state ---
    let corrected = channel.dispute_outputs(&state_1);
    assert_eq!(corrected.len(), 2);
    assert_eq!(corrected[0].value, 4_000_000, "A corrected to 4M");
    assert_eq!(corrected[1].value, 4_000_000, "B corrected to 4M");
}

#[test]
fn dispute_single_sig_cannot_spend_close_script() {
    let (sk_a, pk_a) = make_keypair(50);
    let (_, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let close_program = channel.close_script(1000, &pk_a);

    // Only A's sig — B didn't pre-sign this dispute
    let msg = b"fraudulent-dispute";
    let sig_a = sign(&sk_a, msg);
    let bad_sig = vec![0u8; 64];
    let witness = PaymentChannel::close_cooperative_witness(&sig_a, &bad_sig);

    let ctx = context_with_sig_hash(1050, msg.to_vec());
    assert_eq!(
        eval_ok(&close_program, &witness, &ctx),
        Value::Bool(false),
        "single sig cannot dispute"
    );
}

// ── Dispute script direct tests ──

#[test]
fn dispute_script_challenge_within_window() {
    let (sk_a, pk_a) = make_keypair(50);
    let (sk_b, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let program = channel.dispute_script(1000);
    assert!(program.validate_structure().is_ok());
    assert!(typecheck(&program).is_ok());

    let msg = b"challenge";
    let sig_a = sign(&sk_a, msg);
    let sig_b = sign(&sk_b, msg);

    // Challenge path (Left): both sigs within window
    let witness = PaymentChannel::dispute_challenge_witness(&sig_a, &sig_b);
    let ctx = context_with_sig_hash(1050, msg.to_vec()); // < 1144
    assert_eq!(eval_ok(&program, &witness, &ctx), Value::Bool(true));
}

#[test]
fn dispute_script_challenge_outside_window_fails() {
    let (sk_a, pk_a) = make_keypair(50);
    let (sk_b, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let program = channel.dispute_script(1000);

    let msg = b"late-challenge";
    let sig_a = sign(&sk_a, msg);
    let sig_b = sign(&sk_b, msg);
    let witness = PaymentChannel::dispute_challenge_witness(&sig_a, &sig_b);

    // height 1200 >= window_end 1144 -> height_lt(1144) fails
    let ctx = context_with_sig_hash(1200, msg.to_vec());
    match eval_result(&program, &witness, &ctx) {
        Ok(Value::Bool(false)) => {}
        Err(_) => {}
        other => panic!("expected failure outside window, got {:?}", other),
    }
}

#[test]
fn dispute_script_cooperative_override_any_time() {
    let (sk_a, pk_a) = make_keypair(50);
    let (sk_b, pk_b) = make_keypair(51);

    let channel = PaymentChannel::new(pk_a, pk_b, 144);
    let program = channel.dispute_script(1000);

    let msg = b"coop-override";
    let sig_a = sign(&sk_a, msg);
    let sig_b = sign(&sk_b, msg);

    // Cooperative path (Right): no time restriction
    let witness = PaymentChannel::dispute_cooperative_witness(&sig_a, &sig_b);
    let ctx = context_with_sig_hash(999_999, msg.to_vec());
    assert_eq!(eval_ok(&program, &witness, &ctx), Value::Bool(true));
}

// ═══════════════════════════════════════════════════════════════════
// Script validity & serialization
// ═══════════════════════════════════════════════════════════════════

#[test]
fn all_channel_scripts_typecheck() {
    let pk_a = [50u8; 32];
    let pk_b = [51u8; 32];
    let channel = PaymentChannel::new(pk_a, pk_b, 144);

    let scripts = [
        channel.funding_script(),
        channel.close_script(1000, &pk_a),
        channel.close_script(1000, &pk_b),
        channel.dispute_script(1000),
    ];

    for (i, program) in scripts.iter().enumerate() {
        assert!(
            program.validate_structure().is_ok(),
            "script {} structure invalid",
            i
        );
        assert!(typecheck(program).is_ok(), "script {} type-check failed", i);
    }
}

#[test]
fn all_channel_scripts_serialize_roundtrip() {
    let pk_a = [50u8; 32];
    let pk_b = [51u8; 32];
    let channel = PaymentChannel::new(pk_a, pk_b, 144);

    let scripts = [
        channel.funding_script(),
        channel.close_script(1000, &pk_a),
        channel.dispute_script(1000),
    ];

    for (i, program) in scripts.iter().enumerate() {
        let bytes = serialize_program(program);
        let rt = deserialize_program(&bytes)
            .unwrap_or_else(|e| panic!("script {} deserialize failed: {:?}", i, e));
        assert_eq!(
            program.nodes.len(),
            rt.nodes.len(),
            "script {} node count mismatch",
            i
        );
        assert_eq!(program.root, rt.root, "script {} root mismatch", i);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Full lifecycle integration
// ═══════════════════════════════════════════════════════════════════

#[test]
fn full_lifecycle_open_update_close() {
    let (sk_a, pk_a) = make_keypair(50);
    let (sk_b, pk_b) = make_keypair(51);
    let channel = PaymentChannel::new(pk_a, pk_b, 144);

    // 1. Open: create funding UTXO
    let s0 = ChannelState::initial(5_000_000, 5_000_000);
    let funding_output = channel.funding_output(&s0);
    assert_eq!(funding_output.value, 10_000_000);

    // 2. Off-chain updates
    let s1 = s0.update(4_500_000, 5_500_000);
    let s2 = s1.update(4_000_000, 6_000_000);
    let s3 = s2.update(3_500_000, 6_500_000);
    assert_eq!(s3.sequence, 3);
    assert_eq!(s3.total(), 10_000_000);

    // 3. Cooperative close on final state
    let close_outputs = channel.cooperative_close_outputs(&s3);
    assert_eq!(close_outputs[0].value, 3_500_000);
    assert_eq!(close_outputs[1].value, 6_500_000);

    // Both sign the close tx spending the funding UTXO
    let msg = b"close-tx-final";
    let sig_a = sign(&sk_a, msg);
    let sig_b = sign(&sk_b, msg);
    let witness = PaymentChannel::multisig_witness(&sig_a, &sig_b);
    let ctx = context_with_sig_hash(500, msg.to_vec());
    let funding_program = channel.funding_script();
    assert_eq!(eval_ok(&funding_program, &witness, &ctx), Value::Bool(true));
}
