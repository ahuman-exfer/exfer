//! Payment channel: bilateral state channel with dispute mechanism.
//!
//! Gated behind `feature = "channels"` (default off).
//!
//! # Lifecycle
//!
//! 1. **Open**: both parties fund a 2-of-2 multisig output.
//! 2. **Update**: off-chain, parties exchange signed state vectors.
//!    For each state N→N+1 they also pre-sign a *dispute transaction*
//!    that can revoke state N if it is ever published.
//! 3. **Cooperative close**: both sign a settlement tx spending the
//!    funding UTXO directly to each party's balance.
//! 4. **Unilateral close**: one party publishes a pre-signed commitment
//!    tx. The counterparty's share pays out immediately; the publisher's
//!    share is locked by `close_script` (timelock + dispute window).
//! 5. **Dispute**: if an old commitment was published, the counterparty
//!    broadcasts a pre-signed dispute tx spending the `close_script`
//!    output via its cooperative path (both sigs, no timelock).
//!
//! # Security model
//!
//! The 2-of-2 signature requirement on the dispute path is the safety
//! property: pre-signed dispute transactions are exchanged during each
//! state update. Without datum-introspection jets, on-chain sequence
//! comparison is not possible, but the pre-signed dispute tx mechanism
//! guarantees that only mutually-agreed state transitions can execute.

use super::builder::ScriptBuilder;
use crate::script::ast::Program;
use crate::script::serialize::serialize_program;
use crate::script::value::Value;
use crate::types::transaction::TxOutput;

/// Payment channel between two parties.
pub struct PaymentChannel {
    pub party_a: [u8; 32],
    pub party_b: [u8; 32],
    pub dispute_window: u64,
}

/// Off-chain channel state.
#[derive(Clone, Debug)]
pub struct ChannelState {
    pub sequence: u64,
    pub balance_a: u64,
    pub balance_b: u64,
}

impl PaymentChannel {
    /// Create a new payment channel.
    pub fn new(party_a: [u8; 32], party_b: [u8; 32], dispute_window: u64) -> Self {
        PaymentChannel {
            party_a,
            party_b,
            dispute_window,
        }
    }

    // ── Scripts ──

    /// Funding output script: 2-of-2 multisig.
    ///
    /// Both parties must sign to spend (cooperative close or commitment).
    /// Witness: `[sig_a][sig_b]`
    pub fn funding_script(&self) -> Program {
        super::multisig::multisig_2of2(&self.party_a, &self.party_b)
    }

    /// Unilateral close output script: OR(cooperative, timelock).
    ///
    /// Locks the publisher's share after a unilateral close.
    ///
    /// Two paths:
    /// - **Left (cooperative)**: both sigs → immediate. Also serves as
    ///   the entry point for dispute transactions (pre-signed by both).
    /// - **Right (finalize)**: after `close_height + dispute_window`,
    ///   publisher alone can claim.
    ///
    /// **Cooperative** witness: `[Left(Unit)][sig_a][sig_b]`
    /// **Finalize** witness: `[Right(Unit)][sig_publisher]`
    pub fn close_script(&self, close_height: u64, publisher: &[u8; 32]) -> Program {
        let mut b = ScriptBuilder::new();

        // Cooperative path: 2-of-2 multisig
        let check_a = b.sig_check(&self.party_a);
        let check_b = b.sig_check(&self.party_b);
        let cooperative = b.and(check_a, check_b);

        // Finalize path: timelock + publisher's sig
        let timeout_height = close_height.saturating_add(self.dispute_window);
        let time_check = b.height_gt(timeout_height);
        let pub_check = b.sig_check(publisher);
        let finalize = b.and(time_check, pub_check);

        // Dispatch
        let selector = b.witness();
        let case_node = b.case(cooperative, finalize);
        let _root = b.comp(selector, case_node);
        b.build()
    }

    /// Dispute script: allows challenging a unilateral close with newer state.
    ///
    /// Two paths:
    /// - **Left (challenge)**: both sigs + must be within dispute window.
    ///   The 2-of-2 requirement is the safety property: challengers must
    ///   present a pre-signed dispute tx (exchanged during state updates).
    /// - **Right (cooperative)**: both sigs, no time restriction.
    ///
    /// **Challenge** witness: `[Left(Unit)][sig_a][sig_b]`
    /// **Cooperative** witness: `[Right(Unit)][sig_a][sig_b]`
    pub fn dispute_script(&self, close_height: u64) -> Program {
        let mut b = ScriptBuilder::new();

        // Challenge path: both sigs + within dispute window
        let check_a1 = b.sig_check(&self.party_a);
        let check_b1 = b.sig_check(&self.party_b);
        let both_signed = b.and(check_a1, check_b1);
        let window_end = close_height.saturating_add(self.dispute_window);
        let in_window = b.height_lt(window_end);
        let challenge = b.and(both_signed, in_window);

        // Cooperative override: both sign, no time restriction
        let check_a2 = b.sig_check(&self.party_a);
        let check_b2 = b.sig_check(&self.party_b);
        let cooperative = b.and(check_a2, check_b2);

        // Dispatch
        let selector = b.witness();
        let case_node = b.case(challenge, cooperative);
        let _root = b.comp(selector, case_node);
        b.build()
    }

    // ── Output construction ──

    /// Build the funding output (single UTXO locked by 2-of-2 multisig).
    pub fn funding_output(&self, state: &ChannelState) -> TxOutput {
        let script = serialize_program(&self.funding_script());
        TxOutput {
            value: state.total(),
            script,
            datum: None,
            datum_hash: None,
        }
    }

    /// Build outputs for a cooperative close (immediate settlement).
    ///
    /// Returns two P2PKH outputs paying each party their balance.
    /// Skips zero-balance outputs.
    pub fn cooperative_close_outputs(&self, state: &ChannelState) -> Vec<TxOutput> {
        let mut outputs = Vec::new();
        if state.balance_a > 0 {
            outputs.push(TxOutput::new_p2pkh(state.balance_a, &self.party_a));
        }
        if state.balance_b > 0 {
            outputs.push(TxOutput::new_p2pkh(state.balance_b, &self.party_b));
        }
        outputs
    }

    /// Build outputs for a unilateral close (commitment tx).
    ///
    /// - Output 0: counterparty's balance → immediate P2PKH
    /// - Output 1: publisher's balance → locked by `close_script`
    ///
    /// Skips zero-balance outputs. `publisher` must be one of the two
    /// channel parties.
    pub fn commitment_outputs(
        &self,
        state: &ChannelState,
        publisher: &[u8; 32],
        close_height: u64,
    ) -> Vec<TxOutput> {
        let (publisher_balance, counterparty_balance, counterparty_key) =
            if *publisher == self.party_a {
                (state.balance_a, state.balance_b, &self.party_b)
            } else {
                (state.balance_b, state.balance_a, &self.party_a)
            };

        let mut outputs = Vec::new();

        // Counterparty gets immediate P2PKH
        if counterparty_balance > 0 {
            outputs.push(TxOutput::new_p2pkh(counterparty_balance, counterparty_key));
        }

        // Publisher's share is timelocked via close_script
        if publisher_balance > 0 {
            let script = serialize_program(&self.close_script(close_height, publisher));
            outputs.push(TxOutput {
                value: publisher_balance,
                script,
                datum: None,
                datum_hash: None,
            });
        }

        outputs
    }

    /// Build outputs for a dispute transaction.
    ///
    /// When a stale commitment is published, the counterparty disputes
    /// by spending the `close_script` output (cooperative path) and
    /// creating outputs that reflect the correct (newer) state.
    ///
    /// Returns two P2PKH outputs paying each party per `new_state`.
    pub fn dispute_outputs(&self, new_state: &ChannelState) -> Vec<TxOutput> {
        self.cooperative_close_outputs(new_state)
    }

    // ── Witness construction ──

    /// Witness for spending a 2-of-2 multisig (funding_script).
    ///
    /// Used for both cooperative close and pre-signed commitments.
    pub fn multisig_witness(sig_a: &[u8], sig_b: &[u8]) -> Vec<u8> {
        witness_values(&[Value::Bytes(sig_a.to_vec()), Value::Bytes(sig_b.to_vec())])
    }

    /// Witness for the cooperative path of close_script (Left branch).
    ///
    /// Used by dispute transactions (pre-signed by both parties).
    pub fn close_cooperative_witness(sig_a: &[u8], sig_b: &[u8]) -> Vec<u8> {
        witness_values(&[
            Value::Left(Box::new(Value::Unit)),
            Value::Bytes(sig_a.to_vec()),
            Value::Bytes(sig_b.to_vec()),
        ])
    }

    /// Witness for the finalize path of close_script (Right branch).
    ///
    /// Used by the publisher after the dispute window expires.
    pub fn close_finalize_witness(sig_publisher: &[u8]) -> Vec<u8> {
        witness_values(&[
            Value::Right(Box::new(Value::Unit)),
            Value::Bytes(sig_publisher.to_vec()),
        ])
    }

    /// Witness for the challenge path of dispute_script (Left branch).
    pub fn dispute_challenge_witness(sig_a: &[u8], sig_b: &[u8]) -> Vec<u8> {
        witness_values(&[
            Value::Left(Box::new(Value::Unit)),
            Value::Bytes(sig_a.to_vec()),
            Value::Bytes(sig_b.to_vec()),
        ])
    }

    /// Witness for the cooperative path of dispute_script (Right branch).
    pub fn dispute_cooperative_witness(sig_a: &[u8], sig_b: &[u8]) -> Vec<u8> {
        witness_values(&[
            Value::Right(Box::new(Value::Unit)),
            Value::Bytes(sig_a.to_vec()),
            Value::Bytes(sig_b.to_vec()),
        ])
    }
}

impl ChannelState {
    /// Create an initial channel state.
    pub fn initial(balance_a: u64, balance_b: u64) -> Self {
        ChannelState {
            sequence: 0,
            balance_a,
            balance_b,
        }
    }

    /// Total channel capacity.
    pub fn total(&self) -> u64 {
        self.balance_a.saturating_add(self.balance_b)
    }

    /// Create a new state with updated balances and incremented sequence.
    pub fn update(&self, new_balance_a: u64, new_balance_b: u64) -> Self {
        ChannelState {
            sequence: self.sequence.saturating_add(1),
            balance_a: new_balance_a,
            balance_b: new_balance_b,
        }
    }

    /// Check if this state is newer than another.
    pub fn is_newer_than(&self, other: &ChannelState) -> bool {
        self.sequence > other.sequence
    }
}

/// Serialize a slice of Values into witness bytes.
fn witness_values(values: &[Value]) -> Vec<u8> {
    let mut data = Vec::new();
    for v in values {
        data.extend_from_slice(&v.serialize());
    }
    data
}
