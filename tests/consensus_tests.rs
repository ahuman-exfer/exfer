//! Comprehensive consensus tests for every validation rule in SPEC.md v2.
//! Each consensus rule has at least one positive test (valid) and one negative test (invalid).

use exfer::chain::state::{UtxoEntry, UtxoSet};
use exfer::consensus::cost::{self, ceil_div_u128};
use exfer::consensus::difficulty::{
    add_work, genesis_target, needs_retarget, production_genesis_target, retarget, work_from_target,
};
use exfer::consensus::pow::{compute_pow, verify_pow};
use exfer::consensus::reward::block_reward;
use exfer::consensus::validation::{
    compute_tx_root, median_time_past, validate_block_header, validate_coinbase,
    validate_transaction, ValidationError,
};
use exfer::types::block::{Block, BlockHeader, HEADER_SIZE};
use exfer::types::hash::{merkle_root, Hash256};
use exfer::types::transaction::{OutPoint, Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::*;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

// ======================================================================
// Helper functions
// ======================================================================

fn make_keypair() -> (SigningKey, [u8; 32]) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

/// Build a v2 witness: pubkey(32) || signature(64) for each input.
fn sign_tx(tx: &mut Transaction, sk: &SigningKey) {
    let pk = sk.verifying_key().to_bytes();
    let msg = tx.sig_message().unwrap();
    let sig = sk.sign(&msg);
    let mut witness_data = Vec::with_capacity(96);
    witness_data.extend_from_slice(&pk);
    witness_data.extend_from_slice(&sig.to_bytes());

    tx.witnesses.clear();
    for _ in 0..tx.inputs.len() {
        tx.witnesses.push(TxWitness {
            witness: witness_data.clone(),
            redeemer: None,
        });
    }
}

fn make_utxo_set_with_coins(
    pubkey: &[u8; 32],
    coins: &[(Hash256, u32, u64)], // (tx_id, output_index, value)
    is_coinbase: bool,
    height: u64,
) -> UtxoSet {
    let mut utxo_set = UtxoSet::new();
    for (tx_id, idx, value) in coins {
        let _ = utxo_set.insert(
            OutPoint::new(*tx_id, *idx),
            UtxoEntry {
                output: TxOutput::new_p2pkh(*value, pubkey),
                height,
                is_coinbase,
            },
        );
    }
    utxo_set
}

/// Maximum target (very easy) for tests.
fn easy_target() -> Hash256 {
    Hash256([0xFF; 32])
}

// ======================================================================
// 1. Domain-Separated Hashing Tests (Section 2.2)
// ======================================================================

#[test]
fn test_domain_hash_consistency() {
    let h = Hash256::domain_hash(b"EXFER-TX", &[0x00]);
    assert_ne!(h, Hash256::ZERO);
    assert_eq!(h, Hash256::domain_hash(b"EXFER-TX", &[0x00]));
}

#[test]
fn test_different_domains_produce_different_hashes() {
    let domains = [
        b"EXFER-TX" as &[u8],
        b"EXFER-SIG",
        b"EXFER-ADDR",
        b"EXFER-STATE",
    ];
    let data = [0x42u8; 10];
    let hashes: Vec<Hash256> = domains
        .iter()
        .map(|d| Hash256::domain_hash(d, &data))
        .collect();
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "domains {} and {} collide", i, j);
        }
    }
}

// ======================================================================
// 2. Block Header Tests (Section 3)
// ======================================================================

#[test]
fn test_header_serialization_is_156_bytes() {
    let header = BlockHeader {
        version: 1,
        height: 12345,
        prev_block_id: Hash256::sha256(b"parent"),
        timestamp: 1700000000,
        difficulty_target: genesis_target(),
        nonce: 999,
        tx_root: Hash256::sha256(b"txroot"),
        state_root: Hash256::sha256(b"stateroot"),
    };
    assert_eq!(header.serialize().len(), HEADER_SIZE);
    assert_eq!(HEADER_SIZE, 156);
}

#[test]
fn test_block_id_is_sha256_not_argon2id() {
    let header = BlockHeader {
        version: 1,
        height: 0,
        prev_block_id: Hash256::ZERO,
        timestamp: 1700000000,
        difficulty_target: easy_target(),
        nonce: 42,
        tx_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
    };
    let id = header.block_id();
    let expected = Hash256::sha256(&header.serialize());
    assert_eq!(id, expected);
}

#[test]
fn test_block_id_changes_with_any_field() {
    let base = BlockHeader {
        version: 1,
        height: 0,
        prev_block_id: Hash256::ZERO,
        timestamp: 1700000000,
        difficulty_target: easy_target(),
        nonce: 0,
        tx_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
    };

    let mut modified = base.clone();
    modified.nonce = 1;
    assert_ne!(base.block_id(), modified.block_id());

    let mut modified = base.clone();
    modified.timestamp = 1700000001;
    assert_ne!(base.block_id(), modified.block_id());

    let mut modified = base.clone();
    modified.height = 1;
    assert_ne!(base.block_id(), modified.block_id());
}

// ======================================================================
// 3. Transaction Tests (Section 4)
// ======================================================================

#[test]
fn test_tx_id_excludes_witnesses() {
    // Spec 4.4: tx_id computed from signing_bytes which excludes witnesses
    let tx1 = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"prev"),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(1000, &[0xAA; 32])],
        witnesses: vec![TxWitness {
            witness: vec![0xBB; 96],
            redeemer: None,
        }],
    };

    let mut tx2 = tx1.clone();
    tx2.witnesses[0].witness = vec![0xCC; 96];

    assert_eq!(tx1.tx_id().unwrap(), tx2.tx_id().unwrap());
}

#[test]
fn test_coinbase_detection() {
    // Spec 4.6: coinbase has prev_tx_id all zeros
    let coinbase = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0, // height 0
        }],
        outputs: vec![TxOutput::new_p2pkh(10_000_000_000, &[1; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    assert!(coinbase.is_coinbase());

    let non_coinbase = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"something"),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(1000, &[1; 32])],
        witnesses: vec![TxWitness {
            witness: vec![0; 96],
            redeemer: None,
        }],
    };
    assert!(!non_coinbase.is_coinbase());
}

#[test]
fn test_pubkey_hash_is_domain_separated() {
    // Spec 4.3: pubkey_hash = SHA-256("EXFER-ADDR" || pubkey)
    let pk = [0x42u8; 32];
    let hash = TxOutput::pubkey_hash_from_key(&pk);
    let expected = Hash256::domain_hash(DS_ADDR, &pk);
    assert_eq!(hash, expected);
}

// ======================================================================
// 4. Merkle Root Tests (Section 3.5)
// ======================================================================

#[test]
fn test_single_tx_merkle_root_equals_wtx_id() {
    // Single tx: tx_root = wtx_id (witness-committed hash)
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(100, &[0; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    let root = compute_tx_root(std::slice::from_ref(&tx)).unwrap();
    assert_eq!(root, tx.wtx_id().unwrap());
}

#[test]
fn test_merkle_root_odd_count_duplicates_last() {
    // Spec 3.5: "If a level has an odd number of nodes, the last node is duplicated"
    let h1 = Hash256::sha256(b"a");
    let h2 = Hash256::sha256(b"b");
    let h3 = Hash256::sha256(b"c");

    let root3 = merkle_root(DS_TXROOT, &[h1, h2, h3]);

    // Manual: pair (h1,h2) -> node01, pair (h3,h3) -> node23, then (node01,node23) -> root
    let mut pair01 = [0u8; 64];
    pair01[..32].copy_from_slice(h1.as_bytes());
    pair01[32..].copy_from_slice(h2.as_bytes());
    let node01 = Hash256::domain_hash(DS_TXROOT, &pair01);

    let mut pair23 = [0u8; 64];
    pair23[..32].copy_from_slice(h3.as_bytes());
    pair23[32..].copy_from_slice(h3.as_bytes()); // duplicated
    let node23 = Hash256::domain_hash(DS_TXROOT, &pair23);

    let mut pair_root = [0u8; 64];
    pair_root[..32].copy_from_slice(node01.as_bytes());
    pair_root[32..].copy_from_slice(node23.as_bytes());
    let expected = Hash256::domain_hash(DS_TXROOT, &pair_root);

    assert_eq!(root3, expected);
}

// ======================================================================
// 5. Proof of Work Tests (Section 5)
// ======================================================================

#[test]
fn test_pow_is_argon2id() {
    // Spec 5.1: pow = Argon2id(pw, salt, 65536, 2, 1, 32)
    //   where pw = SHA-256("EXFER-POW-P" || header_bytes)
    //   and salt = SHA-256("EXFER-POW-S" || header_bytes)
    let header = BlockHeader {
        version: 1,
        height: 0,
        prev_block_id: Hash256::ZERO,
        timestamp: 1700000000,
        difficulty_target: easy_target(),
        nonce: 0,
        tx_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
    };

    let pow = compute_pow(&header).unwrap();
    // PoW must be deterministic
    assert_eq!(pow, compute_pow(&header).unwrap());
    // PoW must differ from block_id (SHA-256 vs Argon2id)
    assert_ne!(pow, header.block_id());
}

#[test]
fn test_pow_uses_independent_domain_separators() {
    // pw and salt must use different domain separators
    let header = BlockHeader {
        version: 1,
        height: 0,
        prev_block_id: Hash256::ZERO,
        timestamp: 1700000000,
        difficulty_target: easy_target(),
        nonce: 0,
        tx_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
    };

    let header_bytes = header.serialize();
    let pw = Hash256::domain_hash(DS_POW_P, &header_bytes);
    let salt = Hash256::domain_hash(DS_POW_S, &header_bytes);
    assert_ne!(pw, salt, "password and salt must differ");
}

#[test]
fn test_pow_verification_against_target() {
    // Spec 5.3: pow < target
    let header = BlockHeader {
        version: 1,
        height: 0,
        prev_block_id: Hash256::ZERO,
        timestamp: 1700000000,
        difficulty_target: Hash256([0xFF; 32]), // extremely easy
        nonce: 0,
        tx_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
    };
    assert!(verify_pow(&header).unwrap());

    // Impossible target (zero)
    let mut hard_header = header.clone();
    hard_header.difficulty_target = Hash256::ZERO; // target = 0
    assert!(!verify_pow(&hard_header).unwrap());
}

// ======================================================================
// 6. Difficulty Adjustment Tests (Section 6)
// ======================================================================

#[test]
fn test_retarget_window() {
    // Spec 6.1: retarget every 4,320 blocks
    assert!(!needs_retarget(0));
    assert!(!needs_retarget(1));
    assert!(needs_retarget(4320));
    assert!(!needs_retarget(4321));
    assert!(needs_retarget(8640));
}

#[test]
fn test_retarget_identity() {
    // If actual == expected, target should not change
    let target = genesis_target();
    let expected_time = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
    let new_target = retarget(&target, expected_time);
    assert_eq!(target, new_target);
}

#[test]
fn test_retarget_too_fast_decreases_target() {
    // Spec 6.1: when blocks come too fast, target decreases (harder)
    let target = genesis_target();
    let expected = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
    let new_target = retarget(&target, expected / 2);
    assert!(
        new_target.as_bytes() < target.as_bytes(),
        "target should decrease when blocks are fast"
    );
}

#[test]
fn test_retarget_too_slow_increases_target() {
    // Spec 6.1: when blocks come too slow, target increases (easier)
    // Use production target (2^248) so there's room to increase
    let target = production_genesis_target();
    let expected = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;
    let new_target = retarget(&target, expected * 2);
    assert!(
        new_target.as_bytes() > target.as_bytes(),
        "target should increase when blocks are slow"
    );
}

#[test]
fn test_retarget_clamp_4x() {
    // Spec 6.1: maximum 4x adjustment per window
    let target = genesis_target();
    let expected = (RETARGET_WINDOW - 1) * TARGET_BLOCK_TIME_SECS;

    // Very slow (100x) should be same as 4x
    let clamped = retarget(&target, expected * 100);
    let at_4x = retarget(&target, expected * 4);
    assert_eq!(clamped, at_4x);

    // Very fast (1 second total) should be same as 1/4x
    let clamped_fast = retarget(&target, 1);
    let at_quarter = retarget(&target, expected / 4);
    assert_eq!(clamped_fast, at_quarter);
}

#[test]
fn test_genesis_target_value() {
    // Verify production target is 2^248: byte[0] = 0x01 in 32-byte big-endian
    let target = production_genesis_target();
    assert_eq!(target.0[0], 0x01);
    for i in 1..32 {
        assert_eq!(target.0[i], 0x00, "byte {} should be 0", i);
    }
}

#[test]
fn test_work_from_target_ordering() {
    // Higher target (easier) -> less work
    let easy = Hash256([0xFF; 32]);
    let mut hard_bytes = [0u8; 32];
    hard_bytes[15] = 0x01; // 2^128
    let hard = Hash256(hard_bytes);
    let easy_work = work_from_target(&easy);
    let hard_work = work_from_target(&hard);
    assert!(hard_work > easy_work);
}

// ======================================================================
// 7. Emission / Reward Tests (Section 7)
// ======================================================================

#[test]
fn test_reward_at_genesis() {
    // Spec 7.3: R(0) = 10,000,000,000 (100.0 EXFER)
    assert_eq!(block_reward(0), 10_000_000_000);
}

#[test]
fn test_reward_at_half_life() {
    // Spec 7.3: R(6,307,200) ~ 5,050,000,000
    let r = block_reward(HALF_LIFE);
    let expected = 5_050_000_000u64;
    let tolerance = expected / 1000; // 0.1%
    assert!(
        r.abs_diff(expected) <= tolerance,
        "R({}) = {}, expected ~ {}",
        HALF_LIFE,
        r,
        expected
    );
}

#[test]
fn test_reward_at_two_half_lives() {
    // Spec 7.3: R(12,614,400) ~ 2,575,000,000
    let r = block_reward(2 * HALF_LIFE);
    let expected = 2_575_000_000u64;
    let tolerance = expected / 1000;
    assert!(r.abs_diff(expected) <= tolerance);
}

#[test]
fn test_reward_tail_emission() {
    // Spec 7.3: R(630,720,000) = 100,000,000 (1.0 EXFER)
    assert_eq!(block_reward(630_720_000), BASE_REWARD);
}

#[test]
fn test_reward_monotonically_decreasing() {
    let mut prev = block_reward(0);
    for h in (1..200_000).step_by(997) {
        let r = block_reward(h);
        assert!(r <= prev, "reward increased at height {}", h);
        prev = r;
    }
}

#[test]
fn test_reward_never_below_base() {
    // Tail emission: reward should never go below BASE_REWARD
    for h in [0, 1, 1000, 100_000, 6_307_200, 630_720_000, u64::MAX] {
        assert!(
            block_reward(h) >= BASE_REWARD,
            "reward below base at height {}",
            h
        );
    }
}

#[test]
fn test_reward_no_floating_point() {
    // Verify integer-only: rewards should be exact u64 values
    let r0 = block_reward(0);
    assert_eq!(r0, 10_000_000_000u64); // Exact, not approximate
}

// ======================================================================
// 8. Transaction Validation Tests (Section 8)
// ======================================================================

#[test]
fn test_tx_valid_basic() {
    // Positive test: a properly formed and signed transaction passes
    let (sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 1_000_000_000)], false, 0);

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(900_000_000, &[0xBB; 32])],
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    let (fee, _, _) = validate_transaction(&tx, &utxo_set, 100).unwrap();
    assert_eq!(fee, 100_000_000); // 1B - 900M = 100M fee
}

#[test]
fn test_tx_rule1_no_inputs() {
    // Spec 8.1 Rule 1: input_count >= 1
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![TxOutput::new_p2pkh(1000, &[0; 32])],
        witnesses: vec![],
    };
    let utxo_set = UtxoSet::new();
    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::NoInputs)
    ));
}

#[test]
fn test_tx_rule1_no_outputs() {
    // Spec 8.1 Rule 1: output_count >= 1
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"x"),
            output_index: 0,
        }],
        outputs: vec![],
        witnesses: vec![TxWitness {
            witness: vec![0; 96],
            redeemer: None,
        }],
    };
    let utxo_set = UtxoSet::new();
    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::NoOutputs)
    ));
}

#[test]
fn test_tx_witness_count_mismatch() {
    // Witness count must match input count
    let (_sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 1_000_000_000)], false, 0);

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(1000, &[0; 32])],
        witnesses: vec![], // no witnesses!
    };

    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::WitnessCountMismatch {
            inputs: 1,
            witnesses: 0
        })
    ));
}

#[test]
fn test_tx_rule2_utxo_not_found() {
    // Spec 8.1 Rule 2: input must reference existing unspent UTXO
    let (sk, _pk) = make_keypair();
    let utxo_set = UtxoSet::new(); // empty

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"nonexistent"),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32])],
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::UtxoNotFound(_))
    ));
}

#[test]
fn test_tx_rule3_duplicate_input() {
    // Spec 8.1 Rule 3: no duplicate inputs
    let (sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 2_000_000_000)], false, 0);

    let mut tx = Transaction {
        inputs: vec![
            TxInput {
                prev_tx_id,
                output_index: 0,
            },
            TxInput {
                prev_tx_id,
                output_index: 0, // duplicate!
            },
        ],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32])],
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::DuplicateInput(_))
    ));
}

#[test]
fn test_tx_rule4_pubkey_hash_mismatch() {
    // Spec 8.1 Rule 4: pubkey hash must match
    let (_sk, pk) = make_keypair();
    let (_, _wrong_pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    // UTXO is locked to pk, but we provide wrong_pk in witness
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 1_000_000_000)], false, 0);

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32])],
        witnesses: vec![],
    };

    // Manually set wrong pubkey in witness
    let wrong_sk = SigningKey::generate(&mut OsRng);
    let wrong_pk_bytes = wrong_sk.verifying_key().to_bytes();
    let msg = tx.sig_message().unwrap();
    let sig = wrong_sk.sign(&msg);
    let mut witness_data = Vec::with_capacity(96);
    witness_data.extend_from_slice(&wrong_pk_bytes);
    witness_data.extend_from_slice(&sig.to_bytes());
    tx.witnesses = vec![TxWitness {
        witness: witness_data,
        redeemer: None,
    }];

    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::PubkeyHashMismatch { .. })
    ));
}

#[test]
fn test_tx_rule5_invalid_signature() {
    // Spec 8.1 Rule 5: signature must be valid
    let (_sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 1_000_000_000)], false, 0);

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32])],
        witnesses: vec![TxWitness {
            witness: {
                let mut w = Vec::with_capacity(96);
                w.extend_from_slice(&pk); // correct pubkey
                w.extend_from_slice(&[0xFF; 64]); // invalid signature
                w
            },
            redeemer: None,
        }],
    };

    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::SignatureInvalid { .. })
    ));
}

#[test]
fn test_tx_rule5_wrong_witness_length() {
    // Witness must be exactly 96 bytes for Phase 1
    let (_sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 1_000_000_000)], false, 0);

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32])],
        witnesses: vec![TxWitness {
            witness: vec![0xFF; 50], // wrong length
            redeemer: None,
        }],
    };

    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::WitnessInvalid { .. })
    ));
}

#[test]
fn test_tx_rule6_output_below_dust() {
    // Spec 8.1 Rule 6/9: every output value >= dust_threshold (200 exfers)
    let (sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 1_000_000_000)], false, 0);

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD - 1, &[0; 32])], // below dust
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::OutputBelowDust { .. })
    ));
}

#[test]
fn test_tx_rule6_zero_value_output() {
    // Zero is below dust threshold
    let (sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 1_000_000_000)], false, 0);

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(0, &[0; 32])],
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::OutputBelowDust { .. })
    ));
}

#[test]
fn test_tx_rule7_insufficient_input_value() {
    // Spec 8.1 Rule 7: sum(inputs) >= sum(outputs)
    let (sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, DUST_THRESHOLD)], false, 0);

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD + 1000, &[0; 32])], // more than input
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::InsufficientInputValue)
    ));
}

#[test]
fn test_tx_rule8_fee_below_minimum() {
    // Spec 8.1 Rule 8: fee >= min_fee = ceil_div(tx_cost, 100)
    let (sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");

    // Build tx first to compute min_fee, then set UTXO value so fee is just below
    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32])],
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    let min = cost::min_fee(&tx).unwrap();
    // Set UTXO value so fee = min - 1
    let utxo_value = DUST_THRESHOLD + min - 1;
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, utxo_value)], false, 0);

    // Re-sign because tx hasn't changed
    let mut tx2 = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32])],
        witnesses: vec![],
    };
    sign_tx(&mut tx2, &sk);

    assert!(matches!(
        validate_transaction(&tx2, &utxo_set, 0),
        Err(ValidationError::FeeBelowMinimum { .. })
    ));
}

#[test]
fn test_tx_rule8_fee_at_minimum() {
    // Fee exactly at min_fee should pass
    let (sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32])],
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    let min = cost::min_fee(&tx).unwrap();
    let utxo_value = DUST_THRESHOLD + min;
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, utxo_value)], false, 0);

    // Re-sign
    let mut tx2 = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32])],
        witnesses: vec![],
    };
    sign_tx(&mut tx2, &sk);

    let (fee, _, _) = validate_transaction(&tx2, &utxo_set, 0).unwrap();
    assert_eq!(fee, min);
}

#[test]
fn test_tx_rule9_coinbase_maturity() {
    // Spec 8.1 Rule 9: coinbase outputs locked for 360 blocks
    let (sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"cb");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 1_000_000_000)], true, 100);

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32])],
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    // At height 459 (age = 359 blocks), should fail
    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 459),
        Err(ValidationError::CoinbaseImmature { .. })
    ));

    // At height 460 (age = 360 blocks), should succeed
    let (fee, _, _) = validate_transaction(&tx, &utxo_set, 460).unwrap();
    assert_eq!(fee, 1_000_000_000 - DUST_THRESHOLD);
}

#[test]
fn test_tx_rule10_size_limit() {
    // Spec 8.1 Rule 10: max 1 MiB
    let (sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, u64::MAX / 2)], false, 0);

    // Create a transaction with many outputs to exceed 1 MiB
    let mut outputs = Vec::new();
    for _ in 0..30000 {
        outputs.push(TxOutput::new_p2pkh(DUST_THRESHOLD, &[0; 32]));
    }

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs,
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    assert!(matches!(
        validate_transaction(&tx, &utxo_set, 0),
        Err(ValidationError::TxTooLarge { .. })
    ));
}

// ======================================================================
// 8.2 Coinbase Validation Tests (Section 8.2)
// ======================================================================

#[test]
fn test_coinbase_valid() {
    let reward = block_reward(0);
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0, // height 0
        }],
        outputs: vec![TxOutput::new_p2pkh(reward, &[1; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    assert!(validate_coinbase(&tx, 0, reward).is_ok());
}

#[test]
fn test_coinbase_wrong_output_index() {
    // Spec 8.2 Rule 2: output_index must equal height as u32
    let reward = block_reward(100);
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0, // should be 100
        }],
        outputs: vec![TxOutput::new_p2pkh(reward, &[1; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    assert!(matches!(
        validate_coinbase(&tx, 100, reward),
        Err(ValidationError::CoinbaseBadOutputIndex {
            expected: 100,
            got: 0
        })
    ));
}

#[test]
fn test_coinbase_wrong_reward() {
    // Spec 8.2 Rule 3: outputs must sum to exactly block_reward + fees
    let reward = block_reward(0);
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(reward + 1, &[1; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    assert!(matches!(
        validate_coinbase(&tx, 0, reward),
        Err(ValidationError::CoinbaseWrongReward { .. })
    ));
}

#[test]
fn test_coinbase_zero_output() {
    // Spec 8.2 Rule 4: all outputs > 0
    let reward = block_reward(0);
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![
            TxOutput::new_p2pkh(reward, &[1; 32]),
            TxOutput::new_p2pkh(0, &[1; 32]),
        ],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    assert!(matches!(
        validate_coinbase(&tx, 0, reward),
        Err(ValidationError::OutputBelowDust { .. })
    ));
}

// ======================================================================
// 9. Signature Tests (Section 4.5)
// ======================================================================

#[test]
fn test_signature_uses_domain_separator() {
    // Spec 4.5: message = "EXFER-SIG" || signing_bytes
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"prev"),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(100, &[0; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let sig_msg = tx.sig_message().unwrap();
    assert!(sig_msg.starts_with(DS_SIG));
    // Genesis block ID must follow DS_SIG prefix (chain-bound signatures).
    let genesis_id = &*exfer::genesis::GENESIS_BLOCK_ID;
    assert_eq!(
        &sig_msg[DS_SIG.len()..DS_SIG.len() + 32],
        genesis_id.as_bytes()
    );
}

// ======================================================================
// 10. Fork Choice Tests (Section 10)
// ======================================================================

#[test]
fn test_cumulative_work_increases_with_difficulty() {
    // Spec 10.1: work = 2^256 / (target + 1)
    let easy = Hash256([0xFF; 32]);
    let mut hard_bytes = [0u8; 32];
    hard_bytes[15] = 0x01;
    let hard = Hash256(hard_bytes);
    let easy_work = work_from_target(&easy);
    let hard_work = work_from_target(&hard);
    assert!(hard_work > easy_work);
}

#[test]
fn test_work_additivity() {
    let target = genesis_target();
    let w1 = work_from_target(&target);
    let w2 = work_from_target(&target);
    let sum = add_work(&w1, &w2);

    // Sum should be larger than each individual
    assert!(sum > w1);
    assert!(sum > w2);
}

// ======================================================================
// 11. UTXO State Tests
// ======================================================================

#[test]
fn test_utxo_apply_coinbase() {
    let mut utxo_set = UtxoSet::new();
    let coinbase = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(10_000_000_000, &[1; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let tx_id = coinbase.tx_id().unwrap();
    utxo_set.apply_transaction(&coinbase, 0).unwrap();

    let outpoint = OutPoint::new(tx_id, 0);
    let entry = utxo_set.get(&outpoint).unwrap();
    assert_eq!(entry.output.value, 10_000_000_000);
    assert!(entry.is_coinbase);
    assert_eq!(entry.height, 0);
}

#[test]
fn test_utxo_apply_removes_spent_inputs() {
    let (_, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let mut utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 1000)], false, 0);

    let spend_tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(900, &[0; 32])],
        witnesses: vec![TxWitness {
            witness: vec![0; 96],
            redeemer: None,
        }],
    };

    utxo_set.apply_transaction(&spend_tx, 1).unwrap();

    // Old UTXO should be gone
    assert!(utxo_set.get(&OutPoint::new(prev_tx_id, 0)).is_none());
    // New UTXO should exist
    assert!(utxo_set
        .get(&OutPoint::new(spend_tx.tx_id().unwrap(), 0))
        .is_some());
}

#[test]
fn test_state_root_deterministic() {
    let (_, pk) = make_keypair();
    let mut utxo_set = UtxoSet::new();

    let cb = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(10_000_000_000, &pk)],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    utxo_set.apply_transaction(&cb, 0).unwrap();

    let root1 = utxo_set.state_root();
    let root2 = utxo_set.state_root();
    assert_eq!(root1, root2);
    assert_ne!(root1, Hash256::ZERO);
}

// ======================================================================
// 12. Median Time Past Tests (Section 9, Rule 7)
// ======================================================================

#[test]
fn test_mtp_11_ancestors() {
    let timestamps = vec![110, 100, 109, 98, 107, 96, 105, 94, 103, 92, 101];
    let mtp = median_time_past(&timestamps);
    // sorted: [92, 94, 96, 98, 100, 101, 103, 105, 107, 109, 110]
    // median at index 5 = 101
    assert_eq!(mtp, 101);
}

#[test]
fn test_mtp_fewer_ancestors() {
    // With fewer than 11 ancestors (near genesis), MTP still works
    let timestamps = vec![100, 90, 80];
    let mtp = median_time_past(&timestamps);
    assert_eq!(mtp, 90); // median of [80, 90, 100]
}

// ======================================================================
// 13. Value Conservation Tests (Consensus Rule 7)
// ======================================================================

#[test]
fn test_value_conservation_with_fee() {
    // Spec: sum(inputs) = sum(outputs) + fee, exact, no rounding
    let (sk, pk) = make_keypair();
    let prev_tx_id = Hash256::sha256(b"prev");
    let utxo_set = make_utxo_set_with_coins(&pk, &[(prev_tx_id, 0, 1_000_000_000)], false, 0);

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(900_000_000, &[0; 32])],
        witnesses: vec![],
    };
    sign_tx(&mut tx, &sk);

    let (fee, _, _) = validate_transaction(&tx, &utxo_set, 100).unwrap();
    assert_eq!(fee, 100_000_000);
}

// ======================================================================
// 14. Serialization Canonicality Tests
// ======================================================================

#[test]
fn test_header_serialization_canonical() {
    // Same header always produces the same bytes
    let h = BlockHeader {
        version: 1,
        height: 12345,
        prev_block_id: Hash256::sha256(b"parent"),
        timestamp: 1700000000,
        difficulty_target: genesis_target(),
        nonce: 42,
        tx_root: Hash256::sha256(b"txs"),
        state_root: Hash256::sha256(b"state"),
    };
    assert_eq!(h.serialize(), h.serialize());

    // Deserialize and re-serialize gives same bytes
    let bytes = h.serialize();
    let h2 = BlockHeader::deserialize(&bytes);
    assert_eq!(bytes, h2.serialize());
}

#[test]
fn test_transaction_serialization_canonical() {
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"prev"),
            output_index: 3,
        }],
        outputs: vec![TxOutput::new_p2pkh(999_999_999, &[0x42; 32])],
        witnesses: vec![TxWitness {
            witness: vec![0xAB; 96],
            redeemer: None,
        }],
    };
    let bytes = tx.serialize().unwrap();
    let (tx2, _) = Transaction::deserialize(&bytes).unwrap();
    assert_eq!(bytes, tx2.serialize().unwrap());
}

#[test]
fn test_little_endian_encoding() {
    // All multi-byte integers must be little-endian
    let h = BlockHeader {
        version: 1,
        height: 0,
        prev_block_id: Hash256::ZERO,
        timestamp: 0,
        difficulty_target: Hash256::ZERO,
        nonce: 0,
        tx_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
    };
    let bytes = h.serialize();
    // Version 1 in little-endian: [1, 0, 0, 0]
    assert_eq!(&bytes[0..4], &[1, 0, 0, 0]);
}

// ======================================================================
// 15. Constants Tests
// ======================================================================

#[test]
fn test_consensus_constants() {
    // Verify all constants match spec section 14
    assert_eq!(VERSION, 1);
    assert_eq!(TARGET_BLOCK_TIME_SECS, 10);
    assert_eq!(RETARGET_WINDOW, 4_320);
    assert_eq!(MAX_RETARGET_FACTOR, 4);
    assert_eq!(COINBASE_MATURITY, 360);
    assert_eq!(MAX_BLOCK_SIZE, 4_194_304);
    assert_eq!(MAX_TX_SIZE, 1_048_576);
    assert_eq!(MTP_WINDOW, 11);
    assert_eq!(MAX_TIMESTAMP_DRIFT, 120);
    assert_eq!(MAX_TIMESTAMP_GAP, 604_800);
    assert_eq!(BASE_REWARD, 100_000_000);
    assert_eq!(DECAY_COMPONENT, 9_900_000_000);
    assert_eq!(HALF_LIFE, 6_307_200);
    assert_eq!(ARGON2_MEMORY_KIB, 65_536);
    assert_eq!(ARGON2_ITERATIONS, 2);
    assert_eq!(ARGON2_PARALLELISM, 1);
    assert_eq!(ARGON2_OUTPUT_LEN, 32);
    assert_eq!(MAX_MESSAGE_SIZE, 8_388_608);
    assert_eq!(MEMPOOL_CAPACITY, 8_192);
    assert_eq!(BLOCK_HEADER_SIZE, 156);
}

#[test]
fn test_fee_cost_constants() {
    assert_eq!(UTXO_LOOKUP_COST, 100);
    assert_eq!(UTXO_CREATE_COST, 100);
    assert_eq!(SMT_DELETE_COST, 500);
    assert_eq!(SMT_INSERT_COST, 500);
    assert_eq!(STANDARD_SPEND_COST, 20_000);
    assert_eq!(MIN_FEE_DIVISOR, 100);
    assert_eq!(DUST_THRESHOLD, 200);
    assert_eq!(PHASE1_SCRIPT_EVAL_COST, 5_000);
}

#[test]
fn test_domain_separators() {
    assert_eq!(DS_SIG, b"EXFER-SIG");
    assert_eq!(DS_TX, b"EXFER-TX");
    assert_eq!(DS_TXROOT, b"EXFER-TXROOT");
    assert_eq!(DS_STATE, b"EXFER-STATE");
    assert_eq!(DS_ADDR, b"EXFER-ADDR");
    assert_eq!(DS_POW_P, b"EXFER-POW-P");
    assert_eq!(DS_POW_S, b"EXFER-POW-S");
    assert_eq!(DS_AGENT, b"EXFER-AGENT");
    assert_eq!(DS_SCRIPT, b"EXFER-SCRIPT");
}

// ======================================================================
// 16. Cost and Min Fee Tests
// ======================================================================

#[test]
fn test_ceil_div_u128() {
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
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"prev"),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(1000, &[1u8; 32])],
        witnesses: vec![TxWitness {
            witness: vec![0u8; 96],
            redeemer: None,
        }],
    };
    let c = cost::tx_cost(&tx).unwrap();
    assert!(c > 0, "tx_cost should be positive for any real transaction");
}

#[test]
fn test_min_fee_positive() {
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"prev"),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(1000, &[1u8; 32])],
        witnesses: vec![TxWitness {
            witness: vec![0u8; 96],
            redeemer: None,
        }],
    };
    let min = cost::min_fee(&tx).unwrap();
    assert!(
        min > 0,
        "min_fee should be positive for any real transaction"
    );
}

// ======================================================================
// 17. Non-Coinbase Sentinel Test
// ======================================================================

#[test]
fn test_non_coinbase_sentinel_rejected() {
    // Only the first transaction may have the sentinel outpoint (all-zero prev_tx_id)
    let (_sk, pk) = make_keypair();
    let _prev_tx_id = Hash256::sha256(b"prev");

    // Build a valid coinbase
    let reward = block_reward(0);
    let coinbase = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(reward, &pk)],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    // A second "coinbase" (sentinel outpoint in non-first position)
    let fake_coinbase = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO, // sentinel!
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(1000, &pk)],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let tx_root = compute_tx_root(&[coinbase.clone(), fake_coinbase.clone()]).unwrap();
    let block = Block {
        header: BlockHeader {
            version: 1,
            height: 0,
            prev_block_id: Hash256::ZERO,
            timestamp: 1700000000,
            difficulty_target: easy_target(),
            nonce: 0,
            tx_root,
            state_root: Hash256::ZERO,
        },
        transactions: vec![coinbase, fake_coinbase],
    };

    let result = validate_block_header(&block, None, &[], &easy_target(), Some(1700000000));
    assert!(matches!(
        result,
        Err(ValidationError::NonCoinbaseSentinel { tx_index: 1 })
    ));
}
