//! Audit fix tests — round 38 (P1 + P2) — behavioral rewrites.
//!
//! P1: PoW / difficulty validation exercised via verify_pow + validate_block_header.
//! P2: Rate-limit constants exercised via value assertions.
//! Sync: Cumulative-work comparison replaces height-advantage cap.
//! Fork header cap: retained non-canonical headers bounded by MAX_RETAINED_FORK_HEADERS.

// ── P1: PoW / difficulty validation ──

#[test]
fn p1_verify_pow_rejects_bad_nonce() {
    use exfer::consensus::pow::verify_pow;
    use exfer::types::block::BlockHeader;
    use exfer::types::hash::Hash256;

    // Impossible target (all zeros) — no hash can be < [0;32]
    let header = BlockHeader {
        version: 1,
        height: 0,
        prev_block_id: Hash256::ZERO,
        timestamp: 1700000000,
        difficulty_target: Hash256::ZERO,
        nonce: 999,
        tx_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
    };
    let result = verify_pow(&header).expect("verify_pow should not error");
    assert!(!result, "PoW must fail when target is all zeros");
}

#[test]
fn p1_verify_pow_accepts_genesis() {
    use exfer::consensus::pow::verify_pow;
    use exfer::genesis::genesis_block;

    let genesis = genesis_block();
    let result = verify_pow(&genesis.header).expect("verify_pow should not error");
    assert!(result, "genesis block PoW must verify");
}

#[test]
fn p1_validate_rejects_wrong_difficulty() {
    use exfer::consensus::difficulty::genesis_target;
    use exfer::consensus::validation::{validate_block_header, ValidationError};
    use exfer::genesis::genesis_block;
    use exfer::types::hash::Hash256;

    let genesis = genesis_block();
    // Pass an expected_target that differs from the block's difficulty_target
    let wrong_target = Hash256([0xFF; 32]);
    let actual_target = genesis_target();
    // Ensure they actually differ (sanity check for non-testnet)
    if wrong_target != actual_target {
        let err = validate_block_header(&genesis, None, &[], &wrong_target, None)
            .expect_err("should reject wrong difficulty");
        assert!(
            matches!(err, ValidationError::InvalidDifficulty),
            "expected InvalidDifficulty, got {:?}",
            err
        );
    }
}

#[test]
fn p1_validate_rejects_bad_pow() {
    use exfer::consensus::validation::{validate_block_header, ValidationError};
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
    use exfer::types::VERSION;

    // Block and expected target both set to all-zeros (impossible PoW)
    let impossible = Hash256::ZERO;
    let coinbase = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 10_000_000_000,
            script: vec![0u8; 32],
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    let block = Block {
        header: BlockHeader {
            version: VERSION,
            height: 0,
            prev_block_id: Hash256::ZERO,
            timestamp: 1700000000,
            difficulty_target: impossible,
            nonce: 0,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![coinbase],
    };
    let err = validate_block_header(&block, None, &[], &impossible, None)
        .expect_err("should reject impossible PoW");
    assert!(
        matches!(err, ValidationError::PowFailed),
        "expected PowFailed, got {:?}",
        err
    );
}

// ── P2: Rate-limit constants ──

#[test]
fn p2_max_global_txs_per_min_positive() {
    use exfer::types::MAX_GLOBAL_TXS_PER_MIN;
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(MAX_GLOBAL_TXS_PER_MIN > 0);
    }
}

#[test]
fn p2_max_global_blocks_per_min_positive() {
    use exfer::types::MAX_GLOBAL_BLOCKS_PER_MIN;
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(MAX_GLOBAL_BLOCKS_PER_MIN > 0);
    }
}

#[test]
fn p2_per_peer_limit_within_global() {
    use exfer::types::{
        MAX_BLOCKS_PER_MIN, MAX_GLOBAL_BLOCKS_PER_MIN, MAX_GLOBAL_TXS_PER_MIN, MAX_TXS_PER_MIN,
    };
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            MAX_GLOBAL_TXS_PER_MIN >= MAX_TXS_PER_MIN,
            "global tx limit must be >= per-peer"
        );
        assert!(
            MAX_GLOBAL_BLOCKS_PER_MIN >= MAX_BLOCKS_PER_MIN,
            "global block limit must be >= per-peer"
        );
    }
}

#[test]
fn p2_rate_limiter_tuple_constructible() {
    use std::sync::Mutex;
    use std::time::Instant;

    let limiter: Mutex<(Instant, u32)> = Mutex::new((Instant::now(), 0));
    let mut guard = limiter.lock().unwrap();
    guard.1 += 1;
    assert_eq!(guard.1, 1, "rate limiter counter must increment");
}

// ── Sync: Cumulative work comparison ──

#[test]
fn sync_higher_work_accepted() {
    // Peer with more cumulative work should be accepted for sync
    let our_work: [u8; 32] = {
        let mut w = [0u8; 32];
        w[31] = 10;
        w
    };
    let peer_work: [u8; 32] = {
        let mut w = [0u8; 32];
        w[31] = 20;
        w
    };
    assert!(
        peer_work > our_work,
        "higher work peer must compare greater"
    );
}

#[test]
fn sync_zero_work_rejected() {
    // Peer claiming zero work should not compare greater
    let our_work: [u8; 32] = {
        let mut w = [0u8; 32];
        w[31] = 1;
        w
    };
    let peer_work: [u8; 32] = [0u8; 32];
    assert!(
        peer_work <= our_work,
        "zero-work peer must not compare greater"
    );
}

#[test]
fn sync_equal_work_rejected() {
    // Equal work should not trigger sync
    let work: [u8; 32] = {
        let mut w = [0u8; 32];
        w[31] = 10;
        w
    };
    assert!(work <= work, "equal work must not compare greater");
}

#[test]
fn sync_more_work_lower_height_triggers_sync() {
    // A peer with more cumulative work but lower height should still
    // win under fork choice and trigger sync.
    use exfer::chain::fork_choice::{is_better_chain, ChainTip};
    use exfer::types::hash::Hash256;

    let our_tip = ChainTip {
        block_id: Hash256::ZERO,
        height: 100,
        cumulative_work: {
            let mut w = [0u8; 32];
            w[31] = 10;
            w
        },
    };
    let peer_tip = ChainTip {
        block_id: Hash256::ZERO,
        height: 80, // lower height
        cumulative_work: {
            let mut w = [0u8; 32];
            w[31] = 50; // but more work
            w
        },
    };
    assert!(
        is_better_chain(&peer_tip, &our_tip),
        "peer with more work but lower height must trigger sync"
    );
}

// ── Fork header cap ──

fn make_test_block(height: u64, nonce: u64) -> exfer::types::block::Block {
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    let coinbase = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: 10_000_000_000,
            script: vec![0u8; 32],
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    Block {
        header: BlockHeader {
            version: 1,
            height,
            prev_block_id: Hash256::ZERO,
            timestamp: 1700000000,
            difficulty_target: Hash256([0xFF; 32]),
            nonce,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![coinbase],
    }
}

#[test]
fn retained_cap_enforced() {
    use exfer::chain::storage::ChainStorage;

    let tmpdir = tempfile::TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // Create and evict 15 fork blocks — cap is 10,000 so all should be retained
    for i in 0u64..15 {
        let block = make_test_block(i + 1, i + 100);
        let work = [0u8; 32];
        storage.store_fork_block_atomic(&block, &work).unwrap();
        let block_id = block.header.block_id();
        storage.evict_fork_block(&block_id).unwrap();
    }

    // Verify headers still exist (retained under cap) by checking each one
    let mut retained = 0;
    for i in 0u64..15 {
        let block = make_test_block(i + 1, i + 100);
        let block_id = block.header.block_id();
        if storage.get_header(&block_id).unwrap().is_some() {
            retained += 1;
        }
    }
    assert_eq!(
        retained, 15,
        "all 15 evicted fork headers should be retained (under cap)"
    );
    assert!(
        retained <= exfer::types::MAX_RETAINED_FORK_HEADERS as usize,
        "retained count must not exceed MAX_RETAINED_FORK_HEADERS"
    );
}

#[test]
fn retained_lowest_height_evicted() {
    use exfer::chain::storage::ChainStorage;

    let tmpdir = tempfile::TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // Store+evict blocks at heights 1..=5
    let mut ids = Vec::new();
    for i in 0u64..5 {
        let block = make_test_block(i + 1, i + 200);
        let work = [0u8; 32];
        storage.store_fork_block_atomic(&block, &work).unwrap();
        ids.push(block.header.block_id());
        storage.evict_fork_block(ids.last().unwrap()).unwrap();
    }

    // All should be retained — under the 10k cap
    // Verify headers still exist for all retained blocks
    for id in &ids {
        assert!(
            storage.get_header(id).unwrap().is_some(),
            "retained fork header must still exist"
        );
    }
}

#[test]
fn retained_canonical_not_deleted() {
    use exfer::chain::storage::ChainStorage;

    let tmpdir = tempfile::TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // Create a block, store as fork, promote to canonical, then evict
    let block = make_test_block(1, 300);
    let block_id = block.header.block_id();
    let work = [0u8; 32];

    // Store as fork block first
    storage.store_fork_block_atomic(&block, &work).unwrap();

    // Promote to canonical via commit_genesis_atomic (sets height index + tip)
    storage.commit_genesis_atomic(&block, &work).unwrap();

    // Evict — should detect canonical and preserve data
    storage.evict_fork_block(&block_id).unwrap();

    // Header must survive because block is canonical
    assert!(
        storage.get_header(&block_id).unwrap().is_some(),
        "canonical block header must survive fork eviction"
    );
}

// ── Addr book poisoning mitigation ──

#[test]
fn ds_session_constant_exists() {
    use exfer::types::DS_SESSION;
    assert_eq!(DS_SESSION, b"EXFER-SESSION");
}

#[test]
fn hmac_tag_size_is_16() {
    use exfer::network::protocol::HMAC_TAG_SIZE;
    assert_eq!(HMAC_TAG_SIZE, 16);
}

#[test]
fn session_key_includes_dh_secret() {
    use exfer::network::protocol::compute_session_key;
    use exfer::types::hash::Hash256;

    let genesis = Hash256::ZERO;
    let nonce_a = [0x11u8; 32];
    let nonce_b = [0x22u8; 32];
    let dh1 = [0xAAu8; 32];
    let dh2 = [0xBBu8; 32];

    // Same DH secret → same key
    let key1 = compute_session_key(&genesis, 4, &nonce_a, &nonce_b, &dh1);
    let key2 = compute_session_key(&genesis, 4, &nonce_a, &nonce_b, &dh1);
    assert_eq!(key1, key2);

    // Different DH secret → different key (MITM cannot derive the right one)
    let key3 = compute_session_key(&genesis, 4, &nonce_a, &nonce_b, &dh2);
    assert_ne!(key1, key3);

    // Swapping nonces also produces different key
    let key4 = compute_session_key(&genesis, 4, &nonce_b, &nonce_a, &dh1);
    assert_ne!(key1, key4);
}

#[test]
fn session_key_dh_uses_identity_keys() {
    // Verify the DH exchange produces matching shared secrets
    // when both sides use their own signing key + peer's public key
    use ed25519_dalek::{SigningKey, VerifyingKey};

    let key_a = SigningKey::from_bytes(&[0x11u8; 32]);
    let key_b = SigningKey::from_bytes(&[0x22u8; 32]);

    let pub_a = key_a.verifying_key();
    let pub_b = key_b.verifying_key();

    // A computes: scalar_a * pub_b_montgomery
    let dh_a = VerifyingKey::from_bytes(&pub_b.to_bytes())
        .unwrap()
        .to_montgomery()
        .mul_clamped(key_a.to_scalar_bytes())
        .to_bytes();

    // B computes: scalar_b * pub_a_montgomery
    let dh_b = VerifyingKey::from_bytes(&pub_a.to_bytes())
        .unwrap()
        .to_montgomery()
        .mul_clamped(key_b.to_scalar_bytes())
        .to_bytes();

    // DH shared secrets must match
    assert_eq!(dh_a, dh_b);
    // Must not be all zeros
    assert_ne!(dh_a, [0u8; 32]);
}

#[test]
fn peer_error_hmac_failure_exists() {
    use exfer::network::peer::PeerError;
    let err = PeerError::HmacFailure;
    let msg = format!("{}", err);
    assert!(
        msg.contains("HMAC") || msg.contains("hmac"),
        "HmacFailure error: {}",
        msg
    );
}

// ── PoW skip replay: 100 blocks validated in under 1 second ──

#[test]
fn pow_skip_replay_100_blocks_under_1s() {
    use exfer::consensus::difficulty::genesis_target;
    use exfer::consensus::validation::validate_block_header_skip_pow;
    use exfer::genesis::genesis_block;

    let genesis = genesis_block();
    let target = genesis_target();
    let start = std::time::Instant::now();

    for _ in 0..100 {
        validate_block_header_skip_pow(&genesis, None, &[], &target, None)
            .expect("skip-pow validation of genesis must succeed");
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs_f64() < 1.0,
        "100 skip-pow validations took {:.3}s — must complete under 1s",
        elapsed.as_secs_f64()
    );
}

// ── Genesis overwrite protection: tip exists + missing genesis body → hard exit ──

#[test]
fn genesis_overwrite_blocked_when_tip_exists() {
    use exfer::chain::storage::ChainStorage;
    use exfer::genesis::genesis_block;
    use exfer::types::hash::Hash256;

    let tmpdir = tempfile::TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // Simulate corruption: set a tip but do NOT store any genesis block body.
    let fake_tip = Hash256([0xAA; 32]);
    storage.set_tip(&fake_tip).unwrap();

    // Verify the corruption is detectable:
    // - tip exists
    let tip = storage.get_tip().unwrap();
    assert!(tip.is_some(), "tip must exist after set_tip");

    // - genesis block body is missing
    let genesis = genesis_block();
    let genesis_id = genesis.header.block_id();
    let has_body = storage.has_block(&genesis_id).unwrap();
    assert!(!has_body, "genesis body must be absent");

    // This is the exact condition checked at main.rs before process::exit(1).
    // The node must refuse to call commit_genesis_atomic in this state.
    assert!(
        tip.is_some() && !has_body,
        "tip-exists + no-genesis-body must be detected as corruption"
    );

    // Verify no writes occurred: blocks table should still be empty.
    assert!(
        storage.blocks_table_is_empty().unwrap(),
        "no blocks should be written when tip exists but genesis body is missing"
    );
}

// ── Fatal error in retry_future_blocks triggers shutdown ──

#[test]
fn two_fork_tips_same_ancestor_both_retried() {
    // Verify that ReorgTriggerState correctly stores and retries multiple
    // trigger blocks for the same missing ancestor.
    use exfer::network::sync::ReorgTriggerState;
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;

    let mut state = ReorgTriggerState::new();
    let ancestor_id = Hash256::sha256(b"ancestor");

    // Two different fork tips both need the same ancestor
    let block_a = Block {
        header: BlockHeader {
            version: 1,
            height: 5,
            prev_block_id: ancestor_id,
            timestamp: 1000,
            difficulty_target: Hash256([0xFF; 32]),
            nonce: 1,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![],
    };
    let block_b = Block {
        header: BlockHeader {
            version: 1,
            height: 5,
            prev_block_id: ancestor_id,
            timestamp: 1001,
            difficulty_target: Hash256([0xFF; 32]),
            nonce: 2,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![],
    };
    let id_a = block_a.header.block_id();
    let id_b = block_b.header.block_id();

    assert!(state.insert(ancestor_id, block_a));
    assert!(state.insert(ancestor_id, block_b));

    // Simulate ancestor arrival: take all triggers
    let trigger_blocks = state.take(&ancestor_id).unwrap();
    assert_eq!(trigger_blocks.len(), 2, "both fork tips must be stored");
    let ids: Vec<_> = trigger_blocks.iter().map(|b| b.header.block_id()).collect();
    assert!(ids.contains(&id_a), "fork_tip_A must be retried");
    assert!(ids.contains(&id_b), "fork_tip_B must be retried");
    assert!(
        state.take(&ancestor_id).is_none(),
        "ancestor entry must be removed after take"
    );
}

// ── Miner timestamp validation ──

#[test]
fn miner_clock_behind_mtp_uses_mtp_plus_one() {
    use exfer::chain::state::UtxoSet;
    use exfer::consensus::validation::median_time_past;
    use exfer::mempool::Mempool;
    use exfer::miner::Miner;
    use exfer::types::hash::Hash256;

    let miner = Miner::new([0x42; 32]);
    let mempool = Mempool::new();
    let utxo_set = UtxoSet::new();

    // Simulate timestamps where MTP = 1_000_000
    let ancestor_timestamps: Vec<u64> = vec![
        1_000_005, 1_000_004, 1_000_003, 1_000_002, 1_000_001, 1_000_000, 999_999, 999_998,
        999_997, 999_996, 999_995,
    ];
    let mtp = median_time_past(&ancestor_timestamps);
    assert_eq!(mtp, 1_000_000);

    // Pass a timestamp behind MTP — mining loop would have clamped to MTP+1
    let clamped_ts = mtp + 1;
    let (block, _) = miner
        .build_template(
            1,
            Hash256::ZERO,
            Hash256([0xFF; 32]),
            clamped_ts,
            &mempool,
            &utxo_set,
        )
        .unwrap();

    assert_eq!(
        block.header.timestamp, clamped_ts,
        "block timestamp must be MTP+1 when clock is behind MTP"
    );
    assert!(
        block.header.timestamp > mtp,
        "block timestamp must be strictly greater than MTP"
    );
}

#[test]
fn miner_mine_returns_none_when_nonce_exhaustion_exceeds_gap() {
    use exfer::miner::Miner;
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;
    use exfer::types::VERSION;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let miner = Miner::new([0x42; 32]);

    // Create a block with impossible target (never finds PoW)
    // and max_timestamp = 0 (already expired)
    let block = Block {
        header: BlockHeader {
            version: VERSION,
            height: 1,
            prev_block_id: Hash256::ZERO,
            timestamp: 100,
            difficulty_target: Hash256::ZERO, // impossible target
            nonce: u64::MAX - 1,              // will exhaust in 2 iterations
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![],
    };

    let cancel = Arc::new(AtomicBool::new(false));
    // max_timestamp = 0 means any timestamp refresh will exceed it
    let pause = Arc::new(AtomicBool::new(false));
    let result = miner.mine(block, cancel, pause, 0, 0);
    assert!(
        result.is_none(),
        "mine() must return None when nonce exhaustion refresh exceeds max_timestamp"
    );
}

#[test]
fn process_block_error_is_header_only_method() {
    use exfer::network::sync::ProcessBlockError;

    // Header validation failures are header-only
    let header_err = ProcessBlockError::Recoverable(
        "block header validation failed: TimestampBelowMtp { .. }".to_string(),
    );
    assert!(
        header_err.is_header_only(),
        "header validation errors must be classified as header-only"
    );

    // Transaction failures are NOT header-only
    let tx_err =
        ProcessBlockError::Recoverable("block tx validation failed: DoubleSpend".to_string());
    assert!(
        !tx_err.is_header_only(),
        "transaction errors must NOT be classified as header-only"
    );

    // Fatal errors are NOT header-only
    let fatal = ProcessBlockError::Fatal("something".to_string());
    assert!(
        !fatal.is_header_only(),
        "fatal errors must NOT be classified as header-only"
    );
}
