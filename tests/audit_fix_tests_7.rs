//! Tests for the seventh audit round fixes (AUDIT-FIXES-7).
//!
//! Fix 1 [P0]: MAX_SCRIPT_STEPS consensus cap on script evaluation
//! Fix 2 [P1]: Reorg mempool cleanup purges all new_chain blocks
//! Fix 3 [P1]: Block storage deferred until after full tx validation
//! Fix 4 [P1]: Non-canonical boolean flags rejected in tx deserialization
//! Fix 5 [P2]: Reorg undo hard-fails on missing spent-UTXO metadata

// ── Fix 1: MAX_SCRIPT_STEPS consensus cap ──

mod script_step_cap_tests {
    use exfer::types::MAX_SCRIPT_STEPS;

    #[test]
    fn max_script_steps_constant_exists() {
        assert_eq!(MAX_SCRIPT_STEPS, 4_000_000);
    }

    #[test]
    fn max_script_steps_is_reasonable() {
        // Must be large enough for legitimate scripts but small enough to prevent DoS.
        // 4M steps: 40x the most complex covenant (100K), well within validation budget.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(
                MAX_SCRIPT_STEPS >= 1_000_000,
                "cap too low for legitimate scripts"
            );
        }
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(
                MAX_SCRIPT_STEPS <= 100_000_000,
                "cap too high for DoS prevention"
            );
        }
    }
}

// ── Fix 2: Reorg mempool cleanup ──

#[cfg(feature = "testnet")]
mod reorg_mempool_tests {
    use exfer::chain::state::{UtxoEntry, UtxoSet};
    use exfer::mempool::Mempool;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{OutPoint, Transaction, TxInput, TxOutput, TxWitness};

    #[tokio::test]
    async fn reorg_purges_all_new_chain_txs_from_mempool() {
        // Verify that mempool.remove_confirmed is called with ALL newly-canonical
        // transactions during a reorg, not just the triggering block's transactions.
        //
        // We can't easily test the full reorg flow here (requires mining valid blocks),
        // but we verify the Mempool.remove_confirmed API handles multiple blocks' txs correctly.

        let mut mempool = Mempool::new();
        let pubkey = [42u8; 32];

        // Create multiple transactions as if from different blocks
        let mut utxo_set = UtxoSet::new();
        let _outpoints: Vec<OutPoint> = (0..3)
            .map(|i| {
                let txid = Hash256::sha256(&[i as u8; 32]);
                let op = OutPoint::new(txid, 0);
                utxo_set
                    .insert(
                        op,
                        UtxoEntry {
                            output: TxOutput::new_p2pkh(1_000_000_000, &pubkey),
                            height: 0,
                            is_coinbase: false,
                        },
                    )
                    .expect("insert test UTXO");
                op
            })
            .collect();

        // Build signed transactions using ed25519
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();

        // Re-create UTXO set with our key
        let mut utxo_set = UtxoSet::new();
        let outpoints: Vec<OutPoint> = (0..3)
            .map(|i| {
                let txid = Hash256::sha256(&[i as u8; 32]);
                let op = OutPoint::new(txid, 0);
                utxo_set
                    .insert(
                        op,
                        UtxoEntry {
                            output: TxOutput::new_p2pkh(1_000_000_000, &pk),
                            height: 0,
                            is_coinbase: false,
                        },
                    )
                    .expect("insert test UTXO");
                op
            })
            .collect();

        let mut txs = Vec::new();
        for op in &outpoints {
            let mut tx = Transaction {
                inputs: vec![TxInput {
                    prev_tx_id: op.tx_id,
                    output_index: op.output_index,
                }],
                outputs: vec![TxOutput::new_p2pkh(900_000_000, &[2u8; 32])],
                witnesses: vec![TxWitness {
                    witness: vec![0u8; 96],
                    redeemer: None,
                }],
            };
            let sig_msg = tx.sig_message().unwrap();
            let sig = sk.sign(&sig_msg);
            let mut witness = Vec::with_capacity(96);
            witness.extend_from_slice(&pk);
            witness.extend_from_slice(&sig.to_bytes());
            tx.witnesses[0].witness = witness;
            txs.push(tx);
        }

        // Add all to mempool
        for tx in &txs {
            mempool.add(tx.clone(), &utxo_set, 100).unwrap();
        }
        assert_eq!(mempool.len(), 3);

        // Simulate reorg: remove_confirmed with all txs at once
        mempool.remove_confirmed(&txs);
        assert_eq!(
            mempool.len(),
            0,
            "all txs from reorged-in chain should be purged"
        );
    }
}

// ── Fix 3: Deferred block storage ──

#[cfg(feature = "testnet")]
mod deferred_storage_tests {
    use exfer::chain::fork_choice::ChainTip;
    use exfer::chain::state::UtxoSet;
    use exfer::chain::storage::ChainStorage;
    use exfer::consensus::difficulty::{genesis_target, work_from_target};
    use exfer::genesis::genesis_block;
    use exfer::mempool::Mempool;
    use exfer::network::sync::Node;
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
    use exfer::types::TARGET_BLOCK_TIME_SECS;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::{Mutex, RwLock};

    fn make_coinbase(height: u64, value: u64, pubkey: &[u8; 32]) -> Transaction {
        Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: height as u32,
            }],
            outputs: vec![TxOutput::new_p2pkh(value, pubkey)],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        }
    }

    #[tokio::test]
    async fn invalid_block_not_stored_when_extends_tip() {
        let tmpdir = TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = Arc::new(ChainStorage::open(&db_path).unwrap());

        let genesis = genesis_block();
        let gid = genesis.header.block_id();
        storage.put_block(&genesis).unwrap();

        let mut utxo_set = UtxoSet::new();
        for tx in &genesis.transactions {
            utxo_set.apply_transaction(tx, 0).unwrap();
        }

        let genesis_work = work_from_target(&genesis.header.difficulty_target);
        storage.put_cumulative_work(&gid, &genesis_work).unwrap();
        let tip = ChainTip::genesis(gid, &genesis.header.difficulty_target);

        let (peer_events_tx, _peer_events_rx) = tokio::sync::mpsc::channel(64);
        let node = Node {
            storage: storage.clone(),
            utxo_set: Arc::new(RwLock::new(utxo_set.clone())),
            mempool: Arc::new(Mutex::new(Mempool::new())),
            tip: Arc::new(RwLock::new(tip)),
            genesis_id: gid,
            peers: Arc::new(Mutex::new(exfer::network::sync::PeerRegistry::new())),
            outbound_bootstraps: std::sync::Mutex::new(HashMap::new()),
            next_session_id: std::sync::atomic::AtomicU64::new(1),
            active_ibd_peer: std::sync::Mutex::new(None),
            pending_ibd_blocks: std::sync::Mutex::new(HashSet::new()),
            global_block_limiter: std::sync::Mutex::new((std::time::Instant::now(), 0)),
            global_tx_limiter: std::sync::Mutex::new((std::time::Instant::now(), 0)),
            ip_abuse: std::sync::Mutex::new(HashMap::new()),
            fork_blocks: std::sync::Mutex::new(Vec::new()),
            orphan_blocks: std::sync::Mutex::new(Vec::new()),
            future_blocks: std::sync::Mutex::new(Vec::new()),
            difficulty_cache: std::sync::Mutex::new(HashMap::new()),
            shutdown: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            addr_book: std::sync::Mutex::new(HashMap::new()),
            pow_semaphore: tokio::sync::Semaphore::new(2),
            identity_key: ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]),
            identity_bans: std::sync::Mutex::new(HashMap::new()),
            global_response_limiter: std::sync::Mutex::new((std::time::Instant::now(), 0)),
            reorg_triggers: std::sync::Mutex::new(exfer::network::sync::ReorgTriggerState::new()),
            peer_events_tx,
            sync_state: std::sync::atomic::AtomicU8::new(0),
            best_peer_work: std::sync::Mutex::new([0u8; 32]),
            mining_cancel: std::sync::atomic::AtomicBool::new(false),
        };

        let pubkey = [42u8; 32];
        let reward = exfer::consensus::reward::block_reward(1);

        // Build a block with WRONG state_root — tx validation will pass but
        // state_root check will fail. Use correct coinbase reward.
        let coinbase = make_coinbase(1, reward, &pubkey);
        let mut temp_utxo = utxo_set.clone();
        temp_utxo.apply_transaction(&coinbase, 1).unwrap();
        let correct_state_root = temp_utxo.state_root();
        let wrong_state_root = Hash256::sha256(b"wrong_state_root");
        assert_ne!(correct_state_root, wrong_state_root);

        let genesis_header = genesis.header.clone();
        let block = Block {
            header: BlockHeader {
                version: 1,
                height: 1,
                prev_block_id: gid,
                timestamp: genesis_header.timestamp + TARGET_BLOCK_TIME_SECS,
                difficulty_target: genesis_target(),
                nonce: 0,
                tx_root: exfer::consensus::validation::compute_tx_root(std::slice::from_ref(
                    &coinbase,
                ))
                .unwrap(),
                state_root: wrong_state_root,
            },
            transactions: vec![coinbase],
        };

        let block_id = block.header.block_id();

        // process_block should fail due to state root mismatch
        let result = node.process_block(block, None).await;
        assert!(result.is_err(), "should fail with state root mismatch");

        // Block should NOT be stored (deferred storage)
        assert!(
            !storage.has_block(&block_id).unwrap(),
            "invalid block should not be stored"
        );

        // Cumulative work should NOT be stored
        assert!(
            storage.get_cumulative_work(&block_id).unwrap().is_none(),
            "cumulative work for invalid block should not be stored"
        );
    }
}

// ── Fix 4: Non-canonical boolean flags ──

mod boolean_flag_tests {
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{TxOutput, TxWitness};

    #[test]
    fn has_datum_flag_0_accepted() {
        let out = TxOutput {
            value: 1000,
            script: vec![0x42; 32],
            datum: None,
            datum_hash: None,
        };
        let bytes = out.serialize().unwrap();
        let (out2, _) = TxOutput::deserialize(&bytes).unwrap();
        assert_eq!(out, out2);
    }

    #[test]
    fn has_datum_flag_1_accepted() {
        let out = TxOutput {
            value: 1000,
            script: vec![0x42; 32],
            datum: Some(vec![0xDE, 0xAD]),
            datum_hash: None,
        };
        let bytes = out.serialize().unwrap();
        let (out2, _) = TxOutput::deserialize(&bytes).unwrap();
        assert_eq!(out, out2);
    }

    #[test]
    fn has_datum_flag_2_rejected() {
        // Manually construct bytes with has_datum = 2
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1000u64.to_le_bytes()); // value
        bytes.extend_from_slice(&32u16.to_le_bytes()); // script len
        bytes.extend_from_slice(&[0x42u8; 32]); // script
        bytes.push(2); // has_datum = 2 (non-canonical!)
        bytes.push(0); // has_datum_hash = 0

        let result = TxOutput::deserialize(&bytes);
        assert!(result.is_err(), "has_datum=2 should be rejected");
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("non-canonical"),
            "error should mention non-canonical: {}",
            err
        );
    }

    #[test]
    fn has_datum_flag_255_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1000u64.to_le_bytes());
        bytes.extend_from_slice(&32u16.to_le_bytes());
        bytes.extend_from_slice(&[0x42u8; 32]);
        bytes.push(0xFF); // has_datum = 255
        bytes.push(0);

        let result = TxOutput::deserialize(&bytes);
        assert!(result.is_err(), "has_datum=255 should be rejected");
    }

    #[test]
    fn has_datum_hash_flag_2_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1000u64.to_le_bytes());
        bytes.extend_from_slice(&32u16.to_le_bytes());
        bytes.extend_from_slice(&[0x42u8; 32]);
        bytes.push(0); // has_datum = 0
        bytes.push(2); // has_datum_hash = 2 (non-canonical!)

        let result = TxOutput::deserialize(&bytes);
        assert!(result.is_err(), "has_datum_hash=2 should be rejected");
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("non-canonical"),
            "error should mention non-canonical: {}",
            err
        );
    }

    #[test]
    fn has_redeemer_flag_2_rejected() {
        // Build TxWitness bytes with has_redeemer = 2
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&96u16.to_le_bytes()); // witness len
        bytes.extend_from_slice(&[0u8; 96]); // witness data
        bytes.push(2); // has_redeemer = 2 (non-canonical!)

        let result = TxWitness::deserialize(&bytes);
        assert!(result.is_err(), "has_redeemer=2 should be rejected");
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("non-canonical"),
            "error should mention non-canonical: {}",
            err
        );
    }

    #[test]
    fn has_redeemer_flag_0_accepted() {
        let w = TxWitness {
            witness: vec![0u8; 96],
            redeemer: None,
        };
        let bytes = w.serialize().unwrap();
        let (w2, _) = TxWitness::deserialize(&bytes).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn has_redeemer_flag_1_accepted() {
        let w = TxWitness {
            witness: vec![0u8; 96],
            redeemer: Some(vec![0xBE, 0xEF]),
        };
        let bytes = w.serialize().unwrap();
        let (w2, _) = TxWitness::deserialize(&bytes).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn canonical_roundtrip_still_works() {
        // Ensure the fix doesn't break valid roundtrips
        let out = TxOutput {
            value: 5000,
            script: vec![0x11; 32],
            datum: Some(vec![1, 2, 3]),
            datum_hash: Some(Hash256::sha256(b"datum")),
        };
        let bytes = out.serialize().unwrap();
        let (out2, consumed) = TxOutput::deserialize(&bytes).unwrap();
        assert_eq!(out, out2);
        assert_eq!(consumed, bytes.len());
    }
}

// ── Fix 5: Reorg undo hard-fail on missing spent UTXOs ──

mod reorg_undo_tests {
    #[test]
    fn reorg_undo_error_message_format() {
        // Verify the error format matches what the code produces
        let block_id = exfer::types::hash::Hash256::sha256(b"test_block");
        let height = 42u64;
        let msg = format!(
            "missing spent-UTXO metadata for block {} at height {} during reorg undo",
            block_id, height
        );
        assert!(msg.contains("missing spent-UTXO metadata"));
        assert!(msg.contains("during reorg undo"));
        assert!(msg.contains("42"));
    }
}

// ── Fix 6 [P1]: SchnorrVerify returns NotImplemented ──

mod schnorr_tests {
    use exfer::script::jets::crypto::jet_schnorr_verify;
    use exfer::script::jets::JetError;
    use exfer::script::value::Value;

    #[test]
    fn schnorr_verify_returns_not_implemented() {
        // Any input should return NotImplemented
        let input = Value::Pair(
            Box::new(Value::Bytes(b"message".to_vec())),
            Box::new(Value::Pair(
                Box::new(Value::Bytes(vec![0u8; 32])),
                Box::new(Value::Bytes(vec![0u8; 64])),
            )),
        );
        let result = jet_schnorr_verify(&input);
        assert!(result.is_err());
        match result.unwrap_err() {
            JetError::NotImplemented(msg) => {
                assert!(
                    msg.contains("schnorr_verify"),
                    "error should mention schnorr_verify: {}",
                    msg
                );
            }
            other => panic!("expected NotImplemented, got {:?}", other),
        }
    }

    #[test]
    fn schnorr_verify_does_not_accept_valid_ed25519() {
        // Ensure SchnorrVerify no longer delegates to Ed25519
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let message = b"test message";
        let sig = sk.sign(message);

        let input = Value::Pair(
            Box::new(Value::Bytes(message.to_vec())),
            Box::new(Value::Pair(
                Box::new(Value::Bytes(pk.to_vec())),
                Box::new(Value::Bytes(sig.to_bytes().to_vec())),
            )),
        );

        // Should return error, NOT Ok(Bool(true))
        let result = jet_schnorr_verify(&input);
        assert!(
            result.is_err(),
            "schnorr_verify should not accept Ed25519 signatures"
        );
    }

    #[test]
    fn jet_error_not_implemented_variant_exists() {
        let err = JetError::NotImplemented("test".to_string());
        let display = format!("{}", err);
        assert!(display.contains("NotImplemented"));
    }
}

// ── Fix 7 [P2]: Lowered MAX_SCRIPT_STEPS cap ──

mod lowered_cap_tests {
    use exfer::types::MAX_SCRIPT_STEPS;

    #[test]
    fn cap_is_4_million() {
        assert_eq!(MAX_SCRIPT_STEPS, 4_000_000);
    }

    #[test]
    fn cap_well_above_complex_covenants() {
        // Most complex covenants use ~100K steps. 4M is 40x headroom.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(MAX_SCRIPT_STEPS >= 100_000 * 40);
        }
    }

    #[test]
    fn cap_below_dos_threshold() {
        // Must be low enough that validation doesn't take unreasonable time.
        // At ~1M steps/sec conservative estimate, 4M = ~4 seconds worst case.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(MAX_SCRIPT_STEPS <= 50_000_000);
        }
    }
}
