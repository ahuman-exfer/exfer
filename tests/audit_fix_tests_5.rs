//! Tests for the fifth audit round fixes (AUDIT-FIXES-5).
//!
//! Fix 1 [P0]: Intra-block dependency spends are now accepted
//! Fix 2 [P0]: Value::deserialize rejects deeply nested input
//! Fix 3 [P1]: Datum/redeemer size limits enforced during deserialization
//! Fix 4 [P1]: Trailing bytes rejected in wire and script decoding
//! Fix 5 [P2]: Wallet key file permissions forced on every save
//! Fix 6 [P2]: Protocol version checked during handshake

// ── Fix 1: Intra-block dependency spend ──

#[cfg(feature = "testnet")]
mod intra_block_tests {
    use ed25519_dalek::{Signer, SigningKey};
    use exfer::chain::state::UtxoSet;
    use exfer::consensus::difficulty::genesis_target;
    use exfer::consensus::validation::{compute_tx_root, validate_block_transactions};
    use exfer::genesis::genesis_block;
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{OutPoint, Transaction, TxInput, TxOutput, TxWitness};
    use rand::rngs::OsRng;

    fn make_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

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

    #[test]
    fn intra_block_spend_accepted() {
        // Build a block where tx[2] spends an output created by tx[1].
        // This must succeed per SPEC Section 8.2.
        let (sk, pk) = make_keypair();

        // Start from genesis UTXO state
        let genesis = genesis_block();
        let mut utxo_set = UtxoSet::new();
        for tx in &genesis.transactions {
            utxo_set.apply_transaction(tx, 0).unwrap();
        }

        let height = 361; // past coinbase maturity

        // Put a spendable UTXO in the set (non-coinbase, at old height)
        let funding_tx_id = Hash256([0xAA; 32]);
        let outpoint = OutPoint::new(funding_tx_id, 0);
        utxo_set
            .insert(
                outpoint,
                exfer::chain::state::UtxoEntry {
                    output: TxOutput::new_p2pkh(5_000_000_000, &pk),
                    height: 0,
                    is_coinbase: false,
                },
            )
            .expect("insert test UTXO");

        // tx1: spend the funding UTXO, create output locked to same key
        let mut tx1 = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: funding_tx_id,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(4_999_000_000, &pk)],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        sign_tx(&mut tx1, &sk);
        let tx1_id = tx1.tx_id().unwrap();

        // tx2: spend tx1's output (intra-block dependency)
        let mut tx2 = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: tx1_id,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(4_998_000_000, &pk)],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        sign_tx(&mut tx2, &sk);

        // Coinbase: reward + fees
        let reward = exfer::consensus::reward::block_reward(height);
        let fee1 = 5_000_000_000u64 - 4_999_000_000u64;
        let fee2 = 4_999_000_000u64 - 4_998_000_000u64;
        let coinbase = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: height as u32,
            }],
            outputs: vec![TxOutput::new_p2pkh(reward + fee1 + fee2, &pk)],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                height,
                prev_block_id: Hash256([0x01; 32]),
                timestamp: 1773536400 + height * 10,
                difficulty_target: genesis_target(),
                nonce: 0,
                tx_root: compute_tx_root(&[coinbase.clone(), tx1.clone(), tx2.clone()]).unwrap(),
                state_root: Hash256::ZERO, // Not checked by validate_block_transactions
            },
            transactions: vec![coinbase, tx1, tx2],
        };

        let result = validate_block_transactions(&block, &utxo_set);
        assert!(
            result.is_ok(),
            "intra-block dependency spend should be accepted: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap(), fee1 + fee2, "fees should match");
    }

    #[test]
    fn intra_block_spend_missing_utxo_still_rejected() {
        // tx2 references a tx_id that is NOT in the block — should fail.
        let (sk, pk) = make_keypair();

        let genesis = genesis_block();
        let mut utxo_set = UtxoSet::new();
        for tx in &genesis.transactions {
            utxo_set.apply_transaction(tx, 0).unwrap();
        }

        let height = 361;
        let fake_tx_id = Hash256([0xFF; 32]);

        let mut tx1 = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: fake_tx_id,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(1_000_000, &pk)],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        sign_tx(&mut tx1, &sk);

        let reward = exfer::consensus::reward::block_reward(height);
        let coinbase = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: height as u32,
            }],
            outputs: vec![TxOutput::new_p2pkh(reward, &pk)],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                height,
                prev_block_id: Hash256([0x01; 32]),
                timestamp: 1773536400 + height * 10,
                difficulty_target: genesis_target(),
                nonce: 0,
                tx_root: compute_tx_root(&[coinbase.clone(), tx1.clone()]).unwrap(),
                state_root: Hash256::ZERO,
            },
            transactions: vec![coinbase, tx1],
        };

        let result = validate_block_transactions(&block, &utxo_set);
        assert!(
            result.is_err(),
            "spending non-existent UTXO should still fail"
        );
    }
}

// ── Fix 2: Value deserialization depth limit ──

mod value_depth_tests {
    use exfer::script::value::Value;

    #[test]
    fn value_deserialize_rejects_deep_nesting() {
        // Build deeply nested Left(Left(Left(...Unit...)))
        // depth = MAX_VALUE_DEPTH + 10 should be rejected
        let depth = exfer::types::MAX_VALUE_DEPTH + 10;
        let mut data = vec![0x01; depth]; // Left tags
        data.push(0x00); // Unit at the bottom

        let result = Value::deserialize(&data);
        assert!(result.is_err(), "deeply nested value should be rejected");
        assert!(
            result.unwrap_err().contains("depth"),
            "error should mention depth"
        );
    }

    #[test]
    fn value_deserialize_accepts_max_depth() {
        // depth = MAX_VALUE_DEPTH should succeed
        let depth = exfer::types::MAX_VALUE_DEPTH;
        let mut data = vec![0x01; depth]; // Left tags
        data.push(0x00); // Unit at the bottom

        let result = Value::deserialize(&data);
        assert!(
            result.is_ok(),
            "nesting at exactly MAX_VALUE_DEPTH should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn value_roundtrip_still_works() {
        // Basic roundtrip: serialize then deserialize
        let value = Value::Pair(
            Box::new(Value::Left(Box::new(Value::U64(42)))),
            Box::new(Value::Bytes(vec![1, 2, 3])),
        );
        let bytes = value.serialize();
        let (decoded, consumed) = Value::deserialize(&bytes).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(consumed, bytes.len());
    }
}

// ── Fix 3: Datum/redeemer size limits ──

mod datum_redeemer_limit_tests {
    use exfer::types::transaction::{TxOutput, TxWitness};

    #[test]
    fn datum_exceeding_max_rejected() {
        let oversized_datum = vec![0xABu8; exfer::types::MAX_DATUM_SIZE + 1];
        let output = TxOutput {
            value: 1_000_000,
            script: vec![0u8; 32],
            datum: Some(oversized_datum),
            datum_hash: None,
        };
        let serialized = output.serialize().unwrap();
        let result = TxOutput::deserialize(&serialized);
        assert!(
            result.is_err(),
            "datum exceeding MAX_DATUM_SIZE should be rejected"
        );
    }

    #[test]
    fn datum_at_max_accepted() {
        let datum = vec![0xABu8; exfer::types::MAX_DATUM_SIZE];
        let output = TxOutput {
            value: 1_000_000,
            script: vec![0u8; 32],
            datum: Some(datum.clone()),
            datum_hash: None,
        };
        let serialized = output.serialize().unwrap();
        let result = TxOutput::deserialize(&serialized);
        assert!(
            result.is_ok(),
            "datum at exactly MAX_DATUM_SIZE should be accepted"
        );
        let (decoded, _) = result.unwrap();
        assert_eq!(decoded.datum.unwrap().len(), exfer::types::MAX_DATUM_SIZE);
    }

    #[test]
    fn redeemer_exceeding_max_rejected() {
        let oversized_redeemer = vec![0xCDu8; exfer::types::MAX_REDEEMER_SIZE + 1];
        let witness = TxWitness {
            witness: vec![0u8; 96],
            redeemer: Some(oversized_redeemer),
        };
        let serialized = witness.serialize().unwrap();
        let result = TxWitness::deserialize(&serialized);
        assert!(
            result.is_err(),
            "redeemer exceeding MAX_REDEEMER_SIZE should be rejected"
        );
    }

    #[test]
    fn redeemer_at_max_accepted() {
        let redeemer = vec![0xCDu8; exfer::types::MAX_REDEEMER_SIZE];
        let witness = TxWitness {
            witness: vec![0u8; 96],
            redeemer: Some(redeemer.clone()),
        };
        let serialized = witness.serialize().unwrap();
        let result = TxWitness::deserialize(&serialized);
        assert!(
            result.is_ok(),
            "redeemer at exactly MAX_REDEEMER_SIZE should be accepted"
        );
        let (decoded, _) = result.unwrap();
        assert_eq!(
            decoded.redeemer.unwrap().len(),
            exfer::types::MAX_REDEEMER_SIZE
        );
    }
}

// ── Fix 4: Trailing bytes rejection ──

mod trailing_bytes_tests {
    use exfer::network::protocol::Message;
    use exfer::script::ast::{Combinator, Program};
    use exfer::script::serialize::{deserialize_program, serialize_program};
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    #[test]
    fn wire_new_tx_rejects_trailing_bytes() {
        // Build a valid NewTx message, then append junk to the payload
        let tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(1_000_000, &[1u8; 32])],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        let msg = Message::NewTx(tx);
        let mut wire = msg.serialize().unwrap();
        // Append trailing junk byte
        // The wire format is: [msg_type: u8][payload_len: u32 LE][payload]
        // We need to increase payload_len to include the junk, so the
        // outer frame reads it, but inner Transaction::deserialize won't consume it.
        let payload_len = u32::from_le_bytes(wire[1..5].try_into().unwrap()) + 1;
        wire[1..5].copy_from_slice(&payload_len.to_le_bytes());
        wire.push(0xFF); // trailing junk

        let result = Message::deserialize(&wire);
        assert!(
            result.is_err(),
            "trailing bytes in NewTx should be rejected"
        );
    }

    #[test]
    fn wire_new_block_rejects_trailing_bytes() {
        use exfer::consensus::difficulty::genesis_target;
        use exfer::consensus::validation::compute_tx_root;
        use exfer::types::block::{Block, BlockHeader};

        let coinbase = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(10_000_000_000, &[1u8; 32])],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        let block = Block {
            header: BlockHeader {
                version: 1,
                height: 0,
                prev_block_id: Hash256::ZERO,
                timestamp: 1773536400,
                difficulty_target: genesis_target(),
                nonce: 0,
                tx_root: compute_tx_root(std::slice::from_ref(&coinbase)).unwrap(),
                state_root: Hash256::ZERO,
            },
            transactions: vec![coinbase],
        };
        let msg = Message::NewBlock(block);
        let mut wire = msg.serialize().unwrap();
        let payload_len = u32::from_le_bytes(wire[1..5].try_into().unwrap()) + 1;
        wire[1..5].copy_from_slice(&payload_len.to_le_bytes());
        wire.push(0xFF);

        let result = Message::deserialize(&wire);
        assert!(
            result.is_err(),
            "trailing bytes in NewBlock should be rejected"
        );
    }

    #[test]
    fn script_deserialize_rejects_trailing_bytes() {
        // Serialize a valid program, append junk, expect rejection
        let program = Program {
            nodes: vec![Combinator::Unit],
            root: 0,
        };
        let mut data = serialize_program(&program);
        data.push(0xFF); // trailing junk

        let result = deserialize_program(&data);
        assert!(
            result.is_err(),
            "trailing bytes in script should be rejected"
        );
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("trailing"),
            "error should mention trailing: {}",
            err
        );
    }

    #[test]
    fn script_deserialize_accepts_exact_bytes() {
        let program = Program {
            nodes: vec![Combinator::Unit],
            root: 0,
        };
        let data = serialize_program(&program);
        let result = deserialize_program(&data);
        assert!(result.is_ok(), "exact-length script should be accepted");
    }
}

// ── Fix 5: Wallet key file permissions ──

#[cfg(unix)]
mod wallet_permission_tests {
    use exfer::wallet::Wallet;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn wallet_save_forces_permissions_on_existing_file() {
        let tmpdir = TempDir::new().unwrap();
        let key_path = tmpdir.path().join("key.bin");

        // Create file with permissive mode (0o644)
        std::fs::write(&key_path, [0u8; 32]).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mode_before = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_before, 0o644, "pre-condition: file should be 0644");

        // Save wallet over the existing file
        let wallet = Wallet::generate();
        wallet.save_unencrypted(&key_path).unwrap();

        let mode_after = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode_after, 0o600,
            "wallet save must force 0600 on existing files"
        );
    }
}

// ── Fix 6: Handshake version check ──

mod version_check_tests {
    use exfer::network::peer::PeerError;

    #[test]
    fn peer_error_has_version_mismatch() {
        // Verify the variant exists and displays correctly
        let err = PeerError::VersionMismatch;
        let msg = format!("{}", err);
        assert!(
            msg.contains("version"),
            "VersionMismatch display should mention version: {}",
            msg
        );
    }
}
