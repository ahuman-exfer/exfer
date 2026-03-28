//! Live-chain HTLC test.
//!
//! 1. Alice locks 10 EXFER in an HTLC: Bob can claim with preimage, Alice reclaims after timeout.
//! 2. Bob claims the HTLC by revealing the preimage.
//! Both transactions are submitted via RPC and confirmed on-chain.

use exfer::covenants::htlc;
use exfer::rpc::rpc_call;
use exfer::script::serialize::serialize_program;
use exfer::script::value::Value;
use exfer::types::hash::Hash256;
use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::DUST_THRESHOLD;
use exfer::wallet::Wallet;

use ed25519_dalek::Signer;

fn main() {
    let rpc_url = "http://89.127.232.155:9334";

    // Load test wallets
    let alice =
        Wallet::load(std::path::Path::new("/tmp/htlc-test/alice.key"), None).expect("load alice");
    let bob = Wallet::load(std::path::Path::new("/tmp/htlc-test/bob.key"), None).expect("load bob");

    let alice_pubkey = alice.pubkey();
    let bob_pubkey = bob.pubkey();

    println!("Alice pubkey: {}", hex::encode(alice_pubkey));
    println!("Bob pubkey:   {}", hex::encode(bob_pubkey));
    println!("Alice addr:   {}", alice.address());
    println!("Bob addr:     {}", bob.address());
    println!();

    // Step 1: Generate preimage and hash
    let preimage = b"exfer htlc test preimage 2026";
    let hash_lock = Hash256::sha256(preimage);
    println!("Preimage:  {}", hex::encode(preimage));
    println!("Hash lock: {}", hash_lock);
    println!();

    // Get current height
    let height_result =
        rpc_call(rpc_url, "get_block_height", serde_json::json!({})).expect("get_block_height");
    let current_height = height_result["height"].as_u64().unwrap();
    let timeout_height = current_height + 100;
    println!("Current height: {}", current_height);
    println!("HTLC timeout:   {} (current + 100)", timeout_height);
    println!();

    // Step 2: Build the HTLC script
    let program = htlc::htlc(&alice_pubkey, &bob_pubkey, &hash_lock, timeout_height);
    let script_bytes = serialize_program(&program);
    println!("HTLC script: {} bytes", script_bytes.len());

    // Step 3: Get Alice's UTXOs
    let alice_addr_hex = alice.address().to_string();
    let utxos_result = rpc_call(
        rpc_url,
        "get_address_utxos",
        serde_json::json!({ "address": alice_addr_hex }),
    )
    .expect("get_address_utxos");

    let utxos = utxos_result["utxos"].as_array().expect("utxos array");
    assert!(!utxos.is_empty(), "Alice has no UTXOs");

    // Pick the largest UTXO
    let utxos = {
        let mut sorted = utxos.clone();
        sorted.sort_by(|a, b| {
            b.get("value")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .cmp(&a.get("value").and_then(|v| v.as_u64()).unwrap_or(0))
        });
        sorted
    };

    let utxo = &utxos[0];
    let utxo_tx_id_hex = utxo["tx_id"].as_str().unwrap();
    let utxo_output_index = utxo["output_index"].as_u64().unwrap() as u32;
    let utxo_value = utxo["value"].as_u64().unwrap();

    println!(
        "Using UTXO: {}:{} (value: {} exfers)",
        utxo_tx_id_hex, utxo_output_index, utxo_value
    );

    let mut tx_id_bytes = [0u8; 32];
    tx_id_bytes.copy_from_slice(&hex::decode(utxo_tx_id_hex).unwrap());

    let htlc_value: u64 = 500_000_000; // 5 EXFER
    let fee: u64 = 100_000;
    let change = utxo_value.saturating_sub(htlc_value).saturating_sub(fee);

    // Step 4: Build locking transaction
    let mut lock_tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256(tx_id_bytes),
            output_index: utxo_output_index,
        }],
        outputs: vec![
            // HTLC output (script-locked)
            TxOutput {
                value: htlc_value,
                script: script_bytes.clone(),
                datum: None,
                datum_hash: None,
            },
        ],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    // Add change output if above dust
    if change >= DUST_THRESHOLD {
        lock_tx.outputs.push(TxOutput {
            value: change,
            script: alice.address().as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        });
    }

    // Sign the locking transaction
    let sig_message = lock_tx.sig_message().expect("sig_message");
    let alice_signing_key = ed25519_dalek::SigningKey::from_bytes(
        &std::fs::read("/tmp/htlc-test/alice.key").unwrap()[..32]
            .try_into()
            .unwrap(),
    );
    let signature = alice_signing_key.sign(&sig_message);
    lock_tx.witnesses[0].witness =
        [alice_pubkey.as_slice(), signature.to_bytes().as_slice()].concat();

    let lock_tx_id = lock_tx.tx_id().expect("lock tx_id");
    let lock_tx_hex = hex::encode(lock_tx.serialize().expect("serialize lock"));

    println!();
    println!("=== LOCKING TRANSACTION ===");
    println!("TxId:   {}", lock_tx_id);
    println!(
        "HTLC output: {} exfers to script ({} bytes)",
        htlc_value,
        script_bytes.len()
    );
    if change >= DUST_THRESHOLD {
        println!("Change: {} exfers back to Alice", change);
    }
    println!("Fee:    {} exfers", fee);

    // Submit locking tx
    let lock_result = rpc_call(
        rpc_url,
        "send_raw_transaction",
        serde_json::json!({ "tx_hex": lock_tx_hex }),
    );
    match &lock_result {
        Ok(r) => println!("Submitted: {}", r),
        Err(e) => {
            println!("ERROR submitting lock tx: {}", e);
            println!("Raw: {}", lock_tx_hex);
            std::process::exit(1);
        }
    }

    // Wait for confirmation
    println!("\nWaiting for lock tx to confirm...");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let tx_result = rpc_call(
            rpc_url,
            "get_transaction",
            serde_json::json!({ "hash": lock_tx_id.to_string() }),
        );
        if let Ok(r) = &tx_result {
            if r.get("block_height").is_some()
                && !r
                    .get("in_mempool")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true)
            {
                println!(
                    "Confirmed in block {} (height {})",
                    r["block_hash"].as_str().unwrap_or("?"),
                    r["block_height"].as_u64().unwrap_or(0)
                );
                break;
            }
        }
        print!(".");
        use std::io::Write;
        std::io::stdout().flush().ok();
    }

    // Step 5: Build the HTLC claim transaction (Bob claims with preimage)
    println!();
    println!("=== CLAIMING TRANSACTION (Bob + preimage) ===");

    let claim_fee: u64 = 5_000_000; // script evaluation costs more — generous fee
    let claim_value = htlc_value.saturating_sub(claim_fee);

    let mut claim_tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: lock_tx_id,
            output_index: 0, // the HTLC output
        }],
        outputs: vec![TxOutput {
            value: claim_value,
            script: bob.address().as_bytes().to_vec(), // pay to Bob's address
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    // Build witness for hash path:
    // The script expects witness values consumed in order:
    //   1. selector: Left(Unit) for hash path
    //   2. preimage: Bytes
    //   3. signature: Bytes (64-byte Ed25519 sig)
    let claim_sig_message = claim_tx.sig_message().expect("claim sig_message");
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(
        &std::fs::read("/tmp/htlc-test/bob.key").unwrap()[..32]
            .try_into()
            .unwrap(),
    );
    let bob_signature = bob_signing_key.sign(&claim_sig_message);

    // Serialize witness values
    let selector = Value::Left(Box::new(Value::Unit));
    let preimage_val = Value::Bytes(preimage.to_vec());
    let sig_val = Value::Bytes(bob_signature.to_bytes().to_vec());

    let mut witness_data = Vec::new();
    witness_data.extend_from_slice(&selector.serialize());
    witness_data.extend_from_slice(&preimage_val.serialize());
    witness_data.extend_from_slice(&sig_val.serialize());

    claim_tx.witnesses[0].witness = witness_data;

    let claim_tx_id = claim_tx.tx_id().expect("claim tx_id");
    let claim_tx_hex = hex::encode(claim_tx.serialize().expect("serialize claim"));

    println!("TxId:    {}", claim_tx_id);
    println!("Pays:    {} exfers to Bob", claim_value);
    println!("Fee:     {} exfers", claim_fee);

    // Submit claim tx
    let claim_result = rpc_call(
        rpc_url,
        "send_raw_transaction",
        serde_json::json!({ "tx_hex": claim_tx_hex }),
    );
    match &claim_result {
        Ok(r) => println!("Submitted: {}", r),
        Err(e) => {
            println!("ERROR submitting claim tx: {}", e);
            println!("Raw: {}", claim_tx_hex);
            std::process::exit(1);
        }
    }

    // Wait for confirmation
    println!("\nWaiting for claim tx to confirm...");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let tx_result = rpc_call(
            rpc_url,
            "get_transaction",
            serde_json::json!({ "hash": claim_tx_id.to_string() }),
        );
        if let Ok(r) = &tx_result {
            if r.get("block_height").is_some()
                && !r
                    .get("in_mempool")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true)
            {
                println!(
                    "Confirmed in block {} (height {})",
                    r["block_hash"].as_str().unwrap_or("?"),
                    r["block_height"].as_u64().unwrap_or(0)
                );
                break;
            }
        }
        print!(".");
        use std::io::Write;
        std::io::stdout().flush().ok();
    }

    // Verify final balances
    println!();
    println!("=== RESULTS ===");
    println!("Lock TxId:  {}", lock_tx_id);
    println!("Claim TxId: {}", claim_tx_id);

    let bob_balance = rpc_call(
        rpc_url,
        "get_balance",
        serde_json::json!({ "address": bob.address().to_string() }),
    )
    .expect("bob balance");
    println!(
        "Bob balance: {} exfers ({:.2} EXFER)",
        bob_balance["balance"].as_u64().unwrap_or(0),
        bob_balance["balance"].as_u64().unwrap_or(0) as f64 / 100_000_000.0
    );

    println!();
    println!("HTLC test PASSED. Trustless agent commerce is live.");
}
