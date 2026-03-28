//! Live-chain tests for timelock and 2-of-2 multisig covenants.

use exfer::covenants::builder::ScriptBuilder;
use exfer::covenants::multisig;
use exfer::rpc::rpc_call;
use exfer::script::serialize::serialize_program;
use exfer::script::value::Value;
use exfer::types::hash::Hash256;
use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::DUST_THRESHOLD;
use exfer::wallet::Wallet;

use ed25519_dalek::Signer;
use std::path::Path;

const RPC: &str = "http://89.127.232.155:9334";

fn main() {
    let alice = Wallet::load(Path::new("/tmp/htlc-test/alice.key"), None).expect("load alice");
    let bob = Wallet::load(Path::new("/tmp/htlc-test/bob.key"), None).expect("load bob");
    let alice_pk = alice.pubkey();
    let bob_pk = bob.pubkey();
    let alice_sk = ed25519_dalek::SigningKey::from_bytes(
        &std::fs::read("/tmp/htlc-test/alice.key").unwrap()[..32]
            .try_into()
            .unwrap(),
    );
    let bob_sk = ed25519_dalek::SigningKey::from_bytes(
        &std::fs::read("/tmp/htlc-test/bob.key").unwrap()[..32]
            .try_into()
            .unwrap(),
    );

    println!("Alice: {}", hex::encode(alice_pk));
    println!("Bob:   {}", hex::encode(bob_pk));
    println!();

    let height = get_height();

    // ═══════════════════════════════════════════════════════════════
    // TEST 1: TIMELOCK
    // ═══════════════════════════════════════════════════════════════
    println!("══════════════════════════════════════════");
    println!("TEST 1: TIMELOCK (current_height + 10)");
    println!("══════════════════════════════════════════");

    let lock_until = height + 10;
    println!("Current height: {}", height);
    println!("Lock until:     {}", lock_until);

    // Build timelock script: height_gt(lock_until) AND sig_check(alice)
    let timelock_program = {
        let mut b = ScriptBuilder::new();
        let time_check = b.height_gt(lock_until);
        let sig_check = b.sig_check(&alice_pk);
        let _root = b.and(time_check, sig_check);
        b.build()
    };
    let timelock_script = serialize_program(&timelock_program);
    println!("Timelock script: {} bytes", timelock_script.len());

    // Get Alice's UTXO
    let (utxo_txid, utxo_idx, utxo_value) = get_largest_utxo(&alice.address().to_string());
    let lock_value: u64 = 200_000_000; // 2 EXFER
    let fee: u64 = 100_000;
    let change = utxo_value.saturating_sub(lock_value).saturating_sub(fee);

    // Build and submit locking tx
    let mut lock_tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: utxo_txid,
            output_index: utxo_idx,
        }],
        outputs: vec![TxOutput {
            value: lock_value,
            script: timelock_script.clone(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    if change >= DUST_THRESHOLD {
        lock_tx.outputs.push(TxOutput {
            value: change,
            script: alice.address().as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        });
    }
    sign_p2pkh(&mut lock_tx, &alice_sk, &alice_pk);
    let lock_txid = lock_tx.tx_id().unwrap();
    println!("\nLock TxId: {}", lock_txid);
    submit_and_wait(&lock_tx, "timelock lock");

    // Attempt to spend IMMEDIATELY (should fail — height < lock_until)
    println!("\n--- Attempting early spend (should fail) ---");
    let early_height = get_height();
    println!(
        "Current height: {} (lock_until: {})",
        early_height, lock_until
    );

    let mut early_tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: lock_txid,
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: lock_value.saturating_sub(5_000_000),
            script: alice.address().as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    // Witness: sig for the timelock script (no selector — it's just AND(height_gt, sig_check))
    let early_sig_msg = early_tx.sig_message().unwrap();
    let early_sig = alice_sk.sign(&early_sig_msg);
    early_tx.witnesses[0].witness = witness_values(&[Value::Bytes(early_sig.to_bytes().to_vec())]);

    let early_hex = hex::encode(early_tx.serialize().unwrap());
    let early_result = rpc_call(
        RPC,
        "send_raw_transaction",
        serde_json::json!({"tx_hex": early_hex}),
    );
    match early_result {
        Err(e) => println!("CORRECTLY REJECTED: {}", e),
        Ok(r) => println!("UNEXPECTED SUCCESS (bug!): {}", r),
    }

    // Wait for height to pass lock_until
    println!("\n--- Waiting for height > {} ---", lock_until);
    loop {
        let h = get_height();
        if h > lock_until {
            println!("Height {} > {} — timelock expired!", h, lock_until);
            break;
        }
        print!(".");
        use std::io::Write;
        std::io::stdout().flush().ok();
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    // Spend after timelock expires (should succeed)
    println!("\n--- Spending after timelock ---");
    let mut late_tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: lock_txid,
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: lock_value.saturating_sub(5_000_000),
            script: alice.address().as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    let late_sig_msg = late_tx.sig_message().unwrap();
    let late_sig = alice_sk.sign(&late_sig_msg);
    late_tx.witnesses[0].witness = witness_values(&[Value::Bytes(late_sig.to_bytes().to_vec())]);
    let late_txid = late_tx.tx_id().unwrap();
    println!("Spend TxId: {}", late_txid);
    submit_and_wait(&late_tx, "timelock spend");

    println!("\nTIMELOCK TEST PASSED");
    println!("  Lock TxId:  {}", lock_txid);
    println!("  Spend TxId: {}", late_txid);

    // ═══════════════════════════════════════════════════════════════
    // TEST 2: 2-OF-2 MULTISIG
    // ═══════════════════════════════════════════════════════════════
    println!("\n══════════════════════════════════════════");
    println!("TEST 2: 2-OF-2 MULTISIG (Alice + Bob)");
    println!("══════════════════════════════════════════");

    let ms_program = multisig::multisig_2of2(&alice_pk, &bob_pk);
    let ms_script = serialize_program(&ms_program);
    println!("Multisig script: {} bytes", ms_script.len());

    // Get Alice's UTXO for funding
    let (ms_utxo_txid, ms_utxo_idx, ms_utxo_value) = get_largest_utxo(&alice.address().to_string());
    let ms_value: u64 = 200_000_000; // 2 EXFER
    let ms_change = ms_utxo_value.saturating_sub(ms_value).saturating_sub(fee);

    let mut ms_lock_tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: ms_utxo_txid,
            output_index: ms_utxo_idx,
        }],
        outputs: vec![TxOutput {
            value: ms_value,
            script: ms_script.clone(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    if ms_change >= DUST_THRESHOLD {
        ms_lock_tx.outputs.push(TxOutput {
            value: ms_change,
            script: alice.address().as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        });
    }
    sign_p2pkh(&mut ms_lock_tx, &alice_sk, &alice_pk);
    let ms_lock_txid = ms_lock_tx.tx_id().unwrap();
    println!("\nMultisig Lock TxId: {}", ms_lock_txid);
    submit_and_wait(&ms_lock_tx, "multisig lock");

    // Spend the multisig with both signatures
    println!("\n--- Spending with both Alice + Bob signatures ---");
    let mut ms_spend_tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: ms_lock_txid,
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: ms_value.saturating_sub(5_000_000),
            script: bob.address().as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    // 2-of-2 witness: sig_a then sig_b (both via sig_check, reading from witness in order)
    let ms_sig_msg = ms_spend_tx.sig_message().unwrap();
    let sig_a = alice_sk.sign(&ms_sig_msg);
    let sig_b = bob_sk.sign(&ms_sig_msg);
    ms_spend_tx.witnesses[0].witness = witness_values(&[
        Value::Bytes(sig_a.to_bytes().to_vec()),
        Value::Bytes(sig_b.to_bytes().to_vec()),
    ]);

    let ms_spend_txid = ms_spend_tx.tx_id().unwrap();
    println!("Multisig Spend TxId: {}", ms_spend_txid);
    submit_and_wait(&ms_spend_tx, "multisig spend");

    println!("\nMULTISIG TEST PASSED");
    println!("  Lock TxId:  {}", ms_lock_txid);
    println!("  Spend TxId: {}", ms_spend_txid);

    // ═══════════════════════════════════════════════════════════════
    println!("\n══════════════════════════════════════════");
    println!("ALL COVENANT TESTS PASSED");
    println!("══════════════════════════════════════════");
}

// ── Helpers ──

fn get_height() -> u64 {
    let r = rpc_call(RPC, "get_block_height", serde_json::json!({})).unwrap();
    r["height"].as_u64().unwrap()
}

fn get_largest_utxo(address: &str) -> (Hash256, u32, u64) {
    let r = rpc_call(
        RPC,
        "get_address_utxos",
        serde_json::json!({"address": address}),
    )
    .unwrap();
    let utxos = r["utxos"].as_array().unwrap();
    let best = utxos
        .iter()
        .max_by_key(|u| u["value"].as_u64().unwrap_or(0))
        .expect("no UTXOs");
    let tx_id_hex = best["tx_id"].as_str().unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hex::decode(tx_id_hex).unwrap());
    (
        Hash256(arr),
        best["output_index"].as_u64().unwrap() as u32,
        best["value"].as_u64().unwrap(),
    )
}

fn sign_p2pkh(tx: &mut Transaction, sk: &ed25519_dalek::SigningKey, pk: &[u8; 32]) {
    let sig_msg = tx.sig_message().unwrap();
    let sig = sk.sign(&sig_msg);
    tx.witnesses[0].witness = [pk.as_slice(), sig.to_bytes().as_slice()].concat();
}

fn witness_values(vals: &[Value]) -> Vec<u8> {
    let mut buf = Vec::new();
    for v in vals {
        buf.extend_from_slice(&v.serialize());
    }
    buf
}

fn submit_and_wait(tx: &Transaction, label: &str) {
    let tx_hex = hex::encode(tx.serialize().unwrap());
    let tx_id = tx.tx_id().unwrap();
    match rpc_call(
        RPC,
        "send_raw_transaction",
        serde_json::json!({"tx_hex": tx_hex}),
    ) {
        Ok(_) => println!("Submitted {}", label),
        Err(e) => {
            eprintln!("ERROR submitting {}: {}", label, e);
            std::process::exit(1);
        }
    }
    // Wait for confirmation
    loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        if let Ok(r) = rpc_call(
            RPC,
            "get_transaction",
            serde_json::json!({"hash": tx_id.to_string()}),
        ) {
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
                return;
            }
        }
        print!(".");
        use std::io::Write;
        std::io::stdout().flush().ok();
    }
}
