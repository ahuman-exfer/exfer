//! Live-chain tests for vault, escrow, and delegation covenants.

use exfer::covenants::{delegation, escrow, vault};
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
const LOCK_VALUE: u64 = 200_000_000; // 2 EXFER
const FEE: u64 = 100_000;
const SCRIPT_FEE: u64 = 5_000_000;

fn main() {
    let alice = Wallet::load(Path::new("/tmp/htlc-test/alice.key"), None).expect("load alice");
    let bob = Wallet::load(Path::new("/tmp/htlc-test/bob.key"), None).expect("load bob");
    let alice_pk = alice.pubkey();
    let bob_pk = bob.pubkey();
    let alice_sk = load_sk("/tmp/htlc-test/alice.key");
    let bob_sk = load_sk("/tmp/htlc-test/bob.key");

    println!("Alice: {}", hex::encode(alice_pk));
    println!("Bob:   {}", hex::encode(bob_pk));

    let height = get_height();
    println!("Height: {}\n", height);

    // ═══════════════════════════════════════════
    // TEST 1: VAULT — spend via recovery path
    // ═══════════════════════════════════════════
    println!("══════════════════════════════════════════");
    println!("TEST 1: VAULT (recovery path)");
    println!("══════════════════════════════════════════");

    // Primary = Alice (timelocked), Recovery = Bob (anytime)
    let vault_locktime = height + 200; // far in the future
    let vault_prog = vault::vault(&alice_pk, &bob_pk, vault_locktime);
    let vault_script = serialize_program(&vault_prog);
    println!(
        "Vault script: {} bytes (locktime: {})",
        vault_script.len(),
        vault_locktime
    );

    // Fund the vault
    let lock_txid = fund_script(&alice_sk, &alice_pk, &alice.address(), &vault_script);
    println!("Vault Lock TxId: {}", lock_txid);

    // Spend via recovery path (Bob, no timelock)
    // Witness: Right(Unit) selector, then sig_recovery
    println!("\n--- Spending via recovery path (Bob) ---");
    let mut vault_spend = build_spend(lock_txid, LOCK_VALUE, &bob.address());
    let sig_msg = vault_spend.sig_message().unwrap();
    let bob_sig = bob_sk.sign(&sig_msg);
    vault_spend.witnesses[0].witness = witness_values(&[
        Value::Right(Box::new(Value::Unit)),
        Value::Bytes(bob_sig.to_bytes().to_vec()),
    ]);
    let vault_spend_txid = vault_spend.tx_id().unwrap();
    println!("Vault Spend TxId: {}", vault_spend_txid);
    submit_and_wait(&vault_spend, "vault recovery spend");

    println!("\nVAULT TEST PASSED");
    println!("  Lock TxId:  {}", lock_txid);
    println!("  Spend TxId: {}", vault_spend_txid);

    // ═══════════════════════════════════════════
    // TEST 2: ESCROW — spend via mutual path
    // ═══════════════════════════════════════════
    println!("\n══════════════════════════════════════════");
    println!("TEST 2: ESCROW (mutual agreement path)");
    println!("══════════════════════════════════════════");

    // party_a = Alice, party_b = Bob, arbiter = Alice (for simplicity), timeout far future
    let escrow_timeout = height + 200;
    let escrow_prog = escrow::escrow(&alice_pk, &bob_pk, &alice_pk, escrow_timeout);
    let escrow_script = serialize_program(&escrow_prog);
    println!(
        "Escrow script: {} bytes (timeout: {})",
        escrow_script.len(),
        escrow_timeout
    );

    let escrow_lock_txid = fund_script(&alice_sk, &alice_pk, &alice.address(), &escrow_script);
    println!("Escrow Lock TxId: {}", escrow_lock_txid);

    // Spend via mutual path: Left(Left(Unit)) selector, sig_a, sig_b
    println!("\n--- Spending via mutual agreement (Alice + Bob) ---");
    let mut escrow_spend = build_spend(escrow_lock_txid, LOCK_VALUE, &bob.address());
    let esig_msg = escrow_spend.sig_message().unwrap();
    let esig_a = alice_sk.sign(&esig_msg);
    let esig_b = bob_sk.sign(&esig_msg);
    escrow_spend.witnesses[0].witness = witness_values(&[
        Value::Left(Box::new(Value::Left(Box::new(Value::Unit)))),
        Value::Bytes(esig_a.to_bytes().to_vec()),
        Value::Bytes(esig_b.to_bytes().to_vec()),
    ]);
    let escrow_spend_txid = escrow_spend.tx_id().unwrap();
    println!("Escrow Spend TxId: {}", escrow_spend_txid);
    submit_and_wait(&escrow_spend, "escrow mutual spend");

    println!("\nESCROW TEST PASSED");
    println!("  Lock TxId:  {}", escrow_lock_txid);
    println!("  Spend TxId: {}", escrow_spend_txid);

    // ═══════════════════════════════════════════
    // TEST 3: DELEGATION — spend via delegate path
    // ═══════════════════════════════════════════
    println!("\n══════════════════════════════════════════");
    println!("TEST 3: DELEGATION (delegate path)");
    println!("══════════════════════════════════════════");

    // Owner = Alice, Delegate = Bob, expiry far in the future
    let deleg_expiry = height + 200;
    let deleg_prog = delegation::delegation(&alice_pk, &bob_pk, deleg_expiry);
    let deleg_script = serialize_program(&deleg_prog);
    println!(
        "Delegation script: {} bytes (delegate expires: {})",
        deleg_script.len(),
        deleg_expiry
    );

    let deleg_lock_txid = fund_script(&alice_sk, &alice_pk, &alice.address(), &deleg_script);
    println!("Delegation Lock TxId: {}", deleg_lock_txid);

    // Spend via delegate path (Bob, before expiry)
    // Witness: Right(Unit) selector, sig_delegate
    println!("\n--- Spending via delegate path (Bob, before expiry) ---");
    let mut deleg_spend = build_spend(deleg_lock_txid, LOCK_VALUE, &bob.address());
    let dsig_msg = deleg_spend.sig_message().unwrap();
    let dsig_b = bob_sk.sign(&dsig_msg);
    deleg_spend.witnesses[0].witness = witness_values(&[
        Value::Right(Box::new(Value::Unit)),
        Value::Bytes(dsig_b.to_bytes().to_vec()),
    ]);
    let deleg_spend_txid = deleg_spend.tx_id().unwrap();
    println!("Delegation Spend TxId: {}", deleg_spend_txid);
    submit_and_wait(&deleg_spend, "delegation delegate spend");

    println!("\nDELEGATION TEST PASSED");
    println!("  Lock TxId:  {}", deleg_lock_txid);
    println!("  Spend TxId: {}", deleg_spend_txid);

    // ═══════════════════════════════════════════
    println!("\n══════════════════════════════════════════");
    println!("ALL COVENANT TESTS PASSED");
    println!("══════════════════════════════════════════");
}

// ── Helpers ──

fn load_sk(path: &str) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&std::fs::read(path).unwrap()[..32].try_into().unwrap())
}

fn get_height() -> u64 {
    rpc_call(RPC, "get_block_height", serde_json::json!({})).unwrap()["height"]
        .as_u64()
        .unwrap()
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
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hex::decode(best["tx_id"].as_str().unwrap()).unwrap());
    (
        Hash256(arr),
        best["output_index"].as_u64().unwrap() as u32,
        best["value"].as_u64().unwrap(),
    )
}

fn fund_script(
    sk: &ed25519_dalek::SigningKey,
    pk: &[u8; 32],
    addr: &Hash256,
    script: &[u8],
) -> Hash256 {
    let (utxo_txid, utxo_idx, utxo_value) = get_largest_utxo(&addr.to_string());
    let change = utxo_value.saturating_sub(LOCK_VALUE).saturating_sub(FEE);

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: utxo_txid,
            output_index: utxo_idx,
        }],
        outputs: vec![TxOutput {
            value: LOCK_VALUE,
            script: script.to_vec(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    if change >= DUST_THRESHOLD {
        tx.outputs.push(TxOutput {
            value: change,
            script: addr.as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        });
    }
    let sig_msg = tx.sig_message().unwrap();
    let sig = sk.sign(&sig_msg);
    tx.witnesses[0].witness = [pk.as_slice(), sig.to_bytes().as_slice()].concat();

    let txid = tx.tx_id().unwrap();
    submit_and_wait(&tx, "fund script");
    txid
}

fn build_spend(input_txid: Hash256, input_value: u64, pay_to: &Hash256) -> Transaction {
    Transaction {
        inputs: vec![TxInput {
            prev_tx_id: input_txid,
            output_index: 0,
        }],
        outputs: vec![TxOutput {
            value: input_value.saturating_sub(SCRIPT_FEE),
            script: pay_to.as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    }
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
