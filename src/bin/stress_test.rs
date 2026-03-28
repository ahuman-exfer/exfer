//! Stress test: 1,000 payments + edge case tests.
//!
//! Phase 1: Split Alice's UTXO into many small UTXOs (fan-out txs, each confirmed)
//! Phase 2: Blast 1,000 independent txs from those UTXOs
//! Phase 3: Edge case tests

use exfer::rpc::rpc_call;
use exfer::types::hash::Hash256;
use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::DUST_THRESHOLD;
use exfer::wallet::Wallet;

use ed25519_dalek::Signer;
use std::path::Path;
use std::time::Instant;

const RPC: &str = "http://82.221.100.201:9334";
const FEE: u64 = 100_000;
const SPLIT_VALUE: u64 = 200_000; // each split UTXO: 200K exfers (0.002 EXFER) — covers 0.001 payment + 0.001 fee
const PAYMENT: u64 = 100_000; // 0.001 EXFER

fn main() {
    let alice = Wallet::load(Path::new("/tmp/alice.key"), None).expect("load alice");
    let bob = Wallet::load(Path::new("/tmp/bob.key"), None).expect("load bob");
    let alice_sk = load_sk("/tmp/alice.key");
    let bob_sk = load_sk("/tmp/bob.key");
    let alice_pk = alice.pubkey();
    let bob_pk = bob.pubkey();
    let alice_addr = alice.address();
    let bob_addr = bob.address();

    let alice_bal = get_balance(&alice_addr.to_string());
    println!("Alice: {:.2} EXFER", alice_bal as f64 / 1e8);
    println!(
        "Bob:   {:.2} EXFER",
        get_balance(&bob_addr.to_string()) as f64 / 1e8
    );
    println!();

    // ═══════════════════════════════════════════
    // PHASE 1: Split into many UTXOs via fan-out transactions
    // ═══════════════════════════════════════════
    println!("══════════════════════════════════════════");
    println!("PHASE 1: Splitting UTXOs (fan-out)");
    println!("══════════════════════════════════════════");

    // Each fan-out tx creates up to 50 outputs from 1 input.
    // Need 1000 UTXOs. 1000/50 = 20 fan-out txs.
    // Each fan-out tx needs: 50 * SPLIT_VALUE + FEE = 25,100,000 exfers
    // Total: 20 * 25,100,000 = 502,000,000 exfers (~5 EXFER)

    let outputs_per_split = 50usize;
    let total_utxos_needed = 1000usize;
    let splits_needed = (total_utxos_needed + outputs_per_split - 1) / outputs_per_split;

    let mut all_utxos: Vec<(Hash256, u32, u64)> = Vec::new();
    let mut current_utxos = get_all_utxos(&alice_addr.to_string());

    println!(
        "  Alice has {} UTXOs, need {} split txs",
        current_utxos.len(),
        splits_needed
    );

    for split_round in 0..splits_needed {
        // Find a UTXO large enough for this split
        let needed = (outputs_per_split as u64) * SPLIT_VALUE + FEE;
        let big_idx = current_utxos.iter().position(|u| u.2 >= needed);
        let (src_txid, src_idx, src_value) = match big_idx {
            Some(i) => current_utxos.remove(i),
            None => {
                println!(
                    "  No UTXO large enough at round {} (need {} exfers)",
                    split_round, needed
                );
                break;
            }
        };

        let change = src_value - (outputs_per_split as u64) * SPLIT_VALUE - FEE;
        let mut outputs: Vec<TxOutput> = (0..outputs_per_split)
            .map(|_| TxOutput {
                value: SPLIT_VALUE,
                script: alice_addr.as_bytes().to_vec(),
                datum: None,
                datum_hash: None,
            })
            .collect();

        if change >= DUST_THRESHOLD {
            outputs.push(TxOutput {
                value: change,
                script: alice_addr.as_bytes().to_vec(),
                datum: None,
                datum_hash: None,
            });
        }

        let mut tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: src_txid,
                output_index: src_idx,
            }],
            outputs,
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        sign_p2pkh(&mut tx, &alice_sk, &alice_pk);

        let tx_id = tx.tx_id().unwrap();
        match submit(&tx) {
            Ok(_) => {
                // Record the split UTXOs
                for i in 0..outputs_per_split {
                    all_utxos.push((tx_id, i as u32, SPLIT_VALUE));
                }
                // Record change as available for next round
                if change >= DUST_THRESHOLD {
                    current_utxos.push((tx_id, outputs_per_split as u32, change));
                }
                println!(
                    "  Split {}/{}: {} UTXOs created",
                    split_round + 1,
                    splits_needed,
                    outputs_per_split
                );
            }
            Err(e) => {
                println!("  Split {} failed: {}", split_round, truncate(&e, 80));
                break;
            }
        }

        // Wait for confirmation before next split (mempool doesn't allow spending unconfirmed)
        wait_for_tx(&tx_id.to_string());
    }

    println!("  Total split UTXOs: {}", all_utxos.len());

    if all_utxos.len() < 100 {
        println!("Not enough UTXOs for stress test. Need more funds.");
        return;
    }

    // ═══════════════════════════════════════════
    // PHASE 2: Blast 1,000 independent payments
    // ═══════════════════════════════════════════
    println!();
    println!("══════════════════════════════════════════");
    println!("PHASE 2: Blasting {} payments", all_utxos.len());
    println!("══════════════════════════════════════════");

    let start_height = get_height();
    let blast_start = Instant::now();
    let mut submitted = 0u32;
    let mut failed = 0u32;
    let mut tx_ids: Vec<String> = Vec::new();

    for (i, (utxo_txid, utxo_idx, utxo_value)) in all_utxos.iter().enumerate() {
        let pay_value = PAYMENT;
        let change = utxo_value - pay_value - FEE;

        let mut outputs = vec![TxOutput {
            value: pay_value,
            script: bob_addr.as_bytes().to_vec(),
            datum: None,
            datum_hash: None,
        }];
        if change >= DUST_THRESHOLD {
            outputs.push(TxOutput {
                value: change,
                script: alice_addr.as_bytes().to_vec(),
                datum: None,
                datum_hash: None,
            });
        }

        let mut tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: *utxo_txid,
                output_index: *utxo_idx,
            }],
            outputs,
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        sign_p2pkh(&mut tx, &alice_sk, &alice_pk);

        let tx_id = tx.tx_id().unwrap();
        match submit(&tx) {
            Ok(_) => {
                submitted += 1;
                tx_ids.push(tx_id.to_string());
            }
            Err(e) => {
                failed += 1;
                if failed <= 5 {
                    eprintln!("  tx {}: {}", i, truncate(&e, 80));
                }
            }
        }

        if (i + 1) % 100 == 0 {
            println!("  submitted {}/{}...", i + 1, all_utxos.len());
        }
    }

    let submit_elapsed = blast_start.elapsed();
    println!();
    println!(
        "Submitted: {} txs in {:.1}s ({:.0} tx/s)",
        submitted,
        submit_elapsed.as_secs_f64(),
        submitted as f64 / submit_elapsed.as_secs_f64()
    );
    println!("Failed:    {}", failed);

    // Wait for all to confirm
    println!("\nWaiting for confirmations...");
    let mut confirmed = 0u32;
    let mut _not_found = 0u32;
    let confirm_start = Instant::now();

    loop {
        if confirm_start.elapsed().as_secs() > 600 {
            println!("\nTimeout after 10 minutes");
            break;
        }

        confirmed = 0;
        _not_found = 0;
        // Sample check — check every 10th tx instead of all for speed
        for (i, tx_id) in tx_ids.iter().enumerate() {
            if i % 10 != 0 && confirmed < submitted {
                continue;
            }
            match rpc_call(RPC, "get_transaction", serde_json::json!({"hash": tx_id})) {
                Ok(r) => {
                    if r.get("block_height").is_some()
                        && !r
                            .get("in_mempool")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true)
                    {
                        confirmed += 1;
                    }
                }
                _ => {
                    _not_found += 1;
                }
            }
        }
        // Scale up from sample
        let sample_size = tx_ids
            .iter()
            .enumerate()
            .filter(|(i, _)| *i % 10 == 0)
            .count() as u32;
        if sample_size > 0 && confirmed == sample_size {
            // All sampled txs confirmed — check the rest
            confirmed = 0;
            _not_found = 0;
            for tx_id in &tx_ids {
                match rpc_call(RPC, "get_transaction", serde_json::json!({"hash": tx_id})) {
                    Ok(r) => {
                        if r.get("block_height").is_some()
                            && !r
                                .get("in_mempool")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(true)
                        {
                            confirmed += 1;
                        }
                    }
                    _ => {
                        _not_found += 1;
                    }
                }
            }
            if confirmed >= submitted {
                break;
            }
        }

        print!(
            "\r  confirmed: ~{}/{} (sample {}/{})   ",
            confirmed * (submitted / sample_size.max(1)),
            submitted,
            confirmed,
            sample_size
        );
        use std::io::Write;
        std::io::stdout().flush().ok();
        std::thread::sleep(std::time::Duration::from_secs(15));
    }

    let end_height = get_height();
    let total_elapsed = blast_start.elapsed();

    println!();
    println!();
    println!("═══ STRESS TEST RESULTS ═══");
    println!("Submitted:    {}", submitted);
    println!("Confirmed:    {}", confirmed);
    println!("Failed:       {}", failed);
    println!("Lost:         {}", submitted.saturating_sub(confirmed));
    println!(
        "Submit time:  {:.1}s ({:.0} tx/s)",
        submit_elapsed.as_secs_f64(),
        submitted as f64 / submit_elapsed.as_secs_f64().max(0.001)
    );
    println!("Confirm time: {:.1}s", total_elapsed.as_secs_f64());
    println!(
        "Blocks:       {} → {} ({} blocks)",
        start_height,
        end_height,
        end_height - start_height
    );
    if confirmed > 0 && end_height > start_height {
        println!(
            "Avg tx/block: {:.1}",
            confirmed as f64 / (end_height - start_height) as f64
        );
    }

    // ═══════════════════════════════════════════
    // PHASE 3: Edge case tests
    // ═══════════════════════════════════════════
    println!();
    println!("══════════════════════════════════════════");
    println!("EDGE CASE TESTS");
    println!("══════════════════════════════════════════");

    let (edge_txid, edge_idx, edge_value) = get_largest_utxo(&alice_addr.to_string());

    // Test 1: Overspend
    print!("1. OVERSPEND:         ");
    {
        let mut tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: edge_txid,
                output_index: edge_idx,
            }],
            outputs: vec![TxOutput {
                value: edge_value + 1_000_000,
                script: bob_addr.as_bytes().to_vec(),
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        sign_p2pkh(&mut tx, &alice_sk, &alice_pk);
        print_result(submit(&tx));
    }

    // Test 2: Dust
    print!("2. DUST OUTPUT:       ");
    {
        let mut tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: edge_txid,
                output_index: edge_idx,
            }],
            outputs: vec![
                TxOutput {
                    value: 100,
                    script: bob_addr.as_bytes().to_vec(),
                    datum: None,
                    datum_hash: None,
                },
                TxOutput {
                    value: edge_value - 100 - FEE,
                    script: alice_addr.as_bytes().to_vec(),
                    datum: None,
                    datum_hash: None,
                },
            ],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        sign_p2pkh(&mut tx, &alice_sk, &alice_pk);
        print_result(submit(&tx));
    }

    // Test 3: Double spend
    print!("3. DOUBLE SPEND:      ");
    {
        let mut tx = Transaction {
            inputs: vec![
                TxInput {
                    prev_tx_id: edge_txid,
                    output_index: edge_idx,
                },
                TxInput {
                    prev_tx_id: edge_txid,
                    output_index: edge_idx,
                },
            ],
            outputs: vec![TxOutput {
                value: edge_value - FEE,
                script: alice_addr.as_bytes().to_vec(),
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![
                TxWitness {
                    witness: vec![],
                    redeemer: None,
                },
                TxWitness {
                    witness: vec![],
                    redeemer: None,
                },
            ],
        };
        let sig_msg = tx.sig_message().unwrap();
        let sig = alice_sk.sign(&sig_msg);
        let w = [alice_pk.as_slice(), sig.to_bytes().as_slice()].concat();
        tx.witnesses[0].witness = w.clone();
        tx.witnesses[1].witness = w;
        print_result(submit(&tx));
    }

    // Test 4: Invalid signature
    print!("4. INVALID SIGNATURE: ");
    {
        let mut tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: edge_txid,
                output_index: edge_idx,
            }],
            outputs: vec![TxOutput {
                value: edge_value - FEE,
                script: alice_addr.as_bytes().to_vec(),
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        sign_p2pkh(&mut tx, &bob_sk, &bob_pk);
        print_result(submit(&tx));
    }

    // Test 5: Nonexistent UTXO
    print!("5. NONEXISTENT UTXO:  ");
    {
        let mut tx = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256([0xDE; 32]),
                output_index: 0,
            }],
            outputs: vec![TxOutput {
                value: 1000,
                script: alice_addr.as_bytes().to_vec(),
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };
        sign_p2pkh(&mut tx, &alice_sk, &alice_pk);
        print_result(submit(&tx));
    }

    println!();
    println!("══════════════════════════════════════════");
    println!("COMPLETE");
    println!("══════════════════════════════════════════");
}

fn print_result(r: Result<serde_json::Value, String>) {
    match r {
        Err(_) => println!("REJECTED (correct)"),
        Ok(_) => println!("ACCEPTED (BUG!)"),
    }
}

fn load_sk(path: &str) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&std::fs::read(path).unwrap()[..32].try_into().unwrap())
}
fn get_height() -> u64 {
    rpc_call(RPC, "get_block_height", serde_json::json!({})).unwrap()["height"]
        .as_u64()
        .unwrap()
}
fn get_balance(addr: &str) -> u64 {
    rpc_call(RPC, "get_balance", serde_json::json!({"address": addr})).unwrap()["balance"]
        .as_u64()
        .unwrap_or(0)
}
fn get_largest_utxo(addr: &str) -> (Hash256, u32, u64) {
    let r = rpc_call(
        RPC,
        "get_address_utxos",
        serde_json::json!({"address": addr}),
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
fn get_all_utxos(addr: &str) -> Vec<(Hash256, u32, u64)> {
    let r = rpc_call(
        RPC,
        "get_address_utxos",
        serde_json::json!({"address": addr}),
    )
    .unwrap();
    r["utxos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hex::decode(u["tx_id"].as_str().unwrap()).unwrap());
            (
                Hash256(arr),
                u["output_index"].as_u64().unwrap() as u32,
                u["value"].as_u64().unwrap(),
            )
        })
        .collect()
}
fn sign_p2pkh(tx: &mut Transaction, sk: &ed25519_dalek::SigningKey, pk: &[u8; 32]) {
    let sig_msg = tx.sig_message().unwrap();
    let sig = sk.sign(&sig_msg);
    tx.witnesses[0].witness = [pk.as_slice(), sig.to_bytes().as_slice()].concat();
}
fn submit(tx: &Transaction) -> Result<serde_json::Value, String> {
    rpc_call(
        RPC,
        "send_raw_transaction",
        serde_json::json!({"tx_hex": hex::encode(tx.serialize().unwrap())}),
    )
}
fn wait_for_tx(tx_id: &str) {
    loop {
        if let Ok(r) = rpc_call(RPC, "get_transaction", serde_json::json!({"hash": tx_id})) {
            if r.get("block_height").is_some()
                && !r
                    .get("in_mempool")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true)
            {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
