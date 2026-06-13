//! Standalone testnet genesis nonce miner.
//!
//! Iterates nonces from 0, runs Argon2id PoW for each against the testnet
//! target (2^252, ~16 expected hashes), and prints the first valid nonce.
//! Run once to mint the testnet-1 genesis:
//!
//!     EXFER_TESTNET_OVERRIDE=1 cargo run --release \
//!         --features "testnet,allow-testnet-release" --bin mine_testnet_genesis
//!
//! The output nonce/id must be hardcoded as TESTNET_GENESIS_NONCE in
//! src/genesis.rs. The template (timestamp/witness/target) is feature-
//! independent, so plain `cargo run --bin mine_testnet_genesis` works too.

fn main() {
    let start = std::time::Instant::now();

    println!("Mining testnet genesis nonce (Argon2id PoW at testnet target 2^252)...");
    println!("Expected work ~16 hashes; this finishes in seconds.");
    println!();

    let (nonce, block_id) = exfer::genesis::mine_testnet_genesis_nonce(|n| {
        let elapsed = start.elapsed().as_secs();
        eprintln!("  trying nonce={:<6} elapsed={}s", n, elapsed);
    });

    let elapsed = start.elapsed();
    println!();
    println!("Found valid testnet genesis nonce!");
    println!("  TESTNET_GENESIS_NONCE = {}", nonce);
    println!("  block_id              = {}", block_id);
    println!("  elapsed               = {:.2}s", elapsed.as_secs_f64());
    println!();
    println!("Paste into src/genesis.rs:");
    println!("  const TESTNET_GENESIS_NONCE: u64 = {};", nonce);
}
