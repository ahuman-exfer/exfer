//! Standalone genesis nonce miner.
//!
//! Iterates nonces from 0, runs Argon2id PoW for each, and prints the first
//! nonce where pow < target. Run once before launch:
//!
//!     cargo run --release --bin mine_genesis
//!
//! The output nonce must be hardcoded as GENESIS_NONCE in src/genesis.rs.

fn main() {
    let start = std::time::Instant::now();

    println!("Mining genesis nonce (Argon2id PoW at production target)...");
    println!("This may take minutes to hours depending on hardware.");
    println!();

    let (nonce, block_id) = exfer::genesis::mine_genesis_nonce(|n| {
        let elapsed = start.elapsed().as_secs();
        let rate = if elapsed > 0 { n / elapsed } else { 0 };
        eprintln!(
            "  nonce={:<10} elapsed={}s  (~{} nonces/s)",
            n, elapsed, rate
        );
    });

    let elapsed = start.elapsed();
    println!();
    println!("Found valid nonce!");
    println!("  GENESIS_NONCE = {}", nonce);
    println!("  block_id      = {}", block_id);
    println!("  elapsed       = {:.1}s", elapsed.as_secs_f64());
    println!();
    println!("Paste into src/genesis.rs:");
    println!("  const GENESIS_NONCE: u64 = {};", nonce);
}
