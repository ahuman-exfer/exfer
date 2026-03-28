//! Mine the production genesis nonce.
//!
//! Run with: cargo test --release -p exfer --test mine_genesis -- --ignored --nocapture
//!
//! This takes several hours at the 2^248 production target (~256 expected
//! Argon2id hashes at ~50ms each in release mode ≈ ~1 hour).

#[test]
#[ignore]
fn mine_genesis() {
    use std::time::Instant;

    let start = Instant::now();
    let (nonce, block_id) = exfer::genesis::mine_genesis_nonce(|n| {
        if n % 1000 == 0 {
            let elapsed = start.elapsed().as_secs();
            let rate = if elapsed > 0 { n / elapsed } else { 0 };
            eprintln!("  nonce={:>8}  elapsed={}s  rate={}/s", n, elapsed, rate);
        }
    });

    let elapsed = start.elapsed();
    eprintln!();
    eprintln!("=== GENESIS NONCE FOUND ===");
    eprintln!("  nonce    = {}", nonce);
    eprintln!("  block_id = {}", block_id);
    eprintln!("  elapsed  = {:.1}s", elapsed.as_secs_f64());
    eprintln!();
    eprintln!("Update src/genesis.rs line 29:");
    eprintln!("  const GENESIS_NONCE: u64 = {};", nonce);
}
