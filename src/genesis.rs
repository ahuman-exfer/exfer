//! Deterministic genesis block.
//!
//! The genesis block is a protocol constant — identical on every node.
//! All fields are hardcoded. No randomness, no wall clock.
//!
//! The `GENESIS_NONCE` was found by mining (Argon2id PoW at 2^248 target).
//! To re-mine, run: `cargo test --release --test mine_genesis -- --ignored --nocapture`
//!
//! Testnet (`--features testnet`) uses a trivial target (all 0xFF), so nonce=0 is valid.

use crate::chain::state::UtxoSet;
use crate::consensus::difficulty::genesis_target;
use crate::consensus::validation::compute_tx_root;
use crate::types::block::{Block, BlockHeader};
use crate::types::hash::Hash256;
use crate::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use crate::types::VERSION;

/// Fixed genesis timestamp: 2026-03-15T01:00:00Z
const GENESIS_TIMESTAMP: u64 = 1773536400;

/// Devnet genesis timestamp: canonical + 1 second. This gives devnet a
/// different genesis block id, so a devnet datadir is a different chain and
/// devnet signatures are bound away from testnet/mainnet.
const DEVNET_GENESIS_TIMESTAMP: u64 = GENESIS_TIMESTAMP + 1;

/// Mined genesis nonce (satisfies Argon2id PoW at 2^248 target).
/// Testnet uses a trivial difficulty target, so any nonce works there.
/// Devnet reuses this nonce because `exfer devnet` is testnet-build-only.
const GENESIS_NONCE: u64 = 259;

static DEVNET_GENESIS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Switch this process to the devnet genesis. Call before any chain/signature
/// operation; panics if GENESIS_BLOCK_ID was already initialized canonically.
pub fn set_devnet_genesis() {
    DEVNET_GENESIS.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        *GENESIS_BLOCK_ID,
        devnet_genesis_block().header.block_id(),
        "set_devnet_genesis() called after canonical GENESIS_BLOCK_ID initialization"
    );
}

/// Build the genesis block template (everything except nonce).
/// Used by `genesis_block()`, `devnet_genesis_block()` and `mine_genesis_nonce()`.
fn genesis_template_for(devnet: bool) -> (Block, UtxoSet) {
    // Genesis coinbase: 100 EXFER to unspendable output (all-zeros script).
    // SPEC: coinbase should pay the miner's pubkey hash; for the genesis block
    // the all-zeros script is intentionally unspendable (no private key).
    let coinbase = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0, // height 0
        }],
        outputs: vec![TxOutput {
            value: 10_000_000_000, // 100 EXFER
            script: vec![0u8; 32], // Unspendable
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: "NIST Beacon 2026-03-14T22:23:00Z 561AA26B4214EE8F3AAD4F5B8BD3B449DF3503C09611110E50AC28F39379B6D8904F833047EFF6109C94BB59AD4BB33359307C77F71C2FC3BA6D1073AE881F81 — Designed, audited, and built by autonomous machines. A human provided minimal necessary support.".as_bytes().to_vec(),
            redeemer: None,
        }],
    };

    let tx_root = compute_tx_root(std::slice::from_ref(&coinbase))
        .expect("genesis coinbase must be serializable");

    // Compute state root from the genesis UTXO
    let mut utxo_set = UtxoSet::new();
    utxo_set
        .apply_transaction(&coinbase, 0)
        .expect("genesis coinbase must be serializable");
    let state_root = utxo_set.state_root();

    let block = Block {
        header: BlockHeader {
            version: VERSION,
            height: 0,
            prev_block_id: Hash256::ZERO,
            timestamp: if devnet { DEVNET_GENESIS_TIMESTAMP } else { GENESIS_TIMESTAMP },
            difficulty_target: genesis_target(),
            nonce: 0, // placeholder — caller sets the real nonce
            tx_root,
            state_root,
        },
        transactions: vec![coinbase],
    };

    (block, utxo_set)
}

/// Returns the deterministic genesis block for the current process mode:
/// canonical by default, devnet after [`set_devnet_genesis`].
///
/// All fields are protocol constants. This function always returns
/// the same block on every machine.
/// Production: difficulty target is 2^248 (real mining required; GENESIS_NONCE must be mined).
/// Testnet (--features testnet): difficulty target is all 0xFF (nonce=0 passes).
pub fn genesis_block() -> Block {
    let (mut block, _) =
        genesis_template_for(DEVNET_GENESIS.load(std::sync::atomic::Ordering::Relaxed));
    block.header.nonce = GENESIS_NONCE;
    block
}

/// Returns the devnet genesis block unconditionally.
pub fn devnet_genesis_block() -> Block {
    let (mut block, _) = genesis_template_for(true);
    block.header.nonce = GENESIS_NONCE;
    block
}

/// Lazy genesis block ID — computed once on first access.
///
/// Deterministic: always the same value because `genesis_block()` is fully
/// deterministic. Used by `sig_message()` to bind signatures to this chain,
/// preventing cross-chain transaction replay.
pub static GENESIS_BLOCK_ID: std::sync::LazyLock<Hash256> =
    std::sync::LazyLock::new(|| genesis_block().header.block_id());

/// Returns the genesis block ID.
///
/// Deterministic: always the same value because genesis_block() is fully
/// deterministic. Computed from genesis_block() each call (cheap: one SHA-256).
#[allow(dead_code)]
pub fn genesis_block_id() -> Hash256 {
    genesis_block().header.block_id()
}

/// Mine the genesis nonce by brute-forcing Argon2id PoW.
///
/// Returns `(nonce, block_id)` when a valid nonce is found.
/// For the production target (2^248), this takes ~256 Argon2id hashes
/// at ~200ms each → several hours on commodity hardware.
///
/// Progress is reported every 100 nonces via the callback.
#[allow(dead_code)]
pub fn mine_genesis_nonce(progress: impl Fn(u64)) -> (u64, Hash256) {
    use crate::consensus::pow::verify_pow;

    let (mut block, _) = genesis_template_for(false);

    for nonce in 0..u64::MAX {
        block.header.nonce = nonce;
        if verify_pow(&block.header).unwrap_or(false) {
            let block_id = block.header.block_id();
            return (nonce, block_id);
        }
        if nonce % 100 == 0 {
            progress(nonce);
        }
    }
    unreachable!("nonce space exhausted")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_genesis_is_a_distinct_chain() {
        let (mut canonical, _) = genesis_template_for(false);
        canonical.header.nonce = GENESIS_NONCE;
        let devnet = devnet_genesis_block();

        assert_ne!(canonical.header.block_id(), devnet.header.block_id());
        assert_eq!(devnet.header.timestamp, canonical.header.timestamp + 1);
        assert_eq!(canonical.header.tx_root, devnet.header.tx_root);
        assert_eq!(canonical.header.state_root, devnet.header.state_root);
        assert_eq!(canonical.transactions, devnet.transactions);
    }
}
