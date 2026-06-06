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

/// Mined genesis nonce (satisfies Argon2id PoW at 2^248 target).
/// Testnet uses a trivial difficulty target, so any nonce works there.
const GENESIS_NONCE: u64 = 259;

/// Build the genesis block template (everything except nonce).
/// Used by both `genesis_block()` and `mine_genesis_nonce()`.
fn genesis_template() -> (Block, UtxoSet) {
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
            timestamp: GENESIS_TIMESTAMP,
            difficulty_target: genesis_target(),
            nonce: 0, // placeholder — caller sets the real nonce
            tx_root,
            state_root,
        },
        transactions: vec![coinbase],
    };

    (block, utxo_set)
}

/// Returns the deterministic genesis block.
///
/// All fields are protocol constants. This function always returns
/// the same block on every machine.
/// Production: difficulty target is 2^248 (real mining required; GENESIS_NONCE must be mined).
/// Testnet (--features testnet): difficulty target is all 0xFF (nonce=0 passes).
pub fn genesis_block() -> Block {
    let (mut block, _) = genesis_template();
    block.header.nonce = GENESIS_NONCE;
    block
}

/// Distinct genesis timestamp for `exfer devnet` — one second past the
/// mainnet/testnet genesis. Its only purpose is a DIFFERENT genesis
/// `block_id`, which makes devnet a separate chain: `open_chain` refuses to
/// load a devnet datadir under the canonical genesis (and vice versa — the
/// issue #29 cross-open footgun), and the P2P handshake (which gates on
/// `genesis_block_id`) refuses cross-network peers. The block carries the
/// same coinbase and UTXO state as canonical genesis — only the header
/// timestamp (and hence the id) differs.
///
/// Scope note (signature domain): this isolates devnet at the chain / datadir /
/// P2P-handshake layer ONLY — NOT at the signature layer. `sig_message`
/// (transaction.rs) binds signatures to the canonical [`GENESIS_BLOCK_ID`], not
/// the active genesis, so a devnet process and a same-build testnet/devnet node
/// share one signature domain. Coinbases are deterministic, so two same-build
/// chains can hold an identical outpoint (same height + miner pubkey + reward →
/// byte-identical coinbase → identical tx_id), and a devnet-signed spend of it
/// would verify on the other chain. (The genesis coinbase specifically is
/// unspendable — all-zeros script, no key — so it has nothing to replay; the
/// risk is non-genesis coinbases.)
///
/// Why this is accepted, not fixed: the signature domain is a process-global
/// read by every SIGNER as well as the verifier — the CLI `wallet send`,
/// `walletd`, and the MCP server all sign via `sig_message` in their own
/// processes (README: "point any client at it"). A node cannot override the
/// domain unilaterally without rejecting every client spend, and those clients
/// (some in separate repos) have no devnet signal. True separation requires a
/// coordinated change across all signing clients (e.g. derive the domain from
/// the node's genesis id over RPC) and is deferred until a real testnet network
/// makes it load-bearing — tracked as a follow-up.
///
/// Mainnet is unaffected regardless: `exfer devnet` requires a `--features
/// testnet` build (enforced in the Devnet command), and a testnet build's
/// `GENESIS_BLOCK_ID` already differs from mainnet's (the difficulty target is
/// part of `block_id`), so the shared domain is confined to devnet<->testnet,
/// both dev-only, and no testnet network is deployed.
const DEVNET_GENESIS_TIMESTAMP: u64 = GENESIS_TIMESTAMP + 1;

/// Genesis block for an isolated `exfer devnet` chain.
///
/// Deliberately distinct from [`genesis_block`] (see [`DEVNET_GENESIS_TIMESTAMP`]).
/// `nonce = 0`, so it only satisfies PoW under trivial difficulty — i.e.
/// `exfer devnet` requires a `--features testnet` build, which the `Devnet`
/// command enforces before this is ever loaded.
pub fn devnet_genesis_block() -> Block {
    let (mut block, _) = genesis_template();
    block.header.timestamp = DEVNET_GENESIS_TIMESTAMP;
    block.header.nonce = 0;
    block
}

#[cfg(test)]
mod devnet_genesis_tests {
    use super::*;

    #[test]
    fn devnet_genesis_is_distinct_from_canonical() {
        // Distinct id (separate chain) but identical coinbase/state — only the
        // header timestamp differs. This is what makes a devnet datadir refuse
        // to open as a networked node (issue #29), and a canonical datadir
        // refuse to open as devnet.
        let canonical = genesis_block();
        let devnet = devnet_genesis_block();
        assert_ne!(
            canonical.header.block_id(),
            devnet.header.block_id(),
            "devnet genesis must have a distinct block_id from canonical"
        );
        assert_eq!(
            canonical.header.state_root, devnet.header.state_root,
            "devnet genesis carries the same UTXO state as canonical"
        );
        assert_eq!(
            canonical.transactions, devnet.transactions,
            "devnet genesis carries the same coinbase as canonical"
        );
    }
}

/// Lazy genesis block ID — computed once on first access.
///
/// Deterministic: always the same value because `genesis_block()` is fully
/// deterministic. Used by `sig_message()` to bind signatures to this chain,
/// preventing cross-chain transaction replay. This is the canonical genesis id
/// on every build (build-dependent: testnet vs production differ by difficulty
/// target) and is used even inside an `exfer devnet` process — see the scope
/// note on [`DEVNET_GENESIS_TIMESTAMP`].
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

    let (mut block, _) = genesis_template();

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
