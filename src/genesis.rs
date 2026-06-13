//! Deterministic genesis block.
//!
//! The genesis block is a protocol constant — identical on every node.
//! All fields are hardcoded. No randomness, no wall clock.
//!
//! The `GENESIS_NONCE` was found by mining (Argon2id PoW at 2^248 target).
//! To re-mine, run: `cargo test --release --test mine_genesis -- --ignored --nocapture`
//!
//! Testnet (`--features testnet`) uses a dedicated genesis with its own
//! timestamp, witness string, and a REAL low target (2^252, ~16 Argon2id
//! hashes/block — see [`crate::consensus::difficulty::testnet_genesis_target`]),
//! so [`TESTNET_GENESIS_NONCE`] is genuinely mined and the genesis id is not
//! trivially re-mineable. To re-mine it run:
//!     `EXFER_TESTNET_OVERRIDE=1 cargo run --release \
//!          --features "testnet,allow-testnet-release" --bin mine_testnet_genesis`

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

/// Returns the deterministic genesis block for this build's network.
///
/// All fields are protocol constants. This function always returns the same
/// block on every machine for a given build.
///
/// Production (default): the mainnet genesis — `genesis_template()` (the
/// NIST-beacon witness) at target 2^248 with the mined `GENESIS_NONCE`.
/// Testnet (`--features testnet`): the dedicated persistent-testnet genesis —
/// [`testnet_genesis_block`] (its own timestamp + witness) at the real low
/// target 2^252 with the mined `TESTNET_GENESIS_NONCE`. (Previously testnet
/// reused the mainnet template at a trivial 0xFF target; that produced a
/// trivially re-mineable, spammable genesis and is gone.)
pub fn genesis_block() -> Block {
    #[cfg(feature = "testnet")]
    {
        testnet_genesis_block()
    }
    #[cfg(not(feature = "testnet"))]
    {
        let (mut block, _) = genesis_template();
        block.header.nonce = GENESIS_NONCE;
        block
    }
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
/// Scope note (signature domain, issue #32): devnet is also separated at the
/// signature layer, but NOT through this constant directly. `sig_message`
/// (transaction.rs) binds the process [`signature_domain`]: the compiled
/// [`GENESIS_BLOCK_ID`] unless [`bind_signature_domain`] was called. An
/// `exfer devnet` process binds the devnet genesis id at startup (via
/// `types::enter_devnet`), and signing clients bind the id the node reports
/// over RPC after checking it against what they already hold — see the trust
/// rule on [`bind_signature_domain`]. Without that separation, coinbases being
/// deterministic means two same-build chains can hold an identical outpoint
/// (same height + miner pubkey + reward → byte-identical coinbase → identical
/// tx_id), and a spend signed on one chain would verify on the other.
const DEVNET_GENESIS_TIMESTAMP: u64 = GENESIS_TIMESTAMP + 1;

/// Genesis block for an isolated `exfer devnet` chain.
///
/// Deliberately distinct from [`genesis_block`] (see [`DEVNET_GENESIS_TIMESTAMP`]).
/// `nonce = 0`, so it only satisfies PoW under the **trivial** all-`0xFF`
/// target — devnet is a throwaway single-process chain that does no real PoW.
///
/// The target is pinned to all-`0xFF` explicitly (NOT `genesis_target()`): the
/// public testnet now uses a real low target (2^252) for `genesis_target()`
/// under `--features testnet`, which `nonce = 0` would NOT satisfy. Pinning the
/// trivial target here keeps devnet's nonce=0 valid AND makes the devnet
/// genesis id feature-independent — it no longer silently changes between a
/// mainnet build (where `genesis_target()` was 2^248) and a testnet build, so
/// every process that derives the devnet signature domain / address HRP agrees
/// on one id. `exfer devnet` still requires a `--features testnet` build, which
/// the `Devnet` command enforces before this is ever loaded.
pub fn devnet_genesis_block() -> Block {
    let (mut block, _) = genesis_template();
    block.header.timestamp = DEVNET_GENESIS_TIMESTAMP;
    block.header.difficulty_target = Hash256([0xFF; 32]);
    block.header.nonce = 0;
    block
}

// ── Persistent public testnet genesis (#testnet-1) ──

/// Fixed testnet genesis timestamp: 2026-06-13T00:00:00Z (epoch 1_781_308_800).
///
/// A chosen constant (NOT `now()`), distinct from the mainnet genesis timestamp,
/// so the testnet genesis id differs from mainnet/devnet and the P2P handshake
/// (which gates on `genesis_block_id`) refuses cross-network peers. Replay
/// safety across mainnet is already provided by the per-genesis signature
/// domain (#32/#33): a distinct genesis id ⇒ distinct `signature_domain()` ⇒
/// a testnet tx cannot verify on mainnet even with a colliding deterministic
/// coinbase. This constant is the public, committed anchor for "testnet-1";
/// a consensus-breaking reset would bump it to a new value ("testnet-2").
///
/// MUST be in the PAST relative to launch wall-clock: the height-1 block a node
/// mines carries `now()` as its timestamp, and consensus rejects a block whose
/// timestamp is at/below its parent's (MTP rule), so a future-dated genesis
/// strands the chain at height 0 until wall-clock passes it. The original
/// pin was 1_781_481_600 — which is 2026-06-**15**, ~2 days ahead of the
/// 2026-06-13 launch — so every freshly-mined height-1 block timestamped
/// "now" fell before genesis and was silently not accepted as tip (the chain
/// reached Live and mined but never advanced past 0). Corrected to the actual
/// 2026-06-13T00:00:00Z epoch, safely before launch.
const TESTNET_GENESIS_TIMESTAMP: u64 = 1_781_308_800;

/// Mined testnet genesis nonce — satisfies Argon2id PoW at the testnet target
/// (2^252, [`crate::consensus::difficulty::testnet_genesis_target`]). Unlike
/// the old trivial all-`0xFF` testnet target where `nonce=0` always passed,
/// this nonce was genuinely mined, so the testnet genesis id is not trivially
/// re-mineable. Re-mine with the `mine_testnet_genesis` bin (see module docs).
///
/// Minted 2026-06-13 against target 2^252 over the 2026-06-13T00:00:00Z genesis
/// timestamp; the resulting testnet-1 genesis id is
/// c35d676e284b06ee5ae089b8a9dceb6341ace7e6f4e43e859c2eeb6f4a5ad806.
const TESTNET_GENESIS_NONCE: u64 = 20;

/// Build the testnet genesis template (everything except nonce).
///
/// Distinct from the mainnet template in two visible ways: a different witness
/// string and the real low testnet target (pinned via `testnet_genesis_target`
/// so the template is identical regardless of which cargo feature this is built
/// under — the mining bin and the no-feature unit test must produce the exact
/// same template and id as a `--features testnet` build). The coinbase value
/// and the unspendable all-zeros script match mainnet (no premine).
fn testnet_genesis_template() -> (Block, UtxoSet) {
    let coinbase = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0, // height 0
        }],
        outputs: vec![TxOutput {
            value: 10_000_000_000, // 100 EXFER
            script: vec![0u8; 32],  // Unspendable
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: "Exfer testnet-1 genesis 2026-06-13 — a persistent public network where an agent can mine for itself. Real proof-of-work, no premine, valueless coins. Designed, audited, and built by autonomous machines."
                .as_bytes()
                .to_vec(),
            redeemer: None,
        }],
    };

    let tx_root = compute_tx_root(std::slice::from_ref(&coinbase))
        .expect("testnet genesis coinbase must be serializable");

    let mut utxo_set = UtxoSet::new();
    utxo_set
        .apply_transaction(&coinbase, 0)
        .expect("testnet genesis coinbase must be serializable");
    let state_root = utxo_set.state_root();

    let block = Block {
        header: BlockHeader {
            version: VERSION,
            height: 0,
            prev_block_id: Hash256::ZERO,
            timestamp: TESTNET_GENESIS_TIMESTAMP,
            // Pin the testnet target explicitly (not `genesis_target()`), so the
            // template is feature-independent: the mining bin / unit tests build
            // without `--features testnet` yet must mint and validate the same
            // genesis a testnet node loads.
            difficulty_target: crate::consensus::difficulty::testnet_genesis_target(),
            nonce: 0, // placeholder — caller sets the real nonce
            tx_root,
            state_root,
        },
        transactions: vec![coinbase],
    };

    (block, utxo_set)
}

/// Genesis block for the persistent public testnet ("testnet-1").
///
/// Own timestamp + witness + real low target + a genuinely mined nonce. Loaded
/// by a `--features testnet` build (where `genesis_block()` returns the mainnet
/// template). Distinct id ⇒ separate chain (datadir cross-open refused, issue
/// #29; cross-network peers refused at handshake) and a distinct signature
/// domain (#32). This function is available regardless of feature flags so the
/// mining bin and the no-mainnet-change tests can construct it directly.
#[allow(dead_code)]
pub fn testnet_genesis_block() -> Block {
    let (mut block, _) = testnet_genesis_template();
    block.header.nonce = TESTNET_GENESIS_NONCE;
    block
}

/// Lazy testnet genesis block id — computed once on first access.
///
/// Deterministic (testnet_genesis_block() is fully deterministic). On a
/// `--features testnet` build this equals the compiled [`GENESIS_BLOCK_ID`]
/// (both call `genesis_block()`, which returns the testnet genesis), and hence
/// the default `signature_domain()`. Exposed so ops/clients can publish and
/// pin the testnet-1 genesis id.
#[allow(dead_code)]
pub static TESTNET_GENESIS_BLOCK_ID: std::sync::LazyLock<Hash256> =
    std::sync::LazyLock::new(|| testnet_genesis_block().header.block_id());

/// Mine the testnet genesis nonce by brute-forcing Argon2id PoW at the testnet
/// target (2^252). Returns `(nonce, block_id)` for the first valid nonce.
/// Expected work ≈ 16 hashes; finishes in seconds. Drives `mine_testnet_genesis`.
#[allow(dead_code)]
pub fn mine_testnet_genesis_nonce(progress: impl Fn(u64)) -> (u64, Hash256) {
    use crate::consensus::pow::verify_pow;

    let (mut block, _) = testnet_genesis_template();
    for nonce in 0..u64::MAX {
        block.header.nonce = nonce;
        if verify_pow(&block.header).unwrap_or(false) {
            let block_id = block.header.block_id();
            return (nonce, block_id);
        }
        if nonce % 8 == 0 {
            progress(nonce);
        }
    }
    unreachable!("nonce space exhausted")
}

#[cfg(test)]
mod devnet_genesis_tests {
    use super::*;

    #[test]
    fn devnet_genesis_is_distinct_from_canonical() {
        // Distinct id (separate chain) but identical coinbase/state to the
        // MAINNET template — devnet is built from the mainnet template (only the
        // timestamp + trivial target differ). Compare against the template
        // directly, not `genesis_block()`: under `--features testnet`,
        // `genesis_block()` is the dedicated testnet genesis (its own witness),
        // so this stays feature-robust. This is what makes a devnet datadir
        // refuse to open as a networked node (issue #29), and vice versa.
        let (canonical, _) = genesis_template();
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

#[cfg(test)]
mod testnet_genesis_tests {
    use super::*;
    use crate::consensus::pow::verify_pow;

    #[test]
    fn testnet_genesis_validates_under_testnet_target() {
        // The minted nonce must satisfy Argon2id PoW at the testnet target
        // (2^252) — i.e. the testnet-1 genesis is genuinely mined, not trivial.
        let block = testnet_genesis_block();
        assert_eq!(
            block.header.difficulty_target,
            crate::consensus::difficulty::testnet_genesis_target(),
            "testnet genesis must carry the real low target"
        );
        assert!(
            verify_pow(&block.header).expect("pow check"),
            "minted TESTNET_GENESIS_NONCE must satisfy PoW at the testnet target"
        );
    }

    #[test]
    fn testnet_genesis_id_is_pinned() {
        // Locks the published testnet-1 genesis id (the value ops/clients pin).
        let id = *TESTNET_GENESIS_BLOCK_ID;
        assert_eq!(
            hex::encode(id.as_bytes()),
            "c35d676e284b06ee5ae089b8a9dceb6341ace7e6f4e43e859c2eeb6f4a5ad806",
            "testnet-1 genesis id must match the minted/published value"
        );
        assert_eq!(id, testnet_genesis_block().header.block_id());
    }

    #[test]
    fn testnet_genesis_is_distinct_from_mainnet_and_devnet() {
        let testnet = testnet_genesis_block();
        // Distinct from the production mainnet genesis (own timestamp + witness +
        // target ⇒ distinct id ⇒ distinct signature domain ⇒ no cross-chain
        // replay, no cross-network peers).
        let mainnet_template_id = {
            // Reconstruct the production genesis id independent of build feature:
            // mainnet template at the production target with the mainnet nonce.
            let (mut b, _) = genesis_template();
            b.header.difficulty_target =
                crate::consensus::difficulty::production_genesis_target();
            b.header.nonce = GENESIS_NONCE;
            b.header.block_id()
        };
        assert_ne!(
            testnet.header.block_id(),
            mainnet_template_id,
            "testnet genesis must differ from mainnet genesis"
        );
        assert_ne!(
            testnet.header.block_id(),
            devnet_genesis_block().header.block_id(),
            "testnet genesis must differ from devnet genesis"
        );
        // Distinct witness string (visible separation).
        assert_ne!(
            testnet.transactions[0].witnesses[0].witness,
            genesis_template().0.transactions[0].witnesses[0].witness,
            "testnet genesis must carry its own witness string"
        );
    }

    #[test]
    fn mainnet_genesis_unchanged_no_mainnet_change_invariant() {
        // Lock the no-mainnet-change invariant: the production genesis id and the
        // mainnet assume-valid height must be exactly today's values, regardless
        // of any testnet work. Build the production genesis id feature-
        // independently (production target + mainnet nonce).
        let (mut b, _) = genesis_template();
        b.header.difficulty_target = crate::consensus::difficulty::production_genesis_target();
        b.header.nonce = GENESIS_NONCE;
        let prod_id = b.header.block_id();
        assert_eq!(
            hex::encode(prod_id.as_bytes()),
            "d7b6805c8fd793703db88102b5aed2600af510b79e3cb340ca72c1f762d1e051",
            "mainnet genesis id must be unchanged by the testnet work"
        );
        // Mainnet assume-valid checkpoint constants unchanged.
        assert_eq!(
            crate::types::ASSUME_VALID_HEIGHT,
            500_000,
            "mainnet ASSUME_VALID_HEIGHT must be unchanged"
        );
        // Mainnet genesis nonce/timestamp/target unchanged.
        assert_eq!(GENESIS_NONCE, 259);
        assert_eq!(GENESIS_TIMESTAMP, 1_773_536_400);
    }
}

/// Lazy genesis block ID — computed once on first access.
///
/// Deterministic: always the same value because `genesis_block()` is fully
/// deterministic. This is the canonical genesis id on every build
/// (build-dependent: testnet vs production differ by difficulty target) and is
/// the default [`signature_domain`] when no override is bound. It is never
/// mutated — devnet and foreign-chain signing bind a separate override instead
/// (issue #32).
pub static GENESIS_BLOCK_ID: std::sync::LazyLock<Hash256> =
    std::sync::LazyLock::new(|| genesis_block().header.block_id());

/// Process-global signature-domain override (issue #32).
///
/// Never bound → [`signature_domain`] falls back to the compiled
/// [`GENESIS_BLOCK_ID`], byte-for-byte what every release signed and verified
/// before this override existed. `node`/`mine` never bind it; only the
/// `exfer devnet` path (`types::enter_devnet`) and signing clients that
/// verified a node-reported genesis id do.
static SIGNATURE_DOMAIN: std::sync::OnceLock<Hash256> = std::sync::OnceLock::new();

/// Bind the process signature domain to `genesis_id` (issue #32).
///
/// Set-once: a process that could re-bind mid-run would sign transactions in
/// two different domains, so re-binding to a DIFFERENT id returns
/// `Err(already_bound_id)` and the caller must abort. Re-binding the SAME id
/// is an idempotent `Ok` — every pre-sign helper routes through the bind, so
/// a multi-lookup flow hits it more than once.
///
/// Trust rule for callers that bind a node-reported id: anchor on what this
/// process already holds — the compiled [`GENESIS_BLOCK_ID`], or an id the
/// operator named explicitly — and bind the exact id that was checked, never
/// an unchecked or re-fetched one. Binding whatever an RPC answers would let
/// a malicious node move the signer into a foreign domain, where a colliding
/// deterministic-coinbase outpoint makes the signature replayable.
pub fn bind_signature_domain(genesis_id: Hash256) -> Result<(), Hash256> {
    match SIGNATURE_DOMAIN.set(genesis_id) {
        Ok(()) => Ok(()),
        Err(_) => {
            let bound = *SIGNATURE_DOMAIN
                .get()
                .expect("OnceLock::set failed, so it is initialized");
            if bound == genesis_id {
                Ok(())
            } else {
                Err(bound)
            }
        }
    }
}

/// The signature domain for this process: the bound override when set, else
/// the compiled canonical [`GENESIS_BLOCK_ID`]. Read by `sig_message()` on
/// every sign AND every verify in this process.
pub fn signature_domain() -> Hash256 {
    *SIGNATURE_DOMAIN.get().unwrap_or(&*GENESIS_BLOCK_ID)
}

/// Whether [`bind_signature_domain`] has been called in this process.
/// (Used by integration tests via the lib target; the bin never reads it.)
#[allow(dead_code)]
pub fn signature_domain_is_bound() -> bool {
    SIGNATURE_DOMAIN.get().is_some()
}

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
