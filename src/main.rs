// Prevent accidental release builds with testnet consensus parameters.
#[cfg(all(
    feature = "testnet",
    not(debug_assertions),
    not(feature = "allow-testnet-release")
))]
compile_error!(
    "testnet feature must not be used in release builds. \
     This produces a binary with trivial difficulty and no genesis PoW check. \
     Use debug builds for testnet, or add --features allow-testnet-release to override."
);

mod chain;
mod consensus;
mod covenants;
mod genesis;
mod mempool;
mod miner;
mod network;
mod rpc;
mod script;
mod types;
mod wallet;

use chain::fork_choice::ChainTip;
use chain::state::UtxoSet;
use chain::storage::ChainStorage;
use clap::{Parser, Subcommand};
use consensus::difficulty::{add_work, expected_difficulty, work_from_target};
use consensus::validation::validate_and_apply_block_transactions_atomic;
use consensus::validation::{
    median_time_past, validate_block_header, validate_block_header_skip_pow,
};
use genesis::genesis_block;
use mempool::Mempool;
use miner::Miner;
use network::sync::{run_outbound_manager, run_sync_manager, Node, OutboundBootstrap, ProcessBlockOutcome, RetryState, SyncState, MAX_FORK_BLOCKS};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};
use types::hash::Hash256;
use types::{MAX_TIMESTAMP_GAP, MTP_WINDOW};
use wallet::{is_encrypted_wallet, prompt_passphrase, prompt_passphrase_confirm, Wallet};

/// Parse an amount string: raw integer (exfers) or "10 EXFER" / "10EXFER" / "0.5 EXFER"
/// Parse an amount string: raw integer (exfers) or "10 EXFER" / "0.5 EXFER".
/// No floating point — uses string-based decimal parsing to avoid precision loss.
fn parse_amount(s: &str) -> Result<u64, String> {
    let s = s.trim();
    // Try raw integer first
    if let Ok(v) = s.parse::<u64>() {
        return Ok(v);
    }
    // Try "N EXFER" or "NEXFER" format
    let upper = s.to_uppercase();
    let num_str = upper
        .trim_end_matches("EXFER")
        .trim_end_matches("EXF")
        .trim();
    if num_str.is_empty() {
        return Err(format!("invalid amount: {}", s));
    }
    // Whole number of EXFER
    if let Ok(whole) = num_str.parse::<u64>() {
        return Ok(whole.checked_mul(100_000_000).ok_or("amount overflow")?);
    }
    // Decimal EXFER — string-based parsing, no f64
    if let Some(dot_pos) = num_str.find('.') {
        let whole_part = &num_str[..dot_pos];
        let frac_part = &num_str[dot_pos + 1..];
        if frac_part.len() > 8 {
            return Err("too many decimal places (max 8 for exfer precision)".into());
        }
        let whole: u64 = if whole_part.is_empty() {
            0
        } else {
            whole_part
                .parse::<u64>()
                .map_err(|_| format!("invalid amount: {}", s))?
        };
        // Pad fractional part to 8 digits
        let mut frac_padded = frac_part.to_string();
        while frac_padded.len() < 8 {
            frac_padded.push('0');
        }
        let frac: u64 = frac_padded
            .parse::<u64>()
            .map_err(|_| format!("invalid fraction: {}", s))?;
        let total = whole
            .checked_mul(100_000_000)
            .and_then(|w| w.checked_add(frac))
            .ok_or("amount overflow")?;
        return Ok(total);
    }
    Err(format!(
        "invalid amount: {} (use integer exfers or '10 EXFER')",
        s
    ))
}

#[derive(Parser)]
#[command(name = "exfer", about = "Exfer blockchain node")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a full node
    Node {
        /// Bind address for P2P
        #[arg(long, default_value = "0.0.0.0:9333")]
        bind: SocketAddr,
        /// Peer addresses to connect to
        #[arg(long)]
        peers: Vec<SocketAddr>,
        /// Data directory
        #[arg(long, default_value = "data")]
        datadir: PathBuf,
        /// Auto-repair insecure node_identity.key permissions instead of exiting
        #[arg(long)]
        repair_perms: bool,
        /// JSON-RPC API bind address (disabled if not set)
        #[arg(long)]
        rpc_bind: Option<SocketAddr>,
        /// Verify PoW for ALL blocks during replay, not just recent ones.
        /// Use if database integrity is suspect (corruption, tampering).
        #[arg(long)]
        verify_all: bool,
        /// Disable assume-valid: verify Argon2id PoW for all blocks during IBD,
        /// even below the hardcoded checkpoint height.
        #[arg(long)]
        no_assume_valid: bool,
    },
    /// Run the miner
    Mine {
        /// Bind address for P2P
        #[arg(long, default_value = "0.0.0.0:9333")]
        bind: SocketAddr,
        /// Peer addresses to connect to
        #[arg(long)]
        peers: Vec<SocketAddr>,
        /// Wallet key file (not needed if --miner-pubkey is set)
        #[arg(long, default_value = "wallet.key")]
        wallet: PathBuf,
        /// Mine using this public key (hex) for coinbase payouts.
        /// No private key needed on the server — only the pubkey.
        #[arg(long)]
        miner_pubkey: Option<String>,
        /// Data directory
        #[arg(long, default_value = "data")]
        datadir: PathBuf,
        /// Store wallet key unencrypted (testing only)
        #[arg(long)]
        no_encrypt: bool,
        /// Create a new wallet if one does not exist (required for first run)
        #[arg(long)]
        create_wallet: bool,
        /// Auto-repair insecure node_identity.key permissions instead of exiting
        #[arg(long)]
        repair_perms: bool,
        /// JSON-RPC API bind address (disabled if not set)
        #[arg(long)]
        rpc_bind: Option<SocketAddr>,
        /// Verify PoW for ALL blocks during replay, not just recent ones.
        /// Use if database integrity is suspect (corruption, tampering).
        #[arg(long)]
        verify_all: bool,
        /// Disable assume-valid: verify Argon2id PoW for all blocks during IBD,
        /// even below the hardcoded checkpoint height.
        #[arg(long)]
        no_assume_valid: bool,
    },
    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        action: WalletCommands,
    },
    /// Script operations (HTLC, covenants)
    Script {
        #[command(subcommand)]
        action: ScriptCommands,
    },
    /// Initialize a new Exfer node: create wallet, start syncing
    Init {
        /// Data directory
        #[arg(long, default_value = "~/.exfer")]
        datadir: String,
        /// Enable mining after init
        #[arg(long)]
        mine: bool,
        /// Read wallet passphrase from this environment variable (non-interactive)
        #[arg(long, conflicts_with = "no_passphrase")]
        passphrase_env: Option<String>,
        /// Create unencrypted wallet (not recommended)
        #[arg(long, conflicts_with = "passphrase_env")]
        no_passphrase: bool,
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
        /// RPC port
        #[arg(long, default_value = "9334")]
        rpc_port: u16,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Generate a new wallet keypair
    Generate {
        /// Output key file
        #[arg(long, default_value = "wallet.key")]
        output: PathBuf,
        /// Store key unencrypted (testing only)
        #[arg(long)]
        no_encrypt: bool,
        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Show wallet address and public key
    Info {
        /// Wallet key file
        #[arg(long, default_value = "wallet.key")]
        wallet: PathBuf,
        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Show wallet balance
    Balance {
        /// Wallet key file
        #[arg(long, default_value = "wallet.key")]
        wallet: PathBuf,
        /// Data directory
        #[arg(long, default_value = "data")]
        datadir: PathBuf,
        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
        /// Query a remote node via JSON-RPC instead of local database
        #[arg(long)]
        rpc: Option<String>,
    },
    /// Send EXFER to an address
    Send {
        /// Wallet key file
        #[arg(long, default_value = "wallet.key")]
        wallet: PathBuf,
        /// Recipient pubkey hash (hex)
        #[arg(long)]
        to: String,
        /// Amount: integer in exfers, or "10 EXFER" / "10EXFER" for whole units
        #[arg(long, value_parser = parse_amount)]
        amount: u64,
        /// Fee: integer in exfers, or "0.001 EXFER" for whole units
        #[arg(long, default_value = "100000", value_parser = parse_amount)]
        fee: u64,
        /// Data directory
        #[arg(long, default_value = "data")]
        datadir: PathBuf,
        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
        /// Submit transaction to a remote node via JSON-RPC
        #[arg(long)]
        rpc: Option<String>,
    },
}

#[derive(Subcommand)]
enum ScriptCommands {
    /// Lock funds in an HTLC (hash time-locked contract)
    HtlcLock {
        /// Wallet key file (sender)
        #[arg(long, default_value = "wallet.key")]
        wallet: PathBuf,
        /// Receiver's pubkey (hex, 64 chars)
        #[arg(long)]
        receiver: String,
        /// SHA-256 hash of the preimage (hex, 64 chars)
        #[arg(long)]
        hash_lock: String,
        /// Timeout block height (sender reclaims after this)
        #[arg(long)]
        timeout: u64,
        /// Amount to lock
        #[arg(long, value_parser = parse_amount)]
        amount: u64,
        /// Fee in exfers
        #[arg(long, default_value = "100000", value_parser = parse_amount)]
        fee: u64,
        /// RPC endpoint
        #[arg(long)]
        rpc: String,
        /// Output JSON
        #[arg(long)]
        json: bool,
    },
    /// Claim an HTLC by revealing the preimage
    HtlcClaim {
        /// Wallet key file (receiver)
        #[arg(long, default_value = "wallet.key")]
        wallet: PathBuf,
        /// Transaction ID of the HTLC locking tx (hex)
        #[arg(long)]
        tx_id: String,
        /// Output index of the HTLC output in the locking tx
        #[arg(long, default_value = "0")]
        output_index: u32,
        /// The preimage (hex)
        #[arg(long)]
        preimage: String,
        /// Sender's pubkey (hex, 64 chars) — needed to reconstruct the HTLC script
        #[arg(long)]
        sender: String,
        /// Timeout height used when the HTLC was created
        #[arg(long)]
        timeout: u64,
        /// Fee in exfers
        #[arg(long, default_value = "100000", value_parser = parse_amount)]
        fee: u64,
        /// RPC endpoint
        #[arg(long)]
        rpc: String,
        /// Output JSON
        #[arg(long)]
        json: bool,
    },
    /// Reclaim an HTLC after timeout (sender path)
    HtlcReclaim {
        /// Wallet key file (sender)
        #[arg(long, default_value = "wallet.key")]
        wallet: PathBuf,
        /// Transaction ID of the HTLC locking tx (hex)
        #[arg(long)]
        tx_id: String,
        /// Output index of the HTLC output in the locking tx
        #[arg(long, default_value = "0")]
        output_index: u32,
        /// Receiver's pubkey (hex, 64 chars) — needed to reconstruct the HTLC script
        #[arg(long)]
        receiver: String,
        /// The hash lock used when the HTLC was created (hex, 64 chars)
        #[arg(long)]
        hash_lock: String,
        /// Timeout height used when the HTLC was created
        #[arg(long)]
        timeout: u64,
        /// Fee in exfers
        #[arg(long, default_value = "100000", value_parser = parse_amount)]
        fee: u64,
        /// RPC endpoint
        #[arg(long)]
        rpc: String,
        /// Output JSON
        #[arg(long)]
        json: bool,
    },
}

/// Hardcoded fallback seed peers.
const FALLBACK_SEEDS: &[&str] = &[
    "89.127.232.155:9333",
    "82.221.100.201:9333",
    "80.78.31.82:9333",
];

/// Default mainnet seed peers. Used when --peers is not specified.
/// Resolves seed.exfer.org first, falls back to hardcoded IPs if DNS fails.
fn default_peers_if_empty(peers: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    if !peers.is_empty() {
        return peers;
    }

    // Try DNS seed first
    match std::net::ToSocketAddrs::to_socket_addrs(&("seed.exfer.org", 9333)) {
        Ok(addrs) => {
            let resolved: Vec<std::net::SocketAddr> = addrs.collect();
            if !resolved.is_empty() {
                tracing::info!("Resolved {} seed peers from seed.exfer.org", resolved.len());
                return resolved;
            }
        }
        Err(e) => {
            tracing::warn!("DNS seed resolution failed (seed.exfer.org): {}", e);
        }
    }

    // Fall back to hardcoded seeds
    tracing::info!("Using hardcoded seed peers");
    FALLBACK_SEEDS
        .iter()
        .map(|s| s.parse().unwrap())
        .collect()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("exfer=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Node {
            bind,
            peers,
            datadir,
            repair_perms,
            rpc_bind,
            verify_all,
            no_assume_valid,
        } => {
            let peers = default_peers_if_empty(peers);
            if let Err(e) = run_node(bind, peers, datadir, None, repair_perms, rpc_bind, verify_all, no_assume_valid).await {
                error!("Node failed to start: {e}");
                std::process::exit(1);
            }
        }
        Commands::Mine {
            bind,
            peers: raw_peers,
            wallet,
            miner_pubkey,
            datadir,
            no_encrypt,
            create_wallet,
            repair_perms,
            rpc_bind,
            verify_all,
            no_assume_valid,
        } => {
            let pubkey = if let Some(hex_str) = miner_pubkey {
                let bytes = hex::decode(&hex_str).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid --miner-pubkey hex: {e}");
                    std::process::exit(1);
                });
                if bytes.len() != 32 {
                    eprintln!(
                        "ERROR: --miner-pubkey must be exactly 32 bytes (64 hex chars), got {}",
                        bytes.len()
                    );
                    std::process::exit(1);
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&bytes);
                pk
            } else {
                let w = load_or_create_wallet(&wallet, no_encrypt, create_wallet);
                w.pubkey()
            };
            let peers = default_peers_if_empty(raw_peers);
            if let Err(e) =
                run_node(bind, peers, datadir, Some(pubkey), repair_perms, rpc_bind, verify_all, no_assume_valid).await
            {
                error!("Node failed to start: {e}");
                std::process::exit(1);
            }
        }
        Commands::Wallet { action } => match action {
            WalletCommands::Generate {
                output,
                no_encrypt,
                json,
            } => {
                let w = Wallet::generate();
                if no_encrypt {
                    warn!("WARNING: --no-encrypt specified. Private key will be stored in PLAINTEXT. Do not use in production.");
                    if let Err(e) = w.save_unencrypted(&output) {
                        eprintln!("ERROR: failed to save wallet: {}", e);
                        std::process::exit(1);
                    }
                } else {
                    let passphrase = match prompt_passphrase_confirm() {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("ERROR: failed to read passphrase: {}", e);
                            std::process::exit(1);
                        }
                    };
                    if let Err(e) = w.save_encrypted(&output, &passphrase) {
                        eprintln!("ERROR: failed to save wallet: {}", e);
                        std::process::exit(1);
                    }
                }
                if json {
                    let j = serde_json::json!({
                        "file": output.display().to_string(),
                        "pubkey": hex::encode(w.pubkey()),
                        "address": w.address().to_string(),
                    });
                    println!("{}", serde_json::to_string_pretty(&j).unwrap());
                } else {
                    println!("Wallet generated: {}", output.display());
                    println!("Public key: {}", hex::encode(w.pubkey()));
                    println!("Address:    {}", w.address());
                }
            }
            WalletCommands::Info { wallet: path, json } => {
                let w = load_wallet_interactive(&path);
                if json {
                    let j = serde_json::json!({
                        "pubkey": hex::encode(w.pubkey()),
                        "address": w.address().to_string(),
                    });
                    println!("{}", serde_json::to_string_pretty(&j).unwrap());
                } else {
                    println!("Public key: {}", hex::encode(w.pubkey()));
                    println!("Address:    {}", w.address());
                }
            }
            WalletCommands::Balance {
                wallet: path,
                datadir,
                json,
                rpc: rpc_url,
            } => {
                let w = load_wallet_interactive(&path);
                let address_hex = w.address().to_string();

                if rpc_url.is_none() {
                    // Local balance from UTXO set
                    let (utxo_set, tip_height) = rebuild_utxo_set(&datadir);
                    let bal = w.balance(&utxo_set, tip_height + 1);
                    if json {
                        let j = serde_json::json!({
                            "address": address_hex,
                            "balance": bal,
                            "tip_height": tip_height,
                            "source": "local",
                        });
                        println!("{}", serde_json::to_string_pretty(&j).unwrap());
                    } else {
                        println!("Address:    {}", w.address());
                        println!("Balance:    {} exfers (tip height: {})", bal, tip_height);
                    }
                } else {
                    // Query remote node via RPC
                    let url = rpc_url.unwrap();
                    match rpc::rpc_call(
                        &url,
                        "get_balance",
                        serde_json::json!({ "address": address_hex }),
                    ) {
                        Ok(result) => {
                            let balance =
                                result.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
                            if json {
                                let j = serde_json::json!({
                                    "address": address_hex,
                                    "balance": balance,
                                    "source": "rpc",
                                    "rpc_url": url,
                                });
                                println!("{}", serde_json::to_string_pretty(&j).unwrap());
                            } else {
                                println!("Address:    {}", address_hex);
                                println!("Balance:    {} exfers (via RPC {})", balance, url);
                            }
                        }
                        Err(e) => {
                            eprintln!("ERROR: RPC call failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
            WalletCommands::Send {
                wallet: path,
                to,
                amount,
                fee,
                datadir,
                json,
                rpc: rpc_url,
            } => {
                let w = load_wallet_interactive(&path);
                let recipient_bytes = match hex::decode(&to) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("ERROR: invalid hex for recipient: {}", e);
                        std::process::exit(1);
                    }
                };
                if recipient_bytes.len() != 32 {
                    eprintln!("recipient must be 32 bytes (64 hex chars)");
                    std::process::exit(1);
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&recipient_bytes);
                let recipient = Hash256(hash);

                let (utxo_set, tip_height) = if let Some(ref url) = rpc_url {
                    // Fetch UTXOs from remote node via RPC
                    let address_hex = w.address().to_string();
                    let result = match rpc::rpc_call(
                        url,
                        "get_address_utxos",
                        serde_json::json!({ "address": address_hex }),
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("ERROR: failed to fetch UTXOs via RPC: {}", e);
                            std::process::exit(1);
                        }
                    };

                    let tip_h = result
                        .get("tip_height")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let utxo_entries = result
                        .get("utxos")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();

                    // Build a local UtxoSet from the RPC response
                    let mut utxo_set = chain::state::UtxoSet::new();
                    for entry in &utxo_entries {
                        let tx_id_hex = entry.get("tx_id").and_then(|v| v.as_str()).unwrap_or("");
                        let output_index = entry
                            .get("output_index")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32;
                        let value = entry.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
                        let height = entry.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                        let is_coinbase = entry
                            .get("is_coinbase")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                        let tx_id_bytes = match hex::decode(tx_id_hex) {
                            Ok(b) if b.len() == 32 => {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&b);
                                arr
                            }
                            _ => continue,
                        };

                        let outpoint = types::transaction::OutPoint {
                            tx_id: Hash256(tx_id_bytes),
                            output_index,
                        };
                        let utxo_entry = chain::state::UtxoEntry {
                            output: types::transaction::TxOutput {
                                value,
                                script: w.address().as_bytes().to_vec(),
                                datum: None,
                                datum_hash: None,
                            },
                            height,
                            is_coinbase,
                        };
                        let _ = utxo_set.insert(outpoint, utxo_entry);
                    }

                    (utxo_set, tip_h)
                } else {
                    rebuild_utxo_set(&datadir)
                };

                let tx =
                    match w.build_transaction(recipient, amount, fee, &utxo_set, tip_height + 1) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("ERROR: failed to build transaction: {}", e);
                            std::process::exit(1);
                        }
                    };
                let tx_id = match tx.tx_id() {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("ERROR: failed to compute tx_id: {}", e);
                        std::process::exit(1);
                    }
                };
                let serialized = match tx.serialize() {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("ERROR: failed to serialize transaction: {}", e);
                        std::process::exit(1);
                    }
                };

                // If --rpc is set, submit to remote node
                if let Some(url) = rpc_url {
                    let tx_hex = hex::encode(&serialized);
                    match rpc::rpc_call(
                        &url,
                        "send_raw_transaction",
                        serde_json::json!({ "tx_hex": tx_hex }),
                    ) {
                        Ok(result) => {
                            if json {
                                let j = serde_json::json!({
                                    "tx_id": tx_id.to_string(),
                                    "size": serialized.len(),
                                    "tip_height": tip_height,
                                    "submitted": true,
                                    "rpc_url": url,
                                    "rpc_result": result,
                                });
                                println!("{}", serde_json::to_string_pretty(&j).unwrap());
                            } else {
                                println!("TxId:      {}", tx_id);
                                println!("Size:      {} bytes", serialized.len());
                                println!("Tip:       height {}", tip_height);
                                println!("Submitted: via RPC {}", url);
                            }
                        }
                        Err(e) => {
                            eprintln!("ERROR: RPC submission failed: {}", e);
                            eprintln!("Raw tx: {}", hex::encode(&serialized));
                            std::process::exit(1);
                        }
                    }
                } else if json {
                    let j = serde_json::json!({
                        "tx_id": tx_id.to_string(),
                        "size": serialized.len(),
                        "tip_height": tip_height,
                        "raw": hex::encode(&serialized),
                    });
                    println!("{}", serde_json::to_string_pretty(&j).unwrap());
                } else {
                    println!("TxId:    {}", tx_id);
                    println!("Size:    {} bytes", serialized.len());
                    println!("Tip:     height {}", tip_height);
                    println!("Raw:     {}", hex::encode(&serialized));
                }
            }
        },
        Commands::Script { action } => match action {
            ScriptCommands::HtlcLock {
                wallet: path,
                receiver,
                hash_lock,
                timeout,
                amount,
                fee,
                rpc,
                json,
            } => {
                let w = load_wallet_interactive(&path);
                let sender_pk = w.pubkey();

                let receiver_bytes = hex::decode(&receiver).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid receiver hex: {}", e);
                    std::process::exit(1);
                });
                if receiver_bytes.len() != 32 {
                    eprintln!("ERROR: receiver must be 32 bytes (64 hex chars)");
                    std::process::exit(1);
                }
                let mut receiver_pk = [0u8; 32];
                receiver_pk.copy_from_slice(&receiver_bytes);

                let hash_bytes = hex::decode(&hash_lock).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid hash_lock hex: {}", e);
                    std::process::exit(1);
                });
                if hash_bytes.len() != 32 {
                    eprintln!("ERROR: hash_lock must be 32 bytes (64 hex chars)");
                    std::process::exit(1);
                }
                let mut hash_arr = [0u8; 32];
                hash_arr.copy_from_slice(&hash_bytes);
                let hash_lock_val = Hash256(hash_arr);

                // Build HTLC script
                let program =
                    covenants::htlc::htlc(&sender_pk, &receiver_pk, &hash_lock_val, timeout);
                let script_bytes = script::serialize_program(&program);

                // Fetch UTXOs
                let address_hex = w.address().to_string();
                let utxos_result = rpc::rpc_call(
                    &rpc,
                    "get_address_utxos",
                    serde_json::json!({"address": address_hex}),
                )
                .unwrap_or_else(|e| {
                    eprintln!("ERROR: {}", e);
                    std::process::exit(1);
                });
                let tip_h = utxos_result["tip_height"].as_u64().unwrap_or(0);

                // Build local UtxoSet from RPC response
                let utxo_entries = utxos_result["utxos"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let mut utxo_set = chain::state::UtxoSet::new();
                for entry in &utxo_entries {
                    let tx_id_hex = entry["tx_id"].as_str().unwrap_or("");
                    let output_index = entry["output_index"].as_u64().unwrap_or(0) as u32;
                    let value = entry["value"].as_u64().unwrap_or(0);
                    let height = entry["height"].as_u64().unwrap_or(0);
                    let is_coinbase = entry["is_coinbase"].as_bool().unwrap_or(false);
                    let tx_id_bytes = match hex::decode(tx_id_hex) {
                        Ok(b) if b.len() == 32 => {
                            let mut a = [0u8; 32];
                            a.copy_from_slice(&b);
                            a
                        }
                        _ => continue,
                    };
                    let outpoint = types::transaction::OutPoint {
                        tx_id: Hash256(tx_id_bytes),
                        output_index,
                    };
                    let utxo_entry = chain::state::UtxoEntry {
                        output: types::transaction::TxOutput {
                            value,
                            script: w.address().as_bytes().to_vec(),
                            datum: None,
                            datum_hash: None,
                        },
                        height,
                        is_coinbase,
                    };
                    let _ = utxo_set.insert(outpoint, utxo_entry);
                }

                // Build locking tx using wallet's build logic for input selection
                let htlc_output = types::transaction::TxOutput {
                    value: amount,
                    script: script_bytes,
                    datum: None,
                    datum_hash: None,
                };
                // Simple input selection: find a UTXO large enough
                let my_utxos = w.list_utxos(&utxo_set, tip_h + 1);
                let needed = amount + fee;
                let mut selected = None;
                for (outpoint, val) in &my_utxos {
                    if *val >= needed {
                        selected = Some((*outpoint, *val));
                        break;
                    }
                }
                let (sel_outpoint, sel_value) = selected.unwrap_or_else(|| {
                    eprintln!("ERROR: no UTXO large enough for {} + {} fee", amount, fee);
                    std::process::exit(1);
                });

                let change = sel_value - amount - fee;
                let mut outputs = vec![htlc_output];
                if change >= types::DUST_THRESHOLD {
                    outputs.push(types::transaction::TxOutput {
                        value: change,
                        script: w.address().as_bytes().to_vec(),
                        datum: None,
                        datum_hash: None,
                    });
                }

                let mut tx = types::transaction::Transaction {
                    inputs: vec![types::transaction::TxInput {
                        prev_tx_id: sel_outpoint.tx_id,
                        output_index: sel_outpoint.output_index,
                    }],
                    outputs,
                    witnesses: vec![types::transaction::TxWitness {
                        witness: vec![],
                        redeemer: None,
                    }],
                };

                // Sign (P2PKH)
                let sig_msg = tx.sig_message().unwrap();
                use ed25519_dalek::Signer;
                let signing_key = w.signing_key_for_cli();
                let sig = signing_key.sign(&sig_msg);
                tx.witnesses[0].witness =
                    [sender_pk.as_slice(), sig.to_bytes().as_slice()].concat();

                let tx_id = tx.tx_id().unwrap();
                let tx_hex = hex::encode(tx.serialize().unwrap());

                // Submit
                match rpc::rpc_call(
                    &rpc,
                    "send_raw_transaction",
                    serde_json::json!({"tx_hex": tx_hex}),
                ) {
                    Ok(_) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "tx_id": tx_id.to_string(),
                                    "htlc_output_index": 0,
                                    "amount": amount,
                                    "hash_lock": hash_lock,
                                    "timeout": timeout,
                                    "receiver": receiver,
                                    "submitted": true,
                                }))
                                .unwrap()
                            );
                        } else {
                            println!("HTLC Lock TxId: {}", tx_id);
                            println!("HTLC output:    index 0, {} exfers", amount);
                            println!("Hash lock:      {}", hash_lock);
                            println!("Timeout:        block {}", timeout);
                            println!("Submitted via:  {}", rpc);
                        }
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            ScriptCommands::HtlcClaim {
                wallet: path,
                tx_id: lock_tx_id_hex,
                output_index,
                preimage: preimage_hex,
                sender,
                timeout: _timeout,
                fee,
                rpc,
                json,
            } => {
                let w = load_wallet_interactive(&path);
                let _receiver_pk = w.pubkey();

                let sender_bytes = hex::decode(&sender).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid sender hex: {}", e);
                    std::process::exit(1);
                });
                if sender_bytes.len() != 32 {
                    eprintln!("ERROR: sender must be 32 bytes");
                    std::process::exit(1);
                }
                let mut sender_pk = [0u8; 32];
                sender_pk.copy_from_slice(&sender_bytes);

                let preimage_bytes = hex::decode(&preimage_hex).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid preimage hex: {}", e);
                    std::process::exit(1);
                });
                let _hash_lock = Hash256::sha256(&preimage_bytes);

                let lock_tx_bytes = hex::decode(&lock_tx_id_hex).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid tx_id hex: {}", e);
                    std::process::exit(1);
                });
                if lock_tx_bytes.len() != 32 {
                    eprintln!("ERROR: tx_id must be 32 bytes");
                    std::process::exit(1);
                }
                let mut lock_arr = [0u8; 32];
                lock_arr.copy_from_slice(&lock_tx_bytes);
                let lock_tx_id = Hash256(lock_arr);

                // Fetch the locking tx to get the HTLC output value
                let tx_result = rpc::rpc_call(
                    &rpc,
                    "get_transaction",
                    serde_json::json!({"hash": lock_tx_id_hex}),
                )
                .unwrap_or_else(|e| {
                    eprintln!("ERROR: {}", e);
                    std::process::exit(1);
                });
                let tx_hex_str = tx_result["tx_hex"].as_str().unwrap_or_else(|| {
                    eprintln!("ERROR: transaction not found");
                    std::process::exit(1);
                });
                let lock_tx_raw = hex::decode(tx_hex_str).unwrap();
                let (lock_tx, _) = types::transaction::Transaction::deserialize(&lock_tx_raw)
                    .unwrap_or_else(|e| {
                        eprintln!("ERROR: failed to deserialize lock tx: {:?}", e);
                        std::process::exit(1);
                    });
                let htlc_value = lock_tx
                    .outputs
                    .get(output_index as usize)
                    .map(|o| o.value)
                    .unwrap_or_else(|| {
                        eprintln!("ERROR: output index {} not found in lock tx", output_index);
                        std::process::exit(1);
                    });

                let claim_value = htlc_value.saturating_sub(fee);

                // Build claim tx
                let mut claim_tx = types::transaction::Transaction {
                    inputs: vec![types::transaction::TxInput {
                        prev_tx_id: lock_tx_id,
                        output_index,
                    }],
                    outputs: vec![types::transaction::TxOutput {
                        value: claim_value,
                        script: w.address().as_bytes().to_vec(),
                        datum: None,
                        datum_hash: None,
                    }],
                    witnesses: vec![types::transaction::TxWitness {
                        witness: vec![],
                        redeemer: None,
                    }],
                };

                // Build witness: Left(Unit) selector, preimage, signature
                let claim_sig_msg = claim_tx.sig_message().unwrap();
                use ed25519_dalek::Signer;
                let signing_key = w.signing_key_for_cli();
                let sig = signing_key.sign(&claim_sig_msg);

                use script::value::Value;
                let selector = Value::Left(Box::new(Value::Unit));
                let preimage_val = Value::Bytes(preimage_bytes);
                let sig_val = Value::Bytes(sig.to_bytes().to_vec());
                let mut witness_data = Vec::new();
                witness_data.extend_from_slice(&selector.serialize());
                witness_data.extend_from_slice(&preimage_val.serialize());
                witness_data.extend_from_slice(&sig_val.serialize());
                claim_tx.witnesses[0].witness = witness_data;

                let claim_tx_id = claim_tx.tx_id().unwrap();
                let claim_tx_hex = hex::encode(claim_tx.serialize().unwrap());

                match rpc::rpc_call(
                    &rpc,
                    "send_raw_transaction",
                    serde_json::json!({"tx_hex": claim_tx_hex}),
                ) {
                    Ok(_) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "tx_id": claim_tx_id.to_string(),
                                    "claimed_from": lock_tx_id_hex,
                                    "amount": claim_value,
                                    "fee": fee,
                                    "submitted": true,
                                }))
                                .unwrap()
                            );
                        } else {
                            println!("HTLC Claim TxId: {}", claim_tx_id);
                            println!(
                                "Claimed:         {} exfers from {}",
                                claim_value, lock_tx_id_hex
                            );
                            println!("Submitted via:   {}", rpc);
                        }
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            ScriptCommands::HtlcReclaim {
                wallet: path,
                tx_id: lock_tx_id_hex,
                output_index,
                receiver,
                hash_lock,
                timeout,
                fee,
                rpc,
                json,
            } => {
                let w = load_wallet_interactive(&path);
                let sender_pk = w.pubkey();

                let receiver_bytes = hex::decode(&receiver).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid receiver hex: {}", e);
                    std::process::exit(1);
                });
                if receiver_bytes.len() != 32 {
                    eprintln!("ERROR: receiver must be 32 bytes");
                    std::process::exit(1);
                }
                let mut receiver_pk = [0u8; 32];
                receiver_pk.copy_from_slice(&receiver_bytes);

                let hash_bytes = hex::decode(&hash_lock).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid hash_lock hex: {}", e);
                    std::process::exit(1);
                });
                if hash_bytes.len() != 32 {
                    eprintln!("ERROR: hash_lock must be 32 bytes");
                    std::process::exit(1);
                }
                let mut hash_arr = [0u8; 32];
                hash_arr.copy_from_slice(&hash_bytes);
                let hash_lock_val = Hash256(hash_arr);

                let lock_tx_bytes = hex::decode(&lock_tx_id_hex).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid tx_id hex: {}", e);
                    std::process::exit(1);
                });
                if lock_tx_bytes.len() != 32 {
                    eprintln!("ERROR: tx_id must be 32 bytes");
                    std::process::exit(1);
                }
                let mut lock_arr = [0u8; 32];
                lock_arr.copy_from_slice(&lock_tx_bytes);
                let lock_tx_id = Hash256(lock_arr);

                // Fetch the locking tx to get the HTLC output value
                let tx_result = rpc::rpc_call(
                    &rpc,
                    "get_transaction",
                    serde_json::json!({"hash": lock_tx_id_hex}),
                )
                .unwrap_or_else(|e| {
                    eprintln!("ERROR: {}", e);
                    std::process::exit(1);
                });
                let tx_hex_str = tx_result["tx_hex"].as_str().unwrap_or_else(|| {
                    eprintln!("ERROR: transaction not found");
                    std::process::exit(1);
                });
                let lock_tx_raw = hex::decode(tx_hex_str).unwrap();
                let (lock_tx, _) = types::transaction::Transaction::deserialize(&lock_tx_raw)
                    .unwrap_or_else(|e| {
                        eprintln!("ERROR: failed to deserialize lock tx: {:?}", e);
                        std::process::exit(1);
                    });
                let htlc_value = lock_tx
                    .outputs
                    .get(output_index as usize)
                    .map(|o| o.value)
                    .unwrap_or_else(|| {
                        eprintln!("ERROR: output index {} not found in lock tx", output_index);
                        std::process::exit(1);
                    });

                // Check current height vs timeout
                let current_height = rpc::rpc_call(&rpc, "get_block_height", serde_json::json!({}))
                    .unwrap_or_else(|e| {
                        eprintln!("ERROR: {}", e);
                        std::process::exit(1);
                    })["height"]
                    .as_u64()
                    .unwrap_or(0);
                if current_height <= timeout {
                    eprintln!(
                        "ERROR: timeout not reached (current height {} <= timeout {})",
                        current_height, timeout
                    );
                    std::process::exit(1);
                }

                let reclaim_value = htlc_value.saturating_sub(fee);

                // Reconstruct the HTLC script to validate spending
                let _program =
                    covenants::htlc::htlc(&sender_pk, &receiver_pk, &hash_lock_val, timeout);

                // Build reclaim tx
                let mut reclaim_tx = types::transaction::Transaction {
                    inputs: vec![types::transaction::TxInput {
                        prev_tx_id: lock_tx_id,
                        output_index,
                    }],
                    outputs: vec![types::transaction::TxOutput {
                        value: reclaim_value,
                        script: w.address().as_bytes().to_vec(),
                        datum: None,
                        datum_hash: None,
                    }],
                    witnesses: vec![types::transaction::TxWitness {
                        witness: vec![],
                        redeemer: None,
                    }],
                };

                // Build witness: Right(Unit) selector, signature (timeout path)
                let sig_msg = reclaim_tx.sig_message().unwrap();
                use ed25519_dalek::Signer;
                let signing_key = w.signing_key_for_cli();
                let sig = signing_key.sign(&sig_msg);

                use script::value::Value;
                let selector = Value::Right(Box::new(Value::Unit));
                let sig_val = Value::Bytes(sig.to_bytes().to_vec());
                let mut witness_data = Vec::new();
                witness_data.extend_from_slice(&selector.serialize());
                witness_data.extend_from_slice(&sig_val.serialize());
                reclaim_tx.witnesses[0].witness = witness_data;

                let reclaim_tx_id = reclaim_tx.tx_id().unwrap();
                let reclaim_tx_hex = hex::encode(reclaim_tx.serialize().unwrap());

                match rpc::rpc_call(
                    &rpc,
                    "send_raw_transaction",
                    serde_json::json!({"tx_hex": reclaim_tx_hex}),
                ) {
                    Ok(_) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "tx_id": reclaim_tx_id.to_string(),
                                    "reclaimed_from": lock_tx_id_hex,
                                    "amount": reclaim_value,
                                    "fee": fee,
                                    "submitted": true,
                                }))
                                .unwrap()
                            );
                        } else {
                            println!("HTLC Reclaim TxId: {}", reclaim_tx_id);
                            println!(
                                "Reclaimed:         {} exfers from {}",
                                reclaim_value, lock_tx_id_hex
                            );
                            println!("Submitted via:     {}", rpc);
                        }
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Init {
            datadir,
            mine,
            passphrase_env,
            no_passphrase,
            json,
            rpc_port,
        } => {
            run_init(datadir, mine, passphrase_env, no_passphrase, json, rpc_port);
        }
    }
}

fn run_init(
    datadir_str: String,
    mine: bool,
    passphrase_env: Option<String>,
    no_passphrase: bool,
    json_output: bool,
    rpc_port: u16,
) {
    // JSON mode requires non-interactive passphrase
    if json_output && passphrase_env.is_none() && !no_passphrase {
        eprintln!("ERROR: Use --passphrase-env with --json for non-interactive mode");
        std::process::exit(1);
    }

    // Expand ~ in datadir (cross-platform)
    let datadir = if datadir_str.starts_with("~/") || datadir_str.starts_with("~\\") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(&datadir_str[2..])
    } else if datadir_str == "~" {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
    } else {
        PathBuf::from(&datadir_str)
    };

    // Step 1: Create datadir
    if let Err(e) = std::fs::create_dir_all(&datadir) {
        eprintln!("ERROR: failed to create {}: {}", datadir.display(), e);
        std::process::exit(1);
    }

    // Step 2: Atomically check for existing init via exclusive file create.
    // O_CREAT|O_EXCL fails if the file already exists — no TOCTOU race.
    let wallet_path = datadir.join("wallet.key");
    let lock_path = datadir.join(".init.lock");
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => {} // We hold the lock
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lock file exists — either another init is running or a previous
            // init completed. Check for wallet.key to distinguish.
            if wallet_path.exists() {
                eprintln!(
                    "Error: already initialized at {}. Use --datadir to specify a different path.",
                    datadir.display()
                );
            } else {
                eprintln!(
                    "Error: another exfer init may be running for {}. Remove {}.init.lock if stale.",
                    datadir.display(),
                    datadir.display()
                );
            }
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("ERROR: failed to create lock file: {}", e);
            std::process::exit(1);
        }
    }

    // Run the rest inside a closure so we can clean up the lock on all paths.
    // std::process::exit() skips Drop, so we use a closure + manual cleanup.
    let result = run_init_inner(
        &datadir,
        &wallet_path,
        mine,
        passphrase_env,
        no_passphrase,
        json_output,
        rpc_port,
    );

    // Always clean up the lock file
    let _ = std::fs::remove_file(&lock_path);

    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn run_init_inner(
    datadir: &Path,
    wallet_path: &Path,
    mine: bool,
    passphrase_env: Option<String>,
    no_passphrase: bool,
    json_output: bool,
    rpc_port: u16,
) -> Result<(), String> {
    if wallet_path.exists() {
        return Err(format!(
            "Error: already initialized at {}. Use --datadir to specify a different path.",
            datadir.display()
        ));
    }

    // Step 3: Generate wallet
    let w = Wallet::generate();
    if no_passphrase {
        if !json_output {
            eprintln!("WARNING: Creating unencrypted wallet. Not recommended for production.");
        }
        w.save_unencrypted(wallet_path)
            .map_err(|e| format!("ERROR: failed to save wallet: {}", e))?;
    } else if let Some(env_var) = &passphrase_env {
        let passphrase = std::env::var(env_var)
            .map_err(|_| format!("ERROR: Environment variable ${} not set", env_var))?;
        if passphrase.is_empty() {
            return Err(format!("ERROR: Environment variable ${} is empty", env_var));
        }
        w.save_encrypted(wallet_path, passphrase.as_bytes())
            .map_err(|e| format!("ERROR: failed to save wallet: {}", e))?;
        // Clear the passphrase env var so child processes don't inherit it
        std::env::remove_var(env_var);
    } else {
        // Interactive mode
        let passphrase = prompt_passphrase_confirm()
            .map_err(|e| format!("ERROR: failed to read passphrase: {}", e))?;
        w.save_encrypted(wallet_path, &passphrase)
            .map_err(|e| format!("ERROR: failed to save wallet: {}", e))?;
    }

    let pubkey_hex = hex::encode(w.pubkey());
    let address = w.address().to_string();
    let rpc_url = format!("http://127.0.0.1:{}", rpc_port);
    let log_path = datadir.join("node.log");
    let pid_path = datadir.join("node.pid");

    // Step 4: Write config
    let config_path = datadir.join("config.toml");
    let config_content = format!(
        "rpc_port = {}\np2p_port = 9333\ndatadir = \"{}\"\ndns_seeds = [\"seed.exfer.org\"]\n",
        rpc_port,
        datadir.display()
    );
    if let Err(e) = std::fs::write(&config_path, &config_content) {
        eprintln!("WARNING: failed to write config: {}", e);
    }

    // Step 5: Start node
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("exfer"));
    let log_file = std::fs::File::create(&log_path)
        .map_err(|e| format!("ERROR: failed to create log file: {}", e))?;
    let log_err = log_file.try_clone().unwrap();

    let mut cmd = std::process::Command::new(&exe);
    if mine {
        cmd.arg("mine")
            .arg("--datadir")
            .arg(&datadir)
            .arg("--miner-pubkey")
            .arg(&pubkey_hex)
            .arg("--rpc-bind")
            .arg(format!("127.0.0.1:{}", rpc_port))
            .arg("--repair-perms");
    } else {
        cmd.arg("node")
            .arg("--datadir")
            .arg(&datadir)
            .arg("--rpc-bind")
            .arg(format!("127.0.0.1:{}", rpc_port))
            .arg("--repair-perms");
    }

    let child = cmd
        .stdout(log_file)
        .stderr(log_err)
        .stdin(std::process::Stdio::null())
        .spawn();

    let node_started = match child {
        Ok(mut child) => {
            let pid = child.id();
            if let Err(e) = std::fs::write(&pid_path, pid.to_string()) {
                if !json_output {
                    eprintln!("WARNING: failed to write PID file: {}", e);
                }
            }
            // Wait briefly to verify the child didn't die immediately
            std::thread::sleep(std::time::Duration::from_millis(500));
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Child already exited — startup failed
                    let _ = std::fs::remove_file(&pid_path);
                    if !json_output {
                        eprintln!(
                            "WARNING: node exited immediately (status: {}). Check {}",
                            status, log_path.display()
                        );
                    }
                    false
                }
                Ok(None) => {
                    // Still running — success. Dropping Child closes handles
                    // but does NOT kill the process on any platform.
                    drop(child);
                    true
                }
                Err(_) => {
                    // Can't check — assume running
                    drop(child);
                    true
                }
            }
        }
        Err(e) => {
            if !json_output {
                eprintln!("WARNING: failed to start node: {}", e);
                eprintln!("Check {}", log_path.display());
            }
            false
        }
    };

    // Step 6: Wait for RPC (best effort, up to 10s)
    let mut sync_height: Option<u64> = None;
    if node_started {
        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            if let Ok(output) = std::process::Command::new("curl")
                .args(["-s", &rpc_url, "-d",
                    r#"{"jsonrpc":"2.0","id":1,"method":"get_block_height"}"#])
                .output()
            {
                if let Ok(text) = String::from_utf8(output.stdout) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(h) = v["result"]["height"].as_u64() {
                            sync_height = Some(h);
                            break;
                        }
                    }
                }
            }
        }
    }

    // Step 7: Print summary
    let task_server = "http://82.221.100.201:8080/api/v1/tasks";

    if json_output {
        let j = serde_json::json!({
            "address": address,
            "pubkey": pubkey_hex,
            "rpc": rpc_url,
            "datadir": datadir.display().to_string(),
            "wallet": wallet_path.display().to_string(),
            "log": log_path.display().to_string(),
            "node_started": node_started,
            "mining": mine,
            "sync": {
                "current_height": sync_height,
                "status": if sync_height.is_some() { "syncing" } else { "starting" },
            },
            "task_server": task_server,
        });
        println!("{}", serde_json::to_string_pretty(&j).unwrap());
    } else {
        println!();
        println!("Exfer initialized.");
        println!();
        println!("Address : {}", address);
        println!("Pubkey  : {}", pubkey_hex);
        println!("RPC     : {}", rpc_url);
        println!("Log     : {}", log_path.display());
        println!();
        if let Some(h) = sync_height {
            println!("Node is syncing. Current height: {}", h);
        } else if node_started {
            println!("Node started. Waiting for sync to begin...");
        } else {
            println!("Node failed to start. Check {}", log_path.display());
        }
        if mine {
            println!("Mining enabled. Rewards go to {}", address);
        }
        println!();
        println!("Earn EXFER by completing tasks: {}", task_server);
        println!();
        println!(
            "To check balance:  exfer wallet balance --wallet {} --rpc {}",
            wallet_path.display(),
            rpc_url
        );
        if !mine {
            println!(
                "To enable mining:  exfer mine --datadir {} --miner-pubkey {} --rpc-bind 127.0.0.1:{}",
                datadir.display(),
                pubkey_hex,
                rpc_port
            );
        }
    }

    Ok(())
}

/// Rebuild the UTXO set by replaying the chain from storage.
/// Returns the UTXO set and the tip height (0 if only genesis exists).
///
/// Performs the same integrity checks as the node startup replay path:
/// chain linkage, genesis verification, header validation, state root
/// verification, and tip consistency.
fn rebuild_utxo_set(datadir: &Path) -> (UtxoSet, u64) {
    match rebuild_utxo_set_inner(datadir) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("ERROR: wallet replay failed: {}", e);
            eprintln!("Database may be corrupt. Delete data directory and re-sync.");
            std::process::exit(1);
        }
    }
}

fn rebuild_utxo_set_inner(datadir: &Path) -> Result<(UtxoSet, u64), String> {
    let db_path = datadir.join("chain.redb");
    let storage =
        ChainStorage::open(&db_path).map_err(|e| format!("failed to open database: {}", e))?;

    let mut utxo_set = UtxoSet::new();
    let expected_genesis_id = genesis_block().header.block_id();

    let tip_id = match storage
        .get_tip()
        .map_err(|e| format!("db error reading tip: {}", e))?
    {
        Some(id) => id,
        None => {
            // Fail-closed: if TIP is missing but HEIGHT_INDEX has entries,
            // the database is corrupt — do not silently normalize.
            if !storage
                .height_index_is_empty()
                .map_err(|e| format!("db error checking height index: {}", e))?
            {
                return Err(
                    "tip metadata missing but height index is not empty; database may be corrupt"
                        .to_string(),
                );
            }

            if !storage
                .blocks_table_is_empty()
                .map_err(|e| format!("db error checking blocks table: {}", e))?
            {
                return Err(
                    "tip metadata missing but blocks table is not empty; database may be corrupt"
                        .to_string(),
                );
            }

            // No tip — apply genesis only
            let genesis = genesis_block();
            for tx in &genesis.transactions {
                utxo_set
                    .apply_transaction(tx, 0)
                    .map_err(|e| format!("genesis transaction failed: {:?}", e))?;
            }
            return Ok((utxo_set, 0));
        }
    };

    let tip_header = storage
        .get_header(&tip_id)
        .map_err(|e| format!("db error reading tip header: {}", e))?
        .ok_or_else(|| format!("tip header {} not found", tip_id))?;
    let tip_height = tip_header.height;

    // Assume-valid for wallet replay: same policy as startup replay.
    // Skip PoW only if checkpoint block exists in storage and matches.
    let wallet_assume_valid_proven = tip_height >= types::ASSUME_VALID_HEIGHT
        && storage
            .get_block_id_by_height(types::ASSUME_VALID_HEIGHT)
            .ok()
            .flatten()
            .map(|id| id == Hash256(types::ASSUME_VALID_HASH))
            .unwrap_or(false);

    let mut prev_id = Hash256::ZERO; // genesis has prev = ZERO

    for height in 0..=tip_height {
        let block_id = storage
            .get_block_id_by_height(height)
            .map_err(|e| format!("db error at height {}: {}", height, e))?
            .ok_or_else(|| {
                format!(
                    "height index missing entry at height {} during wallet replay",
                    height
                )
            })?;

        // Genesis check
        if height == 0 && block_id != expected_genesis_id {
            return Err(format!(
                "height 0 block {} does not match expected genesis {}; \
                 database belongs to a different chain",
                block_id, expected_genesis_id
            ));
        }

        let block = storage
            .get_block(&block_id)
            .map_err(|e| format!("db error reading block at height {}: {}", height, e))?
            .ok_or_else(|| {
                format!(
                    "block {} at height {} not found during wallet replay",
                    block_id, height
                )
            })?;

        // Chain linkage
        if block.header.prev_block_id != prev_id {
            return Err(format!(
                "chain linkage broken at height {}: block prev_block_id {} != expected {}",
                height, block.header.prev_block_id, prev_id
            ));
        }

        // Header validation (skip genesis — no parent)
        if height > 0 {
            let parent_header = storage
                .get_header(&block.header.prev_block_id)
                .map_err(|e| format!("db error reading parent header at height {}: {}", height, e))?
                .ok_or_else(|| {
                    format!(
                        "parent header not found at height {} during wallet replay",
                        height
                    )
                })?;
            let ancestor_timestamps = storage
                .get_ancestor_timestamps(&block.header.prev_block_id, MTP_WINDOW)
                .map_err(|e| {
                    format!(
                        "db error reading ancestor timestamps at height {}: {}",
                        height, e
                    )
                })?;
            let expected_target = consensus::difficulty::expected_difficulty(
                &storage,
                &block.header.prev_block_id,
                block.header.height,
            )
            .map_err(|e| format!("difficulty computation failed at height {}: {}", height, e))?;

            // Wallet replay uses same assume-valid policy as startup replay:
            // skip PoW only if checkpoint is proven in storage.
            let skip_pow = wallet_assume_valid_proven && height <= types::ASSUME_VALID_HEIGHT;
            if !skip_pow {
                validate_block_header(
                    &block,
                    Some(&parent_header),
                    &ancestor_timestamps,
                    &expected_target,
                    None,
                )
            } else {
                validate_block_header_skip_pow(
                    &block,
                    Some(&parent_header),
                    &ancestor_timestamps,
                    &expected_target,
                    None,
                )
            }
            .map_err(|e| {
                format!(
                    "block header validation failed at height {}: {:?}",
                    height, e
                )
            })?;
        }

        let (_fees, spent_utxos) =
            validate_and_apply_block_transactions_atomic(&block, &mut utxo_set).map_err(|e| {
                format!(
                    "block transaction validation failed at height {}: {:?}",
                    height, e
                )
            })?;

        // Wallet replay is read-only — do NOT write spent-UTXO metadata here.
        let _ = spent_utxos; // silence unused warning

        // State root verification
        let computed = utxo_set.state_root();
        if computed != block.header.state_root {
            return Err(format!(
                "state root mismatch at height {}: expected {}, got {}",
                height, block.header.state_root, computed
            ));
        }

        prev_id = block_id;
    }

    // Tip consistency: last replayed block must equal persisted tip
    if prev_id != tip_id {
        return Err(format!(
            "replay/tip mismatch: last replayed block {} != persisted tip {}; \
             height index and tip metadata are inconsistent",
            prev_id, tip_id
        ));
    }

    Ok((utxo_set, tip_height))
}

fn load_or_create_wallet(path: &Path, no_encrypt: bool, create_wallet: bool) -> Wallet {
    if path.exists() {
        load_wallet_interactive(path)
    } else {
        if !create_wallet {
            eprintln!(
                "ERROR: wallet file '{}' does not exist.\n\
                 To create a new wallet, re-run with --create-wallet.\n\
                 Never silently generate a new keypair.",
                path.display()
            );
            std::process::exit(1);
        }
        let w = Wallet::generate();
        if no_encrypt {
            warn!("WARNING: --no-encrypt specified. Private key will be stored in PLAINTEXT. Do not use in production.");
            if let Err(e) = w.save_unencrypted(path) {
                eprintln!("ERROR: failed to save wallet: {}", e);
                std::process::exit(1);
            }
        } else {
            let passphrase = match prompt_passphrase_confirm() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("ERROR: failed to read passphrase: {}", e);
                    std::process::exit(1);
                }
            };
            if let Err(e) = w.save_encrypted(path, &passphrase) {
                eprintln!("ERROR: failed to save wallet: {}", e);
                std::process::exit(1);
            }
        }
        info!("Generated new wallet at {}", path.display());
        w
    }
}

/// Load a wallet, prompting for passphrase if the file is encrypted.
fn load_wallet_interactive(path: &Path) -> Wallet {
    if is_encrypted_wallet(path) {
        let passphrase = match prompt_passphrase("Enter wallet passphrase: ") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("ERROR: failed to read passphrase: {}", e);
                std::process::exit(1);
            }
        };
        match Wallet::load(path, Some(&passphrase)) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("ERROR: failed to load wallet '{}': {}", path.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        match Wallet::load(path, None) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("ERROR: failed to load wallet '{}': {}", path.display(), e);
                std::process::exit(1);
            }
        }
    }
}

/// Replay the canonical chain from genesis to tip, rebuilding the UTXO set
/// and validating every block. Returns the chain tip on success.
///
/// All corruption/inconsistency conditions return `Err` instead of panicking,
/// so the caller can log cleanly and exit gracefully.
fn replay_chain(
    storage: &Arc<ChainStorage>,
    utxo_set: &mut UtxoSet,
    expected_genesis_id: &Hash256,
    assume_valid: bool,
) -> Result<ChainTip, String> {
    let tip_id = match storage
        .get_tip()
        .map_err(|e| format!("db error reading tip: {}", e))?
    {
        Some(id) => id,
        None => {
            // Fail-closed: if TIP is missing but HEIGHT_INDEX has entries,
            // the database is corrupt — do not silently normalize.
            if !storage
                .height_index_is_empty()
                .map_err(|e| format!("db error checking height index: {}", e))?
            {
                return Err(
                    "tip metadata missing but height index is not empty; database may be corrupt"
                        .to_string(),
                );
            }

            // Also check blocks table — only commit genesis into a truly empty database.
            if !storage
                .blocks_table_is_empty()
                .map_err(|e| format!("db error checking blocks table: {}", e))?
            {
                return Err(
                    "tip metadata missing but blocks table is not empty; database may be corrupt"
                        .to_string(),
                );
            }

            // First start: apply genesis atomically (block + header +
            // height index + work + tip in one write transaction).
            let genesis = genesis_block();
            let gid = genesis.header.block_id();

            for tx in &genesis.transactions {
                utxo_set
                    .apply_transaction(tx, 0)
                    .map_err(|e| format!("genesis transaction failed: {:?}", e))?;
            }

            let genesis_work = work_from_target(&genesis.header.difficulty_target);
            storage
                .commit_genesis_atomic(&genesis, &genesis_work)
                .map_err(|e| format!("failed to commit genesis: {}", e))?;

            return Ok(ChainTip::genesis(gid, &genesis.header.difficulty_target));
        }
    };

    // Get tip height for bounded forward walk
    let tip_header = storage
        .get_header(&tip_id)
        .map_err(|e| format!("db error reading tip header: {}", e))?
        .ok_or_else(|| format!("tip block header {} not found", tip_id))?;
    let tip_height = tip_header.height;

    // Check if assume-valid checkpoint is proven: chain must be at or past
    // checkpoint height AND the block at that height must match the hash.
    let assume_valid_proven = assume_valid && tip_height >= types::ASSUME_VALID_HEIGHT && {
        match storage
            .get_block_id_by_height(types::ASSUME_VALID_HEIGHT)
            .map_err(|e| format!("db error checking checkpoint: {}", e))?
        {
            Some(id) => id == Hash256(types::ASSUME_VALID_HASH),
            None => false,
        }
    };
    if assume_valid {
        if assume_valid_proven {
            info!(
                "Assume-valid checkpoint verified in storage at height {}",
                types::ASSUME_VALID_HEIGHT
            );
        } else {
            info!("Assume-valid checkpoint not yet proven — full PoW verification during replay");
        }
    }

    let mut cumulative_work = [0u8; 32];
    let mut block_count = 0u64;
    let mut prev_id = Hash256::ZERO; // genesis has prev = ZERO

    let replay_start = std::time::Instant::now();

    info!("Replaying {} blocks...", tip_height + 1);

    // Forward walk using height index — one block at a time, no Vec accumulation
    for height in 0..=tip_height {
        let block_id = storage
            .get_block_id_by_height(height)
            .map_err(|e| format!("db error at height {}: {}", height, e))?
            .ok_or_else(|| {
                format!(
                    "height index missing entry at height {} during replay",
                    height
                )
            })?;

        // Verify height 0 is our expected genesis
        if height == 0 && block_id != *expected_genesis_id {
            return Err(format!(
                "height 0 block {} does not match expected genesis {}; \
                 database belongs to a different chain",
                block_id, expected_genesis_id
            ));
        }

        let block = storage
            .get_block(&block_id)
            .map_err(|e| format!("db error reading block at height {}: {}", height, e))?
            .ok_or_else(|| {
                format!(
                    "block {} at height {} not found during replay",
                    block_id, height
                )
            })?;

        // Verify chain linkage (catches corrupt height index)
        if block.header.prev_block_id != prev_id {
            return Err(format!(
                "chain linkage broken at height {}: block prev_block_id {} != expected {}",
                height, block.header.prev_block_id, prev_id
            ));
        }

        // Full consensus validation (skip header for genesis — already PoW-checked)
        if block.header.height > 0 {
            let parent_header = storage
                .get_header(&block.header.prev_block_id)
                .map_err(|e| format!("db error reading parent header at height {}: {}", height, e))?
                .ok_or_else(|| {
                    format!("parent header not found at height {} during replay", height)
                })?;
            let ancestor_timestamps = storage
                .get_ancestor_timestamps(&block.header.prev_block_id, MTP_WINDOW)
                .map_err(|e| {
                    format!(
                        "db error reading ancestor timestamps at height {}: {}",
                        height, e
                    )
                })?;
            let expected_target =
                expected_difficulty(storage, &block.header.prev_block_id, block.header.height)
                    .map_err(|e| {
                        format!("difficulty computation failed at height {}: {}", height, e)
                    })?;

            // Assume-valid: skip PoW for blocks at/below checkpoint, but ONLY
            // if the checkpoint block is already in storage and matches.
            // If chain is shorter than checkpoint, verify full PoW.
            let skip_pow = assume_valid_proven && height <= types::ASSUME_VALID_HEIGHT;
            if !skip_pow {
                validate_block_header(
                    &block,
                    Some(&parent_header),
                    &ancestor_timestamps,
                    &expected_target,
                    None,
                )
            } else {
                validate_block_header_skip_pow(
                    &block,
                    Some(&parent_header),
                    &ancestor_timestamps,
                    &expected_target,
                    None,
                )
            }
            .map_err(|e| {
                format!(
                    "block header validation failed at height {}: {:?}",
                    block.header.height, e
                )
            })?;

            // Assume-valid checkpoint during replay (redundant if already proven,
            // but verifies integrity on every replay)
            if assume_valid_proven && height == types::ASSUME_VALID_HEIGHT {
                use crate::types::hash::Hash256;
                let expected = Hash256(types::ASSUME_VALID_HASH);
                let actual = block.header.block_id();
                if actual != expected {
                    return Err(format!(
                        "assume-valid checkpoint failed during replay at height {}: expected {}, got {}",
                        types::ASSUME_VALID_HEIGHT, expected, actual
                    ));
                }
            }
        }

        // Full transaction validation with automatic rollback on failure
        let (_fees, spent_utxos) = validate_and_apply_block_transactions_atomic(&block, utxo_set)
            .map_err(|e| {
            format!(
                "block transaction validation failed at height {}: {:?}",
                block.header.height, e
            )
        })?;

        // TX indexing during replay is deferred — commit_block_atomic and
        // commit_reorg_atomic index new blocks as they arrive. Doing per-block
        // index_tx writes during replay of 28K+ blocks causes OOM on
        // memory-constrained nodes (each write transaction buffers in redb).

        // Verify state integrity (O(1) with incremental SMT)
        let computed = utxo_set.state_root();
        if computed != block.header.state_root {
            return Err(format!(
                "state root mismatch at height {}: expected {}, got {}",
                block.header.height, block.header.state_root, computed
            ));
        }

        // Persist spent-UTXO metadata so reorg undo works
        storage
            .store_spent_utxos(&block_id, &spent_utxos)
            .map_err(|e| {
                format!(
                    "failed to store spent UTXOs at height {}: {}",
                    block.header.height, e
                )
            })?;

        let block_work = work_from_target(&block.header.difficulty_target);
        cumulative_work = add_work(&cumulative_work, &block_work);
        storage
            .put_cumulative_work(&block_id, &cumulative_work)
            .map_err(|e| format!("failed to store work at height {}: {}", height, e))?;

        // Progress logging every 1000 blocks
        if (height + 1) % 1000 == 0 || height == tip_height {
            let elapsed = replay_start.elapsed().as_secs();
            let pct = (height + 1) as f64 / (tip_height + 1) as f64 * 100.0;
            info!(
                "Replay progress: {}/{} blocks ({:.1}%) in {}s",
                height + 1,
                tip_height + 1,
                pct,
                elapsed,
            );
        }

        prev_id = block_id;
        block_count += 1;
    }

    // Final consistency check: last replayed block must equal persisted tip
    if prev_id != tip_id {
        return Err(format!(
            "replay/tip mismatch: last replayed block {} != persisted tip {}; \
             height index and tip metadata are inconsistent",
            prev_id, tip_id
        ));
    }

    let (smt_nodes, smt_leaves) = utxo_set.smt_stats();
    info!(
        "Replayed {} blocks, UTXO set has {} entries, SMT: {} nodes + {} leaves",
        block_count,
        utxo_set.len(),
        smt_nodes,
        smt_leaves,
    );

    // Memory diagnostics: log RSS after replay
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") || line.starts_with("VmSize:") {
                    info!("Memory after replay: {}", line.trim());
                }
            }
        }
    }

    Ok(ChainTip {
        block_id: tip_id,
        height: tip_height,
        cumulative_work,
    })
}

async fn run_node(
    bind: SocketAddr,
    peers: Vec<SocketAddr>,
    datadir: PathBuf,
    miner_pubkey: Option<[u8; 32]>,
    repair_perms: bool,
    rpc_bind: Option<SocketAddr>,
    verify_all: bool,
    no_assume_valid: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let assume_valid = !no_assume_valid && !verify_all;
    std::fs::create_dir_all(&datadir)
        .map_err(|e| format!("failed to create data directory {}: {e}", datadir.display()))?;

    let db_path = datadir.join("chain.redb");
    let storage = Arc::new(
        ChainStorage::open(&db_path)
            .map_err(|e| format!("failed to open database {}: {e}", db_path.display()))?,
    );

    // Load or generate persistent node identity key (Ed25519)
    let identity_key = {
        let key_path = datadir.join("node_identity.key");
        if key_path.exists() {
            // Fail-closed: reject insecure permissions BEFORE reading key material.
            // With --repair-perms, auto-fix instead of exiting.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&key_path)
                    .map_err(|e| format!("node_identity.key metadata: {e}"))?
                    .permissions()
                    .mode()
                    & 0o777;
                if mode != 0o600 {
                    if repair_perms {
                        warn!(
                            "node_identity.key has insecure permissions {:04o}, repairing to 0600",
                            mode
                        );
                        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                            .map_err(|e| {
                                format!("failed to repair node_identity.key permissions: {e}")
                            })?;
                    } else {
                        return Err(format!(
                            "node_identity.key has insecure permissions {:04o} (expected 0600). \
                             Fix with: chmod 600 {}\n\
                             Or pass --repair-perms to auto-fix.",
                            mode,
                            key_path.display()
                        )
                        .into());
                    }
                }
            }
            let seed_bytes = std::fs::read(&key_path)
                .map_err(|e| format!("failed to read node_identity.key: {e}"))?;
            if seed_bytes.len() != 32 {
                return Err(format!(
                    "node_identity.key has invalid length {} (expected 32)",
                    seed_bytes.len()
                )
                .into());
            }
            let seed: [u8; 32] = seed_bytes
                .try_into()
                .map_err(|_| "node_identity.key: unexpected length")?;
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            info!(
                "Loaded node identity: {}",
                hex::encode(ed25519_dalek::VerifyingKey::from(&key).as_bytes())
            );
            key
        } else {
            use rand::RngCore;
            use std::io::Write;
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);

            // Atomic write: temp file + fsync + rename, same pattern as wallet saves.
            let parent = key_path
                .parent()
                .ok_or("node_identity.key path has no parent directory")?;
            let tmp_name = format!(
                ".identity_tmp_{}_{}",
                std::process::id(),
                rand::random::<u32>()
            );
            let tmp_path = parent.join(tmp_name);
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let write_result = (|| -> Result<(), String> {
                let mut file = opts
                    .open(&tmp_path)
                    .map_err(|e| format!("failed to create temp identity file: {e}"))?;
                file.write_all(&seed)
                    .map_err(|e| format!("failed to write temp identity file: {e}"))?;
                file.sync_all()
                    .map_err(|e| format!("failed to fsync temp identity file: {e}"))?;
                drop(file);
                std::fs::rename(&tmp_path, &key_path)
                    .map_err(|e| format!("failed to rename identity file: {e}"))?;
                // Windows does not support opening a directory as a file for fsync.
                #[cfg(unix)]
                {
                    let dir = std::fs::File::open(parent)
                        .map_err(|e| format!("failed to open parent dir for fsync: {e}"))?;
                    dir.sync_all()
                        .map_err(|e| format!("failed to fsync parent dir: {e}"))?;
                }
                Ok(())
            })();
            if write_result.is_err() {
                let _ = std::fs::remove_file(&tmp_path);
            }
            write_result?;
            info!(
                "Generated new node identity: {}",
                hex::encode(ed25519_dalek::VerifyingKey::from(&key).as_bytes())
            );
            key
        }
    };
    let mut utxo_set = UtxoSet::new();

    #[cfg(feature = "testnet")]
    {
        warn!("========================================");
        warn!("  TESTNET BUILD — NOT FOR PRODUCTION");
        warn!("  Trivial difficulty, no genesis PoW check");
        warn!("========================================");
        eprintln!("WARNING: This is a TESTNET build. NOT FOR PRODUCTION.");
        eprintln!("Sleeping 5 seconds so operators can abort if unintended...");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    // Ensure genesis block is stored and has valid PoW
    let genesis = genesis_block();
    let expected_genesis_id = genesis.header.block_id();

    // Validate genesis PoW — refuse to start with a placeholder nonce
    if !crate::consensus::pow::verify_pow(&genesis.header).unwrap_or(false) {
        #[cfg(not(feature = "testnet"))]
        {
            return Err(format!(
                "Genesis block PoW is INVALID (nonce={}). \
                 Run `cargo run --release --bin mine_genesis` to find a valid nonce before production launch.",
                genesis.header.nonce
            )
            .into());
        }
    }

    // Foreign chain detection: if the database already has a tip, verify its
    // genesis matches ours.  Refuse to start if the database belongs to a
    // different chain — do not overwrite, do not attempt recovery.
    if let Some(existing_tip) = storage
        .get_tip()
        .map_err(|e| format!("db error reading tip: {e}"))?
    {
        let stored_genesis_id = storage
            .get_block_id_by_height(0)
            .map_err(|e| format!("db error reading height-0: {e}"))?;
        match stored_genesis_id {
            Some(id) if id == expected_genesis_id => { /* match — continue */ }
            Some(id) => {
                return Err(format!(
                    "database contains foreign chain data: genesis at height 0 is {} \
                     but expected {}. Refusing to start.",
                    id, expected_genesis_id
                )
                .into());
            }
            None => {
                return Err(format!(
                    "database contains foreign chain data: tip {} exists but no \
                     genesis block at height 0. Refusing to start.",
                    existing_tip
                )
                .into());
            }
        }
    }

    let has_tip = storage
        .get_tip()
        .map_err(|e| format!("db error reading tip: {e}"))?
        .is_some();
    let has_genesis_body = storage
        .has_block(&expected_genesis_id)
        .map_err(|e| format!("db error checking genesis block: {e}"))?;

    if has_tip && !has_genesis_body {
        return Err(
            "database corruption: tip exists but genesis block missing. \
                    Delete data directory and re-sync."
                .into(),
        );
    }

    if !has_tip && !has_genesis_body {
        let genesis_work = work_from_target(&genesis.header.difficulty_target);
        // Atomic genesis bootstrap: block + height_index + cumulative_work + tip
        // in a single redb transaction. A crash mid-write cannot leave the
        // database half-initialized (e.g. block stored but no tip pointer).
        storage
            .commit_genesis_atomic(&genesis, &genesis_work)
            .map_err(|e| format!("failed to store genesis block: {e}"))?;
        info!("Stored genesis block: {}", expected_genesis_id);
    }

    // P1-5: Reconstruct state by replaying chain from genesis to tip
    let tip = replay_chain(&storage, &mut utxo_set, &expected_genesis_id, assume_valid).map_err(|e| {
        format!(
            "Chain replay failed: {e}. Database may be corrupt. Delete data directory and re-sync."
        )
    })?;

    // Stale HEIGHT_INDEX detection: if there are height entries above the
    // tip, the database is corrupt (e.g. partial reorg write).  Refuse to
    // start — a stale index could cause the node to serve phantom headers.
    if storage
        .has_stale_height_entries(tip.height)
        .map_err(|e| format!("db error checking stale height entries: {e}"))?
    {
        return Err(format!(
            "database corrupt: HEIGHT_INDEX contains entries above tip height {}. \
             Delete data directory and re-sync.",
            tip.height
        )
        .into());
    }

    let genesis_id = expected_genesis_id;

    let restored_fork_blocks = storage
        .load_fork_blocks(MAX_FORK_BLOCKS)
        .map_err(|e| format!("Failed to load fork blocks: {e}. Database may be corrupt."))?;

    // Load persisted IP bans (P2a)
    let mut restored_ip_abuse = HashMap::new();
    match storage.load_ip_bans() {
        Ok(bans) => {
            let now = std::time::Instant::now();
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            for (ip, banned_until_unix) in &bans {
                let remaining = banned_until_unix.saturating_sub(now_unix);
                if remaining > 0 {
                    restored_ip_abuse.insert(
                        *ip,
                        network::sync::IpAbuseEntry {
                            strikes: 10, // IP_BAN_STRIKE_THRESHOLD
                            banned_until: Some(now + std::time::Duration::from_secs(remaining)),
                            last_strike: now,
                        },
                    );
                }
            }
            if !restored_ip_abuse.is_empty() {
                info!("Restored {} IP bans from storage", restored_ip_abuse.len());
            }
        }
        Err(e) => {
            warn!("Failed to load persisted IP bans: {} (continuing)", e);
        }
    }

    // Load persisted identity bans
    let mut restored_identity_bans: HashMap<[u8; 32], std::time::Instant> = HashMap::new();
    match storage.load_identity_bans() {
        Ok(bans) => {
            let now = std::time::Instant::now();
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            for (pubkey, banned_until_unix) in &bans {
                let remaining = banned_until_unix.saturating_sub(now_unix);
                if remaining > 0 {
                    restored_identity_bans
                        .insert(*pubkey, now + std::time::Duration::from_secs(remaining));
                }
            }
            if !restored_identity_bans.is_empty() {
                info!(
                    "Restored {} identity bans from storage",
                    restored_identity_bans.len()
                );
            }
        }
        Err(e) => {
            warn!("Failed to load persisted identity bans: {} (continuing)", e);
        }
    }

    // Load persisted known addresses (P1b)
    let mut initial_addr_book = HashMap::new();
    match storage.get_known_addrs() {
        Ok(addrs) => {
            for (addr, last_seen) in addrs {
                initial_addr_book.insert(
                    addr,
                    network::sync::AddrInfo {
                        entry: network::protocol::AddrEntry { addr, last_seen },
                        last_attempt: None,
                        last_success: None,
                        fail_count: 0,
                        sources: std::collections::HashSet::new(), // loaded from disk, no identity
                        contributed_by: None,
                    },
                );
            }
            if !initial_addr_book.is_empty() {
                info!(
                    "Loaded {} known addresses from storage",
                    initial_addr_book.len()
                );
            }
        }
        Err(e) => {
            warn!("Failed to load known addresses: {} (continuing)", e);
        }
    }

    // Seed addr book with CLI --peers
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for peer_addr in &peers {
        initial_addr_book
            .entry(*peer_addr)
            .or_insert(network::sync::AddrInfo {
                entry: network::protocol::AddrEntry {
                    addr: *peer_addr,
                    last_seen: now_unix,
                },
                last_attempt: None,
                last_success: None,
                fail_count: 0,
                sources: std::collections::HashSet::new(), // seed peer, no announcing identity
                contributed_by: None,
            });
    }

    // Central event channel for peer tasks → sync manager
    let (peer_events_tx, peer_events_rx) = tokio::sync::mpsc::channel(4096);

    // Seed configured peers into outbound_bootstraps
    let mut initial_bootstraps: HashMap<std::net::SocketAddr, OutboundBootstrap> = HashMap::new();
    for peer_addr in &peers {
        initial_bootstraps.insert(
            *peer_addr,
            OutboundBootstrap {
                retry: RetryState {
                    backoff_secs: 5,
                    next_attempt_at: std::time::Instant::now(),
                },
                desired_outbound: true,
            },
        );
    }

    // Check if assume-valid checkpoint is already proven in storage
    let checkpoint_proven = assume_valid
        && tip.height >= types::ASSUME_VALID_HEIGHT
        && storage
            .get_block_id_by_height(types::ASSUME_VALID_HEIGHT)
            .ok()
            .flatten()
            .map(|id| id == Hash256(types::ASSUME_VALID_HASH))
            .unwrap_or(false);

    let node = Arc::new(Node {
        storage,
        utxo_set: Arc::new(RwLock::new(utxo_set)),
        mempool: Arc::new(Mutex::new(Mempool::new())),
        tip: Arc::new(RwLock::new(tip)),
        genesis_id,
        peers: Arc::new(Mutex::new(
            network::sync::PeerRegistry::new(),
        )),
        outbound_bootstraps: std::sync::Mutex::new(initial_bootstraps),
        next_session_id: std::sync::atomic::AtomicU64::new(1),
        active_ibd_peer: std::sync::Mutex::new(None),
        global_block_limiter: std::sync::Mutex::new((std::time::Instant::now(), 0)),
        global_tx_limiter: std::sync::Mutex::new((std::time::Instant::now(), 0)),
        ip_abuse: std::sync::Mutex::new(restored_ip_abuse),
        fork_blocks: std::sync::Mutex::new(restored_fork_blocks),
        orphan_blocks: std::sync::Mutex::new(Vec::new()),
        future_blocks: std::sync::Mutex::new(Vec::new()),
        difficulty_cache: std::sync::Mutex::new(HashMap::new()),
        shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        addr_book: std::sync::Mutex::new(initial_addr_book),
        pow_semaphore: tokio::sync::Semaphore::new(2),
        identity_key,
        identity_bans: std::sync::Mutex::new(restored_identity_bans),
        global_response_limiter: std::sync::Mutex::new((std::time::Instant::now(), 0)),
        reorg_triggers: std::sync::Mutex::new(network::sync::ReorgTriggerState::new()),
        peer_events_tx,
        sync_state: std::sync::atomic::AtomicU8::new(SyncState::CatchingUp as u8),
        best_peer_work: std::sync::Mutex::new([0u8; 32]),
        mining_cancel: std::sync::atomic::AtomicBool::new(true),
        assume_valid,
        assume_valid_verified: std::sync::atomic::AtomicBool::new(checkpoint_proven),
    });

    let listen_node = node.clone();
    let shutdown_on_bind = node.shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = listen_node.listen(bind).await {
            error!("FATAL: P2P listener failed on {}: {}", bind, e);
            shutdown_on_bind.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    // Spawn the central sync manager
    let sync_node = node.clone();
    tokio::spawn(async move {
        run_sync_manager(sync_node, peer_events_rx).await;
    });

    // Start the single outbound manager task (replaces per-address reconnect loops)
    let outbound_node = node.clone();
    tokio::spawn(async move {
        run_outbound_manager(outbound_node).await;
    });

    // Start JSON-RPC server if --rpc-bind is set
    if let Some(rpc_addr) = rpc_bind {
        let rpc_node = node.clone();
        tokio::spawn(async move {
            rpc::run_rpc_server(rpc_addr, rpc_node).await;
        });
    }

    if let Some(pubkey) = miner_pubkey {
        let mine_node = node.clone();
        tokio::spawn(async move {
            mining_loop(mine_node, pubkey).await;
        });
    }

    // Background discovery task: queues candidates into outbound_bootstraps
    let discovery_node = node.clone();
    tokio::spawn(async move {
        let mut last_flush = std::time::Instant::now();
        loop {
            if discovery_node
                .shutdown
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;

            let outbound_count = {
                let peers = discovery_node.peers.lock().await;
                peers.outbound_count()
            };
            if outbound_count < types::MAX_OUTBOUND_PEERS {
                if let Some(candidate) = discovery_node.addr_book_select_for_connect() {
                    // Queue into outbound_bootstraps instead of spawning connect() directly
                    let mut bootstraps = discovery_node
                        .outbound_bootstraps
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    bootstraps.entry(candidate).or_insert(OutboundBootstrap {
                        retry: RetryState {
                            backoff_secs: 5,
                            next_attempt_at: std::time::Instant::now(),
                        },
                        desired_outbound: false,
                    });
                }
            }

            // Periodic addr flush
            if last_flush.elapsed()
                >= std::time::Duration::from_secs(types::ADDR_FLUSH_INTERVAL_SECS)
            {
                discovery_node.flush_addr_book();
                last_flush = std::time::Instant::now();
            }
        }
    });

    info!("Node running. Press Ctrl+C to stop.");

    // Wait for either Ctrl+C or graceful shutdown flag (set on fatal errors)
    let shutdown_node = node.clone();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received, shutting down.");
        }
        _ = async {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                if shutdown_node.shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
            }
        } => {
            error!("Fatal shutdown flag set, terminating node.");
        }
    }
    // Signal all tasks to stop
    node.shutdown
        .store(true, std::sync::atomic::Ordering::SeqCst);
    // Flush addr book to storage before exit (P1b)
    node.flush_addr_book();
    info!("Shutting down.");
    Ok(())
}

async fn mining_loop(node: Arc<Node>, pubkey: [u8; 32]) {
    let miner = Miner::new(pubkey);

    loop {
        // Check graceful shutdown flag
        if node.shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            error!("Shutdown flag set, exiting mining loop");
            return;
        }

        // MiningReady gate: must be Live AND our tip within 1 block of
        // the best confirmed peer. Prevents mining on stale tips when the
        // node is Live but lagging due to processing latency.
        let sync = node.sync_state.load(std::sync::atomic::Ordering::Relaxed);
        if sync != SyncState::Live as u8 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        let tip = node.tip.read().await.clone();
        let best_work = *node.best_peer_work.lock().unwrap_or_else(|e| e.into_inner());
        // All-zeros means no confirmed peers (bootstrap) — mine freely.
        // Otherwise, only mine when our work matches or exceeds the best peer's.
        if best_work != [0u8; 32] && tip.cumulative_work < best_work {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            continue;
        }

        let height = tip.height + 1;

        // Compute expected difficulty from stored headers (no cached field)
        let diff_target = match expected_difficulty(&node.storage, &tip.block_id, height) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to compute difficulty: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        // Clamp timestamp to satisfy consensus rules:
        //   - Must be strictly greater than MTP (Rule 7)
        //   - Must be at most parent.timestamp + MAX_TIMESTAMP_GAP (Rule 9)
        let ancestor_timestamps = match node
            .storage
            .get_ancestor_timestamps(&tip.block_id, MTP_WINDOW)
        {
            Ok(ts) => ts,
            Err(e) => {
                error!("Failed to read ancestor timestamps: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        let parent_timestamp = match node.storage.get_header(&tip.block_id) {
            Ok(Some(hdr)) => hdr.timestamp,
            Ok(None) => {
                error!("Parent header not found for tip {}", tip.block_id);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            Err(e) => {
                error!("Failed to read parent header: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        let min_timestamp = if ancestor_timestamps.is_empty() {
            0
        } else {
            median_time_past(&ancestor_timestamps) + 1
        };
        let max_timestamp = parent_timestamp.saturating_add(MAX_TIMESTAMP_GAP);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > max_timestamp {
            warn!(
                "Clock ({}) exceeds gap limit (parent {} + {} = {}); \
                 chain may have stalled or clock is skewed — waiting",
                now, parent_timestamp, MAX_TIMESTAMP_GAP, max_timestamp
            );
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            continue;
        }

        let clamped_timestamp = now.max(min_timestamp);

        let utxo_set = node.utxo_set.read().await.clone();
        // Clone candidate list under the lock, then release immediately.
        // Template assembly (trial-apply, revalidation) runs without holding
        // the mempool lock, so tx admission is never blocked by the miner.
        let candidate_txs = {
            let mempool = node.mempool.lock().await;
            let max_tx_space = crate::types::MAX_BLOCK_SIZE.saturating_sub(400);
            let (txs, _fees) = mempool.select_transactions(max_tx_space);
            txs
            // mempool lock released here
        };

        let template_result = miner.build_template_from_txs(
            height,
            tip.block_id,
            diff_target,
            clamped_timestamp,
            &candidate_txs,
            &utxo_set,
        );
        drop(utxo_set);

        let (template, skipped_ids) = match template_result {
            Some(result) => result,
            None => {
                error!(
                    "Cannot build template at height {} (see preceding log for cause)",
                    height
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        // Purge txs that failed validation/application during template
        // assembly. This prevents mempool pinning: stale txs hold
        // spent_outpoints, blocking replacement spends as DoubleSpend.
        if !skipped_ids.is_empty() {
            let mut mempool = node.mempool.lock().await;
            for tx_id in &skipped_ids {
                mempool.remove(tx_id);
            }
            tracing::info!(
                "Purged {} stale txs from mempool during template build",
                skipped_ids.len()
            );
        }

        info!("Mining block at height {} (nonce grinding)...", height);

        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_clone = cancel.clone();

        // Watch for tip changes and cancel stale template
        let cancel_for_watch = cancel.clone();
        let node_for_watch = node.clone();
        let tip_block_id = tip.block_id;
        let tip_watcher = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if cancel_for_watch.load(std::sync::atomic::Ordering::Relaxed) {
                    break; // mining finished naturally
                }
                // Cancel immediately if sync manager entered CatchingUp
                if node_for_watch
                    .mining_cancel
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    info!("Sync state changed to CatchingUp, cancelling mining");
                    cancel_for_watch.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                let current_tip = node_for_watch.tip.read().await;
                if current_tip.block_id != tip_block_id {
                    info!("Tip changed during mining, cancelling stale template");
                    cancel_for_watch.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
        });

        let template_clone = template;
        let miner_clone = miner.clone();
        // No pause flag needed — block processing runs in the sync manager task,
        // not competing with mining for the same thread.
        let no_pause = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = tokio::task::spawn_blocking(move || {
            miner_clone.mine(
                template_clone,
                cancel_clone,
                no_pause,
                min_timestamp,
                max_timestamp,
            )
        })
        .await;

        // Signal watcher to stop (mining done) and await it
        cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = tip_watcher.await;

        match result {
            Ok(Some(block)) => {
                let block_id = block.header.block_id();
                info!("Mined block {} at height {}", block_id, block.header.height);

                let wall_clock = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs());
                match node.process_block(block.clone(), wall_clock).await {
                    Ok(ProcessBlockOutcome::Accepted) => {
                        info!("Block {} accepted", block_id);
                        node.broadcast(&network::protocol::Message::NewBlock(block), None)
                            .await;
                    }
                    Ok(_) => {
                        // Stored as fork, already known, or buffered as future
                        info!("Block {} not accepted as tip", block_id);
                    }
                    Err(e) if e.is_fatal() => {
                        error!(
                            fatal = true,
                            error = %e,
                            "FATAL: consensus state corrupted during mined block processing, initiating graceful shutdown"
                        );
                        node.shutdown
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        return;
                    }
                    Err(e) => {
                        error!("Mined block rejected: {}", e);
                        // Only purge mempool when the rejection is due to
                        // transaction invalidity. Header-only rejections
                        // (bad timestamp, bad difficulty, bad PoW) mean the
                        // transactions themselves are still valid.
                        if !e.is_header_only() {
                            let mut mempool = node.mempool.lock().await;
                            for tx in &block.transactions {
                                if !tx.is_coinbase() {
                                    if let Ok(tx_id) = tx.tx_id() {
                                        mempool.remove(&tx_id);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                info!("Mining cancelled, retrying with new template");
            }
            Err(e) => {
                error!("Mining task panicked: {}", e);
            }
        }
    }
}
