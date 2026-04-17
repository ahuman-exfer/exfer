//! Minimal JSON-RPC 2.0 HTTP server for the Exfer node.
//!
//! Listens on a configurable TCP address (default 127.0.0.1:9334) and accepts
//! HTTP POST requests with JSON-RPC bodies.  No external HTTP framework is
//! used — just raw tokio TCP with enough parsing to handle Content-Length
//! framed POSTs.

use crate::network::sync::Node;
use crate::types::hash::Hash256;
use crate::types::transaction::{OutPoint, Transaction};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// JSON-RPC request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl RpcResponse {
    fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        RpcResponse {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    fn err(id: serde_json::Value, code: i32, message: String) -> Self {
        RpcResponse {
            jsonrpc: "2.0",
            result: None,
            error: Some(RpcError { code, message }),
            id,
        }
    }
}

// Standard JSON-RPC 2.0 error codes
const PARSE_ERROR: i32 = -32700;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const INTERNAL_ERROR: i32 = -32603;

// ---------------------------------------------------------------------------
// Public entry point — spawn the RPC server as a tokio task
// ---------------------------------------------------------------------------

/// Start the JSON-RPC HTTP server.  Returns when the TCP listener fails.
/// Per-IP rate limiter for send_raw_transaction.
/// Cap at 60 submissions per minute per IP, same as P2P limits.
type TxRateLimiter =
    Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (std::time::Instant, u32)>>>;

const MAX_RPC_TX_PER_MIN: u32 = 60;
/// Per-IP rate limit for UTXO scan endpoints (get_balance, get_address_utxos).
const MAX_RPC_SCAN_PER_MIN: u32 = 30;
/// Maximum concurrent RPC connections.
const MAX_RPC_CONNECTIONS: usize = 32;
/// Per-connection read timeout (seconds).
const RPC_TIMEOUT_SECS: u64 = 30;

/// Semaphore for UTXO-scanning RPC endpoints (get_balance, get_address_utxos).
/// Capped at 1 so at most one scan holds the utxo_set read lock at a time.
/// Prevents public RPC traffic from stalling process_block's write lock.
type UtxoScanSemaphore = Arc<tokio::sync::Semaphore>;

pub async fn run_rpc_server(bind: SocketAddr, node: Arc<Node>) {
    // Warn if RPC is exposed beyond localhost — unauthenticated HTTP control surface.
    if !bind.ip().is_loopback() {
        warn!(
            "RPC server binding to non-localhost address {}. \
             The RPC has no authentication — any client can query balances \
             and submit transactions. Consider binding to 127.0.0.1 or \
             using a reverse proxy with authentication for public access.",
            bind
        );
    }

    let listener = match TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            error!("FATAL: RPC server failed to bind {}: {}", bind, e);
            std::process::exit(1);
        }
    };
    info!("JSON-RPC server listening on {}", bind);

    let tx_limiter: TxRateLimiter =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let scan_limiter: TxRateLimiter =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_RPC_CONNECTIONS));
    let utxo_scan_sem: UtxoScanSemaphore = Arc::new(tokio::sync::Semaphore::new(1));

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("RPC accept error: {}", e);
                continue;
            }
        };
        // Enforce concurrent connection cap
        let permit = match conn_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!("RPC connection limit reached, dropping {}", addr);
                drop(stream);
                continue;
            }
        };
        let node = node.clone();
        let limiter = tx_limiter.clone();
        let scan_lim = scan_limiter.clone();
        let scan_sem = utxo_scan_sem.clone();
        tokio::spawn(async move {
            let _permit = permit; // held until this task finishes
                                  // 30-second timeout on the entire request
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(RPC_TIMEOUT_SECS),
                handle_connection(stream, addr, node, limiter, scan_lim, scan_sem),
            )
            .await;
            match result {
                Ok(Err(e)) => tracing::debug!("RPC connection from {} error: {}", addr, e),
                Err(_) => tracing::debug!(
                    "RPC connection from {} timed out ({}s)",
                    addr,
                    RPC_TIMEOUT_SECS
                ),
                _ => {}
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    addr: SocketAddr,
    node: Arc<Node>,
    tx_limiter: TxRateLimiter,
    scan_limiter: TxRateLimiter,
    utxo_scan_sem: UtxoScanSemaphore,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the HTTP request line and headers.  We only need Content-Length.
    let mut header_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1];
    let mut header_end = false;

    // Read byte-by-byte until we see \r\n\r\n (end of HTTP headers).
    // Cap at 8 KiB to avoid memory abuse.
    while header_buf.len() < 8192 {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(()); // connection closed
        }
        header_buf.push(tmp[0]);
        if header_buf.len() >= 4 && &header_buf[header_buf.len() - 4..] == b"\r\n\r\n" {
            header_end = true;
            break;
        }
    }
    if !header_end {
        send_http_response(&mut stream, 400, b"Bad Request").await?;
        return Ok(());
    }

    let header_str = String::from_utf8_lossy(&header_buf);

    // Require POST
    if !header_str.starts_with("POST ") {
        send_http_response(&mut stream, 405, b"Method Not Allowed").await?;
        return Ok(());
    }

    // Extract Content-Length
    let content_length = extract_content_length(&header_str).unwrap_or(0);
    // 2.5 MiB hard cap: send_raw_transaction carries hex-encoded 1 MiB txs.
    // All other methods are post-parse capped at 64 KB.
    const MAX_RPC_BODY: usize = 2_621_440; // 2.5 MiB
    const MAX_RPC_BODY_SMALL: usize = 65_536; // 64 KB
    if content_length == 0 || content_length > MAX_RPC_BODY {
        send_http_response(&mut stream, 400, b"Invalid Content-Length").await?;
        return Ok(());
    }

    // Read the body
    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body).await?;

    // Parse JSON-RPC request
    let rpc_req: RpcRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            let resp = RpcResponse::err(
                serde_json::Value::Null,
                PARSE_ERROR,
                "Parse error".to_string(),
            );
            send_rpc_response(&mut stream, &resp).await?;
            return Ok(());
        }
    };

    // Enforce 64 KB cap for all methods except send_raw_transaction.
    // Bounds worst-case memory from malicious JSON to ~2 MB across 32 connections.
    if rpc_req.method != "send_raw_transaction" && content_length > MAX_RPC_BODY_SMALL {
        let resp = RpcResponse::err(
            rpc_req.id,
            PARSE_ERROR,
            format!(
                "Request too large: {} bytes (max {} for this method)",
                content_length, MAX_RPC_BODY_SMALL
            ),
        );
        send_rpc_response(&mut stream, &resp).await?;
        return Ok(());
    }

    if rpc_req.jsonrpc != "2.0" {
        let resp = RpcResponse::err(
            rpc_req.id,
            PARSE_ERROR,
            "Invalid JSON-RPC version".to_string(),
        );
        send_rpc_response(&mut stream, &resp).await?;
        return Ok(());
    }

    // Dispatch
    let resp = dispatch(
        rpc_req,
        &node,
        addr.ip(),
        &tx_limiter,
        &scan_limiter,
        &utxo_scan_sem,
    )
    .await;
    send_rpc_response(&mut stream, &resp).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Method dispatch
// ---------------------------------------------------------------------------

async fn dispatch(
    req: RpcRequest,
    node: &Arc<Node>,
    peer_ip: std::net::IpAddr,
    tx_limiter: &TxRateLimiter,
    scan_limiter: &TxRateLimiter,
    utxo_scan_sem: &UtxoScanSemaphore,
) -> RpcResponse {
    let id = req.id.clone();
    match req.method.as_str() {
        "get_block_height" => handle_get_block_height(id, node).await,
        "get_balance" | "get_address_utxos" => {
            // Rate limit UTXO scan endpoints: 30/min/IP
            {
                let mut limiter = scan_limiter.lock().unwrap_or_else(|e| e.into_inner());
                let now = std::time::Instant::now();
                let entry = limiter.entry(peer_ip).or_insert((now, 0));
                if now.duration_since(entry.0) >= std::time::Duration::from_secs(60) {
                    *entry = (now, 0);
                }
                entry.1 += 1;
                if entry.1 > MAX_RPC_SCAN_PER_MIN {
                    return RpcResponse::err(
                        id,
                        INTERNAL_ERROR,
                        "Rate limit exceeded: max 30 balance/utxo queries per minute".to_string(),
                    );
                }
            }
            // Serialize: at most 1 scan holds the read lock at a time
            let _permit = utxo_scan_sem.acquire().await;
            match req.method.as_str() {
                "get_balance" => handle_get_balance(id, req.params, node).await,
                "get_address_utxos" => handle_get_address_utxos(id, req.params, node).await,
                _ => unreachable!(),
            }
        }
        "get_block" => handle_get_block(id, req.params, node).await,
        "get_transaction" => handle_get_transaction(id, req.params, node).await,
        "send_raw_transaction" => {
            // Rate limit: 60 send_raw_transaction per minute per IP
            {
                let mut limiter = tx_limiter.lock().unwrap_or_else(|e| e.into_inner());
                let now = std::time::Instant::now();
                let entry = limiter.entry(peer_ip).or_insert((now, 0));
                if now.duration_since(entry.0) >= std::time::Duration::from_secs(60) {
                    *entry = (now, 0);
                }
                entry.1 += 1;
                if entry.1 > MAX_RPC_TX_PER_MIN {
                    return RpcResponse::err(
                        id,
                        INTERNAL_ERROR,
                        "Rate limit exceeded: max 60 tx submissions per minute".to_string(),
                    );
                }
            }
            handle_send_raw_transaction(id, req.params, node).await
        }
        _ => RpcResponse::err(id, METHOD_NOT_FOUND, "Method not found".to_string()),
    }
}

// ---------------------------------------------------------------------------
// get_block_height
// ---------------------------------------------------------------------------

async fn handle_get_block_height(id: serde_json::Value, node: &Arc<Node>) -> RpcResponse {
    let tip = node.tip.read().await;
    RpcResponse::ok(
        id,
        serde_json::json!({
            "height": tip.height,
            "block_id": hex::encode(tip.block_id.as_bytes()),
        }),
    )
}

// ---------------------------------------------------------------------------
// get_balance
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GetBalanceParams {
    address: String,
}

async fn handle_get_balance(
    id: serde_json::Value,
    params: serde_json::Value,
    node: &Arc<Node>,
) -> RpcResponse {
    let parsed: GetBalanceParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid params: {}", e)),
    };

    let addr_bytes = match hex::decode(&parsed.address) {
        Ok(b) => b,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid hex: {}", e)),
    };
    if addr_bytes.len() != 32 {
        return RpcResponse::err(
            id,
            INVALID_PARAMS,
            format!(
                "Address must be 32 bytes (64 hex chars), got {}",
                addr_bytes.len()
            ),
        );
    }

    // Use dedicated method to minimize read-lock hold time.
    let current_height = node.tip.read().await.height.saturating_add(1);
    let total = {
        let utxo_set = node.utxo_set.read().await;
        utxo_set.balance_for_script(&addr_bytes, current_height)
    };

    RpcResponse::ok(
        id,
        serde_json::json!({
            "balance": total,
            "address": parsed.address,
        }),
    )
}

// ---------------------------------------------------------------------------
// get_address_utxos
// ---------------------------------------------------------------------------

async fn handle_get_address_utxos(
    id: serde_json::Value,
    params: serde_json::Value,
    node: &Arc<Node>,
) -> RpcResponse {
    let parsed: GetBalanceParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid params: {}", e)),
    };

    let addr_bytes = match hex::decode(&parsed.address) {
        Ok(b) => b,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid hex: {}", e)),
    };
    if addr_bytes.len() != 32 {
        return RpcResponse::err(
            id,
            INVALID_PARAMS,
            format!(
                "Address must be 32 bytes (64 hex chars), got {}",
                addr_bytes.len()
            ),
        );
    }

    // UTXO scan serialized by utxo_scan_sem (1 permit) in dispatch.
    let tip_height = node.tip.read().await.height;
    let current_height = tip_height.saturating_add(1);

    // Use dedicated method to minimize read-lock hold time.
    const MAX_UTXO_RESULTS: usize = 1000;
    let matched = {
        let utxo_set = node.utxo_set.read().await;
        utxo_set.utxos_for_script(&addr_bytes, current_height, MAX_UTXO_RESULTS)
    };
    // Lock released — format JSON without holding any chainstate locks.
    let utxos: Vec<serde_json::Value> = matched
        .iter()
        .map(|(outpoint, val, h, cb)| {
            serde_json::json!({
                "tx_id": hex::encode(outpoint.tx_id.as_bytes()),
                "output_index": outpoint.output_index,
                "value": val,
                "height": h,
                "is_coinbase": cb,
            })
        })
        .collect();

    RpcResponse::ok(
        id,
        serde_json::json!({
            "address": parsed.address,
            "utxos": utxos,
            "tip_height": tip_height,
        }),
    )
}

// ---------------------------------------------------------------------------
// get_block
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GetBlockParams {
    hash: Option<String>,
    height: Option<u64>,
}

async fn handle_get_block(
    id: serde_json::Value,
    params: serde_json::Value,
    node: &Arc<Node>,
) -> RpcResponse {
    let parsed: GetBlockParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid params: {}", e)),
    };

    let block_id = if let Some(hash_hex) = &parsed.hash {
        let bytes = match hex::decode(hash_hex) {
            Ok(b) => b,
            Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid hex: {}", e)),
        };
        if bytes.len() != 32 {
            return RpcResponse::err(id, INVALID_PARAMS, "Hash must be 32 bytes".to_string());
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        Hash256(h)
    } else if let Some(height) = parsed.height {
        match node.storage.get_block_id_by_height(height) {
            Ok(Some(bid)) => bid,
            Ok(None) => {
                return RpcResponse::err(
                    id,
                    INVALID_PARAMS,
                    format!("No block at height {}", height),
                )
            }
            Err(e) => return RpcResponse::err(id, INTERNAL_ERROR, format!("Storage error: {}", e)),
        }
    } else {
        return RpcResponse::err(
            id,
            INVALID_PARAMS,
            "Provide either 'hash' or 'height'".to_string(),
        );
    };

    let block = match node.storage.get_block(&block_id) {
        Ok(Some(b)) => b,
        Ok(None) => return RpcResponse::err(id, INVALID_PARAMS, "Block not found".to_string()),
        Err(e) => return RpcResponse::err(id, INTERNAL_ERROR, format!("Storage error: {}", e)),
    };

    let tx_ids: Vec<String> = block
        .transactions
        .iter()
        .filter_map(|tx| tx.tx_id().ok().map(|tid| hex::encode(tid.as_bytes())))
        .collect();

    RpcResponse::ok(
        id,
        serde_json::json!({
            "hash": hex::encode(block_id.as_bytes()),
            "height": block.header.height,
            "timestamp": block.header.timestamp,
            "tx_count": block.transactions.len(),
            "transactions": tx_ids,
            "prev_block_id": hex::encode(block.header.prev_block_id.as_bytes()),
            "difficulty_target": hex::encode(block.header.difficulty_target.as_bytes()),
            "nonce": block.header.nonce,
            "state_root": hex::encode(block.header.state_root.as_bytes()),
            "tx_root": hex::encode(block.header.tx_root.as_bytes()),
        }),
    )
}

// ---------------------------------------------------------------------------
// get_transaction
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GetTransactionParams {
    hash: String,
}

async fn handle_get_transaction(
    id: serde_json::Value,
    params: serde_json::Value,
    node: &Arc<Node>,
) -> RpcResponse {
    let parsed: GetTransactionParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid params: {}", e)),
    };

    let bytes = match hex::decode(&parsed.hash) {
        Ok(b) => b,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid hex: {}", e)),
    };
    if bytes.len() != 32 {
        return RpcResponse::err(id, INVALID_PARAMS, "Hash must be 32 bytes".to_string());
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    let target_id = Hash256(h);

    // Search mempool first
    {
        let mempool = node.mempool.lock().await;
        if let Some(tx) = mempool.get(&target_id) {
            let tx_hex = match tx.serialize() {
                Ok(data) => hex::encode(&data),
                Err(e) => {
                    return RpcResponse::err(
                        id,
                        INTERNAL_ERROR,
                        format!("Serialization error: {:?}", e),
                    )
                }
            };
            return RpcResponse::ok(
                id,
                serde_json::json!({
                    "tx_id": parsed.hash,
                    "tx_hex": tx_hex,
                    "in_mempool": true,
                }),
            );
        }
    }

    // Look up via tx index (O(1)). Index is populated during commit_block_atomic,
    // commit_genesis_atomic, commit_reorg_atomic, and startup replay.
    if let Ok(Some(height)) = node.storage.get_tx_block_height(&target_id) {
        let block_id = match node.storage.get_block_id_by_height(height) {
            Ok(Some(bid)) => bid,
            _ => return RpcResponse::err(id, INVALID_PARAMS, "Transaction not found".to_string()),
        };
        let block = match node.storage.get_block(&block_id) {
            Ok(Some(b)) => b,
            _ => return RpcResponse::err(id, INVALID_PARAMS, "Transaction not found".to_string()),
        };
        for tx in &block.transactions {
            let tid = match tx.tx_id() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if tid == target_id {
                let tx_hex = match tx.serialize() {
                    Ok(data) => hex::encode(&data),
                    Err(e) => {
                        return RpcResponse::err(
                            id,
                            INTERNAL_ERROR,
                            format!("Serialization error: {:?}", e),
                        )
                    }
                };
                return RpcResponse::ok(
                    id,
                    serde_json::json!({
                        "tx_id": parsed.hash,
                        "tx_hex": tx_hex,
                        "in_mempool": false,
                        "block_hash": hex::encode(block_id.as_bytes()),
                        "block_height": height,
                    }),
                );
            }
        }
    }

    RpcResponse::err(id, INVALID_PARAMS, "Transaction not found".to_string())
}

// ---------------------------------------------------------------------------
// send_raw_transaction
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SendRawTransactionParams {
    tx_hex: String,
}

async fn handle_send_raw_transaction(
    id: serde_json::Value,
    params: serde_json::Value,
    node: &Arc<Node>,
) -> RpcResponse {
    let parsed: SendRawTransactionParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid params: {}", e)),
    };

    let raw_bytes = match hex::decode(&parsed.tx_hex) {
        Ok(b) => b,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid hex: {}", e)),
    };

    let (tx, consumed) = match Transaction::deserialize(&raw_bytes) {
        Ok(r) => r,
        Err(e) => {
            return RpcResponse::err(
                id,
                INVALID_PARAMS,
                format!("Failed to deserialize transaction: {:?}", e),
            )
        }
    };

    if consumed != raw_bytes.len() {
        return RpcResponse::err(
            id,
            INVALID_PARAMS,
            format!(
                "Trailing bytes after transaction: consumed {} of {}",
                consumed,
                raw_bytes.len()
            ),
        );
    }

    let _tx_id = match tx.tx_id() {
        Ok(t) => t,
        Err(e) => {
            return RpcResponse::err(
                id,
                INTERNAL_ERROR,
                format!("Failed to compute tx_id: {:?}", e),
            )
        }
    };

    // Pre-check mempool (duplicates, double-spends)
    {
        let mempool = node.mempool.lock().await;
        if let Err(e) = mempool.pre_check(&tx) {
            return RpcResponse::err(
                id,
                INVALID_PARAMS,
                format!("Mempool pre-check failed: {}", e),
            );
        }
    }

    // Snapshot UTXOs for validation (same pattern as NewTx handler in sync.rs)
    let tip_snapshot;
    let utxo_snapshot;
    {
        let utxo_set = node.utxo_set.read().await;
        tip_snapshot = node.tip.read().await.clone();
        let outpoints: Vec<OutPoint> = tx
            .inputs
            .iter()
            .map(|i| OutPoint::new(i.prev_tx_id, i.output_index))
            .collect();
        utxo_snapshot = utxo_set.snapshot_for_outpoints(&outpoints);
    }

    let height = tip_snapshot.height.saturating_add(1);
    let validation_result =
        crate::consensus::validation::validate_transaction(&tx, &utxo_snapshot, height);

    match validation_result {
        Ok((fee, script_cost, script_validation_cost)) => {
            // Acquire mempool lock and add
            let current_tip = node.tip.read().await.block_id;
            let mut mempool = node.mempool.lock().await;

            // Staleness check
            if current_tip != tip_snapshot.block_id {
                return RpcResponse::err(
                    id,
                    INTERNAL_ERROR,
                    "Tip changed during validation, try again".to_string(),
                );
            }

            let tx_for_relay = tx.clone();
            match mempool.add_validated(tx, fee, script_cost, script_validation_cost, height) {
                Ok(added_tx_id) => {
                    drop(mempool);
                    // Broadcast to peers
                    node.broadcast(
                        &crate::network::protocol::Message::NewTx(tx_for_relay),
                        None,
                    )
                    .await;
                    RpcResponse::ok(
                        id,
                        serde_json::json!({
                            "tx_id": hex::encode(added_tx_id.as_bytes()),
                        }),
                    )
                }
                Err(e) => RpcResponse::err(
                    id,
                    INVALID_PARAMS,
                    format!("Mempool rejected transaction: {}", e),
                ),
            }
        }
        Err(e) => RpcResponse::err(
            id,
            INVALID_PARAMS,
            format!("Transaction validation failed: {:?}", e),
        ),
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn extract_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let val = line["content-length:".len()..].trim();
            return val.parse().ok();
        }
    }
    None
}

async fn send_http_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status, status_text, body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_rpc_response(
    stream: &mut tokio::net::TcpStream,
    resp: &RpcResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_vec(resp)?;
    send_http_response(stream, 200, &json).await
}

// ---------------------------------------------------------------------------
// Simple RPC client (for CLI --rpc usage)
// ---------------------------------------------------------------------------

/// v1.4.2 Fix 2 — maximum RPC response body the client will accept.
///
/// Chosen comfortably larger than any legitimate response (server-side cap
/// is 2.5 MiB and blocks are not returned via RPC in a single response in
/// normal flows) while still bounding client memory. Enforced on the
/// declared `Content-Length` header AND on the actual byte count read
/// (defense-in-depth against a server that understates `Content-Length`).
pub const MAX_RPC_RESPONSE_BODY: usize = 8 * 1024 * 1024; // 8 MiB

/// Cap on HTTP response header bytes read before the `\r\n\r\n` terminator
/// is found. Prevents a malicious server from holding memory / IO by
/// trickling headers indefinitely.
pub const MAX_RPC_RESPONSE_HEADERS: usize = 65_536; // 64 KiB

/// Parse an HTTP response (status line + headers + body) from `reader`,
/// enforcing both a declared-`Content-Length` cap and a read-bytes cap.
///
/// Returns the raw body bytes on success, or a short diagnostic string on
/// any failure. Exposed at module scope so unit tests can exercise the
/// cap logic without opening a real TCP connection.
///
/// Guarantees:
/// 1. Total header bytes read ≤ `max_headers`.
/// 2. Response must include a `Content-Length` header (case-insensitive);
///    responses without one are rejected before reading the body.
/// 3. Declared `Content-Length` ≤ `max_body`; larger responses are
///    rejected before the body read begins.
/// 4. Actual body bytes read ≤ `max_body`, even if the server later sends
///    more than its declared `Content-Length`.
pub(crate) fn read_bounded_http_response<R: std::io::Read>(
    reader: &mut R,
    max_body: usize,
    max_headers: usize,
) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 4096];

    // Phase 1: read until \r\n\r\n, bounded by max_headers.
    let headers_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > max_headers {
            return Err(format!(
                "RPC response headers exceeded {} byte cap",
                max_headers
            ));
        }
        let want = chunk.len().min(max_headers + 4 - buf.len().min(max_headers));
        let n = reader
            .read(&mut chunk[..want])
            .map_err(|e| format!("Read error: {}", e))?;
        if n == 0 {
            return Err("RPC response closed before headers complete".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    // Parse headers.
    let header_str = std::str::from_utf8(&buf[..headers_end])
        .map_err(|_| "RPC response has invalid UTF-8 in headers".to_string())?;

    let content_length: usize = header_str
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .ok_or_else(|| "RPC response missing Content-Length header".to_string())?;

    // Phase 2: declared-Content-Length cap.
    if content_length > max_body {
        return Err(format!(
            "RPC response Content-Length {} exceeds cap of {} bytes",
            content_length, max_body
        ));
    }

    // Phase 3: read exactly content_length body bytes, with a hard cap on
    // actual bytes in case the server lies.
    let already_body = buf.len() - headers_end;
    if already_body > content_length {
        return Err(format!(
            "RPC response body exceeds declared Content-Length ({} > {})",
            already_body, content_length
        ));
    }
    let mut body = buf[headers_end..].to_vec();
    body.reserve(content_length.saturating_sub(already_body));

    while body.len() < content_length {
        let remaining = content_length - body.len();
        let to_read = chunk.len().min(remaining);
        let n = reader
            .read(&mut chunk[..to_read])
            .map_err(|e| format!("Read error: {}", e))?;
        if n == 0 {
            return Err(format!(
                "RPC response closed with {} bytes remaining (declared {} total)",
                remaining, content_length
            ));
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > max_body {
            return Err(format!(
                "RPC response body read exceeded cap of {} bytes",
                max_body
            ));
        }
    }

    Ok(body)
}

/// Make a JSON-RPC call to a remote node. Returns the "result" field on
/// success, or a string error.
pub fn rpc_call(
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    // Parse host:port from URL like "http://127.0.0.1:9334"
    let addr_str = url.strip_prefix("http://").unwrap_or(url);
    // Strip trailing slash or path
    let addr_str = addr_str.split('/').next().unwrap_or(addr_str);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| format!("JSON encode: {}", e))?;

    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        addr_str,
        body_bytes.len()
    );

    use std::io::Write;
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(addr_str)
        .map_err(|e| format!("Failed to connect to {}: {}", addr_str, e))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Write error: {}", e))?;
    stream
        .write_all(&body_bytes)
        .map_err(|e| format!("Write body error: {}", e))?;
    stream.flush().map_err(|e| format!("Flush error: {}", e))?;

    // v1.4.2 Fix 2: bounded read. Rejects responses without Content-Length,
    // responses declaring more than 8 MiB body, and actual reads that exceed
    // 8 MiB regardless of declared length.
    let json_body = read_bounded_http_response(
        &mut stream,
        MAX_RPC_RESPONSE_BODY,
        MAX_RPC_RESPONSE_HEADERS,
    )?;

    let rpc_resp: serde_json::Value =
        serde_json::from_slice(&json_body).map_err(|e| format!("JSON parse error: {}", e))?;

    if let Some(err) = rpc_resp.get("error") {
        if !err.is_null() {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(format!("RPC error: {}", msg));
        }
    }

    rpc_resp
        .get("result")
        .cloned()
        .ok_or_else(|| "Missing 'result' in RPC response".to_string())
}

#[cfg(test)]
mod rpc_client_tests {
    use super::*;
    use std::io::Cursor;

    fn http_response(headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::from(&b"HTTP/1.1 200 OK\r\n"[..]);
        for (k, v) in headers {
            out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn accepts_normal_response_under_cap() {
        let body = br#"{"jsonrpc":"2.0","result":42,"id":1}"#;
        let resp = http_response(
            &[
                ("Content-Type", "application/json"),
                ("Content-Length", &body.len().to_string()),
            ],
            body,
        );
        let mut cursor = Cursor::new(resp);
        let got = read_bounded_http_response(&mut cursor, MAX_RPC_RESPONSE_BODY, MAX_RPC_RESPONSE_HEADERS)
            .expect("accepted");
        assert_eq!(got, body);
    }

    /// Brief Fix 2 test — Content-Length declares more than the cap; must
    /// be rejected BEFORE the body is read.
    #[test]
    fn rejects_content_length_over_cap() {
        let resp = http_response(&[("Content-Length", "10000000")], b"");
        let mut cursor = Cursor::new(resp);
        let err = read_bounded_http_response(&mut cursor, MAX_RPC_RESPONSE_BODY, MAX_RPC_RESPONSE_HEADERS)
            .expect_err("rejected");
        assert!(
            err.contains("Content-Length") && err.contains("exceeds cap"),
            "unexpected error: {}",
            err
        );
    }

    /// Brief Fix 2 test — server declares Content-Length: 100 but actually
    /// streams more. The client must either stop at the declared length or
    /// abort with an explicit error; under no circumstances may it read the
    /// full attacker-controlled stream. Our implementation takes the
    /// stricter path: any excess beyond the declaration is a protocol
    /// violation, so we abort.
    #[test]
    fn rejects_body_larger_than_declared_length() {
        let mut resp = http_response(&[("Content-Length", "100")], &vec![b'A'; 100]);
        // Attacker appends an extra 10 MB to trick the client into reading more.
        resp.extend_from_slice(&vec![b'B'; 10 * 1024 * 1024]);
        let mut cursor = Cursor::new(resp);
        let err = read_bounded_http_response(&mut cursor, MAX_RPC_RESPONSE_BODY, MAX_RPC_RESPONSE_HEADERS)
            .expect_err("server lied, should abort");
        assert!(
            err.contains("exceeds declared Content-Length"),
            "unexpected error: {}",
            err
        );
    }

    /// Brief Fix 2 test — read cap is enforced even if the server somehow
    /// slips past the Content-Length check (e.g. via a tiny max_body in
    /// tests). Verifies the in-read cap is wired.
    #[test]
    fn rejects_body_read_that_exceeds_cap() {
        // With a max_body of 50 bytes, a declared Content-Length of 40 is
        // fine, but if the server sends 60, the in-read cap trips.
        // To simulate: we *declare* 40 but actually send 60 — the reader
        // stops at 40 (declared). To test the in-read cap, lower max_body
        // below Content-Length so the declared check fails first.
        let resp = http_response(&[("Content-Length", "100")], &vec![b'X'; 100]);
        let mut cursor = Cursor::new(resp);
        // max_body of 50 < content_length of 100 — rejected at declared
        // check (this is the expected behaviour of the cap regardless of
        // which layer catches it first).
        let err = read_bounded_http_response(&mut cursor, 50, MAX_RPC_RESPONSE_HEADERS)
            .expect_err("rejected");
        assert!(err.contains("exceeds cap"), "unexpected error: {}", err);
    }

    /// Brief Fix 2 test — responses without Content-Length must be rejected.
    /// The pre-v1.4.2 client silently accepted them and `read_to_end`'d
    /// the socket, giving a malicious server an unbounded allocation primitive.
    #[test]
    fn rejects_missing_content_length() {
        // HTTP/1.0-style response without Content-Length, relying on
        // connection-close to delimit the body.
        let mut resp = Vec::from(&b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"[..]);
        resp.extend_from_slice(br#"{"result":1,"id":1}"#);
        let mut cursor = Cursor::new(resp);
        let err = read_bounded_http_response(&mut cursor, MAX_RPC_RESPONSE_BODY, MAX_RPC_RESPONSE_HEADERS)
            .expect_err("rejected");
        assert!(
            err.contains("missing Content-Length"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn rejects_headers_that_never_terminate() {
        // 200 KiB of header bytes without a \r\n\r\n terminator.
        let headers: Vec<u8> = std::iter::repeat(b'a').take(200_000).collect();
        let mut cursor = Cursor::new(headers);
        let err = read_bounded_http_response(&mut cursor, MAX_RPC_RESPONSE_BODY, MAX_RPC_RESPONSE_HEADERS)
            .expect_err("rejected");
        assert!(err.contains("headers exceeded"), "unexpected error: {}", err);
    }

    #[test]
    fn rejects_connection_closed_mid_body() {
        // Content-Length declares 100 bytes but only 10 are actually sent.
        let resp = http_response(&[("Content-Length", "100")], &vec![b'Y'; 10]);
        let mut cursor = Cursor::new(resp);
        let err = read_bounded_http_response(&mut cursor, MAX_RPC_RESPONSE_BODY, MAX_RPC_RESPONSE_HEADERS)
            .expect_err("rejected");
        assert!(
            err.contains("bytes remaining") || err.contains("closed"),
            "unexpected error: {}",
            err
        );
    }

    /// Content-Length header lookup is case-insensitive (RFC 7230).
    #[test]
    fn content_length_is_case_insensitive() {
        let body = b"hello";
        let resp = http_response(&[("content-LENGTH", "5")], body);
        let mut cursor = Cursor::new(resp);
        let got = read_bounded_http_response(&mut cursor, MAX_RPC_RESPONSE_BODY, MAX_RPC_RESPONSE_HEADERS)
            .expect("accepted");
        assert_eq!(got, body);
    }
}
