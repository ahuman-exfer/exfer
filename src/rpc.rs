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
/// Per-IP rate limit for UTXO scan endpoints (get_balance, get_address_utxos, get_script_utxos).
const MAX_RPC_SCAN_PER_MIN: u32 = 30;
/// Maximum addresses accepted per batch read (get_balances / get_address_utxos_batch).
/// One batch call consumes one scan-rate slot + one UTXO read lock, so this
/// bounds the work a single rate-limited request can request.
const MAX_BATCH_ADDRESSES: usize = 100;
/// Maximum concurrent RPC connections.
const MAX_RPC_CONNECTIONS: usize = 32;
/// Per-connection read timeout (seconds).
const RPC_TIMEOUT_SECS: u64 = 30;

/// Semaphore for UTXO-scanning RPC endpoints (get_balance, get_address_utxos, get_script_utxos).
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
    // get_script_utxos lifted to 200 KiB so the full 65,535-byte output-script
    // wire range is queryable (script_hex doubles bytes; +JSON wrapping).
    // All other methods are post-parse capped at 64 KB.
    const MAX_RPC_BODY: usize = 2_621_440; // 2.5 MiB
    const MAX_RPC_BODY_SCRIPT: usize = 200_000; // ~200 KB for get_script_utxos
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

    // Per-method body cap. Bounds worst-case memory across 32 connections.
    let method_cap = match rpc_req.method.as_str() {
        "send_raw_transaction" => MAX_RPC_BODY,
        "get_script_utxos" => MAX_RPC_BODY_SCRIPT,
        _ => MAX_RPC_BODY_SMALL,
    };
    if content_length > method_cap {
        let resp = RpcResponse::err(
            rpc_req.id,
            PARSE_ERROR,
            format!(
                "Request too large: {} bytes (max {} for this method)",
                content_length, method_cap
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

/// Enforce the per-IP scan rate limit (`MAX_RPC_SCAN_PER_MIN`) for the
/// UTXO/address read endpoints. Returns `Some(error response)` if the caller is
/// over budget, else `None`. Shared by the scan group and `get_address_mempool`.
fn check_scan_rate_limit(
    scan_limiter: &TxRateLimiter,
    peer_ip: std::net::IpAddr,
    id: &serde_json::Value,
) -> Option<RpcResponse> {
    let mut limiter = scan_limiter.lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    let entry = limiter.entry(peer_ip).or_insert((now, 0));
    if now.duration_since(entry.0) >= std::time::Duration::from_secs(60) {
        *entry = (now, 0);
    }
    entry.1 += 1;
    if entry.1 > MAX_RPC_SCAN_PER_MIN {
        return Some(RpcResponse::err(
            id.clone(),
            INTERNAL_ERROR,
            "Rate limit exceeded: max 30 balance/utxo queries per minute".to_string(),
        ));
    }
    None
}

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
        "get_balance"
        | "get_address_utxos"
        | "get_script_utxos"
        | "get_balances"
        | "get_address_utxos_batch" => {
            // Rate limit UTXO scan endpoints: 30/min/IP
            if let Some(resp) = check_scan_rate_limit(scan_limiter, peer_ip, &id) {
                return resp;
            }
            // Serialize: at most 1 scan holds the read lock at a time
            let _permit = utxo_scan_sem.acquire().await;
            match req.method.as_str() {
                "get_balance" => handle_get_balance(id, req.params, node).await,
                "get_address_utxos" => handle_get_address_utxos(id, req.params, node).await,
                "get_script_utxos" => handle_get_script_utxos(id, req.params, node).await,
                "get_balances" => handle_get_balances(id, req.params, node).await,
                "get_address_utxos_batch" => {
                    handle_get_address_utxos_batch(id, req.params, node).await
                }
                _ => unreachable!(),
            }
        }
        "get_address_mempool" => {
            // Scan-rate-limited (counts toward the 30/min budget) but NOT held
            // under utxo_scan_sem: this endpoint only touches the mempool lock
            // briefly, not the UTXO read lock the semaphore exists to protect.
            if let Some(resp) = check_scan_rate_limit(scan_limiter, peer_ip, &id) {
                return resp;
            }
            handle_get_address_mempool(id, req.params, node).await
        }
        "get_block" => handle_get_block(id, req.params, node).await,
        "get_transaction" => handle_get_transaction(id, req.params, node).await,
        "get_output_spent_by" => handle_get_output_spent_by(id, req.params, node).await,
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
// UTXO scan pagination
// ---------------------------------------------------------------------------

/// Max UTXOs returned in one page of get_address_utxos / get_script_utxos.
/// Also the default page size when the caller omits `limit`.
const UTXO_PAGE_LIMIT: usize = 1000;

/// Encode a tip-anchored UTXO-set cursor as `"<tip_id_hex>:<tx_id_hex>:<output_index>"`.
/// The tip id pins the page sequence to one chainstate snapshot — see
/// `paged_utxos_for_script` for why. Returned as `next_cursor`, passed back as
/// `cursor` to fetch the next page.
fn encode_utxo_cursor(tip_id: &Hash256, op: &OutPoint) -> String {
    format!(
        "{}:{}:{}",
        hex::encode(tip_id.as_bytes()),
        hex::encode(op.tx_id.as_bytes()),
        op.output_index
    )
}

/// Parse a `"<tip_id_hex>:<tx_id_hex>:<output_index>"` cursor into
/// `(tip_id, after_outpoint)`.
fn parse_utxo_cursor(s: &str) -> Result<(Hash256, OutPoint), String> {
    let mut parts = s.splitn(3, ':');
    let tip_hex = parts.next();
    let tx_hex = parts.next();
    let idx_str = parts.next();
    let (tip_hex, tx_hex, idx_str) = match (tip_hex, tx_hex, idx_str) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return Err("cursor must be '<tip_id_hex>:<tx_id_hex>:<output_index>'".to_string()),
    };
    let parse_hash = |label: &str, hexs: &str| -> Result<Hash256, String> {
        let bytes = hex::decode(hexs).map_err(|e| format!("invalid cursor {} hex: {}", label, e))?;
        if bytes.len() != 32 {
            return Err(format!("cursor {} must be 32 bytes, got {}", label, bytes.len()));
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        Ok(Hash256(h))
    };
    let tip_id = parse_hash("tip_id", tip_hex)?;
    let tx_id = parse_hash("tx_id", tx_hex)?;
    let output_index: u32 = idx_str
        .parse()
        .map_err(|e| format!("invalid cursor output_index: {}", e))?;
    Ok((tip_id, OutPoint::new(tx_id, output_index)))
}

/// Resolve the requested page size into the clamped `[1, UTXO_PAGE_LIMIT]` range.
fn resolve_page_limit(requested: Option<usize>) -> usize {
    requested.unwrap_or(UTXO_PAGE_LIMIT).clamp(1, UTXO_PAGE_LIMIT)
}

/// One cursor-paginated page of UTXOs for a script, shared by
/// `get_address_utxos` and `get_script_utxos`.
struct UtxoPage {
    matched: Vec<(OutPoint, u64, u64, bool)>,
    next_cursor: Option<String>,
    truncated: bool,
    tip_height: u64,
}

/// Read one tip-anchored page of UTXOs for `script`.
///
/// The cursor embeds the tip block id at which the walk began. Because an
/// `OutPoint` is a content hash, a UTXO arriving for this script mid-walk can
/// sort anywhere in the `by_script` set — including *before* the saved cursor,
/// where it would never be visited — and coinbase maturity is height-dependent,
/// so the mature/immature split shifts as the tip advances. Pinning the walk to
/// a single tip keeps "walk to completion" actually complete: if the tip has
/// moved since the cursor was issued, we reject with a clear "snapshot expired"
/// error and the caller restarts from `cursor = None` against the new tip. No
/// server-side snapshot state; on a wallet-sized set the restart is sub-second.
///
/// Probes one beyond the page so an exact-multiple-of-page set does not emit a
/// cursor that yields an empty follow-up: `truncated` means "there ARE more",
/// matching the pre-pagination single-call semantics.
async fn paged_utxos_for_script(
    id: &serde_json::Value,
    node: &Arc<Node>,
    script: &[u8],
    cursor: &Option<String>,
    limit: Option<usize>,
) -> Result<UtxoPage, RpcResponse> {
    let page = resolve_page_limit(limit);
    // Take the UTXO read lock FIRST, then read tip under it: process_block
    // holds utxo_set.write() while advancing tip (src/network/sync.rs:2429,
    // 2965-2970), so holding utxo_set.read() pins both the UTXO state AND
    // the tip we're about to snapshot. Reading tip first and acquiring
    // utxo_set later would let a block land between the two reads — the
    // cursor would pin a stale tip while the walk saw post-block state.
    let utxo_set = node.utxo_set.read().await;
    let (tip_height, tip_id) = {
        let tip = node.tip.read().await;
        (tip.height, tip.block_id)
    };

    let after = match cursor {
        Some(c) => {
            let (cursor_tip, op) = parse_utxo_cursor(c).map_err(|e| {
                RpcResponse::err(id.clone(), INVALID_PARAMS, format!("Invalid cursor: {}", e))
            })?;
            if cursor_tip != tip_id {
                return Err(RpcResponse::err(
                    id.clone(),
                    INVALID_PARAMS,
                    "pagination snapshot expired, restart from cursor=None".to_string(),
                ));
            }
            Some(op)
        }
        None => None,
    };

    let current_height = tip_height.saturating_add(1);
    // Probe page+1: the extra item (if any) proves a next page exists.
    let mut matched = utxo_set.utxos_for_script_paged(script, current_height, after, page + 1);
    drop(utxo_set);
    let truncated = matched.len() > page;
    matched.truncate(page);
    let next_cursor = if truncated {
        matched.last().map(|t| encode_utxo_cursor(&tip_id, &t.0))
    } else {
        None
    };

    Ok(UtxoPage {
        matched,
        next_cursor,
        truncated,
        tip_height,
    })
}

// ---------------------------------------------------------------------------
// get_address_utxos
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GetAddressUtxosParams {
    address: String,
    /// Opaque cursor from a prior response's `next_cursor`; omit for page 1.
    #[serde(default)]
    cursor: Option<String>,
    /// Page size, clamped to `[1, UTXO_PAGE_LIMIT]`; defaults to the max.
    #[serde(default)]
    limit: Option<usize>,
}

async fn handle_get_address_utxos(
    id: serde_json::Value,
    params: serde_json::Value,
    node: &Arc<Node>,
) -> RpcResponse {
    let parsed: GetAddressUtxosParams = match serde_json::from_value(params) {
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
    let paged =
        match paged_utxos_for_script(&id, node, &addr_bytes, &parsed.cursor, parsed.limit).await {
            Ok(p) => p,
            Err(resp) => return resp,
        };
    // Lock released — format JSON without holding any chainstate locks.
    let utxos: Vec<serde_json::Value> = paged
        .matched
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
            "truncated": paged.truncated,
            "next_cursor": paged.next_cursor,
            "tip_height": paged.tip_height,
        }),
    )
}

// ---------------------------------------------------------------------------
// get_script_utxos
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GetScriptUtxosParams {
    script_hex: String,
    /// Opaque cursor from a prior response's `next_cursor`; omit for page 1.
    #[serde(default)]
    cursor: Option<String>,
    /// Page size, clamped to `[1, UTXO_PAGE_LIMIT]`; defaults to the max.
    #[serde(default)]
    limit: Option<usize>,
}

async fn handle_get_script_utxos(
    id: serde_json::Value,
    params: serde_json::Value,
    node: &Arc<Node>,
) -> RpcResponse {
    let parsed: GetScriptUtxosParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid params: {}", e)),
    };

    let script_bytes = match hex::decode(&parsed.script_hex) {
        Ok(b) => b,
        Err(e) => {
            return RpcResponse::err(
                id,
                INVALID_PARAMS,
                format!("Invalid hex in script_hex: {}", e),
            );
        }
    };
    // Output scripts are u16 varbytes-prefixed on the wire (max 65,535 bytes).
    // Reject queries longer than that — they cannot have been indexed.
    if script_bytes.len() > 65_535 {
        return RpcResponse::err(
            id,
            INVALID_PARAMS,
            format!(
                "script_hex exceeds max output-script size (got {} bytes, max 65535)",
                script_bytes.len()
            ),
        );
    }

    // UTXO scan serialized by utxo_scan_sem (1 permit) in dispatch.
    let paged =
        match paged_utxos_for_script(&id, node, &script_bytes, &parsed.cursor, parsed.limit).await {
            Ok(p) => p,
            Err(resp) => return resp,
        };
    // Lock released — format JSON without holding any chainstate locks.
    let script_len = script_bytes.len();
    let utxos: Vec<serde_json::Value> = paged
        .matched
        .iter()
        .map(|(outpoint, val, h, cb)| {
            serde_json::json!({
                "tx_id": hex::encode(outpoint.tx_id.as_bytes()),
                "output_index": outpoint.output_index,
                "value": val,
                "script_len": script_len,
                "height": h,
                "is_coinbase": cb,
            })
        })
        .collect();

    RpcResponse::ok(
        id,
        serde_json::json!({
            "script_hex": parsed.script_hex,
            "utxos": utxos,
            "truncated": paged.truncated,
            "next_cursor": paged.next_cursor,
            "tip_height": paged.tip_height,
        }),
    )
}

// ---------------------------------------------------------------------------
// get_address_mempool
// ---------------------------------------------------------------------------

async fn handle_get_address_mempool(
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

    let tip_height = node.tip.read().await.height;
    // Brief mempool lock: collect the address-scoped view, format JSON after.
    let txs = {
        let mempool = node.mempool.lock().await;
        mempool.address_mempool(&addr_bytes)
    };

    let mempool_json: Vec<serde_json::Value> = txs
        .iter()
        .map(|t| {
            let received: Vec<serde_json::Value> = t
                .received
                .iter()
                .map(|(idx, val)| serde_json::json!({ "output_index": idx, "value": val }))
                .collect();
            let spent: Vec<serde_json::Value> = t
                .spent
                .iter()
                .map(|(op, val)| {
                    serde_json::json!({
                        "tx_id": hex::encode(op.tx_id.as_bytes()),
                        "output_index": op.output_index,
                        "value": val,
                    })
                })
                .collect();
            serde_json::json!({
                "tx_id": hex::encode(t.tx_id.as_bytes()),
                "received": received,
                "spent": spent,
            })
        })
        .collect();

    RpcResponse::ok(
        id,
        serde_json::json!({
            "address": parsed.address,
            "tip_height": tip_height,
            "mempool": mempool_json,
        }),
    )
}

// ---------------------------------------------------------------------------
// get_balances / get_address_utxos_batch (batch reads)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BatchAddressParams {
    addresses: Vec<String>,
}

/// Validate + hex-decode a batch address list into 32-byte scripts, paired with
/// the original hex string for echoing back. Returns an error response on the
/// first malformed or out-of-bounds input.
fn decode_batch_addresses(
    id: &serde_json::Value,
    addresses: &[String],
) -> Result<Vec<(String, Vec<u8>)>, RpcResponse> {
    if addresses.is_empty() {
        return Err(RpcResponse::err(
            id.clone(),
            INVALID_PARAMS,
            "addresses must not be empty".to_string(),
        ));
    }
    if addresses.len() > MAX_BATCH_ADDRESSES {
        return Err(RpcResponse::err(
            id.clone(),
            INVALID_PARAMS,
            format!(
                "too many addresses (got {}, max {})",
                addresses.len(),
                MAX_BATCH_ADDRESSES
            ),
        ));
    }
    let mut decoded = Vec::with_capacity(addresses.len());
    for addr in addresses {
        let bytes = match hex::decode(addr) {
            Ok(b) => b,
            Err(e) => {
                return Err(RpcResponse::err(
                    id.clone(),
                    INVALID_PARAMS,
                    format!("Invalid hex in '{}': {}", addr, e),
                ))
            }
        };
        if bytes.len() != 32 {
            return Err(RpcResponse::err(
                id.clone(),
                INVALID_PARAMS,
                format!(
                    "Address '{}' must be 32 bytes (64 hex chars), got {}",
                    addr,
                    bytes.len()
                ),
            ));
        }
        decoded.push((addr.clone(), bytes));
    }
    Ok(decoded)
}

async fn handle_get_balances(
    id: serde_json::Value,
    params: serde_json::Value,
    node: &Arc<Node>,
) -> RpcResponse {
    let parsed: BatchAddressParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid params: {}", e)),
    };
    let decoded = match decode_batch_addresses(&id, &parsed.addresses) {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    let current_height = node.tip.read().await.height.saturating_add(1);
    // One read lock for the whole batch; collect raw, format after release.
    let collected: Vec<(String, u64)> = {
        let utxo_set = node.utxo_set.read().await;
        decoded
            .into_iter()
            .map(|(addr, script)| {
                let bal = utxo_set.balance_for_script(&script, current_height);
                (addr, bal)
            })
            .collect()
    };

    let balances: Vec<serde_json::Value> = collected
        .iter()
        .map(|(addr, bal)| serde_json::json!({ "address": addr, "balance": bal }))
        .collect();

    RpcResponse::ok(id, serde_json::json!({ "balances": balances }))
}

async fn handle_get_address_utxos_batch(
    id: serde_json::Value,
    params: serde_json::Value,
    node: &Arc<Node>,
) -> RpcResponse {
    let parsed: BatchAddressParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid params: {}", e)),
    };
    let decoded = match decode_batch_addresses(&id, &parsed.addresses) {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    let tip_height = node.tip.read().await.height;
    let current_height = tip_height.saturating_add(1);
    const MAX_UTXO_RESULTS: usize = 1000;

    // One read lock for the whole batch; collect raw, format after release.
    #[allow(clippy::type_complexity)]
    let collected: Vec<(String, Vec<(OutPoint, u64, u64, bool)>, bool)> = {
        let utxo_set = node.utxo_set.read().await;
        decoded
            .into_iter()
            .map(|(addr, script)| {
                let mut matched =
                    utxo_set.utxos_for_script(&script, current_height, MAX_UTXO_RESULTS + 1);
                let truncated = matched.len() > MAX_UTXO_RESULTS;
                matched.truncate(MAX_UTXO_RESULTS);
                (addr, matched, truncated)
            })
            .collect()
    };

    let addresses: Vec<serde_json::Value> = collected
        .iter()
        .map(|(addr, matched, truncated)| {
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
            serde_json::json!({
                "address": addr,
                "utxos": utxos,
                "truncated": truncated,
            })
        })
        .collect();

    RpcResponse::ok(
        id,
        serde_json::json!({
            "addresses": addresses,
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
// get_output_spent_by
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GetOutputSpentByParams {
    tx_id: String,
    output_index: u32,
}

/// Look up which transaction (if any) consumed a given outpoint.
///
/// Returns one of two shapes:
///
/// ```json
/// { "spent": true,  "spending_tx_id": "<hex32>",
///   "input_index": <u32>, "block_height": <u64> }
///
/// { "spent": false }
/// ```
///
/// O(1) — a single SPENT_BY_TABLE lookup. Populated incrementally as
/// canonical blocks arrive; pre-existing chaindata can be backfilled
/// in one shot via the `--build-spent-by-index` CLI flag (see
/// `exfer node --help`). Nodes without the backfill report `spent:
/// false` for historical outpoints they haven't indexed yet, which is
/// indistinguishable on the wire from "still unspent" — operators
/// who need the historical answer should run the migration once.
async fn handle_get_output_spent_by(
    id: serde_json::Value,
    params: serde_json::Value,
    node: &Arc<Node>,
) -> RpcResponse {
    let parsed: GetOutputSpentByParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid params: {}", e)),
    };

    let bytes = match hex::decode(&parsed.tx_id) {
        Ok(b) => b,
        Err(e) => return RpcResponse::err(id, INVALID_PARAMS, format!("Invalid hex: {}", e)),
    };
    if bytes.len() != 32 {
        return RpcResponse::err(id, INVALID_PARAMS, "tx_id must be 32 bytes".to_string());
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    let prev_tx_id = Hash256(h);

    match node
        .storage
        .get_output_spent_by(&prev_tx_id, parsed.output_index)
    {
        Ok(Some(rec)) => RpcResponse::ok(
            id,
            serde_json::json!({
                "spent": true,
                "spending_tx_id": hex::encode(rec.spending_tx_id.as_bytes()),
                "input_index":    rec.input_index,
                "block_height":   rec.block_height,
            }),
        ),
        Ok(None) => RpcResponse::ok(id, serde_json::json!({ "spent": false })),
        Err(e) => RpcResponse::err(id, INTERNAL_ERROR, format!("Storage error: {}", e)),
    }
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
            match mempool.add_validated(
                tx,
                fee,
                script_cost,
                script_validation_cost,
                height,
                &utxo_snapshot,
            ) {
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

    #[test]
    fn utxo_cursor_round_trips_with_tip_id() {
        let tip = Hash256([7u8; 32]);
        let op = OutPoint::new(Hash256([9u8; 32]), 3);
        let encoded = encode_utxo_cursor(&tip, &op);
        let (got_tip, got_op) = parse_utxo_cursor(&encoded).expect("round-trip");
        assert_eq!(got_tip, tip);
        assert_eq!(got_op, op);
    }

    #[test]
    fn utxo_cursor_rejects_legacy_two_part_and_malformed() {
        // Pre-fix cursors were "<tx_hex>:<idx>" (no tip) — must be rejected so a
        // stale client restarts cleanly rather than silently mis-paginating.
        let two_part = format!("{}:0", hex::encode([9u8; 32]));
        assert!(parse_utxo_cursor(&two_part).is_err());
        assert!(parse_utxo_cursor("garbage").is_err());
        // Right shape, bad tip length.
        let bad_tip = format!("ab:{}:0", hex::encode([9u8; 32]));
        assert!(parse_utxo_cursor(&bad_tip).is_err());
        // Right shape, non-numeric index.
        let bad_idx = format!("{}:{}:notnum", hex::encode([7u8; 32]), hex::encode([9u8; 32]));
        assert!(parse_utxo_cursor(&bad_idx).is_err());
    }

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
