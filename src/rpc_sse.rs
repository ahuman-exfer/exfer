//! SSE long-lived stream endpoint (issue #15 Tier 2).
//!
//! Wire format: standard `text/event-stream`, one event per blank-line-
//! separated block. The bus emits three event types; on the wire each
//! is `event: <name>\ndata: <json>\n\n`:
//!
//!   event: script_changed     data: {"script":"<hex>"}
//!   event: tip                 data: {"height":N}
//!   event: resync              data: {}
//!
//! The transport carries no per-tx detail by design — see issue #15's
//! "Electrum nudge" rationale. Clients respond by re-pulling
//! `get_address_mempool` + `get_balance` / `get_address_utxos_batch`
//! via the normal JSON-RPC endpoint.
//!
//! Subscription model: addresses are passed as a comma-separated `addresses`
//! query parameter on `GET /sse`. Each address is a 64-char hex script
//! (same encoding the JSON-RPC takes). Re-subscribe = reconnect with a
//! different set; no in-band protocol for add/remove.
//!
//! Operational safeguards:
//!
//!   - separate connection pool (`MAX_RPC_SSE_CONNECTIONS`) so the
//!     long-lived streams cannot starve the 32-slot JSON-RPC pool
//!   - per-IP cap (`MAX_RPC_SSE_PER_IP`) — the obvious abuse vector is
//!     one IP opening hundreds of streams
//!   - per-connection address cap (`MAX_RPC_SSE_ADDRESSES`) — bounds
//!     filter cost and the "subscribe to everything" abuse vector
//!   - heartbeat comment every 25s so reverse proxies / NAT idle timers
//!     don't silently drop the stream
//!
//! Per the design discussion (issue #15 Q4), the linkability story
//! (operator can correlate "subscriber cares about address X" with
//! "tx touching X just appeared") is real. Operators uncomfortable with
//! this surface can disable SSE via `--rpc-sse-enabled false` on the
//! node CLI.

use crate::events::{ChainEvent, EventBus};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::debug;

/// Maximum concurrent SSE connections across the whole node. Tuned for
/// Route A (per-script subscription routing): each event walks the
/// interested-subscribers set, not all connections, so this can sit
/// well above the 32-slot one-shot pool.
pub const MAX_RPC_SSE_CONNECTIONS: usize = 256;

/// Maximum SSE connections per remote IP. Defense against one client
/// monopolising the pool by opening hundreds of streams.
pub const MAX_RPC_SSE_PER_IP: usize = 4;

/// Maximum addresses one SSE connection may subscribe to. Bounds the
/// filter cost and the "subscribe to every address on the chain"
/// trivial abuse vector.
pub const MAX_RPC_SSE_ADDRESSES: usize = 256;

/// Heartbeat comment interval. SSE allows lines starting with `:` as
/// comments — used here to keep reverse proxies and NAT mappings warm.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);

/// Per-IP counter used to enforce `MAX_RPC_SSE_PER_IP`. Held inside
/// the RPC server task and cloned to each connection handler.
pub type SsePerIp = Arc<Mutex<HashMap<std::net::IpAddr, usize>>>;

/// Build the empty per-IP counter. Convenience for `run_rpc_server`.
pub fn new_per_ip_counter() -> SsePerIp {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Build the global SSE connection semaphore.
pub fn new_conn_semaphore() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(MAX_RPC_SSE_CONNECTIONS))
}

/// Decode the `addresses=<hex>,<hex>,...` query parameter into a vec of
/// raw script bytes. Caller has already enforced the per-conn cap.
fn parse_addresses(query: &str) -> Result<Vec<Vec<u8>>, String> {
    // query is everything after `?`. We only care about the `addresses=`
    // pair; ignore any others (forward-compat for future params).
    let mut raw_addrs: Option<&str> = None;
    for pair in query.split('&') {
        if let Some(rest) = pair.strip_prefix("addresses=") {
            raw_addrs = Some(rest);
            break;
        }
    }
    let raw = raw_addrs.ok_or_else(|| "missing addresses= query param".to_string())?;
    if raw.is_empty() {
        return Err("empty addresses list".into());
    }
    let mut out = Vec::new();
    for token in raw.split(',') {
        let bytes = hex::decode(token)
            .map_err(|e| format!("address `{}` is not hex: {}", token, e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "address must decode to 32 bytes, `{}` gave {}",
                token,
                bytes.len()
            ));
        }
        out.push(bytes);
    }
    Ok(out)
}

/// Increment the per-IP counter under cap. Returns Err if we would
/// exceed `MAX_RPC_SSE_PER_IP`. The Drop'd `IpGuard` decrements.
fn try_acquire_per_ip(counter: &SsePerIp, ip: std::net::IpAddr) -> Result<IpGuard, ()> {
    let mut map = counter.lock().unwrap_or_else(|e| e.into_inner());
    let entry = map.entry(ip).or_insert(0);
    if *entry >= MAX_RPC_SSE_PER_IP {
        return Err(());
    }
    *entry += 1;
    Ok(IpGuard {
        counter: counter.clone(),
        ip,
    })
}

struct IpGuard {
    counter: SsePerIp,
    ip: std::net::IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut map = self.counter.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Handle a single `GET /sse?...` connection. The caller has already
/// consumed the request headers from the socket and parsed out the
/// query string (everything after `?` on the request line).
///
/// This function takes ownership of the stream; it returns when the
/// client disconnects, the bus closes, or we send an error response.
pub async fn handle_sse_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    query: &str,
    bus: Arc<EventBus>,
    conn_sem: Arc<Semaphore>,
    per_ip: SsePerIp,
) {
    // Pool cap.
    let _conn_permit = match conn_sem.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let _ = send_status_line(&mut stream, 503, "SSE connection pool exhausted").await;
            return;
        }
    };

    // Per-IP cap.
    let _ip_guard = match try_acquire_per_ip(&per_ip, addr.ip()) {
        Ok(g) => g,
        Err(_) => {
            let _ = send_status_line(&mut stream, 429, "Too many SSE connections from this IP")
                .await;
            return;
        }
    };

    // Address list.
    let scripts = match parse_addresses(query) {
        Ok(v) => v,
        Err(e) => {
            let _ = send_status_line(&mut stream, 400, &format!("bad query: {}", e)).await;
            return;
        }
    };
    if scripts.len() > MAX_RPC_SSE_ADDRESSES {
        let _ = send_status_line(
            &mut stream,
            400,
            &format!(
                "too many addresses ({}); max is {}",
                scripts.len(),
                MAX_RPC_SSE_ADDRESSES
            ),
        )
        .await;
        return;
    }

    // Headers — SSE upgrade. The empty Content-Length / Connection: keep-alive
    // combination keeps reverse proxies happy.
    let headers = "HTTP/1.1 200 OK\r\n\
                   Content-Type: text/event-stream\r\n\
                   Cache-Control: no-cache\r\n\
                   Connection: keep-alive\r\n\
                   X-Accel-Buffering: no\r\n\
                   \r\n";
    if stream.write_all(headers.as_bytes()).await.is_err() {
        return;
    }

    // Subscribe.
    let (sub_id, mut rx) = bus.subscribe(&scripts);
    debug!(
        "SSE subscribed: peer={} sub_id={} addresses={}",
        addr,
        sub_id,
        scripts.len()
    );

    // Initial nudge so the client's snapshot-then-stream pattern kicks in
    // immediately — every subscribed address is "potentially stale, re-pull".
    for s in &scripts {
        let line = format!(
            "event: script_changed\ndata: {{\"script\":\"{}\"}}\n\n",
            hex::encode(s)
        );
        if stream.write_all(line.as_bytes()).await.is_err() {
            bus.unsubscribe(sub_id);
            return;
        }
    }
    let _ = stream.flush().await;

    // Stream loop. Either drain a real event from the bus or fire a
    // heartbeat comment on the idle timer.
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            biased;
            evt = rx.recv() => {
                let Some(evt) = evt else {
                    debug!("SSE bus closed: peer={} sub_id={}", addr, sub_id);
                    break;
                };
                let payload = match evt {
                    ChainEvent::ScriptChanged(s) => format!(
                        "event: script_changed\ndata: {{\"script\":\"{}\"}}\n\n",
                        hex::encode(s)
                    ),
                    ChainEvent::TipChanged { height } => format!(
                        "event: tip\ndata: {{\"height\":{}}}\n\n",
                        height
                    ),
                    ChainEvent::Resync => "event: resync\ndata: {}\n\n".to_string(),
                };
                if stream.write_all(payload.as_bytes()).await.is_err() {
                    debug!("SSE write failed (client disconnected): peer={}", addr);
                    break;
                }
                if stream.flush().await.is_err() {
                    break;
                }
            }
            _ = heartbeat.tick() => {
                if stream.write_all(b": heartbeat\n\n").await.is_err() {
                    break;
                }
                if stream.flush().await.is_err() {
                    break;
                }
            }
        }
    }

    bus.unsubscribe(sub_id);
    debug!("SSE unsubscribed: peer={} sub_id={}", addr, sub_id);
}

/// Tiny one-shot HTTP error response writer. Used only on the
/// pre-upgrade error paths (cap exhausted, bad query). After the
/// 200 OK + event-stream upgrade we never write status lines again.
async fn send_status_line(
    stream: &mut TcpStream,
    code: u16,
    msg: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let reason = match code {
        400 => "Bad Request",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let body = msg.as_bytes();
    let payload = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(payload.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addresses_round_trip() {
        let s1 = vec![0xaa; 32];
        let s2 = vec![0xbb; 32];
        let q = format!("addresses={},{}", hex::encode(&s1), hex::encode(&s2));
        let parsed = parse_addresses(&q).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], s1);
        assert_eq!(parsed[1], s2);
    }

    #[test]
    fn parse_addresses_rejects_missing_param() {
        assert!(parse_addresses("other=1").is_err());
    }

    #[test]
    fn parse_addresses_rejects_wrong_length() {
        let q = format!("addresses={}", hex::encode([1u8; 20]));
        assert!(parse_addresses(&q).is_err());
    }

    #[test]
    fn parse_addresses_rejects_non_hex() {
        assert!(parse_addresses("addresses=notarealhex").is_err());
    }

    #[test]
    fn per_ip_cap_enforced() {
        let counter = new_per_ip_counter();
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let mut guards = Vec::new();
        for _ in 0..MAX_RPC_SSE_PER_IP {
            guards.push(try_acquire_per_ip(&counter, ip).unwrap());
        }
        assert!(try_acquire_per_ip(&counter, ip).is_err());
        // Drop one — should free a slot.
        drop(guards.pop());
        assert!(try_acquire_per_ip(&counter, ip).is_ok());
    }
}
