//! Shared mock JSON-RPC node for the signature-domain tests (issue #32).
//!
//! Speaks just enough HTTP/1.1 for `rpc::rpc_call`: POST with Content-Length,
//! response with Content-Length. Serves a configurable `get_block_height`
//! result; every other method gets a JSON-RPC error, so a flow that passes
//! the domain check cannot accidentally proceed to a successful spend.
//! Records every method name received, letting tests assert that a signing
//! command failed BEFORE any post-domain-check RPC (no `get_transaction`,
//! no `get_address_utxos`, no `send_raw_transaction`).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub struct MockNode {
    pub url: String,
    // Not every test binary that includes this module reads the recordings —
    // each tests/*.rs compiles its own copy, so silence per-binary dead_code.
    #[allow(dead_code)]
    methods_seen: Arc<Mutex<Vec<String>>>,
    shutdown: Arc<AtomicBool>,
    addr: std::net::SocketAddr,
    handle: Option<JoinHandle<()>>,
}

impl MockNode {
    /// Serve `get_block_height` with the given JSON result object.
    pub fn serve(block_height_result: serde_json::Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock node");
        let addr = listener.local_addr().unwrap();
        let methods_seen = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let seen = Arc::clone(&methods_seen);
        let stop = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                handle_connection(stream, &block_height_result, &seen);
            }
        });

        MockNode {
            url: format!("http://{}", addr),
            methods_seen,
            shutdown,
            addr,
            handle: Some(handle),
        }
    }

    #[allow(dead_code)]
    pub fn methods_seen(&self) -> Vec<String> {
        self.methods_seen.lock().unwrap().clone()
    }
}

impl Drop for MockNode {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        // Unblock the accept loop.
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    block_height_result: &serde_json::Value,
    seen: &Arc<Mutex<Vec<String>>>,
) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));

    // Read headers.
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => buf.push(byte[0]),
            _ => return,
        }
        if buf.len() > 16384 {
            return;
        }
    }
    let headers = String::from_utf8_lossy(&buf);
    let content_length: usize = headers
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body = vec![0u8; content_length];
    if stream.read_exact(&mut body).is_err() {
        return;
    }
    let request: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return,
    };
    let method = request
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    seen.lock().unwrap().push(method.clone());

    let response = if method == "get_block_height" {
        serde_json::json!({
            "jsonrpc": "2.0",
            "result": block_height_result,
            "id": 1,
        })
    } else {
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": -32601, "message": "mock node: method disabled" },
            "id": 1,
        })
    };
    let body = serde_json::to_vec(&response).unwrap();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}
