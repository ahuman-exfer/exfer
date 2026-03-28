#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Match the RPC's 64 KiB body cap
    if data.len() > 65_536 {
        return;
    }
    // Simulate RPC JSON parsing — must not panic on malformed input
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Parse as JSON — must not panic
    let val: Result<serde_json::Value, _> = serde_json::from_str(s);
    let val = match val {
        Ok(v) => v,
        Err(_) => return,
    };

    // Try to extract JSON-RPC fields — must not panic
    let _method = val.get("method").and_then(|v| v.as_str());
    let _params = val.get("params");
    let _id = val.get("id");

    // Try to parse as various RPC param types
    if let Some(params) = val.get("params") {
        // get_balance params
        let _ = params.get("address").and_then(|v| v.as_str());
        // get_block params
        let _ = params.get("hash").and_then(|v| v.as_str());
        let _ = params.get("height").and_then(|v| v.as_u64());
        // send_raw_transaction params
        let _ = params.get("tx_hex").and_then(|v| v.as_str()).map(|h| hex::decode(h));
    }
});
