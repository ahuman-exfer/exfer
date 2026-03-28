#![no_main]
use libfuzzer_sys::fuzz_target;
use exfer::network::protocol::Message;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input
    let _ = Message::deserialize(data);
});
