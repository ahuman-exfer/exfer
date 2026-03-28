#![no_main]
use libfuzzer_sys::fuzz_target;
use exfer::types::transaction::Transaction;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input
    let _ = Transaction::deserialize(data);
});
