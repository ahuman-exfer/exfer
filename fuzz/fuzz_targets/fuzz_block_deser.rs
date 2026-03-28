#![no_main]
use libfuzzer_sys::fuzz_target;
use exfer::types::block::Block;

fuzz_target!(|data: &[u8]| {
    let _ = Block::deserialize(data);
});
