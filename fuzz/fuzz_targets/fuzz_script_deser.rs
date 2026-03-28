#![no_main]
use libfuzzer_sys::fuzz_target;
use exfer::script::serialize::deserialize_program;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize_program(data);
});
