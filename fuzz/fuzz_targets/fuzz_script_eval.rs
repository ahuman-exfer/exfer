#![no_main]
use libfuzzer_sys::fuzz_target;
use exfer::script::{deserialize_program, typecheck, evaluate, Budget};
use exfer::script::value::Value;

fuzz_target!(|data: &[u8]| {
    // Try to deserialize a program from random bytes
    let program = match deserialize_program(data) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Must not panic on typecheck
    let _typed = match typecheck(&program) {
        Ok(t) => t,
        Err(_) => return,
    };

    // Evaluate with Unit input and the remaining bytes as witness
    // Use a tight budget to prevent hangs
    let mut budget = Budget::new(10_000, 10_000);
    let witness = if data.len() > 100 { &data[data.len()-50..] } else { &[] };
    let _ = evaluate(&program, Value::Unit, witness, &mut budget);
});
