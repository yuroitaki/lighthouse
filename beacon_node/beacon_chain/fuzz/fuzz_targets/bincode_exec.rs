#![no_main]
use beacon_chain::harness::{Execution, Harness};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(exec) = bincode::deserialize::<Execution>(data) {
        let mut harness = Harness::new();
        harness.apply_execution(exec);
    }
});
