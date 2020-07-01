#![no_main]
use beacon_chain::harness::Execution;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(exec) = bincode::deserialize::<Execution>(data) {
        /*
        if !exec.is_well_formed() {
            return;
        }
        */
        assert_ne!(exec, Execution::linear_chain(33));
    }
});
