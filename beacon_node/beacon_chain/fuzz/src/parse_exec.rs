//! CLI binary to parse a bincoded `Execution` and pretty-print it.
use beacon_chain::harness::Execution;
use std::{env, fs::File};

fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];
    let f = File::open(filename).unwrap();
    let execution: Execution = bincode::deserialize_from(&f).unwrap();
    println!("{:#?}", execution);
    println!("well-formed? {}", execution.is_well_formed());
}
