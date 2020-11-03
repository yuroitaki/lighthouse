use crate::transition_blocks::load_from_ssz;
use clap::ArgMatches;
use ssz::Encode;
use state_processing::{per_block_processing::process_attester_slashings, VerifySignatures};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use types::{AttesterSlashing, BeaconState, EthSpec};

// FIXME(sproul): make generic over op
pub fn run_transition_ops<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let pre_state_path = matches
        .value_of("pre-state")
        .ok_or_else(|| "No pre-state file supplied".to_string())?
        .parse::<PathBuf>()
        .map_err(|e| format!("Failed to parse pre-state path: {}", e))?;

    let op_path = matches
        .value_of("op")
        .ok_or_else(|| "No operation supplied".to_string())?
        .parse::<PathBuf>()
        .map_err(|e| format!("Failed to parse operation path: {}", e))?;

    let output_path = matches
        .value_of("output")
        .ok_or_else(|| "No output file supplied".to_string())?
        .parse::<PathBuf>()
        .map_err(|e| format!("Failed to parse output path: {}", e))?;

    info!("Using {} spec", T::spec_name());
    info!("Pre-state path: {:?}", pre_state_path);
    info!("Op path: {:?}", op_path);

    let pre_state: BeaconState<T> = load_from_ssz(pre_state_path)?;
    let attester_slashing = load_from_ssz(op_path)?;

    let post_state = do_transition(pre_state, attester_slashing)?;

    let mut output_file =
        File::create(output_path).map_err(|e| format!("Unable to create output file: {:?}", e))?;

    output_file
        .write_all(&post_state.as_ssz_bytes())
        .map_err(|e| format!("Unable to write to output file: {:?}", e))?;

    Ok(())
}

fn do_transition<T: EthSpec>(
    mut pre_state: BeaconState<T>,
    attester_slashing: AttesterSlashing<T>,
) -> Result<BeaconState<T>, String> {
    let spec = &T::default_spec();

    pre_state
        .build_all_caches(spec)
        .map_err(|e| format!("Unable to build caches: {:?}", e))?;

    process_attester_slashings(
        &mut pre_state,
        &[attester_slashing],
        VerifySignatures::True,
        spec,
    )
    .map_err(|e| format!("State transition failed: {:?}", e))?;

    Ok(pre_state)
}
