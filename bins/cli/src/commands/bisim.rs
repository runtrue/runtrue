use super::super::{
    absolute, print_json, read_bounded_file, BisimArgs, CliError, EXIT_EXECUTION, EXIT_OK,
};
use runtrue_bisim::{compare_bisim, BisimObservation, MAX_BISIM_RESULT_BYTES};
use std::path::Path;

const MAX_BISIM_OBSERVATION_BYTES: usize = MAX_BISIM_RESULT_BYTES + 1024 * 1024;

pub(crate) fn bisim(workspace: &Path, args: BisimArgs) -> Result<u8, CliError> {
    let left = read_observation(workspace, args.left)?;
    let right = read_observation(workspace, args.right)?;
    let comparison = compare_bisim(&left, &right)?;

    if args.json {
        print_json(&comparison)?;
    } else {
        println!("Bisim match:       {}", comparison.matches);
        println!("Same Capsule:      {}", comparison.same_capsule);
        println!("Same result:       {}", comparison.same_result);
        println!("Same events:       {}", comparison.same_events);
        if !comparison.differences.is_empty() {
            println!("Differences:       {}", comparison.differences.join(", "));
        }
    }

    Ok(if comparison.matches {
        EXIT_OK
    } else {
        EXIT_EXECUTION
    })
}

fn read_observation(
    workspace: &Path,
    path: std::path::PathBuf,
) -> Result<BisimObservation, CliError> {
    let path = absolute(workspace, path);
    let bytes = read_bounded_file(
        &path,
        u64::try_from(MAX_BISIM_OBSERVATION_BYTES).expect("Bisim limit fits u64"),
        "Bisim observation",
    )?;
    let observation: BisimObservation =
        serde_json::from_slice(&bytes).map_err(runtrue_bisim::BisimError::from)?;
    observation.verify()?;
    Ok(observation)
}
