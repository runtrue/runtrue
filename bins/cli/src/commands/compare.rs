use super::{
    super::{
        absolute, print_json, read_bounded_file, read_event, resolve_one_workflow, CliError,
        CompareCapsuleArgs, EXIT_EXECUTION, EXIT_OK,
    },
    compile_path,
};
use runtrue_replay::{ReplayEnvelope, MAX_REPLAY_BUNDLE_BYTES};
use serde::Serialize;
use std::path::Path;

pub(crate) fn compare_capsule(workspace: &Path, args: CompareCapsuleArgs) -> Result<u8, CliError> {
    let bundle_path = absolute(workspace, args.bundle);
    let bytes = read_bounded_file(
        &bundle_path,
        u64::try_from(MAX_REPLAY_BUNDLE_BYTES).expect("replay limit fits u64"),
        "replay bundle",
    )?;
    let envelope = ReplayEnvelope::from_canonical_bytes(&bytes)?;
    let workflow_path = resolve_one_workflow(workspace, args.context.workflow)?;
    let event = read_event(args.context.event.as_deref(), workspace)?;
    let compilation = compile_path(
        workspace,
        &workflow_path,
        event,
        args.context.source_commit,
        args.context.base_commit,
        args.job,
    )?;
    let matches = compilation.capsule_digest == envelope.bundle.capsule_digest;
    let report = CapsuleComparison {
        matches,
        expected_capsule_digest: envelope.bundle.capsule_digest.to_string(),
        actual_capsule_digest: compilation.capsule_digest.to_string(),
        bundle_digest: envelope.bundle_digest.to_string(),
    };
    if args.json {
        print_json(&report)?;
    } else {
        println!("Expected: {}", report.expected_capsule_digest);
        println!("Actual:   {}", report.actual_capsule_digest);
        println!("Match:    {}", report.matches);
    }
    Ok(if matches { EXIT_OK } else { EXIT_EXECUTION })
}

#[derive(Debug, Serialize)]
struct CapsuleComparison {
    matches: bool,
    expected_capsule_digest: String,
    actual_capsule_digest: String,
    bundle_digest: String,
}
