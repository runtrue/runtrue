use super::{
    super::{
        absolute, print_execution_result, print_human_artifacts, print_json, read_bounded_file,
        CliError, ReplayArgs, EXIT_EXECUTION, EXIT_OK,
    },
    validate_local_capsule,
};
use runtrue_engine::{Engine, ExecutionResult, NativeProcessExecutor, RunState};
use runtrue_replay::{ReplayEnvelope, ReplayOutcome, MAX_REPLAY_BUNDLE_BYTES};
use runtrue_runtime_local::{
    LocalArtifactCapture, LocalArtifactConfig, LocalArtifactExecutor, LocalCacheConfig,
    LocalCacheExecutor,
};
use serde::Serialize;
use std::path::Path;

pub(crate) fn replay(workspace: &Path, args: ReplayArgs) -> Result<u8, CliError> {
    if !args.allow_native {
        return Err(CliError::NativeAcknowledgementRequired);
    }
    let path = absolute(workspace, args.bundle);
    let bytes = read_bounded_file(
        &path,
        u64::try_from(MAX_REPLAY_BUNDLE_BYTES).expect("replay limit fits u64"),
        "replay bundle",
    )?;
    let envelope = ReplayEnvelope::from_canonical_bytes(&bytes)?;
    let runtime_context = envelope.bundle.capsule.context.event_context.clone();
    validate_local_capsule(&envelope.bundle.capsule, &runtime_context)?;

    let mut executor = NativeProcessExecutor::new(workspace, args.allow_native);
    executor.set_external_cache_handling(true);
    executor.set_external_artifact_handling(true);
    let executor = LocalCacheExecutor::new(executor, LocalCacheConfig::for_workspace(workspace));
    let executor =
        LocalArtifactExecutor::new(executor, LocalArtifactConfig::for_workspace(workspace));
    let mut engine = Engine::new(executor);
    let result = engine.execute_with_context(&envelope.bundle.capsule, &runtime_context)?;
    let artifacts = engine
        .executor_mut()
        .capture_successful_jobs(&envelope.bundle.capsule, &result)?;
    let actual_outcome = ReplayOutcome::from(&result);
    let outcome_matches = envelope
        .bundle
        .outcome
        .as_ref()
        .is_none_or(|expected| expected == &actual_outcome);
    let succeeded = result.state == RunState::Succeeded && outcome_matches;

    if args.json {
        print_json(&ReplayRunReport {
            bundle_digest: envelope.bundle_digest.to_string(),
            capsule_digest: envelope.bundle.capsule_digest.to_string(),
            outcome_matches,
            recorded_artifact_references: envelope
                .bundle
                .artifact_references
                .iter()
                .map(ToString::to_string)
                .collect(),
            artifacts,
            result,
        })?;
    } else {
        println!("Replay bundle: {}", envelope.bundle_digest);
        println!("Capsule: {}", envelope.bundle.capsule_digest);
        print_execution_result(&result)?;
        print_human_artifacts(&artifacts);
        println!("recorded outcome matches: {outcome_matches}");
    }
    Ok(if succeeded { EXIT_OK } else { EXIT_EXECUTION })
}

#[derive(Debug, Serialize)]
struct ReplayRunReport {
    bundle_digest: String,
    capsule_digest: String,
    outcome_matches: bool,
    recorded_artifact_references: Vec<String>,
    artifacts: Vec<LocalArtifactCapture>,
    result: ExecutionResult,
}
