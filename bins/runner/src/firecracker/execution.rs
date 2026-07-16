pub(super) fn validate_guest_job(job: &runtrue_workflow_ir::PlannedJob) -> Result<(), RunnerError> {
    if job.runner.image.is_some()
        || !job.runner.capabilities.is_empty()
        || !job.services.is_empty()
        || job.permissions != PermissionSet::default()
        || !job.outputs.is_empty()
        || job.steps.is_empty()
    {
        return Err(RunnerError::FirecrackerAssignment(
            "microVM services, image labels, host capabilities, data-plane permissions, outputs, and empty jobs are unsupported"
                .to_owned(),
        ));
    }
    for step in &job.steps {
        if step.condition.is_some()
            || step.capabilities != StepCapabilitySet::default()
            || step.cache.is_some()
            || step
                .inputs
                .values()
                .chain(step.environment.values())
                .any(|value| matches!(value, ValueBinding::Context(_)))
        {
            return Err(RunnerError::FirecrackerAssignment(
                "microVM conditions and secret/OIDC/cache/artifact/filesystem/network/check/context adapters are not wired"
                    .to_owned(),
            ));
        }
        match &step.action {
            StepAction::Command { program, args }
                if Path::new(program).is_absolute()
                    && args
                        .iter()
                        .all(|value| matches!(value, ValueBinding::Literal(_))) => {}
            StepAction::Script {
                shell: Shell::Bash | Shell::Sh,
                ..
            } => {}
            StepAction::Command { .. }
            | StepAction::Container { .. }
            | StepAction::Script { .. }
            | StepAction::Component { .. } => {
                return Err(RunnerError::FirecrackerAssignment(
                    "microVM steps require an absolute literal command or sh/bash script"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn session_id(lease: &AdmittedLease) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"runtrue.firecracker.guest-session.v1\0");
    hasher.update(lease.lease_id.as_bytes());
    hasher.update([0]);
    hasher.update(lease.fencing_generation.to_be_bytes());
    hasher.update(lease.installation_fencing_epoch.to_be_bytes());
    hasher.update(lease.capsule_digest.as_str().as_bytes());
    format!("session-{}", &hex::encode(hasher.finalize())[..32])
}

pub(super) fn job_execution_from_report(
    lease: &AdmittedLease,
    image_set_digest: &ContentDigest,
    report: OneJobReport,
) -> Result<JobExecution, RunnerError> {
    let job = lease
        .capsule
        .jobs
        .iter()
        .find(|job| job.id == lease.job_id)
        .ok_or_else(|| RunnerError::OfferedJobMissing(lease.job_id.clone()))?;
    if report.step_results.len() != job.steps.len()
        || report
            .step_results
            .iter()
            .zip(&job.steps)
            .any(|(result, step)| result.step_id != step.id)
    {
        return Err(RunnerError::FirecrackerAssignment(
            "guest result does not cover the exact signed step sequence".to_owned(),
        ));
    }
    let computed_success = report
        .step_results
        .iter()
        .zip(&job.steps)
        .all(|(result, step)| {
            result.skipped
                || (!result.timed_out
                    && !result.canceled
                    && (result.exit_code == Some(0) || step.continue_on_error))
        });
    if report.succeeded != computed_success {
        return Err(RunnerError::FirecrackerAssignment(
            "guest terminal result contradicts the signed step results".to_owned(),
        ));
    }
    if report
        .logs
        .iter()
        .any(|frame| frame.stream == LogStream::System)
    {
        return Err(RunnerError::FirecrackerAssignment(
            "guest emitted a system log frame, but remote protocol v1 accepts only stdout/stderr"
                .to_owned(),
        ));
    }
    let canceled = report.step_results.iter().any(|step| step.canceled);
    let timed_out = report.step_results.iter().any(|step| step.timed_out);
    let (final_state, error_code) = if canceled {
        ("canceled", "canceled")
    } else if timed_out {
        ("timed_out", "timed_out")
    } else if report.succeeded {
        ("succeeded", "")
    } else {
        ("failed", "execution_failed")
    };
    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct ResultDocument<'a> {
        result_version: u32,
        lease_id: &'a str,
        job_id: &'a str,
        capsule_digest: &'a ContentDigest,
        image_set_digest: &'a ContentDigest,
        succeeded: bool,
        cancellation_acknowledged: bool,
        steps: &'a [GuestStepResult],
        resources: &'a [runtrue_guest_core::ResourceSample],
    }
    let encoded = serde_json::to_vec(&ResultDocument {
        result_version: 1,
        lease_id: &lease.lease_id,
        job_id: &lease.job_id,
        capsule_digest: &lease.capsule_digest,
        image_set_digest,
        succeeded: report.succeeded,
        cancellation_acknowledged: report.cancellation_acknowledged,
        steps: &report.step_results,
        resources: &report.resource_samples,
    })
    .map_err(RunnerError::ResultEncoding)?;
    if encoded.len() > MAX_RESULT_BYTES {
        return Err(RunnerError::ResultLimitExceeded {
            limit: MAX_RESULT_BYTES,
            actual: encoded.len(),
        });
    }
    let wall_time = timestamp(now_unix_ms()?);
    let log_frames = report
        .logs
        .into_iter()
        .take(MAX_LOG_FRAMES)
        .map(|frame| v1::LogFrame {
            run_id: lease.lease_id.clone(),
            job_id: lease.job_id.clone(),
            step_id: frame.step_id,
            sequence: frame.sequence,
            stream: match frame.stream {
                LogStream::Stdout => "stdout",
                LogStream::Stderr => "stderr",
                LogStream::System => unreachable!("system frames were rejected above"),
            }
            .to_owned(),
            monotonic_nanoseconds: frame.sequence.saturating_mul(1_000_000),
            wall_time: Some(wall_time),
            payload: frame.bytes,
            redaction_state: "no_guest_broker_material".to_owned(),
            job_attempt: 1,
        })
        .collect();
    let exit_code = report
        .step_results
        .iter()
        .rev()
        .find(|step| !step.skipped)
        .and_then(|step| step.exit_code);
    Ok(JobExecution {
        final_state: final_state.to_owned(),
        exit_code,
        error_code: error_code.to_owned(),
        result_digest: ContentDigest::sha256(encoded),
        log_frames,
        final_job_attempt: 1,
        artifact_ids: Vec::new(),
        cache_entry_ids: Vec::new(),
        credential_taint: runtrue_engine::CredentialTaint::None,
    })
}

pub(super) fn canceled_job_execution(lease: &AdmittedLease) -> Result<JobExecution, RunnerError> {
    #[derive(Serialize)]
    struct Canceled<'a> {
        state: &'static str,
        lease_id: &'a str,
        job_id: &'a str,
        capsule_digest: &'a ContentDigest,
    }
    let encoded = serde_json::to_vec(&Canceled {
        state: "canceled",
        lease_id: &lease.lease_id,
        job_id: &lease.job_id,
        capsule_digest: &lease.capsule_digest,
    })
    .map_err(RunnerError::ResultEncoding)?;
    Ok(JobExecution {
        final_state: "canceled".to_owned(),
        exit_code: None,
        error_code: "canceled".to_owned(),
        result_digest: ContentDigest::sha256(encoded),
        log_frames: Vec::new(),
        final_job_attempt: 0,
        artifact_ids: Vec::new(),
        cache_entry_ids: Vec::new(),
        credential_taint: runtrue_engine::CredentialTaint::None,
    })
}

fn timestamp(unix_ms: u64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: i64::try_from(unix_ms / 1000).unwrap_or(i64::MAX),
        nanos: i32::try_from((unix_ms % 1000) * 1_000_000).unwrap_or(999_000_000),
    }
}

pub(super) fn now_unix_ms() -> Result<u64, RunnerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(RunnerError::ClockRange)
}
use super::{
    v1, AdmittedLease, ContentDigest, GuestStepResult, JobExecution, LogStream, OneJobReport, Path,
    PermissionSet, RunnerError, Serialize, Sha256, Shell, StepAction, StepCapabilitySet,
    SystemTime, ValueBinding, MAX_LOG_FRAMES, MAX_RESULT_BYTES, UNIX_EPOCH,
};
use sha2::Digest as _;
