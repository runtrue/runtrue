use super::{
    clock::{now_unix_ms, timestamp},
    error::RunnerError,
    remote::reject_broker_capabilities,
};
use crate::broker::RunnerBrokerClient;
use runtrue_engine::{
    CancellationToken, CredentialTaint, Engine, ExecutionResult, JobState, NativeProcessExecutor,
    StepStateObserver,
};
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_runner_core::AdmittedLease;
use runtrue_workflow_ir::Isolation;
use std::{collections::BTreeMap, path::Path, sync::Arc};

const MAX_LOG_FRAME_BYTES: usize = 64 * 1024;
const MAX_LOG_FRAMES: usize = 256;
const MAX_RESULT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct JobExecution {
    pub final_state: String,
    pub exit_code: Option<i32>,
    pub error_code: String,
    pub result_digest: ContentDigest,
    pub log_frames: Vec<v1::LogFrame>,
    pub final_job_attempt: u32,
    pub artifact_ids: Vec<String>,
    pub cache_entry_ids: Vec<String>,
    /// Monotonic credential-release taint for the executed workspace.
    pub credential_taint: CredentialTaint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedContent {
    pub kind: String,
    pub digests: Vec<ContentDigest>,
    pub tier: Option<PreparedContentTier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparedContentTier {
    Warmish,
    Warm,
}

pub trait JobExecutor: Clone + Send + Sync + 'static {
    /// Exact immutable content prepared by this executor and safe to expose to
    /// this runner's tenant-scoped placement inventory.
    fn prepared_content(&self) -> Result<Vec<PreparedContent>, RunnerError> {
        Ok(Vec::new())
    }

    fn preflight(&self, lease: &AdmittedLease) -> Result<(), RunnerError>;

    fn preflight_with_broker(
        &self,
        lease: &AdmittedLease,
        _broker: Option<Arc<dyn RunnerBrokerClient>>,
    ) -> Result<(), RunnerError> {
        self.preflight(lease)
    }

    fn execute(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
    ) -> Result<JobExecution, RunnerError>;

    fn execute_with_services(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
        _services: JobExecutionServices,
    ) -> Result<JobExecution, RunnerError> {
        self.execute(lease, workspace, cancellation)
    }

    fn cleanup_stale(&self) -> Result<(), RunnerError>;
}

#[derive(Clone, Default)]
pub struct JobExecutionServices {
    pub(super) broker: Option<Arc<dyn RunnerBrokerClient>>,
    pub(super) step_state_observer: Option<Arc<dyn StepStateObserver>>,
}

#[derive(Debug, Clone)]
pub struct NativeJobExecutor {
    allow_trusted_native: bool,
}

impl NativeJobExecutor {
    #[must_use]
    pub const fn new(allow_trusted_native: bool) -> Self {
        Self {
            allow_trusted_native,
        }
    }
}

impl JobExecutor for NativeJobExecutor {
    fn preflight(&self, lease: &AdmittedLease) -> Result<(), RunnerError> {
        if !self.allow_trusted_native {
            return Err(RunnerError::NativeExecutionDisabled);
        }
        let offered_job = lease
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == lease.job_id)
            .ok_or_else(|| RunnerError::OfferedJobMissing(lease.job_id.clone()))?;
        if offered_job.runner.isolation != Isolation::Native {
            return Err(RunnerError::UnsupportedIsolation(format!(
                "{:?}",
                offered_job.runner.isolation
            )));
        }
        if offered_job.permissions.network != runtrue_workflow_ir::NetworkPermission::Deny
            || offered_job.steps.iter().any(|step| {
                step.capabilities.network != runtrue_workflow_ir::NetworkPermission::Deny
            })
        {
            return Err(RunnerError::NetworkEnforcementUnavailable(
                "native".to_owned(),
            ));
        }
        reject_broker_capabilities(offered_job, "native")?;
        Ok(())
    }

    fn execute(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
    ) -> Result<JobExecution, RunnerError> {
        if !self.allow_trusted_native {
            return Err(RunnerError::NativeExecutionDisabled);
        }
        let offered_job = lease
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == lease.job_id)
            .ok_or_else(|| RunnerError::OfferedJobMissing(lease.job_id.clone()))?;
        if offered_job.runner.isolation != Isolation::Native {
            return Err(RunnerError::UnsupportedIsolation(format!(
                "{:?}",
                offered_job.runner.isolation
            )));
        }
        let mut executor = NativeProcessExecutor::new(workspace, true);
        executor.set_max_capture_bytes(MAX_LOG_FRAME_BYTES);
        executor.set_external_cache_handling(true);
        executor.set_external_artifact_handling(true);
        let mut engine = Engine::with_cancellation_token(executor, cancellation);
        let result = engine
            .execute_offered_job(&lease.capsule, &lease.job_id)
            .map_err(RunnerError::Engine)?;
        execution_from_engine(lease, result)
    }

    fn execute_with_services(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
        services: JobExecutionServices,
    ) -> Result<JobExecution, RunnerError> {
        self.preflight(lease)?;
        let mut executor = NativeProcessExecutor::new(workspace, true);
        executor.set_max_capture_bytes(MAX_LOG_FRAME_BYTES);
        executor.set_external_cache_handling(true);
        executor.set_external_artifact_handling(true);
        let mut engine = Engine::with_cancellation_token(executor, cancellation);
        engine.set_step_state_observer(services.step_state_observer);
        let result = engine.execute_offered_job(&lease.capsule, &lease.job_id)?;
        execution_from_engine(lease, result)
    }

    fn cleanup_stale(&self) -> Result<(), RunnerError> {
        Ok(())
    }
}

pub(super) fn execution_from_engine(
    lease: &AdmittedLease,
    result: ExecutionResult,
) -> Result<JobExecution, RunnerError> {
    let credential_taint = result.credential_taint();
    let result_bytes = serde_json::to_vec(&result).map_err(RunnerError::ResultEncoding)?;
    if result_bytes.len() > MAX_RESULT_BYTES {
        return Err(RunnerError::ResultLimitExceeded {
            limit: MAX_RESULT_BYTES,
            actual: result_bytes.len(),
        });
    }
    let result_digest = ContentDigest::sha256(result_bytes);
    let job = result
        .jobs
        .get(&lease.job_id)
        .ok_or_else(|| RunnerError::OfferedJobMissing(lease.job_id.clone()))?;
    let (final_state, error_code) = match job.state {
        JobState::Succeeded => ("succeeded", ""),
        // The runner v2 completion protocol has no distinct skipped terminal
        // state. A condition-false job executes no steps and is therefore a
        // successful no-op from the worker's perspective.
        JobState::Skipped => ("succeeded", ""),
        JobState::Canceled => ("canceled", "canceled"),
        JobState::TimedOut => ("timed_out", "timed_out"),
        _ => ("failed", "execution_failed"),
    };
    let exit_code = job
        .attempts
        .last()
        .and_then(|attempt| attempt.steps.last())
        .and_then(|step| step.output.as_ref())
        .and_then(|output| output.exit_code);
    let log_frames = bounded_log_frames(lease, &result)?;
    Ok(JobExecution {
        final_state: final_state.to_owned(),
        exit_code,
        error_code: error_code.to_owned(),
        result_digest,
        log_frames,
        final_job_attempt: job.attempts.last().map_or(0, |attempt| attempt.number),
        artifact_ids: Vec::new(),
        cache_entry_ids: Vec::new(),
        credential_taint,
    })
}

pub(super) fn bounded_log_frames(
    lease: &AdmittedLease,
    result: &ExecutionResult,
) -> Result<Vec<v1::LogFrame>, RunnerError> {
    if result.credential_taint().is_tainted() {
        // Workspace state can carry a transformed credential into later
        // steps, whose individual executor output would otherwise look
        // untainted. Suppress the complete execution log stream once any
        // credential crossed the guest boundary.
        return Ok(Vec::new());
    }
    let mut frames = Vec::new();
    let mut sequences = BTreeMap::<(u32, String, String), u64>::new();
    let Some(job) = result.jobs.get(&lease.job_id) else {
        return Err(RunnerError::OfferedJobMissing(lease.job_id.clone()));
    };
    for attempt in &job.attempts {
        for step in &attempt.steps {
            let Some(output) = &step.output else {
                continue;
            };
            for (stream, payload) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
                let sequence = sequences
                    .entry((attempt.number, step.id.clone(), stream.to_owned()))
                    .or_default();
                for chunk in payload.as_bytes().chunks(MAX_LOG_FRAME_BYTES) {
                    if frames.len() >= MAX_LOG_FRAMES {
                        return Ok(frames);
                    }
                    frames.push(v1::LogFrame {
                        // The v1 offer does not carry a run id. The lease id is
                        // an unambiguous fenced stream scope until that field is
                        // added to a future protocol generation.
                        run_id: lease.lease_id.clone(),
                        job_id: lease.job_id.clone(),
                        step_id: step.id.clone(),
                        sequence: *sequence,
                        stream: stream.to_owned(),
                        monotonic_nanoseconds: u64::try_from(frames.len())
                            .map_err(|_| RunnerError::LogSequenceOverflow)?
                            .saturating_mul(1_000_000),
                        wall_time: Some(timestamp(now_unix_ms()?)),
                        payload: chunk.to_vec(),
                        // A declaration alone says nothing about whether a
                        // credential was released. Tainted frames are omitted
                        // above; these bytes came from an untainted step.
                        redaction_state: "credential_taint_absent".to_owned(),
                        job_attempt: attempt.number,
                    });
                    *sequence = sequence
                        .checked_add(1)
                        .ok_or(RunnerError::LogSequenceOverflow)?;
                }
            }
        }
    }
    Ok(frames)
}
