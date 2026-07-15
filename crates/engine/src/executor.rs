//! Backend-neutral executor contract.

use crate::{ExecutorError, ExecutorOutput, StepExecutionRequest};
use runtrue_workflow_ir::{ExecutionCapsule, PlannedJob};

/// Execution backends implement one synchronous operation. The cancellation
/// token and timeout are part of the request so a backend can interrupt its
/// own isolation boundary correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobAttemptOutcome {
    Succeeded,
    Failed,
    TimedOut,
    Canceled,
    Aborted,
}

pub trait Executor {
    /// Validate that this backend can honor every feature in the complete capsule.
    /// This runs before any step or run-state transition.
    fn preflight(&self, capsule: &ExecutionCapsule) -> Result<(), ExecutorError>;

    fn execute(&mut self, request: &StepExecutionRequest) -> Result<ExecutorOutput, ExecutorError>;

    /// Release every job-scoped resource before an attempt can be reported or
    /// retried. Backends must explicitly opt into a no-op; the default rejects
    /// finalization so a newly added stateful backend cannot silently leak.
    fn finish_job_attempt(
        &mut self,
        _job: &PlannedJob,
        _attempt: u32,
        _outcome: JobAttemptOutcome,
    ) -> Result<(), ExecutorError> {
        Err(ExecutorError::UnsupportedCapsuleFeature(
            "execution backend does not implement job-attempt finalization".to_owned(),
        ))
    }
}
