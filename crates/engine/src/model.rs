//! Public execution result and request model.

use crate::{CancellationToken, EngineEvent};
use runtrue_lifecycle::{JobState, RunState, SkipReason, StepState};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{
    RunnerRequirements, ScalarValue, Shell, StepCapabilitySet, TypedOutputRecord,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type RuntimeContext = BTreeMap<String, ScalarValue>;

/// Conservative information-flow marker for guest-visible credentials.
///
/// This is intentionally not a claim that an untainted execution is free of
/// all sensitive data. It records the narrower, auditable fact that a secret
/// or OIDC credential crossed the executor's guest boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialTaint {
    #[default]
    None,
    CredentialReleased,
}

impl CredentialTaint {
    #[must_use]
    pub const fn is_tainted(self) -> bool {
        matches!(self, Self::CredentialReleased)
    }

    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        if self.is_tainted() || other.is_tainted() {
            Self::CredentialReleased
        } else {
            Self::None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub state: RunState,
    pub jobs: BTreeMap<String, JobResult>,
    pub events: Vec<EngineEvent>,
    #[serde(default, skip_serializing_if = "credential_taint_is_none")]
    pub credential_taint: CredentialTaint,
}

impl ExecutionResult {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.state == RunState::Succeeded
    }

    /// Aggregate credential-release taint across every job attempt.
    #[must_use]
    pub fn credential_taint(&self) -> CredentialTaint {
        self.jobs
            .values()
            .flat_map(|job| &job.attempts)
            .fold(self.credential_taint, |taint, attempt| {
                taint.merge(attempt.credential_taint())
            })
    }

    /// Apply a monotonic workspace-level taint discovered outside an executor
    /// output, such as an OCI credential file injected by the runner.
    pub fn apply_credential_taint(&mut self, taint: CredentialTaint) {
        self.credential_taint = self.credential_taint.merge(taint);
        if !self.credential_taint.is_tainted() {
            return;
        }
        for job in self.jobs.values_mut() {
            job.outputs.clear();
            for attempt in &mut job.attempts {
                attempt.credential_taint = attempt.credential_taint.merge(self.credential_taint);
                for step in attempt.steps.iter_mut().chain(&mut attempt.finalizers) {
                    step.outputs.clear();
                    if let Some(output) = &mut step.output {
                        output.credential_taint =
                            output.credential_taint.merge(self.credential_taint);
                        output.suppress_tainted_publication();
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResult {
    pub id: String,
    pub state: JobState,
    pub skip_reason: Option<SkipReason>,
    pub attempts: Vec<JobAttemptResult>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub outputs: BTreeMap<String, TypedOutputRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobAttemptResult {
    pub number: u32,
    /// Result of normal steps before finalizers. Finalizers cannot rewrite it.
    pub primary_state: JobState,
    #[serde(default, skip_serializing_if = "credential_taint_is_none")]
    pub credential_taint: CredentialTaint,
    pub steps: Vec<StepResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finalizers: Vec<StepResult>,
}

impl JobAttemptResult {
    /// Return the conservative effective taint, validating the aggregate field
    /// against its nested executor outputs.
    #[must_use]
    pub fn credential_taint(&self) -> CredentialTaint {
        self.steps
            .iter()
            .chain(&self.finalizers)
            .filter_map(|step| step.output.as_ref())
            .fold(self.credential_taint, |taint, output| {
                taint.merge(output.credential_taint)
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    pub id: String,
    pub state: StepState,
    pub continued_on_error: bool,
    pub skip_reason: Option<SkipReason>,
    pub output: Option<ExecutorOutput>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub outputs: BTreeMap<String, TypedOutputRecord>,
}

/// An action after all value bindings have been resolved to inert strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedAction {
    Component {
        reference: String,
        inputs: BTreeMap<String, String>,
    },
    Command {
        program: String,
        args: Vec<String>,
    },
    Script {
        shell: Shell,
        script: String,
        script_digest: ContentDigest,
    },
}

/// Fully prepared input to an execution backend.
#[derive(Debug, Clone)]
pub struct StepExecutionRequest {
    pub job_id: String,
    pub step_id: String,
    pub job_attempt: u32,
    pub runner: RunnerRequirements,
    pub action: PreparedAction,
    pub environment: BTreeMap<String, String>,
    pub working_directory: Option<String>,
    pub capabilities: StepCapabilitySet,
    pub timeout_ms: Option<u64>,
    pub cancellation: CancellationToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// Backend-produced, canonical structured output. Component executors use
    /// this for their typed JSON object; process backends leave it unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_output: Option<String>,
    /// Set only when credential material crossed into the guest. Durable
    /// publishers must fail closed when this is tainted.
    #[serde(default, skip_serializing_if = "credential_taint_is_none")]
    pub credential_taint: CredentialTaint,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub canceled: bool,
    pub duration_ms: u64,
}

impl ExecutorOutput {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && !self.canceled
    }

    /// Convenience constructor for backend and engine tests.
    #[must_use]
    pub fn success() -> Self {
        Self {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            structured_output: None,
            credential_taint: CredentialTaint::None,
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            canceled: false,
            duration_ms: 0,
        }
    }

    /// Convenience constructor for a normal non-zero process exit.
    #[must_use]
    pub fn failure(exit_code: i32) -> Self {
        Self {
            exit_code: Some(exit_code),
            ..Self::success()
        }
    }

    /// Remove all guest-controlled material that could encode or transform a
    /// released credential while retaining lifecycle and diagnostic metadata.
    pub fn suppress_tainted_publication(&mut self) {
        if self.credential_taint.is_tainted() {
            self.stdout.clear();
            self.stderr.clear();
            self.structured_output = None;
        }
    }
}

fn credential_taint_is_none(taint: &CredentialTaint) -> bool {
    *taint == CredentialTaint::None
}
