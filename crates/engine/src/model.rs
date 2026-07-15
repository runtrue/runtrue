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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub state: RunState,
    pub jobs: BTreeMap<String, JobResult>,
    pub events: Vec<EngineEvent>,
}

impl ExecutionResult {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.state == RunState::Succeeded
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
    pub steps: Vec<StepResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finalizers: Vec<StepResult>,
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
}
