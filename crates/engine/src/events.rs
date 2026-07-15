//! Deterministic lifecycle events and observers.

use crate::CredentialTaint;
use runtrue_lifecycle::{JobState, RunState, StepState};
use serde::{Deserialize, Serialize};

/// Deterministic events emitted by the state machine. Sequence numbers are
/// local to a single run; wall-clock timestamps are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineEvent {
    pub sequence: u64,
    pub kind: EngineEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineEventKind {
    RunStateChanged {
        from: Option<RunState>,
        to: RunState,
    },
    JobStateChanged {
        job_id: String,
        from: Option<JobState>,
        to: JobState,
    },
    JobAttemptStarted {
        job_id: String,
        attempt: u32,
    },
    StepStateChanged {
        job_id: String,
        step_id: String,
        job_attempt: u32,
        from: Option<StepState>,
        to: StepState,
    },
}

/// A synchronous observation emitted at the exact point a step state
/// transition is recorded. Remote runners use this hook to put fenced state
/// on their live control stream before a capability adapter can execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepStateObservation {
    pub job_id: String,
    pub step_id: String,
    pub job_attempt: u32,
    pub from: Option<StepState>,
    pub to: StepState,
    /// Credential taint observed while executing this step. Non-terminal
    /// observations carry [`CredentialTaint::None`].
    pub credential_taint: CredentialTaint,
}

/// Observer for real-time step lifecycle transitions.
///
/// Implementations must not retain references to the observation. Returning
/// an error fails the execution before the next state-machine operation.
pub trait StepStateObserver: Send + Sync {
    fn observe(&self, observation: &StepStateObservation) -> Result<(), String>;
}
