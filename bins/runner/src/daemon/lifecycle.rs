use super::{error::RunnerError, executor::JobExecution, observations::StepLifecycleMessage};
use crate::state::PersistedCommittedObject;
use runtrue_engine::CancellationToken;
use runtrue_protocol::v1;
use runtrue_runner_core::LeaseExecutionGuard;
use std::{path::PathBuf, sync::Arc};
use tokio::task::JoinHandle;

use super::admission_gate::LeaseAdmissionPermit;

pub(super) struct ActiveExecution {
    pub(super) _admission_permit: Option<Arc<LeaseAdmissionPermit>>,
    pub(super) offer: v1::LeaseOffer,
    pub(super) guard: LeaseExecutionGuard,
    pub(super) cancellation: CancellationToken,
    pub(super) hard_deadline: Option<tokio::time::Instant>,
    pub(super) workspace: PathBuf,
    pub(super) task: JoinHandle<()>,
    pub(super) last_job_attempt: u32,
}

pub(super) struct CompletedExecution {
    pub(super) outcome: JobExecution,
    pub(super) committed_objects: Vec<PersistedCommittedObject>,
}

pub(super) struct ExecutionTaskMessage {
    pub(super) lease_id: String,
    pub(super) result: Result<Result<CompletedExecution, RunnerError>, tokio::task::JoinError>,
}

impl Drop for ActiveExecution {
    fn drop(&mut self) {
        // Any stream/session failure must stop active work. The durable marker
        // and workspace intentionally remain for startup cleanup; execution is
        // never detached and resumed under a new connection.
        self.cancellation.cancel();
        self.task.abort();
    }
}

pub(super) enum LoopEvent {
    Heartbeat,
    Control(Option<v1::ControlMessage>),
    ExecutionFinished(Option<ExecutionTaskMessage>),
    StepLifecycle(Option<StepLifecycleMessage>),
    LeaseDeadline,
    DrainDeadline,
    RotationDeadline,
}
