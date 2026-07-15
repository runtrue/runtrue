use super::{error::RunnerError, executor::JobExecution, observations::StepLifecycleMessage};
use crate::state::PersistedCommittedObject;
use runtrue_engine::CancellationToken;
use runtrue_protocol::v1;
use runtrue_runner_core::LeaseExecutionGuard;
use std::path::PathBuf;
use tokio::{sync::mpsc as tokio_mpsc, task::JoinHandle};

pub(super) struct ActiveExecution {
    pub(super) offer: v1::LeaseOffer,
    pub(super) guard: LeaseExecutionGuard,
    pub(super) cancellation: CancellationToken,
    pub(super) hard_deadline: Option<tokio::time::Instant>,
    pub(super) workspace: PathBuf,
    pub(super) task: JoinHandle<Result<CompletedExecution, RunnerError>>,
    pub(super) lifecycle: tokio_mpsc::Receiver<StepLifecycleMessage>,
    pub(super) lifecycle_open: bool,
    pub(super) last_job_attempt: u32,
}

pub(super) struct CompletedExecution {
    pub(super) outcome: JobExecution,
    pub(super) committed_objects: Vec<PersistedCommittedObject>,
}

impl Drop for ActiveExecution {
    fn drop(&mut self) {
        // Any stream/session failure must stop active work. The durable marker
        // and workspace intentionally remain for startup cleanup; execution is
        // never detached and resumed under a new connection.
        self.cancellation.cancel();
    }
}

pub(super) enum LoopEvent {
    Heartbeat,
    Control(Option<v1::ControlMessage>),
    ExecutionFinished(Result<Result<CompletedExecution, RunnerError>, tokio::task::JoinError>),
    StepLifecycle(Option<StepLifecycleMessage>),
    LeaseDeadline,
    DrainDeadline,
    RotationDeadline,
}
