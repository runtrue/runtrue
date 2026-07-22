use runtrue_engine::{StepStateObservation, StepStateObserver};
use std::sync::mpsc as std_mpsc;
use tokio::sync::mpsc as tokio_mpsc;

pub(super) struct StepLifecycleMessage {
    pub(super) lease_id: String,
    pub(super) observation: StepStateObservation,
    pub(super) response: std_mpsc::SyncSender<Result<(), String>>,
}

pub(super) struct DaemonStepStateObserver {
    pub(super) lease_id: String,
    pub(super) sender: tokio_mpsc::Sender<StepLifecycleMessage>,
}

impl StepStateObserver for DaemonStepStateObserver {
    fn observe(&self, observation: &StepStateObservation) -> Result<(), String> {
        if !publish_step_observation(observation) {
            return Ok(());
        }
        let (response, receiver) = std_mpsc::sync_channel(1);
        self.sender
            .blocking_send(StepLifecycleMessage {
                lease_id: self.lease_id.clone(),
                observation: observation.clone(),
                response,
            })
            .map_err(|_| "runner lifecycle channel closed".to_owned())?;
        receiver
            .recv()
            .map_err(|_| "runner lifecycle acknowledgement channel closed".to_owned())?
    }
}

pub(super) fn publish_step_observation(observation: &StepStateObservation) -> bool {
    observation.to == runtrue_engine::StepState::Running
        || observation.to == runtrue_engine::StepState::Skipped
        || (observation.from == Some(runtrue_engine::StepState::Running)
            && observation.to.is_terminal())
}

pub(super) const fn step_state_name(state: runtrue_engine::StepState) -> &'static str {
    match state {
        runtrue_engine::StepState::Created => "created",
        runtrue_engine::StepState::Running => "running",
        runtrue_engine::StepState::Succeeded => "succeeded",
        runtrue_engine::StepState::Failed => "failed",
        runtrue_engine::StepState::Canceled => "canceled",
        runtrue_engine::StepState::TimedOut => "timed_out",
        runtrue_engine::StepState::Skipped => "skipped",
    }
}

pub(super) const fn step_error_code(state: runtrue_engine::StepState) -> &'static str {
    match state {
        runtrue_engine::StepState::Failed => "step_failed",
        runtrue_engine::StepState::Canceled => "canceled",
        runtrue_engine::StepState::TimedOut => "timed_out",
        runtrue_engine::StepState::Created
        | runtrue_engine::StepState::Running
        | runtrue_engine::StepState::Succeeded
        | runtrue_engine::StepState::Skipped => "",
    }
}
