use crate::GuestAgentError;
use runtrue_guest_core::AuthenticatedEnvelope;
use std::{
    sync::mpsc,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) fn receive_command(
    receiver: &mpsc::Receiver<Result<AuthenticatedEnvelope, GuestAgentError>>,
) -> Result<AuthenticatedEnvelope, GuestAgentError> {
    receiver
        .recv()
        .map_err(|_| GuestAgentError::Transport("host command stream ended".to_owned()))?
}

pub(super) fn now_unix_ms() -> Result<u64, GuestAgentError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| GuestAgentError::Protocol(error.to_string()))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| GuestAgentError::Protocol("wall-clock milliseconds overflow".to_owned()))
}
