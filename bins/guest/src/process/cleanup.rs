use crate::GuestAgentError;
use std::{
    process::{Child, ExitStatus},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use nix::{
    errno::Errno,
    sys::signal::{killpg, Signal},
    unistd::Pid,
};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const CLEANUP_VERIFY_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) fn terminate_child(
    child: &mut Child,
    process_group: i32,
) -> Result<ExitStatus, GuestAgentError> {
    signal_group(process_group, Signal::SIGTERM)?;
    let deadline = Instant::now() + TERMINATION_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => break,
            Err(error) => return Err(GuestAgentError::Process(error.to_string())),
        }
    }
    signal_group(process_group, Signal::SIGKILL)?;
    child
        .wait()
        .map_err(|error| GuestAgentError::Process(error.to_string()))
}

#[cfg(unix)]
fn signal_group(process_group: i32, signal: Signal) -> Result<(), GuestAgentError> {
    match killpg(Pid::from_raw(process_group), signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(GuestAgentError::Process(error.to_string())),
    }
}

#[cfg(not(unix))]
fn signal_group(_process_group: i32, _signal: ()) -> Result<(), GuestAgentError> {
    Err(GuestAgentError::Process(
        "process groups require Unix".to_owned(),
    ))
}

#[cfg(unix)]
pub(super) fn cleanup_and_verify_process_group(
    process_group: i32,
) -> Result<bool, GuestAgentError> {
    signal_group(process_group, Signal::SIGKILL)?;
    let deadline = Instant::now() + CLEANUP_VERIFY_TIMEOUT;
    loop {
        match killpg(Pid::from_raw(process_group), None) {
            Err(Errno::ESRCH) => return Ok(true),
            Ok(()) | Err(Errno::EPERM) if Instant::now() < deadline => {
                thread::sleep(POLL_INTERVAL);
            }
            Ok(()) | Err(Errno::EPERM) => {
                return Err(GuestAgentError::Process(
                    "guest process group is still alive after cleanup".to_owned(),
                ));
            }
            Err(error) => return Err(GuestAgentError::Process(error.to_string())),
        }
    }
}

#[cfg(not(unix))]
pub(super) fn cleanup_and_verify_process_group(
    _process_group: i32,
) -> Result<bool, GuestAgentError> {
    Err(GuestAgentError::Process(
        "process groups require Unix".to_owned(),
    ))
}
