use super::protocol::now_unix_ms;
use crate::{GuestAgentError, GuestFrameWriter, StepExecution};
use runtrue_guest_core::{
    AuthenticatedEnvelope, GuestAction, GuestSession, LogStream, StepSignal, MAX_LOG_FRAME_BYTES,
};
use std::{
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

pub(super) struct StepWorker {
    cancellation: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl StepWorker {
    pub(super) fn new(cancellation: Arc<AtomicBool>, handle: thread::JoinHandle<()>) -> Self {
        Self {
            cancellation,
            handle: Some(handle),
        }
    }

    pub(super) fn finish(&mut self) -> Result<(), GuestAgentError> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        handle
            .join()
            .map_err(|_| GuestAgentError::Process("guest step worker panicked".to_owned()))
    }
}

impl Drop for StepWorker {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        self.cancellation.store(true, Ordering::Release);
        let _ = handle.join();
    }
}

pub(super) fn handle_running_command(
    session: &mut GuestSession,
    command: AuthenticatedEnvelope,
    cancellation: &AtomicBool,
    requested_signal: &mut Option<StepSignal>,
) -> Result<(), GuestAgentError> {
    match session.accept(command, now_unix_ms()?)? {
        GuestAction::SignalStep { signal, .. } if requested_signal.is_none() => {
            *requested_signal = Some(signal);
            cancellation.store(true, Ordering::Release);
            Ok(())
        }
        _ => Err(GuestAgentError::Protocol(
            "only one authenticated signal is accepted while a step runs".to_owned(),
        )),
    }
}

pub(super) fn emit_execution_logs<W: Write>(
    session: &mut GuestSession,
    writer: &mut GuestFrameWriter<W>,
    step_id: &str,
    execution: &StepExecution,
) -> Result<(), GuestAgentError> {
    for chunk in execution.stdout.chunks(MAX_LOG_FRAME_BYTES) {
        writer.send(&session.record_log(
            step_id,
            LogStream::Stdout,
            chunk.to_vec(),
            now_unix_ms()?,
        )?)?;
    }
    for chunk in execution.stderr.chunks(MAX_LOG_FRAME_BYTES) {
        writer.send(&session.record_log(
            step_id,
            LogStream::Stderr,
            chunk.to_vec(),
            now_unix_ms()?,
        )?)?;
    }
    if execution.stdout_truncated || execution.stderr_truncated {
        writer.send(&session.record_log(
            step_id,
            LogStream::System,
            b"runtrue-guest: output was truncated at the configured bound\n".to_vec(),
            now_unix_ms()?,
        )?)?;
    }
    Ok(())
}
