use super::{
    job::validate_admitted_job,
    protocol::{now_unix_ms, receive_command},
    steps::{emit_execution_logs, handle_running_command, StepWorker},
};
use crate::{GuestAgentError, GuestFrameReader, GuestFrameWriter, StepExecutor};
use runtrue_guest_core::{
    GuestAction, GuestBootConfig, GuestCapsuleTrustStore, GuestSession, GuestStepResult,
    ResourceSample,
};
use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);
const RESOURCE_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(250);

pub fn serve_one_job<R, W>(
    mut boot: GuestBootConfig,
    trust: GuestCapsuleTrustStore,
    reader: R,
    writer: W,
    executor: Arc<dyn StepExecutor>,
) -> Result<(), GuestAgentError>
where
    R: Read + Send + 'static,
    W: Write,
{
    boot.validate()?;
    let bootstrap = boot.bootstrap.clone();
    let key = boot.take_session_key()?;
    let mut session = GuestSession::new(bootstrap, key, trust, now_unix_ms()?)?;
    let (command_sender, command_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut reader = GuestFrameReader::new(reader);
        loop {
            let command = reader.receive();
            let failed = command.is_err();
            if command_sender.send(command).is_err() || failed {
                break;
            }
        }
    });
    let mut writer = GuestFrameWriter::new(writer);
    writer.send(&session.hello()?)?;

    let first = receive_command(&command_receiver)?;
    let accepted = session.accept(first, now_unix_ms()?)?;
    let GuestAction::Send(job_accepted) = accepted else {
        return Err(GuestAgentError::Protocol(
            "first authenticated command must admit the signed capsule".to_owned(),
        ));
    };
    let job = session.admitted_job()?.clone();
    validate_admitted_job(&job)?;
    let job_deadline = Instant::now()
        .checked_add(Duration::from_millis(job.timeout_ms))
        .ok_or_else(|| {
            GuestAgentError::InvalidConfiguration("job deadline overflows".to_owned())
        })?;
    writer.send(&job_accepted)?;

    let mut next_step = 0_usize;
    loop {
        let command = receive_command(&command_receiver)?;
        let action = session.accept(command, now_unix_ms()?)?;
        let GuestAction::StartStep(authorized) = action else {
            return Err(GuestAgentError::Protocol(
                "expected an authenticated StartStep command".to_owned(),
            ));
        };
        let expected = job.steps.get(next_step).ok_or_else(|| {
            GuestAgentError::Protocol("host attempted to start an extra step".to_owned())
        })?;
        if authorized.step.id != expected.id {
            return Err(GuestAgentError::Protocol(
                "host attempted to reorder signed job steps".to_owned(),
            ));
        }
        writer.send(&session.step_ready(now_unix_ms()?)?)?;

        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_cancellation = Arc::clone(&cancellation);
        let worker_executor = Arc::clone(&executor);
        let job_timeout = job_deadline.saturating_duration_since(Instant::now());
        if job_timeout.is_zero() {
            return Err(GuestAgentError::Process(
                "signed job deadline elapsed before the step could start".to_owned(),
            ));
        }
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let worker_handle = thread::spawn(move || {
            let result = worker_executor.execute(*authorized, job_timeout, worker_cancellation);
            let _ = result_sender.send(result);
        });
        let mut worker = StepWorker::new(Arc::clone(&cancellation), worker_handle);
        let mut requested_signal = None;
        let step_started = Instant::now();
        let mut last_resource_heartbeat = step_started;
        let execution = loop {
            match command_receiver.try_recv() {
                Ok(command) => handle_running_command(
                    &mut session,
                    command?,
                    &cancellation,
                    &mut requested_signal,
                )?,
                Err(mpsc::TryRecvError::Disconnected) => {
                    cancellation.store(true, Ordering::Release);
                    let _ = worker.finish();
                    return Err(GuestAgentError::Transport(
                        "host command stream disconnected".to_owned(),
                    ));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match result_receiver.try_recv() {
                Ok(result) => break result?,
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(GuestAgentError::Process(
                        "guest step worker disconnected".to_owned(),
                    ));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match command_receiver.recv_timeout(COMMAND_POLL_INTERVAL) {
                Ok(command) => handle_running_command(
                    &mut session,
                    command?,
                    &cancellation,
                    &mut requested_signal,
                )?,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    cancellation.store(true, Ordering::Release);
                    let _ = worker.finish();
                    return Err(GuestAgentError::Transport(
                        "host command stream disconnected".to_owned(),
                    ));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if last_resource_heartbeat.elapsed() >= RESOURCE_HEARTBEAT_INTERVAL {
                writer.send(&session.record_resource_sample(
                    ResourceSample {
                        step_id: expected.id.clone(),
                        monotonic_ms:
                            u64::try_from(step_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        // The direct process adapter does not yet expose a
                        // race-safe pidfd metrics reader. These zero-valued
                        // counters are an authenticated liveness sample, not
                        // fabricated usage evidence.
                        cpu_time_ms: 0,
                        resident_memory_bytes: 0,
                        read_bytes: 0,
                        written_bytes: 0,
                    },
                    now_unix_ms()?,
                )?)?;
                last_resource_heartbeat = Instant::now();
            }
        };
        worker.finish()?;
        if !execution.process_group_clean {
            return Err(GuestAgentError::Process(
                "guest step process group was not cleaned".to_owned(),
            ));
        }
        if let Some(signal) = requested_signal {
            writer.send(&session.acknowledge_signal(&expected.id, signal, now_unix_ms()?)?)?;
        }
        emit_execution_logs(&mut session, &mut writer, &expected.id, &execution)?;
        let result = GuestStepResult {
            step_id: expected.id.clone(),
            attempt: 1,
            exit_code: execution.exit_code,
            timed_out: execution.timed_out,
            canceled: execution.canceled,
            skipped: false,
        };
        writer.send(&session.record_step_result(result.clone(), now_unix_ms()?)?)?;
        next_step += 1;
        let failed = result.timed_out || result.canceled || result.exit_code != Some(0);
        if failed && !expected.continue_on_error {
            for remaining in job.steps.iter().skip(next_step) {
                writer.send(&session.record_step_skipped(&remaining.id, now_unix_ms()?)?)?;
            }
            next_step = job.steps.len();
        }
        if next_step == job.steps.len() {
            writer.send(&session.finish_job(now_unix_ms()?)?)?;
            break;
        }
    }

    let shutdown = receive_command(&command_receiver)?;
    if !matches!(
        session.accept(shutdown, now_unix_ms()?)?,
        GuestAction::Shutdown
    ) {
        return Err(GuestAgentError::Protocol(
            "expected authenticated shutdown".to_owned(),
        ));
    }
    writer.send(&session.shutdown_ready(now_unix_ms()?)?)?;
    Ok(())
}
