//! External runtime process supervision.

use crate::{OciError, RuntimeCommandRunner, RuntimeControl, RuntimeInvocation, RuntimeResult};
use std::{
    fs,
    io::{self, Read},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
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
const TERMINATION_GRACE: Duration = Duration::from_millis(100);
const CLEANUP_VERIFY_TIMEOUT: Duration = Duration::from_secs(1);

/// Real external-runtime supervisor. Construction fails under host root: user
/// namespaces are defense in depth, not permission to launch the runtime as a
/// privileged host process.
#[derive(Debug, Default)]
pub struct ProcessCommandRunner;

impl ProcessCommandRunner {
    pub fn new() -> Result<Self, OciError> {
        #[cfg(target_os = "linux")]
        {
            if effective_uid()? == 0 {
                return Err(OciError::InvalidConfiguration(
                    "the OCI runtime must run as a non-root host user".to_owned(),
                ));
            }
            Ok(Self)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(OciError::UnsupportedPlatform(
                std::env::consts::OS.to_owned(),
            ))
        }
    }

    #[cfg(test)]
    pub(crate) const fn unchecked_for_test() -> Self {
        Self
    }
}

impl RuntimeCommandRunner for ProcessCommandRunner {
    fn invoke(
        &mut self,
        invocation: &RuntimeInvocation,
        control: &RuntimeControl,
    ) -> Result<RuntimeResult, OciError> {
        if control.timeout.is_zero() || control.max_output_bytes == 0 {
            return Err(OciError::InvalidConfiguration(
                "runtime timeout and output bound must be non-zero".to_owned(),
            ));
        }
        crate::validate_environment(
            &invocation.environment,
            crate::OciLimits::default(),
            crate::EnvironmentScope::Runtime,
        )?;
        validate_program(invocation)?;
        let mut command = Command::new(&invocation.program);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        command
            .args(&invocation.arguments)
            .env_clear()
            .envs(&invocation.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|error| OciError::Spawn(error.to_string()))?;
        let process_group = match i32::try_from(child.id()) {
            Ok(process_group) => process_group,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(OciError::ProcessCleanup(
                    "runtime process id does not fit platform pid".to_owned(),
                ));
            }
        };
        let stdout = child.stdout.take().ok_or_else(|| {
            let _ = terminate_child(&mut child, process_group);
            OciError::Spawn("runtime stdout pipe was not created".to_owned())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            let _ = terminate_child(&mut child, process_group);
            OciError::Spawn("runtime stderr pipe was not created".to_owned())
        })?;
        let stdout_reader = match CaptureTask::start(stdout, control.max_output_bytes) {
            Ok(reader) => reader,
            Err(error) => {
                let _ = terminate_child(&mut child, process_group);
                let _ = cleanup_and_verify_process_group(process_group);
                return Err(error);
            }
        };
        let stderr_reader = match CaptureTask::start(stderr, control.max_output_bytes) {
            Ok(reader) => reader,
            Err(error) => {
                let _ = terminate_child(&mut child, process_group);
                let _ = cleanup_and_verify_process_group(process_group);
                drop(stdout_reader);
                return Err(error);
            }
        };
        let deadline = started.checked_add(control.timeout).ok_or_else(|| {
            OciError::InvalidConfiguration("runtime timeout overflows".to_owned())
        })?;
        let wait_result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok((status, false, false)),
                Ok(None) => {}
                Err(error) => {
                    let cleanup = terminate_child(&mut child, process_group);
                    break match cleanup {
                        Ok(_) => Err(OciError::Wait(error.to_string())),
                        Err(cleanup_error) => Err(OciError::Wait(format!(
                            "{error}; process cleanup also failed: {cleanup_error}"
                        ))),
                    };
                }
            }
            if control.cancellation.is_cancelled() {
                break terminate_child(&mut child, process_group)
                    .map(|status| (status, false, true));
            }
            if Instant::now() >= deadline {
                break terminate_child(&mut child, process_group)
                    .map(|status| (status, true, false));
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        };
        let cleanup_result = cleanup_and_verify_process_group(process_group);
        let stdout = stdout_reader.finish("stdout");
        let stderr = stderr_reader.finish("stderr");
        let (status, timed_out, canceled) = wait_result?;
        let process_group_clean = cleanup_result?;
        let stdout = stdout?;
        let stderr = stderr?;
        Ok(RuntimeResult {
            exit_code: status.code(),
            stdout: stdout.bytes,
            stderr: stderr.bytes,
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
            timed_out,
            canceled,
            duration: started.elapsed(),
            process_group_clean,
        })
    }
}

fn validate_program(invocation: &RuntimeInvocation) -> Result<(), OciError> {
    if !invocation.program.is_absolute() {
        return Err(OciError::InvalidConfiguration(
            "runtime executable path must be absolute".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(&invocation.program)
        .map_err(|error| OciError::Spawn(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(OciError::InvalidConfiguration(
            "runtime executable must be a regular non-symlink file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(OciError::InvalidConfiguration(
                "runtime executable is not executable".to_owned(),
            ));
        }
    }
    Ok(())
}

struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

struct CaptureTask {
    stop: Arc<AtomicBool>,
    done: mpsc::Receiver<()>,
    thread: Option<thread::JoinHandle<Result<Captured, io::Error>>>,
}

impl CaptureTask {
    #[cfg(unix)]
    fn start<T>(mut stream: T, limit: usize) -> Result<Self, OciError>
    where
        T: Read + Send + std::os::fd::AsRawFd + 'static,
    {
        use nix::fcntl::{fcntl, FcntlArg, OFlag};
        let descriptor = stream.as_raw_fd();
        let current = fcntl(descriptor, FcntlArg::F_GETFL)
            .map_err(|error| OciError::Wait(error.to_string()))?;
        let flags = OFlag::from_bits_truncate(current) | OFlag::O_NONBLOCK;
        fcntl(descriptor, FcntlArg::F_SETFL(flags))
            .map_err(|error| OciError::Wait(error.to_string()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        let (done_sender, done) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = capture_nonblocking(&mut stream, limit, &reader_stop);
            let _ = done_sender.send(());
            result
        });
        Ok(Self {
            stop,
            done,
            thread: Some(thread),
        })
    }

    #[cfg(not(unix))]
    fn start<T>(mut stream: T, limit: usize) -> Result<Self, OciError>
    where
        T: Read + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        let (done_sender, done) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = capture_nonblocking(&mut stream, limit, &reader_stop);
            let _ = done_sender.send(());
            result
        });
        Ok(Self {
            stop,
            done,
            thread: Some(thread),
        })
    }

    fn finish(mut self, stream_name: &'static str) -> Result<Captured, OciError> {
        if self.done.recv_timeout(Duration::from_millis(100)).is_err() {
            self.stop.store(true, Ordering::Release);
        }
        self.thread
            .take()
            .expect("capture thread is present")
            .join()
            .map_err(|_| OciError::Wait(format!("{stream_name} capture thread panicked")))?
            .map_err(|error| OciError::Wait(error.to_string()))
    }
}

impl Drop for CaptureTask {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn capture_nonblocking(
    stream: &mut impl Read,
    limit: usize,
    stop: &AtomicBool,
) -> Result<Captured, io::Error> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; 16 * 1024];
    let mut truncated = false;
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let retained = limit.saturating_sub(bytes.len()).min(read);
                bytes.extend_from_slice(&buffer[..retained]);
                truncated |= retained < read;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Captured { bytes, truncated })
}

fn terminate_child(child: &mut Child, process_group: i32) -> Result<ExitStatus, OciError> {
    #[cfg(unix)]
    {
        let group = Pid::from_raw(process_group);
        let _ = killpg(group, Signal::SIGTERM);
        let deadline = Instant::now() + TERMINATION_GRACE;
        while Instant::now() < deadline {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| OciError::Wait(error.to_string()))?
            {
                let _ = killpg(group, Signal::SIGKILL);
                return Ok(status);
            }
            thread::sleep(POLL_INTERVAL);
        }
        let _ = killpg(group, Signal::SIGKILL);
    }
    #[cfg(not(unix))]
    {
        let _ = process_group;
    }
    let _ = child.kill();
    child
        .wait()
        .map_err(|error| OciError::Wait(error.to_string()))
}

fn cleanup_and_verify_process_group(process_group: i32) -> Result<bool, OciError> {
    #[cfg(unix)]
    {
        let group = Pid::from_raw(process_group);
        match killpg(group, None) {
            Err(Errno::ESRCH) => return Ok(true),
            Ok(()) | Err(_) => {
                let _ = killpg(group, Signal::SIGTERM);
                thread::sleep(TERMINATION_GRACE);
                let _ = killpg(group, Signal::SIGKILL);
            }
        }
        let deadline = Instant::now() + CLEANUP_VERIFY_TIMEOUT;
        loop {
            match killpg(group, None) {
                Err(Errno::ESRCH) => return Ok(true),
                Ok(()) | Err(_) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                Ok(()) | Err(_) => return Ok(false),
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = process_group;
        Ok(false)
    }
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32, OciError> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| OciError::InvalidConfiguration(error.to_string()))?;
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| OciError::InvalidConfiguration("process Uid is unavailable".to_owned()))?;
    uid_line
        .split_ascii_whitespace()
        .nth(2)
        .ok_or_else(|| OciError::InvalidConfiguration("effective uid is unavailable".to_owned()))?
        .parse::<u32>()
        .map_err(|_| OciError::InvalidConfiguration("effective uid is malformed".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeInvocation, RuntimeInvocationKind};
    use runtrue_engine::CancellationToken;
    use std::collections::BTreeMap;

    fn shell(script: &str) -> RuntimeInvocation {
        RuntimeInvocation {
            kind: RuntimeInvocationKind::Run,
            program: "/usr/bin/dash".into(),
            arguments: vec!["-c".to_owned(), script.to_owned()],
            environment: BTreeMap::new(),
        }
    }

    fn control(timeout: Duration, max_output_bytes: usize) -> RuntimeControl {
        RuntimeControl {
            timeout,
            cancellation: CancellationToken::default(),
            max_output_bytes,
        }
    }

    #[test]
    fn process_runner_bounds_output_and_reaps_inherited_process_group() {
        let mut runner = ProcessCommandRunner::unchecked_for_test();
        let result = runner
            .invoke(
                &shell("printf 0123456789; sleep 10 &"),
                &control(Duration::from_secs(2), 4),
            )
            .unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout, b"0123");
        assert!(result.stdout_truncated);
        assert!(result.process_group_clean);
    }

    #[cfg(unix)]
    #[test]
    fn escaped_descendant_holding_output_pipe_cannot_block_capture_completion() {
        use nix::sys::signal::kill;

        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("escaped.pid");
        let script = format!(
            "/usr/bin/setsid /usr/bin/dash -c 'echo $$ > {0}; /usr/bin/sleep 10' & while [ ! -s {0} ]; do /usr/bin/sleep 0.01; done",
            pid_file.display(),
        );
        let mut runner = ProcessCommandRunner::unchecked_for_test();
        let started = Instant::now();
        let result = runner
            .invoke(&shell(&script), &control(Duration::from_secs(2), 1024))
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(result.process_group_clean);
        let deadline = Instant::now() + Duration::from_millis(500);
        while !pid_file.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let pid = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
    }

    #[test]
    fn process_runner_timeout_kills_and_verifies_the_whole_group() {
        let mut runner = ProcessCommandRunner::unchecked_for_test();
        let result = runner
            .invoke(
                &shell("sleep 10"),
                &control(Duration::from_millis(30), 1024),
            )
            .unwrap();
        assert!(result.timed_out);
        assert!(!result.canceled);
        assert!(result.process_group_clean);
    }

    #[test]
    fn process_runner_observes_cancellation_and_cleans_up() {
        let mut runner = ProcessCommandRunner::unchecked_for_test();
        let cancellation = CancellationToken::default();
        let trigger = cancellation.clone();
        let canceler = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            trigger.cancel();
        });
        let result = runner
            .invoke(
                &shell("sleep 10"),
                &RuntimeControl {
                    timeout: Duration::from_secs(2),
                    cancellation,
                    max_output_bytes: 1024,
                },
            )
            .unwrap();
        canceler.join().unwrap();
        assert!(result.canceled);
        assert!(!result.timed_out);
        assert!(result.process_group_clean);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_runner_constructor_refuses_host_root() {
        if effective_uid().unwrap() == 0 {
            assert!(ProcessCommandRunner::new().is_err());
        }
    }
}
