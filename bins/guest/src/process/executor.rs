use super::{
    capture::Capture,
    cleanup::{cleanup_and_verify_process_group, terminate_child},
    command::{
        literal_environment, prepare_action, resolve_working_directory, validate_executable,
        validate_literal_bindings,
    },
};
use crate::GuestAgentError;
use runtrue_guest_core::AuthorizedStep;
use runtrue_workflow_ir::NetworkPermission;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, PartialEq, Eq)]
pub struct StepExecution {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub canceled: bool,
    pub process_group_clean: bool,
}

impl std::fmt::Debug for StepExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StepExecution")
            .field("exit_code", &self.exit_code)
            .field(
                "stdout",
                &format_args!("<redacted:{} bytes>", self.stdout.len()),
            )
            .field(
                "stderr",
                &format_args!("<redacted:{} bytes>", self.stderr.len()),
            )
            .field("stdout_truncated", &self.stdout_truncated)
            .field("stderr_truncated", &self.stderr_truncated)
            .field("timed_out", &self.timed_out)
            .field("canceled", &self.canceled)
            .field("process_group_clean", &self.process_group_clean)
            .finish()
    }
}

pub trait StepExecutor: Send + Sync + 'static {
    fn execute(
        &self,
        step: AuthorizedStep,
        job_timeout: Duration,
        cancellation: Arc<AtomicBool>,
    ) -> Result<StepExecution, GuestAgentError>;
}

#[derive(Debug, Clone)]
pub struct DirectStepExecutor {
    workspace: PathBuf,
    max_output_bytes: usize,
    max_timeout: Duration,
}

impl DirectStepExecutor {
    pub fn new(workspace: impl Into<PathBuf>) -> Result<Self, GuestAgentError> {
        let workspace = workspace.into();
        if !workspace.is_absolute() {
            return Err(GuestAgentError::InvalidConfiguration(
                "guest workspace must be absolute".to_owned(),
            ));
        }
        let metadata = fs::symlink_metadata(&workspace).map_err(|error| {
            GuestAgentError::Process(format!("cannot inspect guest workspace: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(GuestAgentError::InvalidConfiguration(
                "guest workspace must be a non-symlink directory".to_owned(),
            ));
        }
        Ok(Self {
            workspace,
            max_output_bytes: 4 * 1024 * 1024,
            max_timeout: Duration::from_secs(24 * 60 * 60),
        })
    }

    #[must_use]
    pub fn with_limits(mut self, max_output_bytes: usize, max_timeout: Duration) -> Self {
        self.max_output_bytes = max_output_bytes;
        self.max_timeout = max_timeout;
        self
    }
}

impl StepExecutor for DirectStepExecutor {
    fn execute(
        &self,
        authorized: AuthorizedStep,
        job_timeout: Duration,
        cancellation: Arc<AtomicBool>,
    ) -> Result<StepExecution, GuestAgentError> {
        if self.max_output_bytes == 0 || self.max_timeout.is_zero() || job_timeout.is_zero() {
            return Err(GuestAgentError::InvalidConfiguration(
                "guest execution bounds must be non-zero".to_owned(),
            ));
        }
        if !matches!(
            authorized.step.capabilities.network,
            NetworkPermission::Deny
        ) {
            return Err(GuestAgentError::InvalidConfiguration(
                "guest network policy adapter is unavailable; network capability denied".to_owned(),
            ));
        }
        validate_literal_bindings(&authorized.step.inputs)?;
        let environment = literal_environment(&authorized.step.environment)?;
        let (program, arguments) = prepare_action(&authorized.step.action)?;
        validate_executable(&program)?;
        let working_directory = resolve_working_directory(
            &self.workspace,
            authorized.step.working_directory.as_deref(),
        )?;
        let requested = authorized
            .step
            .timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(job_timeout);
        let timeout = requested.min(job_timeout).min(self.max_timeout);
        if timeout.is_zero() {
            return Err(GuestAgentError::InvalidConfiguration(
                "guest step timeout must be non-zero".to_owned(),
            ));
        }

        let mut command = Command::new(&program);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        command
            .args(arguments)
            .current_dir(working_directory)
            .env_clear()
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| GuestAgentError::Process(error.to_string()))?;
        let process_group = i32::try_from(child.id()).map_err(|_| {
            let _ = child.kill();
            let _ = child.wait();
            GuestAgentError::Process("guest child pid does not fit platform pid".to_owned())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            let _ = terminate_child(&mut child, process_group);
            GuestAgentError::Process("guest stdout pipe is unavailable".to_owned())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            let _ = terminate_child(&mut child, process_group);
            GuestAgentError::Process("guest stderr pipe is unavailable".to_owned())
        })?;
        let stdout = Capture::start(stdout, self.max_output_bytes);
        let stderr = Capture::start(stderr, self.max_output_bytes);
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| GuestAgentError::Process("guest deadline overflows".to_owned()))?;
        let (status, timed_out, canceled) = loop {
            match child.try_wait() {
                Ok(Some(status)) => break (status, false, false),
                Ok(None) => {}
                Err(error) => {
                    let _ = terminate_child(&mut child, process_group);
                    return Err(GuestAgentError::Process(error.to_string()));
                }
            }
            if cancellation.load(Ordering::Acquire) {
                break (terminate_child(&mut child, process_group)?, false, true);
            }
            if Instant::now() >= deadline {
                break (terminate_child(&mut child, process_group)?, true, false);
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        };
        let process_group_clean = cleanup_and_verify_process_group(process_group)?;
        let stdout = stdout.finish()?;
        let stderr = stderr.finish()?;
        Ok(StepExecution {
            exit_code: status.code(),
            stdout: stdout.bytes,
            stderr: stderr.bytes,
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
            timed_out,
            canceled,
            process_group_clean,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_workflow_ir::{
        PlannedStep, ScalarValue, StepAction, StepCapabilitySet, ValueBinding,
    };
    use std::{collections::BTreeMap, path::Path};
    use tempfile::TempDir;

    fn system_executable(path: &str) -> PathBuf {
        fs::canonicalize(path).unwrap()
    }

    fn authorized(program: &Path, arguments: &[&str]) -> AuthorizedStep {
        AuthorizedStep {
            job_id: "job".to_owned(),
            attempt: 1,
            step: PlannedStep {
                id: "step".to_owned(),
                name: "Step".to_owned(),
                condition: None,
                action: StepAction::Command {
                    program: program.display().to_string(),
                    args: arguments
                        .iter()
                        .map(|argument| {
                            ValueBinding::Literal(ScalarValue::String((*argument).to_owned()))
                        })
                        .collect(),
                },
                inputs: BTreeMap::new(),
                environment: BTreeMap::new(),
                capabilities: StepCapabilitySet::default(),
                cache: None,
                timeout_ms: Some(5_000),
                continue_on_error: false,
                outputs: BTreeMap::new(),
                working_directory: None,
            },
        }
    }

    #[test]
    fn cancellation_kills_and_verifies_fake_process_group() {
        let directory = TempDir::new().unwrap();
        let workspace = directory.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let executor = DirectStepExecutor::new(&workspace).unwrap();
        let cancellation = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancellation);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            signal.store(true, Ordering::Release);
        });
        let result = executor
            .execute(
                authorized(&system_executable("/bin/sh"), &["-c", "sleep 30 & wait"]),
                Duration::from_secs(10),
                cancellation,
            )
            .unwrap();
        assert!(result.canceled);
        assert!(result.process_group_clean);
    }

    #[test]
    fn output_is_bounded_without_blocking_child() {
        let directory = TempDir::new().unwrap();
        let workspace = directory.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let executor = DirectStepExecutor::new(&workspace)
            .unwrap()
            .with_limits(1024, Duration::from_secs(10));
        let result = executor
            .execute(
                authorized(
                    &system_executable("/bin/sh"),
                    &[
                        "-c",
                        "i=0; while [ \"$i\" -lt 2048 ]; do printf x; i=$((i + 1)); done",
                    ],
                ),
                Duration::from_secs(10),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
        assert_eq!(result.stdout.len(), 1024);
        assert!(result.stdout_truncated);
    }
}
