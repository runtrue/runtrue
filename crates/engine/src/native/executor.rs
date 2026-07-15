//! Native executor configuration and backend implementation.

pub struct NativeProcessExecutor {
    workspace: PathBuf,
    allow_native: bool,
    external_cache_handling: bool,
    external_artifact_handling: bool,
    base_environment: BTreeMap<String, String>,
    poll_interval: Duration,
    max_capture_bytes: usize,
}

/// A descriptive alias for callers that present this backend as local mode.
pub type LocalProcessExecutor = NativeProcessExecutor;
/// A concise alias for the trusted native backend.
pub type NativeExecutor = NativeProcessExecutor;

impl fmt::Debug for NativeProcessExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeProcessExecutor")
            .field("workspace", &self.workspace)
            .field("allow_native", &self.allow_native)
            .field("external_cache_handling", &self.external_cache_handling)
            .field(
                "external_artifact_handling",
                &self.external_artifact_handling,
            )
            .field(
                "base_environment_keys",
                &self.base_environment.keys().collect::<Vec<_>>(),
            )
            .field("poll_interval", &self.poll_interval)
            .field("max_capture_bytes", &self.max_capture_bytes)
            .finish()
    }
}

impl NativeProcessExecutor {
    #[must_use]
    pub fn new(workspace: impl Into<PathBuf>, allow_native: bool) -> Self {
        let mut base_environment = BTreeMap::new();
        if let Ok(path) = std::env::var("PATH") {
            base_environment.insert("PATH".to_owned(), path);
        }
        Self {
            workspace: workspace.into(),
            allow_native,
            external_cache_handling: false,
            external_artifact_handling: false,
            base_environment,
            poll_interval: Duration::from_millis(5),
            max_capture_bytes: DEFAULT_MAX_CAPTURE_BYTES,
        }
    }

    #[must_use]
    pub fn allow_native(&self) -> bool {
        self.allow_native
    }

    pub fn set_allow_native(&mut self, allow_native: bool) {
        self.allow_native = allow_native;
    }

    /// Declare that an outer executor wrapper owns cache restore/save for the
    /// complete run. This remains disabled by default so a bare native
    /// executor cannot silently ignore cache declarations.
    pub fn set_external_cache_handling(&mut self, enabled: bool) {
        self.external_cache_handling = enabled;
    }

    #[must_use]
    pub fn external_cache_handling(&self) -> bool {
        self.external_cache_handling
    }

    /// Declare that an outer executor wrapper owns durable job-output capture.
    /// Disabled by default so a bare native executor cannot ignore artifacts.
    pub fn set_external_artifact_handling(&mut self, enabled: bool) {
        self.external_artifact_handling = enabled;
    }

    #[must_use]
    pub fn external_artifact_handling(&self) -> bool {
        self.external_artifact_handling
    }

    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Replace the small, explicit environment inherited by every child.
    pub fn set_base_environment(
        &mut self,
        environment: BTreeMap<String, String>,
    ) -> Result<(), ExecutorError> {
        validate_executor_environment(&environment)?;
        self.base_environment = environment;
        Ok(())
    }

    /// Change process polling frequency. A zero duration is rounded up to one
    /// millisecond to avoid a busy loop.
    pub fn set_poll_interval(&mut self, interval: Duration) {
        self.poll_interval = interval.max(Duration::from_millis(1));
    }

    pub fn set_max_capture_bytes(&mut self, bytes: usize) {
        self.max_capture_bytes = bytes;
    }

    fn validate_request(&self, request: &StepExecutionRequest) -> Result<(), ExecutorError> {
        if request.runner.isolation != Isolation::Native {
            return Err(ExecutorError::UnsupportedIsolation(format!(
                "{:?}",
                request.runner.isolation
            )));
        }
        if !self.allow_native {
            return Err(ExecutorError::NativeExecutionDisabled);
        }
        if request.capabilities.network != runtrue_workflow_ir::NetworkPermission::Deny {
            return Err(ExecutorError::UnsupportedCapsuleFeature(
                "native network allow requires an external cgroup-bound enforcement provider"
                    .to_owned(),
            ));
        }

        let (host_os, host_arch) = host_platform()?;
        if request.runner.os != host_os || request.runner.arch != host_arch {
            return Err(ExecutorError::PlatformMismatch {
                requested: format!("{:?}/{:?}", request.runner.os, request.runner.arch),
                host: format!("{host_os:?}/{host_arch:?}"),
            });
        }
        validate_executor_environment(&self.base_environment)?;
        validate_executor_environment(&request.environment)
    }
}

impl Executor for NativeProcessExecutor {
    fn preflight(&self, capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        if !self.allow_native {
            return Err(ExecutorError::NativeExecutionDisabled);
        }
        let (host_os, host_arch) = host_platform()?;
        for job in &capsule.jobs {
            if job.runner.isolation != Isolation::Native {
                return Err(ExecutorError::UnsupportedIsolation(format!(
                    "{:?}",
                    job.runner.isolation
                )));
            }
            if job.runner.os != host_os || job.runner.arch != host_arch {
                return Err(ExecutorError::PlatformMismatch {
                    requested: format!("{:?}/{:?}", job.runner.os, job.runner.arch),
                    host: format!("{host_os:?}/{host_arch:?}"),
                });
            }
            if !job.services.is_empty() {
                return Err(ExecutorError::UnsupportedCapsuleFeature(format!(
                    "job `{}` declares service containers",
                    job.id
                )));
            }
            if job.permissions.network != runtrue_workflow_ir::NetworkPermission::Deny {
                return Err(ExecutorError::UnsupportedCapsuleFeature(format!(
                    "job `{}` requests native network allow without an external cgroup-bound enforcement provider",
                    job.id
                )));
            }
            if !job.outputs.is_empty() && !self.external_artifact_handling {
                return Err(ExecutorError::UnsupportedCapsuleFeature(format!(
                    "job `{}` declares artifact outputs",
                    job.id
                )));
            }
            if job.environment.is_some() {
                return Err(ExecutorError::UnsupportedCapsuleFeature(format!(
                    "job `{}` targets a protected environment",
                    job.id
                )));
            }
            if !job.runner.capabilities.is_empty() || job.concurrency.is_some() {
                return Err(ExecutorError::UnsupportedCapsuleFeature(format!(
                    "job `{}` requests runner capabilities or concurrency",
                    job.id
                )));
            }
            for step in job
                .steps
                .iter()
                .chain(job.finalizers.iter().map(|finalizer| &finalizer.step))
            {
                if step.capabilities.network != runtrue_workflow_ir::NetworkPermission::Deny {
                    return Err(ExecutorError::UnsupportedCapsuleFeature(format!(
                        "step `{}.{}` requests native network allow without an external cgroup-bound enforcement provider",
                        job.id, step.id
                    )));
                }
                if let StepAction::Component { reference } = &step.action {
                    return Err(ExecutorError::UnsupportedComponent(reference.clone()));
                }
                if step.cache.is_some() && !self.external_cache_handling {
                    return Err(ExecutorError::UnsupportedCapsuleFeature(format!(
                        "step `{}.{}` declares a cache",
                        job.id, step.id
                    )));
                }
                if !step.capabilities.secrets.is_empty()
                    || !step.capabilities.oidc_audiences.is_empty()
                {
                    return Err(ExecutorError::UnsupportedCapsuleFeature(format!(
                        "step `{}.{}` requires a secret or identity broker",
                        job.id, step.id
                    )));
                }
                if !step.outputs.is_empty() {
                    return Err(ExecutorError::UnsupportedCapsuleFeature(format!(
                        "step `{}.{}` declares structured outputs but native process execution has no bounded structured output adapter",
                        job.id, step.id
                    )));
                }
            }
        }
        Ok(())
    }

    fn execute(&mut self, request: &StepExecutionRequest) -> Result<ExecutorOutput, ExecutorError> {
        self.validate_request(request)?;
        if request.cancellation.is_cancelled() {
            return Ok(ExecutorOutput {
                canceled: true,
                exit_code: None,
                ..ExecutorOutput::success()
            });
        }
        if request.timeout_ms == Some(0) {
            return Ok(ExecutorOutput {
                timed_out: true,
                exit_code: None,
                ..ExecutorOutput::success()
            });
        }

        let working_directory =
            resolve_working_directory(&self.workspace, request.working_directory.as_deref())?;
        let (program, args) = native_command(&request.action)?;
        validate_command(&program, &args)?;

        let mut command = Command::new(program);
        #[cfg(unix)]
        command.process_group(0);
        command
            .args(args)
            .current_dir(working_directory)
            .env_clear()
            .envs(&self.base_environment)
            .envs(&request.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|error| ExecutorError::Spawn(error.to_string()))?;
        let process_id = child.id();
        let stdout = child.stdout.take().ok_or_else(|| {
            let _ = child.kill();
            ExecutorError::Spawn("child stdout pipe was not created".to_owned())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            let _ = child.kill();
            ExecutorError::Spawn("child stderr pipe was not created".to_owned())
        })?;
        let (stdout_capture, stdout_done) = capture_stream(stdout, self.max_capture_bytes);
        let (stderr_capture, stderr_done) = capture_stream(stderr, self.max_capture_bytes);

        let deadline = request
            .timeout_ms
            .map(Duration::from_millis)
            .and_then(|timeout| started.checked_add(timeout));
        let mut timed_out = false;
        let mut canceled = false;

        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ExecutorError::Wait(error.to_string()));
                }
            }

            if request.cancellation.is_cancelled() {
                canceled = true;
                break kill_and_wait(&mut child)?;
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                timed_out = true;
                break kill_and_wait(&mut child)?;
            }

            let sleep_for = deadline.map_or(self.poll_interval, |deadline| {
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(self.poll_interval)
            });
            thread::sleep(sleep_for.max(Duration::from_millis(1)));
        };

        // A successful shell can leave descendants running with inherited
        // workspace and output descriptors. Native execution is not a
        // sandbox, but every ordinary descendant in the step process group is
        // still a runner-owned resource: terminate it and require an explicit
        // absence proof before the step can be finalized.
        cleanup_and_verify_native_process_group(process_id)?;

        // Normally readers observe EOF immediately after the child is reaped.
        // A descendant may have inherited a pipe, so never let output capture
        // defeat the timeout: after this bounded wait, the reader is detached.
        let _ = stdout_done.recv_timeout(Duration::from_millis(100));
        let _ = stderr_done.recv_timeout(Duration::from_millis(100));
        let stdout = snapshot_capture(&stdout_capture);
        let stderr = snapshot_capture(&stderr_capture);

        Ok(ExecutorOutput {
            exit_code: status.code(),
            stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
            structured_output: None,
            credential_taint: crate::CredentialTaint::None,
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
            timed_out,
            canceled,
            duration_ms: duration_millis(started.elapsed()),
        })
    }

    fn finish_job_attempt(
        &mut self,
        _job: &PlannedJob,
        _attempt: u32,
        _outcome: JobAttemptOutcome,
    ) -> Result<(), ExecutorError> {
        Ok(())
    }
}
use super::{
    capture_stream, cleanup_and_verify_native_process_group, duration_millis, fmt, host_platform,
    kill_and_wait, native_command, resolve_working_directory, snapshot_capture, thread,
    validate_command, validate_executor_environment, BTreeMap, Command, Duration, ExecutionCapsule,
    Executor, ExecutorError, ExecutorOutput, Instant, Isolation, JobAttemptOutcome, Path, PathBuf,
    PlannedJob, Stdio, StepAction, StepExecutionRequest, DEFAULT_MAX_CAPTURE_BYTES,
};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
