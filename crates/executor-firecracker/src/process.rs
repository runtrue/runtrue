use crate::{platform::validate_executable, FirecrackerError, JailerInvocation};
use runtrue_engine::CancellationToken;
use std::{
    collections::BTreeMap,
    process::{Child, Command, Stdio},
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmInvocation {
    pub program: std::path::PathBuf,
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

impl From<JailerInvocation> for VmInvocation {
    fn from(value: JailerInvocation) -> Self {
        Self {
            program: value.program,
            arguments: value.arguments,
            environment: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmControl {
    pub timeout: Duration,
    pub cancellation: CancellationToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmExit {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub canceled: bool,
    pub process_group_clean: bool,
}

pub trait RunningVm: Send {
    fn wait(&mut self, control: &VmControl) -> Result<VmExit, FirecrackerError>;
    fn terminate(&mut self) -> Result<(), FirecrackerError>;
}

pub trait VmLauncher: Send + Sync {
    fn launch(&self, invocation: &VmInvocation) -> Result<Box<dyn RunningVm>, FirecrackerError>;
}

/// Real no-shell process launcher. The jailer starts in a fresh process group;
/// every exit path reaps it and proves that the group is gone.
#[derive(Debug, Default)]
pub struct ProcessVmLauncher;

impl VmLauncher for ProcessVmLauncher {
    fn launch(&self, invocation: &VmInvocation) -> Result<Box<dyn RunningVm>, FirecrackerError> {
        validate_executable(&invocation.program, "jailer")?;
        validate_environment(&invocation.environment)?;
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
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|error| FirecrackerError::Spawn(error.to_string()))?;
        let process_group = match i32::try_from(child.id()) {
            Ok(value) => value,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FirecrackerError::ProcessCleanup(
                    "jailer pid does not fit platform pid".to_owned(),
                ));
            }
        };
        Ok(Box::new(ProcessVm {
            child: Some(child),
            process_group,
        }))
    }
}

struct ProcessVm {
    child: Option<Child>,
    process_group: i32,
}

impl RunningVm for ProcessVm {
    fn wait(&mut self, control: &VmControl) -> Result<VmExit, FirecrackerError> {
        if control.timeout.is_zero() {
            return Err(FirecrackerError::InvalidConfiguration(
                "VM timeout must be non-zero".to_owned(),
            ));
        }
        let deadline = Instant::now().checked_add(control.timeout).ok_or_else(|| {
            FirecrackerError::InvalidConfiguration("VM timeout overflows".to_owned())
        })?;
        let mut timed_out = false;
        let mut canceled = false;
        let status = loop {
            let child = self.child.as_mut().ok_or_else(|| {
                FirecrackerError::Wait("VM process was already reaped".to_owned())
            })?;
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    let cleanup = self.terminate_and_reap();
                    return match cleanup {
                        Ok(()) => Err(FirecrackerError::Wait(error.to_string())),
                        Err(cleanup) => Err(FirecrackerError::Wait(format!(
                            "{error}; cleanup also failed: {cleanup}"
                        ))),
                    };
                }
            }
            if control.cancellation.is_cancelled() {
                canceled = true;
                self.terminate_and_reap()?;
                break self.reaped_status()?;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                self.terminate_and_reap()?;
                break self.reaped_status()?;
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        };
        self.child = None;
        let process_group_clean = cleanup_and_verify_process_group(self.process_group)?;
        Ok(VmExit {
            exit_code: status.code(),
            timed_out,
            canceled,
            process_group_clean,
        })
    }

    fn terminate(&mut self) -> Result<(), FirecrackerError> {
        self.terminate_and_reap()?;
        self.child = None;
        cleanup_and_verify_process_group(self.process_group)?;
        Ok(())
    }
}

impl ProcessVm {
    fn terminate_and_reap(&mut self) -> Result<(), FirecrackerError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        signal_group(self.process_group, SignalKind::Terminate)?;
        let deadline = Instant::now() + TERMINATION_GRACE;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                Ok(None) => break,
                Err(error) => return Err(FirecrackerError::Wait(error.to_string())),
            }
        }
        signal_group(self.process_group, SignalKind::Kill)?;
        child
            .wait()
            .map_err(|error| FirecrackerError::Wait(error.to_string()))?;
        Ok(())
    }

    fn reaped_status(&mut self) -> Result<std::process::ExitStatus, FirecrackerError> {
        self.child
            .as_mut()
            .ok_or_else(|| FirecrackerError::Wait("VM process is unavailable".to_owned()))?
            .try_wait()
            .map_err(|error| FirecrackerError::Wait(error.to_string()))?
            .ok_or_else(|| FirecrackerError::Wait("VM process was not reaped".to_owned()))
    }
}

impl Drop for ProcessVm {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = signal_group(self.process_group, SignalKind::Kill);
            if let Some(child) = self.child.as_mut() {
                let _ = child.wait();
            }
            let _ = cleanup_and_verify_process_group(self.process_group);
        }
    }
}

#[derive(Clone, Copy)]
enum SignalKind {
    Terminate,
    Kill,
}

#[cfg(unix)]
fn signal_group(process_group: i32, signal: SignalKind) -> Result<(), FirecrackerError> {
    let signal = match signal {
        SignalKind::Terminate => Signal::SIGTERM,
        SignalKind::Kill => Signal::SIGKILL,
    };
    match killpg(Pid::from_raw(process_group), signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(FirecrackerError::ProcessCleanup(error.to_string())),
    }
}

#[cfg(not(unix))]
fn signal_group(_process_group: i32, _signal: SignalKind) -> Result<(), FirecrackerError> {
    Err(FirecrackerError::ProcessCleanup(
        "process-group signaling is unsupported".to_owned(),
    ))
}

#[cfg(unix)]
fn cleanup_and_verify_process_group(process_group: i32) -> Result<bool, FirecrackerError> {
    signal_group(process_group, SignalKind::Kill)?;
    let deadline = Instant::now() + CLEANUP_VERIFY_TIMEOUT;
    loop {
        match killpg(Pid::from_raw(process_group), None) {
            Err(Errno::ESRCH) => return Ok(true),
            Ok(()) | Err(Errno::EPERM) if Instant::now() < deadline => {
                thread::sleep(POLL_INTERVAL);
            }
            Ok(()) | Err(Errno::EPERM) => {
                return Err(FirecrackerError::ProcessCleanup(
                    "jailer process group is still alive".to_owned(),
                ));
            }
            Err(error) => return Err(FirecrackerError::ProcessCleanup(error.to_string())),
        }
    }
}

#[cfg(not(unix))]
fn cleanup_and_verify_process_group(_process_group: i32) -> Result<bool, FirecrackerError> {
    Err(FirecrackerError::ProcessCleanup(
        "process-group verification is unsupported".to_owned(),
    ))
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<(), FirecrackerError> {
    if environment.len() > 64 {
        return Err(FirecrackerError::InvalidConfiguration(
            "jailer environment is too large".to_owned(),
        ));
    }
    for (name, value) in environment {
        if name.is_empty()
            || name.len() > 128
            || value.len() > 4096
            || name.contains('=')
            || name.contains('\0')
            || value.contains('\0')
        {
            return Err(FirecrackerError::InvalidConfiguration(
                "jailer environment contains an invalid entry".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt as _, path::Path};
    use tempfile::TempDir;

    fn script(directory: &TempDir, body: &str) -> std::path::PathBuf {
        let path = directory.path().join("jailer-fake");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn fake_process_completes_without_kvm() {
        let directory = TempDir::new().unwrap();
        let invocation = VmInvocation {
            program: script(&directory, "exit 7"),
            arguments: Vec::new(),
            environment: BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]),
        };
        let mut vm = ProcessVmLauncher.launch(&invocation).unwrap();
        let result = vm
            .wait(&VmControl {
                timeout: Duration::from_secs(2),
                cancellation: CancellationToken::default(),
            })
            .unwrap();
        assert_eq!(result.exit_code, Some(7));
        assert!(result.process_group_clean);
    }

    #[test]
    fn fake_process_deadline_kills_complete_group() {
        let directory = TempDir::new().unwrap();
        let invocation = VmInvocation {
            program: script(&directory, "sleep 30 & wait"),
            arguments: Vec::new(),
            environment: BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]),
        };
        let mut vm = ProcessVmLauncher.launch(&invocation).unwrap();
        let result = vm
            .wait(&VmControl {
                timeout: Duration::from_millis(50),
                cancellation: CancellationToken::default(),
            })
            .unwrap();
        assert!(result.timed_out);
        assert!(result.process_group_clean);
    }

    #[test]
    fn rejects_symlink_program() {
        use std::os::unix::fs::symlink;
        let directory = TempDir::new().unwrap();
        let real = script(&directory, "exit 0");
        let link = directory.path().join("link");
        symlink(&real, &link).unwrap();
        let result = ProcessVmLauncher.launch(&VmInvocation {
            program: link,
            arguments: Vec::new(),
            environment: BTreeMap::new(),
        });
        assert!(result.is_err());
        assert!(Path::new(&real).is_file());
    }
}
