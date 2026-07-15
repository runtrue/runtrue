use crate::{GitError, GitRepository};
use nix::{
    sys::signal::{killpg, Signal},
    unistd::Pid,
};
use std::{
    env,
    io::{self, Read},
    path::PathBuf,
    process::{Child, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const READ_BUFFER_BYTES: usize = 64 * 1024;

pub(crate) fn git_hardening_arguments() -> &'static [&'static str] {
    &[
        "-c",
        "credential.helper=",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.clean=",
        "-c",
        "filter.lfs.required=false",
        "-c",
        "diff.external=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "submodule.recurse=false",
        "-c",
        "fetch.recurseSubmodules=false",
        "-c",
        "transfer.fsckObjects=true",
        "-c",
        "fetch.fsckObjects=true",
        "-c",
        "receive.fsckObjects=true",
    ]
}

pub(crate) struct GitCommandOutput {
    pub(crate) stdout: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct CaptureOutput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

pub(crate) fn capture(
    mut stream: impl Read + Send + 'static,
    limit: usize,
) -> thread::JoinHandle<Result<CaptureOutput, io::Error>> {
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        let mut truncated = false;
        let mut buffer = [0_u8; READ_BUFFER_BYTES];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let remaining = limit.saturating_sub(bytes.len());
            let retained = remaining.min(read);
            bytes.extend_from_slice(&buffer[..retained]);
            truncated |= retained < read;
        }
        Ok(CaptureOutput { bytes, truncated })
    })
}

pub(crate) fn wait_bounded(
    child: &mut Child,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<ExitStatus, GitError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(GitError::InvalidConfiguration)?;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| GitError::Wait(source.to_string()))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            terminate_process_tree(child);
            let _ = child.wait();
            return Err(GitError::Timeout);
        }
        thread::sleep(poll_interval);
    }
}

#[cfg(unix)]
fn terminate_process_tree(child: &mut Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate_process_tree(child: &mut Child) {
    let _ = child.kill();
}

pub(crate) fn safe_path() -> PathBuf {
    if cfg!(windows) {
        env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_default()
    } else {
        PathBuf::from("/usr/bin:/bin")
    }
}

#[cfg(unix)]
pub(crate) const fn null_device() -> &'static str {
    "/dev/null"
}

#[cfg(windows)]
pub(crate) const fn null_device() -> &'static str {
    "NUL"
}

pub(crate) fn bounded_diagnostic(bytes: &[u8]) -> String {
    let value = String::from_utf8_lossy(bytes);
    value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(2048)
        .collect()
}

impl GitRepository {
    pub(crate) fn run_git(
        &self,
        arguments: &[&str],
        output_limit: usize,
    ) -> Result<GitCommandOutput, GitError> {
        if output_limit == 0 {
            return Err(GitError::OutputLimit {
                kind: "command output bytes",
                limit: 0,
            });
        }
        let mut command = std::process::Command::new(&self.git_program);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        command
            .arg("--no-pager")
            .arg("--no-optional-locks")
            .args(git_hardening_arguments())
            .arg("-C")
            .arg(self.root())
            .arg("--literal-pathspecs")
            .args(arguments)
            .env_clear()
            .env("PATH", safe_path())
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .env("GIT_CONFIG_SYSTEM", null_device())
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_ASKPASS", null_device())
            .env("SSH_ASKPASS", null_device())
            .env("GIT_SSH_COMMAND", "false")
            .env("GIT_PROTOCOL_FROM_USER", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|source| GitError::Spawn(source.to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| GitError::Spawn("Git stdout pipe unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| GitError::Spawn("Git stderr pipe unavailable".to_owned()))?;
        let stdout_capture = capture(stdout, output_limit);
        let stderr_capture = capture(stderr, 64 * 1024);
        let status = wait_bounded(
            &mut child,
            self.limits.command_timeout,
            self.limits.poll_interval,
        )?;
        let stdout = stdout_capture
            .join()
            .map_err(|_| GitError::CaptureThread)?
            .map_err(GitError::Capture)?;
        let stderr = stderr_capture
            .join()
            .map_err(|_| GitError::CaptureThread)?
            .map_err(GitError::Capture)?;
        if stdout.truncated {
            return Err(GitError::OutputLimit {
                kind: "Git stdout bytes",
                limit: output_limit,
            });
        }
        if !status.success() {
            if status.code() == Some(128)
                && String::from_utf8_lossy(&stderr.bytes).contains("not in the working tree")
            {
                return Err(GitError::PathNotFound);
            }
            return Err(GitError::CommandFailed {
                exit_code: status.code(),
                stderr: bounded_diagnostic(&stderr.bytes),
            });
        }
        Ok(GitCommandOutput {
            stdout: stdout.bytes,
        })
    }
}
