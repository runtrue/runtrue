//! Native command preparation, termination, and process groups.

pub(crate) fn host_platform() -> Result<(OperatingSystem, Architecture), ExecutorError> {
    let os = match std::env::consts::OS {
        "windows" => OperatingSystem::Windows,
        "macos" => OperatingSystem::Macos,
        "linux" => OperatingSystem::Linux,
        other => {
            return Err(ExecutorError::UnsupportedHostPlatform {
                os: other.to_owned(),
                arch: std::env::consts::ARCH.to_owned(),
            });
        }
    };
    let architecture = match std::env::consts::ARCH {
        "aarch64" => Architecture::Arm64,
        "x86_64" => Architecture::Amd64,
        other => {
            return Err(ExecutorError::UnsupportedHostPlatform {
                os: std::env::consts::OS.to_owned(),
                arch: other.to_owned(),
            });
        }
    };
    Ok((os, architecture))
}

pub(super) fn native_command(
    action: &PreparedAction,
) -> Result<(String, Vec<String>), ExecutorError> {
    match action {
        PreparedAction::Component { reference, .. } => {
            Err(ExecutorError::UnsupportedComponent(reference.clone()))
        }
        PreparedAction::Command { program, args } => Ok((program.clone(), args.clone())),
        PreparedAction::Container { .. } => Err(ExecutorError::UnsupportedCapsuleFeature(
            "image entrypoint execution requires the OCI executor".to_owned(),
        )),
        PreparedAction::Script {
            shell,
            script,
            script_digest,
        } => {
            if ContentDigest::sha256(script.as_bytes()) != *script_digest {
                return Err(ExecutorError::InvalidCommand(
                    "static script digest does not match script bytes".to_owned(),
                ));
            }
            let (program, mut args) = match shell {
                Shell::Bash => ("bash", vec!["--noprofile", "--norc", "-c"]),
                Shell::Sh => ("sh", vec!["-c"]),
                Shell::Pwsh => ("pwsh", vec!["-NoProfile", "-NonInteractive", "-Command"]),
                Shell::Cmd => ("cmd", vec!["/D", "/S", "/C"]),
            };
            args.push(script.as_str());
            Ok((
                program.to_owned(),
                args.into_iter().map(str::to_owned).collect(),
            ))
        }
    }
}

pub(super) fn validate_command(program: &str, args: &[String]) -> Result<(), ExecutorError> {
    if program.is_empty() || program.contains('\0') {
        return Err(ExecutorError::InvalidCommand(
            "program must be non-empty and contain no NUL byte".to_owned(),
        ));
    }
    if args.iter().any(|argument| argument.contains('\0')) {
        return Err(ExecutorError::InvalidCommand(
            "arguments must contain no NUL byte".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_executor_environment(
    environment: &BTreeMap<String, String>,
) -> Result<(), ExecutorError> {
    for (name, value) in environment {
        if !is_valid_environment_name(name) {
            return Err(ExecutorError::InvalidEnvironmentName(name.clone()));
        }
        if value.contains('\0') {
            return Err(ExecutorError::InvalidEnvironmentValue(name.clone()));
        }
    }
    Ok(())
}

pub(super) fn resolve_working_directory(
    workspace: &Path,
    requested: Option<&str>,
) -> Result<PathBuf, ExecutorError> {
    let workspace = workspace
        .canonicalize()
        .map_err(|error| ExecutorError::WorkingDirectory(error.to_string()))?;
    if !workspace.is_dir() {
        return Err(ExecutorError::WorkingDirectory(format!(
            "workspace `{}` is not a directory",
            workspace.display()
        )));
    }

    let Some(requested) = requested else {
        return Ok(workspace);
    };
    if requested.is_empty() || requested.contains('\0') || requested.contains('\\') {
        return Err(ExecutorError::UnsafeWorkingDirectory(requested.to_owned()));
    }
    let relative = Path::new(requested);
    for component in relative.components() {
        if !matches!(component, Component::Normal(_) | Component::CurDir) {
            return Err(ExecutorError::UnsafeWorkingDirectory(requested.to_owned()));
        }
    }
    let candidate = workspace
        .join(relative)
        .canonicalize()
        .map_err(|error| ExecutorError::WorkingDirectory(format!("`{requested}`: {error}")))?;
    if !candidate.starts_with(&workspace) || !candidate.is_dir() {
        return Err(ExecutorError::UnsafeWorkingDirectory(requested.to_owned()));
    }
    Ok(candidate)
}

pub(super) fn kill_and_wait(child: &mut std::process::Child) -> Result<ExitStatus, ExecutorError> {
    #[cfg(unix)]
    {
        use nix::{
            sys::signal::{killpg, Signal},
            unistd::Pid,
        };

        if let Ok(process_group) = i32::try_from(child.id()) {
            // Every native step starts in its own process group. Killing the
            // group terminates ordinary descendants as well as the shell or
            // direct child. A deliberately daemonized process can still leave
            // the group; native execution remains a trusted-host boundary.
            let _ = killpg(Pid::from_raw(process_group), Signal::SIGKILL);
        }
    }
    if let Err(error) = child.kill() {
        // `kill` can race with natural process exit. If it is already reaped,
        // return that status; otherwise surface the failure instead of waiting
        // without a bound for a process we failed to terminate.
        if let Some(status) = child
            .try_wait()
            .map_err(|wait_error| ExecutorError::Wait(wait_error.to_string()))?
        {
            return Ok(status);
        }
        return Err(ExecutorError::Wait(format!(
            "could not terminate process: {error}"
        )));
    }
    child
        .wait()
        .map_err(|error| ExecutorError::Wait(error.to_string()))
}

#[cfg(unix)]
pub(super) fn cleanup_and_verify_native_process_group(
    process_id: u32,
) -> Result<(), ExecutorError> {
    use nix::{
        errno::Errno,
        sys::signal::{killpg, Signal},
        unistd::Pid,
    };

    let process_group = i32::try_from(process_id).map(Pid::from_raw).map_err(|_| {
        ExecutorError::Wait("native process id does not fit platform pid".to_owned())
    })?;
    match killpg(process_group, None) {
        Err(Errno::ESRCH) => return Ok(()),
        Ok(()) | Err(_) => {
            let _ = killpg(process_group, Signal::SIGTERM);
            thread::sleep(NATIVE_PROCESS_GROUP_TERMINATION_GRACE);
            let _ = killpg(process_group, Signal::SIGKILL);
        }
    }
    let deadline = Instant::now() + NATIVE_PROCESS_GROUP_VERIFY_TIMEOUT;
    loop {
        match killpg(process_group, None) {
            Err(Errno::ESRCH) => return Ok(()),
            Ok(()) | Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(()) | Err(_) => {
                return Err(ExecutorError::Wait(
                    "native step process-group cleanup could not be proved".to_owned(),
                ));
            }
        }
    }
}

#[cfg(not(unix))]
pub(super) fn cleanup_and_verify_native_process_group(
    _process_id: u32,
) -> Result<(), ExecutorError> {
    Ok(())
}
use super::{
    is_valid_environment_name, thread, Architecture, BTreeMap, Component, ContentDigest, Duration,
    ExecutorError, ExitStatus, Instant, OperatingSystem, Path, PathBuf, PreparedAction, Shell,
    NATIVE_PROCESS_GROUP_TERMINATION_GRACE, NATIVE_PROCESS_GROUP_VERIFY_TIMEOUT,
};
