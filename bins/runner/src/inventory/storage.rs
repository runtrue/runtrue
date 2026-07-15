const STORAGE_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const STORAGE_PROBE_POLL: Duration = Duration::from_millis(10);
const STORAGE_PROBE_GRACE: Duration = Duration::from_millis(100);
const STORAGE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_PROC_FILE_BYTES: u64 = 1024 * 1024;
use nix::{
    errno::Errno,
    sys::signal::{killpg, Signal},
    unistd::Pid,
};

pub(super) fn probe_storage_bytes(path: &Path) -> Result<u64, InventoryError> {
    #[cfg(unix)]
    {
        let program = [Path::new("/bin/df"), Path::new("/usr/bin/df")]
            .into_iter()
            .find(|candidate| storage_probe_program_is_safe(candidate))
            .ok_or(InventoryError::UnsupportedProbe("storage"))?;
        let output = run_storage_probe(program, path, STORAGE_PROBE_TIMEOUT)?;
        if !output.status || output.stdout.len() > MAX_PROC_FILE_BYTES as usize {
            return Err(InventoryError::InvalidStorageProbe);
        }
        let text =
            std::str::from_utf8(&output.stdout).map_err(|_| InventoryError::InvalidStorageProbe)?;
        let blocks = text
            .lines()
            .last()
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(InventoryError::InvalidStorageProbe)?;
        blocks
            .checked_mul(1024)
            .ok_or(InventoryError::CapacityOverflow("storage bytes"))
    }
    #[cfg(not(unix))]
    Err(InventoryError::UnsupportedProbe("storage"))
}

#[cfg(unix)]
pub(super) struct StorageProbeOutput {
    status: bool,
    stdout: Vec<u8>,
}

#[cfg(unix)]
pub(super) fn storage_probe_program_is_safe(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    !metadata.file_type().is_symlink()
        && metadata.file_type().is_file()
        && metadata.permissions().mode() & 0o111 != 0
}

#[cfg(unix)]
pub(super) fn run_storage_probe(
    program: &Path,
    path: &Path,
    timeout: Duration,
) -> Result<StorageProbeOutput, InventoryError> {
    if !program.is_absolute() || !storage_probe_program_is_safe(program) || timeout.is_zero() {
        return Err(InventoryError::UnsafeProbePath(program.to_owned()));
    }
    let mut command = Command::new(program);
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    command
        .arg("-Pk")
        .arg(path)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(InventoryError::StorageProbe)?;
    let process_group = match i32::try_from(child.id()) {
        Ok(value) => value,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(InventoryError::StorageCleanup(
                "storage probe pid does not fit platform pid".to_owned(),
            ));
        }
    };
    let stdout = child.stdout.take().ok_or_else(|| {
        let _ = terminate_storage_probe(&mut child, process_group);
        InventoryError::InvalidStorageProbe
    })?;
    let capture = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_PROC_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(InventoryError::InvalidStorageProbe)?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = terminate_storage_probe(&mut child, process_group);
                let _ = cleanup_storage_group(process_group);
                return Err(InventoryError::StorageProbe(error));
            }
        }
        if Instant::now() >= deadline {
            terminate_storage_probe(&mut child, process_group)?;
            cleanup_storage_group(process_group)?;
            let _ = capture.join();
            return Err(InventoryError::StorageProbeTimedOut);
        }
        thread::sleep(STORAGE_PROBE_POLL.min(deadline.saturating_duration_since(Instant::now())));
    };
    cleanup_storage_group(process_group)?;
    let stdout = capture
        .join()
        .map_err(|_| InventoryError::StorageCleanup("capture thread panicked".to_owned()))?
        .map_err(InventoryError::StorageProbe)?;
    Ok(StorageProbeOutput {
        status: status.success(),
        stdout,
    })
}

#[cfg(unix)]
fn terminate_storage_probe(
    child: &mut Child,
    process_group: i32,
) -> Result<ExitStatus, InventoryError> {
    signal_storage_group(process_group, Signal::SIGTERM)?;
    let deadline = Instant::now() + STORAGE_PROBE_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(STORAGE_PROBE_POLL),
            Ok(None) => break,
            Err(error) => return Err(InventoryError::StorageProbe(error)),
        }
    }
    signal_storage_group(process_group, Signal::SIGKILL)?;
    child.wait().map_err(InventoryError::StorageProbe)
}

#[cfg(unix)]
fn signal_storage_group(process_group: i32, signal: Signal) -> Result<(), InventoryError> {
    match killpg(Pid::from_raw(process_group), signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(InventoryError::StorageCleanup(error.to_string())),
    }
}

#[cfg(unix)]
fn cleanup_storage_group(process_group: i32) -> Result<(), InventoryError> {
    signal_storage_group(process_group, Signal::SIGKILL)?;
    let deadline = Instant::now() + STORAGE_CLEANUP_TIMEOUT;
    loop {
        match killpg(Pid::from_raw(process_group), None) {
            Err(Errno::ESRCH) => return Ok(()),
            Ok(()) | Err(Errno::EPERM) if Instant::now() < deadline => {
                thread::sleep(STORAGE_PROBE_POLL);
            }
            Ok(()) | Err(Errno::EPERM) => {
                return Err(InventoryError::StorageCleanup(
                    "storage probe process group is still alive".to_owned(),
                ));
            }
            Err(error) => return Err(InventoryError::StorageCleanup(error.to_string())),
        }
    }
}
use super::InventoryError;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    fs,
    io::Read as _,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
