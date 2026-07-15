pub(super) fn sorted_directory_entries(directory: &Path) -> Result<Vec<PathBuf>, RunnerError> {
    let mut paths = fs::read_dir(directory)
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    Ok(paths)
}

pub(super) fn validate_private_directory(path: &Path, kind: &str) -> Result<PathBuf, RunnerError> {
    if !path.is_absolute() {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "{kind} must be absolute"
        )));
    }
    validate_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "{kind} is not a real directory"
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "{kind} must have mode 0700"
        )));
    }
    path.canonicalize()
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))
}

pub(super) fn require_absolute(path: &Path, kind: &str) -> Result<(), RunnerError> {
    if !path.is_absolute() {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "{kind} must be absolute"
        )));
    }
    Ok(())
}

pub(super) fn validate_image_payload(path: &Path) -> Result<(), RunnerError> {
    validate_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        RunnerError::FirecrackerConfiguration(format!(
            "cannot inspect image payload `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "image payload `{}` is not a nonempty regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "image payload `{}` must be private and have one hard link",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn validate_executable(path: &Path, name: &str) -> Result<PathBuf, RunnerError> {
    if !path.is_absolute() {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "{name} path must be absolute"
        )));
    }
    validate_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "{name} must be a real regular file"
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "{name} must be executable, immutable to non-owner users, and have one hard link"
        )));
    }
    path.canonicalize()
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))
}

pub(super) fn validate_runtime_binary(
    path: &Path,
    name: &str,
    expected_size: u64,
    expected_digest: &ContentDigest,
) -> Result<PathBuf, RunnerError> {
    let path = validate_executable(path, name)?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?;
    if expected_size == 0
        || expected_size > MAX_RUNTIME_BINARY_BYTES
        || metadata.len() != expected_size
        || digest_file(&path, MAX_RUNTIME_BINARY_BYTES)? != *expected_digest
    {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "{name} bytes differ from the exact version identity in the runtime profile"
        )));
    }
    Ok(path)
}

fn digest_file(path: &Path, maximum: u64) -> Result<ContentDigest, RunnerError> {
    let mut file = File::open(path)
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?;
    let mut hasher = Sha256::new();
    let copied = io::copy(&mut file.by_ref().take(maximum + 1), &mut hasher)
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?;
    if copied == 0 || copied > maximum {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "runtime binary `{}` exceeds its bound",
            path.display()
        )));
    }
    ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))
}

pub(super) fn validate_host_architecture(expected: Architecture) -> Result<(), RunnerError> {
    let actual = match std::env::consts::ARCH {
        "x86_64" => Architecture::Amd64,
        "aarch64" => Architecture::Arm64,
        value => {
            return Err(RunnerError::FirecrackerConfiguration(format!(
                "unsupported Firecracker host architecture `{value}`"
            )))
        }
    };
    if actual != expected || std::env::consts::OS != "linux" {
        return Err(RunnerError::FirecrackerConfiguration(
            "Firecracker runtime profile does not match this Linux host architecture".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn host_memory_bytes() -> Result<u64, RunnerError> {
    let bytes = read_bounded_public_file(Path::new("/proc/meminfo"), 1024 * 1024)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        RunnerError::FirecrackerConfiguration("/proc/meminfo is not UTF-8".to_owned())
    })?;
    let kib = text
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|value| value.split_ascii_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            RunnerError::FirecrackerConfiguration("cannot parse host memory".to_owned())
        })?;
    kib.checked_mul(1024)
        .ok_or_else(|| RunnerError::FirecrackerConfiguration("host memory overflows".to_owned()))
}

pub(super) fn cpu_feature_digest() -> Result<ContentDigest, RunnerError> {
    let bytes = read_bounded_public_file(Path::new("/proc/cpuinfo"), MAX_CPUINFO_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        RunnerError::FirecrackerConfiguration("/proc/cpuinfo is not UTF-8".to_owned())
    })?;
    let mut feature_sets = text
        .lines()
        .filter_map(|line| {
            let (name, values) = line.split_once(':')?;
            matches!(name.trim(), "flags" | "Features").then(|| {
                values
                    .split_ascii_whitespace()
                    .map(ToOwned::to_owned)
                    .collect::<std::collections::BTreeSet<_>>()
            })
        })
        .collect::<Vec<_>>();
    let Some(mut common) = feature_sets.pop() else {
        return Err(RunnerError::FirecrackerConfiguration(
            "host CPU features are unavailable".to_owned(),
        ));
    };
    for features in feature_sets {
        common.retain(|feature| features.contains(feature));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"runtrue.firecracker.cpu-features.v1\0");
    hasher.update(std::env::consts::ARCH.as_bytes());
    hasher.update([0]);
    for feature in common {
        hasher.update(feature.as_bytes());
        hasher.update([0]);
    }
    ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))
}

pub(super) fn mitigation_profile_digest() -> Result<ContentDigest, RunnerError> {
    let directory = Path::new("/sys/devices/system/cpu/vulnerabilities");
    let mut paths = fs::read_dir(directory)
        .map_err(|error| {
            RunnerError::FirecrackerConfiguration(format!(
                "host CPU mitigation evidence is unavailable: {error}"
            ))
        })?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    if paths.is_empty() {
        return Err(RunnerError::FirecrackerConfiguration(
            "host CPU mitigation evidence is empty".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"runtrue.firecracker.mitigation-profile.v1\0");
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                RunnerError::FirecrackerConfiguration(
                    "host mitigation evidence has an invalid name".to_owned(),
                )
            })?;
        let bytes = read_bounded_public_file(&path, MAX_MITIGATION_FILE_BYTES)?;
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| {
                RunnerError::FirecrackerConfiguration(
                    "host mitigation evidence is not UTF-8".to_owned(),
                )
            })?
            .trim();
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(RunnerError::FirecrackerConfiguration(
                "host mitigation evidence is invalid".to_owned(),
            ));
        }
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))
}

fn read_bounded_public_file(path: &Path, maximum: u64) -> Result<Vec<u8>, RunnerError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "unsafe host evidence path `{}`",
            path.display()
        )));
    }
    let mut file = File::open(path)
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(RunnerError::FirecrackerConfiguration(format!(
            "host evidence path `{}` exceeds its bound",
            path.display()
        )));
    }
    Ok(bytes)
}

pub(super) fn acquire_cid_lock(directory: &Path, guest_cid: u32) -> Result<File, RunnerError> {
    let path = directory.join(format!("cid-{guest_cid}.lock"));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(&path).map_err(|error| {
        RunnerError::FirecrackerConfiguration(format!(
            "cannot open Firecracker CID reservation `{}`: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        RunnerError::FirecrackerConfiguration(format!(
            "cannot inspect Firecracker CID reservation: {error}"
        ))
    })?;
    #[cfg(unix)]
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(RunnerError::FirecrackerConfiguration(
            "Firecracker CID reservation is not a private single-link file".to_owned(),
        ));
    }
    flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock).map_err(|error| {
        RunnerError::FirecrackerConfiguration(format!(
            "Firecracker guest CID {guest_cid} is already reserved: {error}"
        ))
    })?;
    Ok(file)
}

pub(super) fn probe_reflink(
    provisioner: &ProcessReflinkProvisioner,
    source: &Path,
    paths: &FirecrackerPaths,
) -> Result<(), RunnerError> {
    let executable = paths.firecracker.file_name().ok_or_else(|| {
        RunnerError::FirecrackerConfiguration("Firecracker executable has no name".to_owned())
    })?;
    let active_root = paths.jail_root.join(executable);
    let destination = active_root.join(".runtrue-reflink-preflight");
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(RunnerError::FirecrackerConfiguration(
            "stale Firecracker reflink preflight state exists".to_owned(),
        ));
    }
    let probe = provisioner.reflink(source, &destination);
    let cleanup = match fs::remove_file(&destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound && probe.is_err() => Ok(()),
        Err(error) => Err(RunnerError::FirecrackerConfiguration(format!(
            "cannot clean Firecracker reflink probe: {error}"
        ))),
    };
    probe?;
    cleanup
}

pub(super) fn probe_cgroup_lifecycle(
    paths: &FirecrackerPaths,
    guest_cid: u32,
) -> Result<(), RunnerError> {
    let parent = Path::new("/sys/fs/cgroup").join(&paths.cgroup_parent);
    let probe = parent.join(format!(".runtrue-preflight-cid-{guest_cid}"));
    if fs::symlink_metadata(&probe).is_ok() {
        return Err(RunnerError::FirecrackerConfiguration(
            "stale Firecracker cgroup preflight state exists".to_owned(),
        ));
    }
    fs::create_dir(&probe).map_err(|error| {
        RunnerError::FirecrackerConfiguration(format!(
            "cannot create a Firecracker cgroup under the configured parent: {error}"
        ))
    })?;
    let result = (|| {
        let procs = fs::read(probe.join("cgroup.procs")).map_err(|error| {
            RunnerError::FirecrackerConfiguration(format!(
                "cannot inspect Firecracker cgroup preflight state: {error}"
            ))
        })?;
        if !String::from_utf8_lossy(&procs).trim().is_empty() {
            return Err(RunnerError::FirecrackerConfiguration(
                "new Firecracker cgroup unexpectedly contains a process".to_owned(),
            ));
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir(&probe).map_err(|error| {
        RunnerError::FirecrackerConfiguration(format!(
            "cannot remove Firecracker cgroup preflight state: {error}"
        ))
    });
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(RunnerError::FirecrackerConfiguration(format!(
            "{error}; cgroup preflight cleanup also failed: {cleanup}"
        ))),
    }
}
use super::{
    flock, fs, io, validate_no_symlink_components, Architecture, ContentDigest, File,
    FirecrackerPaths, FlockArg, OpenOptions, Path, PathBuf, ProcessReflinkProvisioner,
    ReflinkProvisioner, RunnerError, Sha256, MAX_CPUINFO_BYTES, MAX_MITIGATION_FILE_BYTES,
    MAX_RUNTIME_BINARY_BYTES,
};
use sha2::Digest as _;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
