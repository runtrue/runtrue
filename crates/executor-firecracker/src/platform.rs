use crate::FirecrackerError;
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirecrackerPaths {
    pub jailer: PathBuf,
    pub firecracker: PathBuf,
    pub reflink_copy: PathBuf,
    pub jail_root: PathBuf,
    pub cgroup_parent: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRequirements {
    pub paths: FirecrackerPaths,
    /// Configured only when a separate policy adapter makes this TAP the
    /// workload's sole authorized network path.
    pub tap_device: Option<String>,
}

pub trait HostCapabilityProbe: Send + Sync {
    fn preflight(&self, requirements: &HostRequirements) -> Result<(), FirecrackerError>;
}

/// Linux host checks which perform no mutations. Creating a cgroup and tap is
/// an explicit deployment responsibility, never an implicit executor side
/// effect.
#[derive(Debug, Default)]
pub struct LinuxHostCapabilityProbe;

impl HostCapabilityProbe for LinuxHostCapabilityProbe {
    fn preflight(&self, requirements: &HostRequirements) -> Result<(), FirecrackerError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = requirements;
            return Err(FirecrackerError::Preflight(
                "Firecracker is supported only on Linux".to_owned(),
            ));
        }
        #[cfg(target_os = "linux")]
        {
            validate_executable(&requirements.paths.jailer, "jailer")?;
            validate_executable(&requirements.paths.firecracker, "firecracker")?;
            validate_executable(&requirements.paths.reflink_copy, "reflink copy")?;
            validate_private_root(&requirements.paths.jail_root, "jail root")?;
            validate_relative_cgroup(&requirements.paths.cgroup_parent)?;
            validate_private_root(
                &Path::new("/sys/fs/cgroup").join(&requirements.paths.cgroup_parent),
                "cgroup parent",
            )?;
            check_read_write(Path::new("/dev/kvm"), "KVM")?;
            check_read_write(Path::new("/dev/vhost-vsock"), "vhost-vsock")?;
            if let Some(tap_device) = &requirements.tap_device {
                check_read_write(Path::new("/dev/net/tun"), "TUN/TAP")?;
                validate_tap_name(tap_device)?;
                let tap = Path::new("/sys/class/net").join(tap_device);
                let metadata = fs::symlink_metadata(tap).map_err(|error| {
                    FirecrackerError::Preflight(format!(
                        "tap device {tap_device} is unavailable: {error}"
                    ))
                })?;
                if !metadata.is_dir() && !metadata.file_type().is_symlink() {
                    return Err(FirecrackerError::Preflight(format!(
                        "tap device {tap_device} is invalid"
                    )));
                }
            }
            let controllers =
                fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").map_err(|error| {
                    FirecrackerError::Preflight(format!("cgroup v2 is unavailable: {error}"))
                })?;
            for required in ["cpu", "memory", "pids"] {
                if !controllers
                    .split_ascii_whitespace()
                    .any(|value| value == required)
                {
                    return Err(FirecrackerError::Preflight(format!(
                        "cgroup v2 controller {required} is unavailable"
                    )));
                }
            }
            if effective_uid()? != 0 {
                return Err(FirecrackerError::Preflight(
                    "the Firecracker jailer must be launched by host root".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailerInvocation {
    pub program: PathBuf,
    pub arguments: Vec<String>,
}

impl JailerInvocation {
    pub fn build_for_launch(
        requirements: &HostRequirements,
        vm_id: &str,
        uid: u32,
        gid: u32,
        launch: &crate::FirecrackerLaunchPlan,
    ) -> Result<Self, FirecrackerError> {
        match launch {
            crate::FirecrackerLaunchPlan::Cold(_) => Self::build(
                requirements,
                vm_id,
                uid,
                gid,
                Path::new("/firecracker.json"),
            ),
            crate::FirecrackerLaunchPlan::Snapshot(request) => {
                request.verify_firecracker_binary(&requirements.paths.firecracker)?;
                Self::build_snapshot(
                    requirements,
                    vm_id,
                    uid,
                    gid,
                    Path::new(crate::snapshot::IN_JAIL_API_SOCKET),
                )
            }
        }
    }

    pub fn build(
        requirements: &HostRequirements,
        vm_id: &str,
        uid: u32,
        gid: u32,
        firecracker_config: &Path,
    ) -> Result<Self, FirecrackerError> {
        if firecracker_config != Path::new("/firecracker.json") {
            return Err(FirecrackerError::InvalidConfiguration(
                "the in-jail Firecracker config path must be /firecracker.json".to_owned(),
            ));
        }
        Self::with_firecracker_arguments(
            requirements,
            vm_id,
            uid,
            gid,
            vec![
                "--config-file".to_owned(),
                firecracker_config.display().to_string(),
            ],
        )
    }

    pub(crate) fn build_snapshot(
        requirements: &HostRequirements,
        vm_id: &str,
        uid: u32,
        gid: u32,
        api_socket: &Path,
    ) -> Result<Self, FirecrackerError> {
        if api_socket != Path::new(crate::snapshot::IN_JAIL_API_SOCKET) {
            return Err(FirecrackerError::InvalidConfiguration(
                "the in-jail Firecracker API socket must be /run/firecracker-api.sock".to_owned(),
            ));
        }
        Self::with_firecracker_arguments(
            requirements,
            vm_id,
            uid,
            gid,
            vec!["--api-sock".to_owned(), api_socket.display().to_string()],
        )
    }

    fn with_firecracker_arguments(
        requirements: &HostRequirements,
        vm_id: &str,
        uid: u32,
        gid: u32,
        firecracker_arguments: Vec<String>,
    ) -> Result<Self, FirecrackerError> {
        validate_vm_id(vm_id)?;
        validate_relative_cgroup(&requirements.paths.cgroup_parent)?;
        if uid == 0 || gid == 0 {
            return Err(FirecrackerError::InvalidConfiguration(
                "jailed uid and gid must be non-zero".to_owned(),
            ));
        }
        let mut arguments = vec![
            "--id".to_owned(),
            vm_id.to_owned(),
            "--exec-file".to_owned(),
            requirements.paths.firecracker.display().to_string(),
            "--uid".to_owned(),
            uid.to_string(),
            "--gid".to_owned(),
            gid.to_string(),
            "--chroot-base-dir".to_owned(),
            requirements.paths.jail_root.display().to_string(),
            "--cgroup-version".to_owned(),
            "2".to_owned(),
            "--parent-cgroup".to_owned(),
            requirements.paths.cgroup_parent.display().to_string(),
            "--".to_owned(),
        ];
        arguments.extend(firecracker_arguments);
        Ok(Self {
            program: requirements.paths.jailer.clone(),
            arguments,
        })
    }
}

pub(crate) fn validate_executable(path: &Path, name: &str) -> Result<(), FirecrackerError> {
    if !path.is_absolute() {
        return Err(FirecrackerError::InvalidConfiguration(format!(
            "{name} path must be absolute"
        )));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| FirecrackerError::Preflight(format!("cannot inspect {name}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(FirecrackerError::Preflight(format!(
            "{name} must be a regular non-symlink file"
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(FirecrackerError::Preflight(format!(
            "{name} is not executable"
        )));
    }
    Ok(())
}

fn validate_private_root(path: &Path, name: &str) -> Result<(), FirecrackerError> {
    if !path.is_absolute() {
        return Err(FirecrackerError::Preflight(format!(
            "{name} path must be absolute"
        )));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| FirecrackerError::Preflight(format!("cannot inspect {name}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(FirecrackerError::Preflight(format!(
            "{name} must be a non-symlink directory"
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(FirecrackerError::Preflight(format!(
            "{name} must not be writable by group or other"
        )));
    }
    Ok(())
}

fn check_read_write(path: &Path, name: &str) -> Result<(), FirecrackerError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| FirecrackerError::Preflight(format!("{name} is unavailable: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(FirecrackerError::Preflight(format!(
            "{name} device must not be a symlink"
        )));
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| FirecrackerError::Preflight(format!("cannot open {name}: {error}")))?;
    Ok(())
}

fn validate_tap_name(name: &str) -> Result<(), FirecrackerError> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(FirecrackerError::InvalidConfiguration(
            "tap device name is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_cgroup(path: &Path) -> Result<(), FirecrackerError> {
    if path.is_absolute()
        || path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(FirecrackerError::InvalidConfiguration(
            "jailer parent cgroup must be a non-empty relative path".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32, FirecrackerError> {
    let status = fs::read_to_string("/proc/self/status").map_err(|error| {
        FirecrackerError::Preflight(format!("cannot read process uid: {error}"))
    })?;
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|value| value.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| FirecrackerError::Preflight("cannot parse process uid".to_owned()))?;
    Ok(effective)
}

fn validate_vm_id(value: &str) -> Result<(), FirecrackerError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(FirecrackerError::InvalidConfiguration(
            "VM id must contain only lowercase ASCII, digits, and hyphens".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirements() -> HostRequirements {
        HostRequirements {
            paths: FirecrackerPaths {
                jailer: PathBuf::from("/opt/runtrue/jailer"),
                firecracker: PathBuf::from("/opt/runtrue/firecracker"),
                reflink_copy: PathBuf::from("/bin/cp"),
                jail_root: PathBuf::from("/var/lib/runtrue/jailer"),
                cgroup_parent: PathBuf::from("runtrue"),
            },
            tap_device: Some("runtrue0".to_owned()),
        }
    }

    #[test]
    fn jailer_arguments_are_structured_without_a_shell() {
        let invocation = JailerInvocation::build(
            &requirements(),
            "job-deadbeef",
            1000,
            1000,
            Path::new("/firecracker.json"),
        )
        .unwrap();
        assert_eq!(invocation.program, Path::new("/opt/runtrue/jailer"));
        assert!(invocation.arguments.iter().any(|value| value == "--"));
        assert!(!invocation.arguments.iter().any(|value| value == "sh"));
    }

    #[test]
    fn rejects_injectable_vm_id() {
        assert!(JailerInvocation::build(
            &requirements(),
            "job;reboot",
            1000,
            1000,
            Path::new("/firecracker.json")
        )
        .is_err());
    }

    #[test]
    fn snapshot_jailer_uses_api_socket_without_cold_config() {
        let invocation = JailerInvocation::build_snapshot(
            &requirements(),
            "job-deadbeef",
            1000,
            1000,
            Path::new("/run/firecracker-api.sock"),
        )
        .unwrap();
        assert!(invocation
            .arguments
            .iter()
            .any(|value| value == "--api-sock"));
        assert!(!invocation
            .arguments
            .iter()
            .any(|value| value == "--config-file"));
    }
}
