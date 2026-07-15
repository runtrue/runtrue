use super::super::{
    discover_workflows, display_path, print_json, CliError, DoctorArgs, EXIT_OK, EXIT_VALIDATION,
};
use serde::Serialize;
use std::{
    env, fmt, fs, io,
    path::{Path, PathBuf},
};

pub(crate) fn doctor(workspace: &Path, args: DoctorArgs) -> Result<u8, CliError> {
    let mut checks = Vec::new();
    let supported_platform = matches!(env::consts::OS, "linux" | "windows" | "macos")
        && matches!(env::consts::ARCH, "x86_64" | "aarch64");
    checks.push(DoctorCheck::new(
        "host-platform",
        if supported_platform {
            DoctorStatus::Pass
        } else {
            DoctorStatus::Fail
        },
        format!("{}/{}", env::consts::OS, env::consts::ARCH),
    ));

    let workflows = workspace.join(".runtrue/workflows");
    match fs::symlink_metadata(workflows) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            match discover_workflows(workspace) {
                Ok(found) => checks.push(DoctorCheck::new(
                    "workflow-discovery",
                    DoctorStatus::Pass,
                    format!("{} workflow(s)", found.len()),
                )),
                Err(CliError::NoWorkflows(_)) => checks.push(DoctorCheck::new(
                    "workflow-discovery",
                    DoctorStatus::Warn,
                    "workflow directory is empty".to_owned(),
                )),
                Err(error) => checks.push(DoctorCheck::new(
                    "workflow-discovery",
                    DoctorStatus::Fail,
                    error.to_string(),
                )),
            }
        }
        Ok(_) => checks.push(DoctorCheck::new(
            "workflow-discovery",
            DoctorStatus::Fail,
            ".runtrue/workflows is a symlink or is not a directory".to_owned(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => checks.push(DoctorCheck::new(
            "workflow-discovery",
            DoctorStatus::Warn,
            "no .runtrue/workflows directory; pass --workflow or run runtrue init".to_owned(),
        )),
        Err(error) => checks.push(DoctorCheck::new(
            "workflow-discovery",
            DoctorStatus::Fail,
            error.to_string(),
        )),
    }

    checks.push(DoctorCheck::new(
        "native-execution",
        DoctorStatus::Warn,
        "available only with --allow-native; it is not sandboxed".to_owned(),
    ));
    for (name, executable) in [
        ("wasm-backend", "wasmtime"),
        ("oci-backend", "podman"),
        ("microvm-backend", "firecracker"),
    ] {
        let found = find_executable(executable);
        checks.push(DoctorCheck::new(
            name,
            if found.is_some() {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Warn
            },
            found.map_or_else(
                || format!("`{executable}` is unavailable"),
                |path| path.display().to_string(),
            ),
        ));
    }

    let kvm = Path::new("/dev/kvm");
    let kvm_status = match fs::symlink_metadata(kvm) {
        Ok(metadata) if kvm_device_type_is_valid(&metadata) => DoctorCheck::new(
            "kvm-device",
            DoctorStatus::Pass,
            "/dev/kvm is present".to_owned(),
        ),
        Ok(_) => DoctorCheck::new(
            "kvm-device",
            DoctorStatus::Fail,
            "/dev/kvm is not the expected device type".to_owned(),
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => DoctorCheck::new(
            "kvm-device",
            DoctorStatus::Warn,
            "/dev/kvm is unavailable; microVM execution cannot start".to_owned(),
        ),
        Err(error) => DoctorCheck::new("kvm-device", DoctorStatus::Fail, error.to_string()),
    };
    checks.push(kvm_status);

    for (name, path) in [
        ("local-cache", workspace.join(".runtrue/cache")),
        ("local-artifacts", workspace.join(".runtrue/artifacts")),
        ("local-secret-store", workspace.join(".runtrue/secrets")),
    ] {
        let check = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                DoctorCheck::new(name, DoctorStatus::Pass, display_path(workspace, &path))
            }
            Ok(_) => DoctorCheck::new(
                name,
                DoctorStatus::Fail,
                format!("{} is a symlink or is not a directory", path.display()),
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                DoctorCheck::new(name, DoctorStatus::Warn, "not initialized".to_owned())
            }
            Err(error) => DoctorCheck::new(name, DoctorStatus::Fail, error.to_string()),
        };
        checks.push(check);
    }

    let healthy = checks
        .iter()
        .all(|check| check.status != DoctorStatus::Fail);
    let report = DoctorReport { healthy, checks };
    if args.json {
        print_json(&report)?;
    } else {
        for check in &report.checks {
            println!("{:>4}  {:<24} {}", check.status, check.name, check.detail);
        }
        println!("healthy: {}", report.healthy);
    }
    Ok(if healthy { EXIT_OK } else { EXIT_VALIDATION })
}

fn find_executable(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| {
                fs::metadata(candidate)
                    .ok()
                    .is_some_and(|metadata| executable_file(&metadata))
            })
    })
}

#[cfg(unix)]
fn executable_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
}

#[cfg(unix)]
fn kvm_device_type_is_valid(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    metadata.file_type().is_char_device()
}

#[cfg(not(unix))]
fn kvm_device_type_is_valid(_metadata: &fs::Metadata) -> bool {
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

impl fmt::Display for DoctorStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        })
    }
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: &'static str,
    status: DoctorStatus,
    detail: String,
}

impl DoctorCheck {
    fn new(name: &'static str, status: DoctorStatus, detail: String) -> Self {
        Self {
            name,
            status,
            detail,
        }
    }
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    healthy: bool,
    checks: Vec<DoctorCheck>,
}
