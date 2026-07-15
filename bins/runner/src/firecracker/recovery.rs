pub(super) fn recover_abandoned_jails(
    paths: &FirecrackerPaths,
    quarantine_root: &Path,
) -> Result<(), RunnerError> {
    let executable = paths.firecracker.file_name().ok_or_else(|| {
        RunnerError::FirecrackerConfiguration("Firecracker executable has no name".to_owned())
    })?;
    let active_root = paths.jail_root.join(executable);
    for entry in sorted_directory_entries(&active_root)? {
        let name = entry
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                RunnerError::FirecrackerConfiguration("invalid Firecracker jail name".to_owned())
            })?;
        if !name.starts_with("job-")
            || name.len() != 36
            || !name[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RunnerError::FirecrackerConfiguration(format!(
                "unexpected entry in Firecracker jail root `{name}`"
            )));
        }
        let metadata = fs::symlink_metadata(&entry)
            .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RunnerError::FirecrackerConfiguration(
                "abandoned Firecracker jail is not a real directory".to_owned(),
            ));
        }
        if vm_process_exists(name, &entry)? {
            return Err(RunnerError::FirecrackerConfiguration(format!(
                "abandoned Firecracker jail `{name}` still has a live process"
            )));
        }
        verify_cgroup_clean(paths, name)?;
        let boot = entry.join("root/boot-config.img");
        match fs::remove_file(&boot) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RunnerError::FirecrackerConfiguration(format!(
                    "cannot erase abandoned guest boot secret: {error}"
                )))
            }
        }
        let destination = quarantine_root.join(format!("{name}-recovered"));
        if fs::symlink_metadata(&destination).is_ok() {
            return Err(RunnerError::FirecrackerConfiguration(format!(
                "recovered Firecracker quarantine already exists for `{name}`"
            )));
        }
        fs::rename(&entry, &destination).map_err(|error| {
            RunnerError::FirecrackerConfiguration(format!(
                "cannot quarantine abandoned Firecracker jail `{name}`: {error}"
            ))
        })?;
    }
    Ok(())
}

pub(super) fn verify_cgroup_clean(
    paths: &FirecrackerPaths,
    vm_id: &str,
) -> Result<(), RunnerError> {
    let executable = paths.firecracker.file_name().ok_or_else(|| {
        RunnerError::FirecrackerConfiguration("Firecracker executable has no name".to_owned())
    })?;
    let cgroup = Path::new("/sys/fs/cgroup")
        .join(&paths.cgroup_parent)
        .join(executable)
        .join(vm_id);
    let metadata = match fs::symlink_metadata(&cgroup) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(RunnerError::FirecrackerConfiguration(format!(
                "cannot inspect Firecracker cgroup: {error}"
            )))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunnerError::FirecrackerConfiguration(
            "Firecracker cgroup path is unsafe".to_owned(),
        ));
    }
    let procs = fs::read(cgroup.join("cgroup.procs")).map_err(|error| {
        RunnerError::FirecrackerConfiguration(format!(
            "cannot verify Firecracker cgroup membership: {error}"
        ))
    })?;
    if procs.len() > 1024 * 1024
        || procs
            .iter()
            .any(|byte| !byte.is_ascii_whitespace() && !byte.is_ascii_digit())
        || !String::from_utf8_lossy(&procs).trim().is_empty()
    {
        return Err(RunnerError::FirecrackerConfiguration(
            "Firecracker cgroup still contains a process".to_owned(),
        ));
    }
    fs::remove_dir(&cgroup).map_err(|error| {
        RunnerError::FirecrackerConfiguration(format!(
            "cannot remove empty Firecracker cgroup: {error}"
        ))
    })
}

fn vm_process_exists(vm_id: &str, jail: &Path) -> Result<bool, RunnerError> {
    for entry in fs::read_dir("/proc")
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let process = entry.path();
        if fs::read_link(process.join("root")).is_ok_and(|root| root.starts_with(jail.join("root")))
        {
            return Ok(true);
        }
        let command = match fs::read(process.join("cmdline")) {
            Ok(command) if command.len() <= 64 * 1024 => command,
            Ok(_) | Err(_) => continue,
        };
        let arguments = command
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .collect::<Vec<_>>();
        if arguments
            .windows(2)
            .any(|pair| pair[0] == b"--id" && pair[1] == vm_id.as_bytes())
        {
            return Ok(true);
        }
    }
    Ok(false)
}
use super::host::sorted_directory_entries;
use super::{fs, io, FirecrackerPaths, Path, RunnerError};
