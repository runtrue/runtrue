use super::{AdminError, MAX_ADMIN_NAME_BYTES, MAX_VARIABLE_VALUE_BYTES, PRIVATE_TEMP_SEQUENCE};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    path::{Component, Path, PathBuf},
    sync::atomic::Ordering,
};

pub(super) fn validate_name(name: &str) -> Result<(), AdminError> {
    if name.is_empty()
        || name.len() > MAX_ADMIN_NAME_BYTES
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(AdminError::InvalidName);
    }
    Ok(())
}

pub(super) fn validate_variable_value(value: &str) -> Result<(), AdminError> {
    if value.len() > MAX_VARIABLE_VALUE_BYTES {
        return Err(AdminError::VariableValueTooLarge {
            limit: MAX_VARIABLE_VALUE_BYTES,
            actual: value.len(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(AdminError::InvalidVariableValue);
    }
    Ok(())
}

pub(super) fn ensure_runtrue_directory(
    workspace: &Path,
    create: bool,
) -> Result<PathBuf, AdminError> {
    require_real_directory(workspace, "workspace")?;
    let directory = workspace.join(".runtrue");
    ensure_child_directory(workspace, &directory, create, false)?;
    Ok(directory)
}

pub(super) fn ensure_secrets_directory(
    workspace: &Path,
    create: bool,
) -> Result<PathBuf, AdminError> {
    let runtrue = ensure_runtrue_directory(workspace, create)?;
    let directory = runtrue.join("secrets");
    ensure_child_directory(&runtrue, &directory, create, true)?;
    Ok(directory)
}

pub(super) fn ensure_child_directory(
    parent: &Path,
    path: &Path,
    create: bool,
    require_private: bool,
) -> Result<(), AdminError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => require_directory_metadata(path, &metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(AdminError::Write {
                        path: path.to_owned(),
                        source,
                    });
                }
            }
            let metadata = fs::symlink_metadata(path).map_err(|source| AdminError::Read {
                path: path.to_owned(),
                source,
            })?;
            require_directory_metadata(path, &metadata)?;
            set_private_directory_mode(path)?;
            sync_directory(parent)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(AdminError::StateMissing("administration state"));
        }
        Err(source) => {
            return Err(AdminError::Read {
                path: path.to_owned(),
                source,
            });
        }
    }
    if require_private {
        require_private_directory_mode(path)?;
    }
    Ok(())
}

pub(super) fn require_real_directory(path: &Path, kind: &'static str) -> Result<(), AdminError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| AdminError::Read {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AdminError::UnsafePath {
            path: path.to_owned(),
            reason: kind,
        });
    }
    Ok(())
}

pub(super) fn require_directory_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), AdminError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AdminError::UnsafePath {
            path: path.to_owned(),
            reason: "path component is a symlink or is not a directory",
        });
    }
    Ok(())
}

pub(super) fn set_private_directory_mode(path: &Path) -> Result<(), AdminError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            AdminError::Write {
                path: path.to_owned(),
                source,
            }
        })?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(super) fn require_private_directory_mode(path: &Path) -> Result<(), AdminError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let actual = fs::metadata(path)
            .map_err(|source| AdminError::Read {
                path: path.to_owned(),
                source,
            })?
            .permissions()
            .mode()
            & 0o7777;
        if actual != 0o700 {
            return Err(AdminError::InsecurePermissions {
                path: path.to_owned(),
                expected: 0o700,
                actual,
            });
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(super) fn secure_file_exists(path: &Path, kind: &'static str) -> Result<bool, AdminError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AdminError::UnsafePath {
                    path: path.to_owned(),
                    reason: kind,
                });
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(AdminError::Read {
            path: path.to_owned(),
            source,
        }),
    }
}

pub(super) fn read_regular_file(
    path: &Path,
    limit: u64,
    kind: &'static str,
    require_private: bool,
) -> Result<Vec<u8>, AdminError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|source| AdminError::Read {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| AdminError::Read {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(AdminError::UnsafePath {
            path: path.to_owned(),
            reason: kind,
        });
    }
    if require_private {
        require_private_file_mode(path, &metadata)?;
    }
    if metadata.len() > limit {
        return Err(AdminError::InputTooLarge {
            kind,
            limit,
            actual: metadata.len(),
        });
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| AdminError::Read {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(AdminError::InputTooLarge {
            kind,
            limit,
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

pub(super) fn require_private_file_mode(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), AdminError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let actual = metadata.permissions().mode() & 0o7777;
        if actual != 0o600 {
            return Err(AdminError::InsecurePermissions {
                path: path.to_owned(),
                expected: 0o600,
                actual,
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (path, metadata);
    Ok(())
}

pub(super) fn write_private_atomic(
    directory: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), AdminError> {
    require_real_directory(directory, "state directory")?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AdminError::UnsafePath {
                    path: path.to_owned(),
                    reason: "state target is a symlink or is not a regular file",
                });
            }
            require_private_file_mode(path, &metadata)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(AdminError::Read {
                path: path.to_owned(),
                source,
            });
        }
    }
    let (temporary_path, mut temporary) = reserve_private_temporary(directory)?;
    let write_result = temporary
        .write_all(bytes)
        .and_then(|()| temporary.sync_all());
    drop(temporary);
    if let Err(source) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(AdminError::Write {
            path: temporary_path,
            source,
        });
    }
    match fs::rename(&temporary_path, path) {
        Ok(()) => sync_directory(directory),
        Err(source) => {
            let _ = fs::remove_file(&temporary_path);
            Err(AdminError::Write {
                path: path.to_owned(),
                source,
            })
        }
    }
}

pub(super) fn write_revealed_secret(
    workspace: &Path,
    requested: &Path,
    bytes: &[u8],
) -> Result<PathBuf, AdminError> {
    let destination = resolve_explicit_path(workspace, requested)?;
    reject_internal_admin_path(workspace, &destination)?;
    let directory = destination.parent().ok_or_else(|| AdminError::UnsafePath {
        path: destination.clone(),
        reason: "reveal destination has no parent",
    })?;
    validate_directory_chain(directory)?;
    match fs::symlink_metadata(&destination) {
        Ok(_) => return Err(AdminError::RevealTargetExists(destination)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(AdminError::Read {
                path: destination,
                source,
            });
        }
    }
    let (temporary_path, mut temporary) = reserve_private_temporary(directory)?;
    let write_result = temporary
        .write_all(bytes)
        .and_then(|()| temporary.sync_all());
    drop(temporary);
    if let Err(source) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(AdminError::Write {
            path: temporary_path,
            source,
        });
    }
    match fs::hard_link(&temporary_path, &destination) {
        Ok(()) => {
            fs::remove_file(&temporary_path).map_err(|source| AdminError::Write {
                path: temporary_path,
                source,
            })?;
            sync_directory(directory)?;
            Ok(destination)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary_path);
            Err(AdminError::RevealTargetExists(destination))
        }
        Err(source) => {
            let _ = fs::remove_file(&temporary_path);
            Err(AdminError::Write {
                path: destination,
                source,
            })
        }
    }
}

pub(super) fn reserve_private_temporary(directory: &Path) -> Result<(PathBuf, File), AdminError> {
    for _ in 0..1_000 {
        let sequence = PRIVATE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(
            ".runtrue-private-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        match options.open(&path) {
            Ok(file) => {
                if let Err(error) = set_private_file_mode(&path, &file) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                return Ok((path, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(AdminError::Write { path, source }),
        }
    }
    Err(AdminError::TemporaryExhausted(directory.to_owned()))
}

pub(super) fn set_private_file_mode(path: &Path, file: &File) -> Result<(), AdminError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| AdminError::Write {
                path: path.to_owned(),
                source,
            })?;
    }
    #[cfg(not(unix))]
    let _ = (path, file);
    Ok(())
}

pub(super) fn resolve_explicit_path(
    workspace: &Path,
    requested: &Path,
) -> Result<PathBuf, AdminError> {
    let joined = if requested.is_absolute() {
        requested.to_owned()
    } else {
        workspace.join(requested)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(AdminError::UnsafePath {
                    path: requested.to_owned(),
                    reason: "parent traversal is not allowed",
                });
            }
        }
    }
    let parent = normalized.parent().ok_or_else(|| AdminError::UnsafePath {
        path: normalized.clone(),
        reason: "path has no parent",
    })?;
    validate_directory_chain(parent)?;
    Ok(normalized)
}

pub(super) fn validate_directory_chain(path: &Path) -> Result<(), AdminError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
                let metadata =
                    fs::symlink_metadata(&current).map_err(|source| AdminError::Read {
                        path: current.clone(),
                        source,
                    })?;
                require_directory_metadata(&current, &metadata)?;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(AdminError::UnsafePath {
                    path: path.to_owned(),
                    reason: "parent traversal is not allowed",
                });
            }
        }
    }
    Ok(())
}

pub(super) fn reject_internal_admin_path(workspace: &Path, path: &Path) -> Result<(), AdminError> {
    let secrets = workspace.join(".runtrue/secrets");
    let variables = workspace.join(".runtrue/vars.json");
    if path.starts_with(secrets) || path == variables {
        return Err(AdminError::UnsafePath {
            path: path.to_owned(),
            reason: "administration state cannot be used as a secret input or reveal target",
        });
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<(), AdminError> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| AdminError::Write {
                path: path.to_owned(),
                source,
            })?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(super) fn display_path(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub(super) fn print_json<T: Serialize>(value: &T) -> Result<(), AdminError> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value).map_err(AdminError::SerializeOutput)?;
    writeln!(stdout).map_err(AdminError::Output)
}
