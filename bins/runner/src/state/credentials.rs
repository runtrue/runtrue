pub(crate) fn read_bounded_private_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Vec<u8>, StateError> {
    let credentials_directory = systemd_credentials_directory();
    read_bounded_private_file_with_credentials(
        path,
        maximum_bytes,
        credentials_directory.as_deref(),
    )
}

pub(super) fn read_bounded_private_file_with_credentials(
    path: &Path,
    maximum_bytes: u64,
    credentials_directory: Option<&Path>,
) -> Result<Vec<u8>, StateError> {
    validate_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    validate_private_file_with_credentials(path, &metadata, credentials_directory)?;
    if metadata.len() == 0 || metadata.len() > maximum_bytes {
        return Err(StateError::FileLimit {
            path: path.to_owned(),
            maximum_bytes,
        });
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let opened = file.metadata().map_err(|source| io_error(path, source))?;
    validate_private_file_with_credentials(path, &opened, credentials_directory)?;
    #[cfg(unix)]
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(StateError::UnsafePath(path.to_owned()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        return Err(StateError::FileLimit {
            path: path.to_owned(),
            maximum_bytes,
        });
    }
    Ok(bytes)
}

pub(crate) fn validate_private_file(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), StateError> {
    let credentials_directory = systemd_credentials_directory();
    validate_private_file_with_credentials(path, metadata, credentials_directory.as_deref())
}

fn validate_private_file_with_credentials(
    path: &Path,
    metadata: &fs::Metadata,
    credentials_directory: Option<&Path>,
) -> Result<(), StateError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StateError::UnsafePath(path.to_owned()));
    }
    #[cfg(unix)]
    if !private_file_metadata_is_secure(path, metadata, credentials_directory) {
        return Err(StateError::InsecurePermissions(path.to_owned()));
    }
    Ok(())
}

fn systemd_credentials_directory() -> Option<PathBuf> {
    let directory = PathBuf::from(env::var_os("CREDENTIALS_DIRECTORY")?);
    normalized_absolute_path(&directory).then_some(directory)
}

fn normalized_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

fn is_direct_systemd_credential(path: &Path, credentials_directory: Option<&Path>) -> bool {
    let Some(directory) = credentials_directory else {
        return false;
    };
    normalized_absolute_path(directory)
        && normalized_absolute_path(path)
        && path.parent() == Some(directory)
        && path.file_name().is_some()
        && systemd_credentials_directory_is_secure(directory)
}

#[cfg(unix)]
fn systemd_credentials_directory_is_secure(directory: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(directory) else {
        return false;
    };
    let effective_uid = nix::unistd::geteuid().as_raw();
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if metadata.uid() == 0 {
        metadata.gid() == 0 && mode & 0o027 == 0
    } else {
        metadata.uid() == effective_uid && mode & 0o077 == 0
    }
}

#[cfg(not(unix))]
const fn systemd_credentials_directory_is_secure(_directory: &Path) -> bool {
    false
}

#[cfg(unix)]
fn private_file_metadata_is_secure(
    path: &Path,
    metadata: &fs::Metadata,
    credentials_directory: Option<&Path>,
) -> bool {
    if !metadata.is_file() || metadata.nlink() != 1 {
        return false;
    }
    let mode = metadata.permissions().mode() & 0o7777;
    let effective_uid = nix::unistd::geteuid().as_raw();
    let effective_gid = nix::unistd::getegid().as_raw();
    if is_direct_systemd_credential(path, credentials_directory) {
        let safe_owner = metadata.uid() == 0 || metadata.uid() == effective_uid;
        let safe_group = mode == 0o400
            || (metadata.uid() == 0 && metadata.gid() == 0)
            || (metadata.uid() == effective_uid && metadata.gid() == effective_gid);
        return matches!(mode, 0o400 | 0o440) && safe_owner && safe_group;
    }
    mode == 0o600 && metadata.uid() == effective_uid
}
use super::{io_error, validate_no_symlink_components, StateError};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Read as _,
    path::{Component, Path, PathBuf},
};
