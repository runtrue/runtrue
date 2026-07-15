pub(super) fn set_private_directory_permissions(path: &Path) -> Result<(), CredentialError> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(path, source))?;
    Ok(())
}

pub(super) fn remove_unpublished_directory(path: &Path) {
    if fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    {
        let _ = fs::remove_dir_all(path);
    }
}

pub(super) fn map_missing_current(error: StateError, current: &Path) -> CredentialError {
    match error {
        StateError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound => {
            CredentialError::MissingCredentials(current.to_owned())
        }
        other => CredentialError::State(other),
    }
}

use super::CredentialError;
use crate::state::{io_error, StateError};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{fs, io, path::Path};
