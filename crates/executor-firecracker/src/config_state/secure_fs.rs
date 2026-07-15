use crate::{state_io, FirecrackerError};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};
pub(super) fn prepare_private_directory(path: &Path) -> Result<(), FirecrackerError> {
    if !path.is_absolute() {
        return Err(FirecrackerError::InvalidConfiguration(
            "state roots must be absolute".to_owned(),
        ));
    }
    if !path.exists() {
        fs::create_dir_all(path).map_err(|source| state_io(path, source))?;
        set_mode(path, 0o700)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| state_io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(FirecrackerError::InvalidConfiguration(
            "state root must be a non-symlink directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(FirecrackerError::InvalidConfiguration(
            "state root mode must be exactly 0700".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), FirecrackerError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|source| state_io(path, source))?;
    file.write_all(bytes)
        .map_err(|source| state_io(path, source))?;
    file.sync_all().map_err(|source| state_io(path, source))?;
    Ok(())
}

pub(super) fn create_private_fifo_placeholder(path: &Path) -> Result<(), FirecrackerError> {
    // Deployments may replace these with FIFOs before launch; regular private
    // files also satisfy Firecracker's logger/metrics sink contract.
    write_new_private(path, &[])
}

pub(super) fn remove_boot_secret(path: &Path) -> Result<(), FirecrackerError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(state_io(path, source)),
    }
}

pub(super) fn set_mode(path: &Path, mode: u32) -> Result<(), FirecrackerError> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|source| state_io(path, source))
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        Err(FirecrackerError::InvalidConfiguration(
            "private Firecracker state requires Unix permissions".to_owned(),
        ))
    }
}
