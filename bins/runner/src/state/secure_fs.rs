pub(crate) fn prepare_private_directory(path: &Path) -> Result<PathBuf, StateError> {
    validate_no_symlink_components(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(StateError::UnsafePath(path.to_owned()));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|source| io_error(path, source))?;
        }
        Err(source) => return Err(io_error(path, source)),
    }
    validate_no_symlink_components(path)?;
    set_private_directory_permissions(path)?;
    Ok(path.to_owned())
}

pub(crate) fn validate_no_symlink_components(path: &Path) -> Result<(), StateError> {
    let mut checked = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::Normal(_) => checked.push(component.as_os_str()),
            std::path::Component::CurDir => continue,
            std::path::Component::ParentDir => return Err(StateError::UnsafePath(path.to_owned())),
        }
        match fs::symlink_metadata(&checked) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StateError::UnsafePath(checked));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(&checked, source)),
        }
    }
    Ok(())
}

pub(super) fn set_private_directory_permissions(path: &Path) -> Result<(), StateError> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(path, source))?;
    Ok(())
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), StateError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

pub(crate) fn random_hex() -> Result<String, StateError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| StateError::RandomnessUnavailable)?;
    Ok(hex::encode(bytes))
}

pub(crate) fn io_error(path: &Path, source: io::Error) -> StateError {
    StateError::Io {
        path: path.to_owned(),
        source,
    }
}

use super::StateError;
use rand_core::{OsRng, RngCore as _};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};
