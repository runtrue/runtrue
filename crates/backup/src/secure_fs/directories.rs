use super::{
    identity::{require_directory, require_private_permissions, set_directory_permissions},
    paths::{reject_symlink_components, validate_relative_path},
};
use crate::{BackupError, BackupLimits};
use std::{
    fs,
    path::{Component, Path},
};

#[derive(Debug)]
pub(crate) struct PreparedDirectory {
    pub(crate) created: bool,
}

pub(crate) fn prepare_empty_directory(path: &Path) -> Result<PreparedDirectory, BackupError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    require_private_real_directory(parent)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            require_directory(path, &metadata)?;
            require_private_permissions(path, &metadata)?;
            let mut entries = fs::read_dir(path).map_err(|source| BackupError::Io {
                operation: "read empty destination",
                path: path.to_owned(),
                source,
            })?;
            if entries.next().is_some() {
                return Err(BackupError::DestinationNotEmpty(path.to_owned()));
            }
            Ok(PreparedDirectory { created: false })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|source| BackupError::Io {
                operation: "create destination",
                path: path.to_owned(),
                source,
            })?;
            set_directory_permissions(path)?;
            let metadata = fs::symlink_metadata(path).map_err(|source| BackupError::Io {
                operation: "inspect destination",
                path: path.to_owned(),
                source,
            })?;
            require_directory(path, &metadata)?;
            Ok(PreparedDirectory { created: true })
        }
        Err(source) => Err(BackupError::Io {
            operation: "inspect destination",
            path: path.to_owned(),
            source,
        }),
    }
}

pub(crate) fn require_backup_directory(path: &Path) -> Result<(), BackupError> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| BackupError::Io {
        operation: "inspect backup directory",
        path: path.to_owned(),
        source,
    })?;
    require_directory(path, &metadata)?;
    require_private_permissions(path, &metadata)
}

pub(crate) fn require_private_real_directory(path: &Path) -> Result<(), BackupError> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| BackupError::Io {
        operation: "inspect private directory",
        path: path.to_owned(),
        source,
    })?;
    require_directory(path, &metadata)?;
    require_private_permissions(path, &metadata)
}

pub(crate) fn create_private_subdirectory(path: &Path) -> Result<(), BackupError> {
    fs::create_dir(path).map_err(|source| BackupError::Io {
        operation: "create archive directory",
        path: path.to_owned(),
        source,
    })?;
    set_directory_permissions(path)
}

pub(crate) fn ensure_parent_directories(
    root: &Path,
    relative_file: &str,
    limits: BackupLimits,
) -> Result<(), BackupError> {
    let relative = validate_relative_path(relative_file, limits)?;
    let parent = relative
        .parent()
        .ok_or_else(|| BackupError::UnsafePath(relative_file.to_owned()))?;
    let mut current = root.to_owned();
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(BackupError::UnsafePath(relative_file.to_owned()));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => require_directory(&current, &metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_subdirectory(&current)?;
            }
            Err(source) => {
                return Err(BackupError::Io {
                    operation: "inspect restore directory",
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}
