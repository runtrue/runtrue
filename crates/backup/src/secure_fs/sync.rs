use super::identity::require_directory;
use crate::BackupError;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

pub(crate) fn sync_directory(path: &Path) -> Result<(), BackupError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| BackupError::Io {
            operation: "sync directory",
            path: path.to_owned(),
            source,
        })
}

pub(crate) fn sync_directory_tree(root: &Path) -> Result<(), BackupError> {
    let mut directories = Vec::new();
    collect_directories(root, &mut directories)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}

fn collect_directories(path: &Path, directories: &mut Vec<PathBuf>) -> Result<(), BackupError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| BackupError::Io {
        operation: "inspect directory for sync",
        path: path.to_owned(),
        source,
    })?;
    require_directory(path, &metadata)?;
    directories.push(path.to_owned());
    for entry in fs::read_dir(path).map_err(|source| BackupError::Io {
        operation: "read directory for sync",
        path: path.to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| BackupError::Io {
            operation: "read entry for sync",
            path: path.to_owned(),
            source,
        })?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child).map_err(|source| BackupError::Io {
            operation: "inspect entry for sync",
            path: child.clone(),
            source,
        })?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            collect_directories(&child, directories)?;
        } else if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(BackupError::UnsupportedFileType(child));
        }
    }
    Ok(())
}
