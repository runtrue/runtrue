use super::identity::{identity, require_directory};
use crate::{BackupError, BackupLimits};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub(crate) fn collect_relative_files(
    root: &Path,
    limits: BackupLimits,
) -> Result<Vec<String>, BackupError> {
    let mut files = Vec::new();
    let mut nodes = 0_usize;
    collect_directory(root, "", 0, &mut files, &mut nodes, limits)?;
    files.sort();
    Ok(files)
}

fn collect_directory(
    root: &Path,
    relative: &str,
    depth: usize,
    files: &mut Vec<String>,
    nodes: &mut usize,
    limits: BackupLimits,
) -> Result<(), BackupError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or(BackupError::LimitExceeded("archive entries"))?;
    if depth > limits.max_depth || *nodes > limits.max_entries {
        return Err(BackupError::LimitExceeded("archive entries"));
    }
    let directory = if relative.is_empty() {
        root.to_owned()
    } else {
        root.join(relative)
    };
    let metadata = fs::symlink_metadata(&directory).map_err(|source| BackupError::Io {
        operation: "inspect archive directory",
        path: directory.clone(),
        source,
    })?;
    require_directory(&directory, &metadata)?;
    let before = identity(&metadata);
    let mut children = bounded_read_directory(&directory, limits)?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| BackupError::UnsafePath("non-UTF-8 archive path".to_owned()))?;
        validate_component(&name)?;
        let child_relative = if relative.is_empty() {
            name
        } else {
            format!("{relative}/{name}")
        };
        validate_relative_path(&child_relative, limits)?;
        let path = root.join(&child_relative);
        let metadata = fs::symlink_metadata(&path).map_err(|source| BackupError::Io {
            operation: "inspect archive entry",
            path: path.clone(),
            source,
        })?;
        if metadata.is_dir() {
            collect_directory(root, &child_relative, depth + 1, files, nodes, limits)?;
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            *nodes = nodes
                .checked_add(1)
                .ok_or(BackupError::LimitExceeded("archive entries"))?;
            files.push(child_relative);
            if *nodes > limits.max_entries {
                return Err(BackupError::LimitExceeded("archive entries"));
            }
        } else {
            return Err(BackupError::UnsupportedFileType(path));
        }
    }
    let after = fs::symlink_metadata(&directory).map_err(|source| BackupError::Io {
        operation: "reinspect archive directory",
        path: directory.clone(),
        source,
    })?;
    if identity(&after) != before {
        return Err(BackupError::SourceChanged(directory));
    }
    Ok(())
}

pub(crate) fn validate_relative_path(
    value: &str,
    limits: BackupLimits,
) -> Result<PathBuf, BackupError> {
    if value.is_empty()
        || value.len() > limits.max_relative_path_bytes
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\0')
        || value.contains('\\')
    {
        return Err(BackupError::UnsafePath(value.to_owned()));
    }
    let mut depth = 0_usize;
    for component in value.split('/') {
        validate_component(component)?;
        depth = depth
            .checked_add(1)
            .ok_or(BackupError::LimitExceeded("archive path depth"))?;
    }
    if depth > limits.max_depth {
        return Err(BackupError::LimitExceeded("archive path depth"));
    }
    Ok(PathBuf::from(value))
}

pub(super) fn validate_component(value: &str) -> Result<(), BackupError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.contains('/')
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(BackupError::UnsafePath(value.to_owned()));
    }
    Ok(())
}

pub(super) fn bounded_read_directory(
    path: &Path,
    limits: BackupLimits,
) -> Result<Vec<fs::DirEntry>, BackupError> {
    let entries = fs::read_dir(path).map_err(|source| BackupError::Io {
        operation: "read directory",
        path: path.to_owned(),
        source,
    })?;
    let mut collected = Vec::new();
    for entry in entries {
        if collected.len() >= limits.max_entries {
            return Err(BackupError::LimitExceeded("directory entries"));
        }
        collected.push(entry.map_err(|source| BackupError::Io {
            operation: "read directory entry",
            path: path.to_owned(),
            source,
        })?);
    }
    Ok(collected)
}

pub(super) fn reject_symlink_components(path: &Path) -> Result<(), BackupError> {
    let mut checked = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                checked.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(BackupError::UnsafePath(path.display().to_string()));
            }
        }
        match fs::symlink_metadata(&checked) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(BackupError::UnsafePath(checked.display().to_string()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(BackupError::Io {
                    operation: "inspect path component",
                    path: checked,
                    source,
                });
            }
        }
    }
    Ok(())
}
