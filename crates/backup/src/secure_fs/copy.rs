use super::{
    directories::{create_private_subdirectory, require_private_real_directory},
    files::open_new_private_file,
    hashing::stream_hash_copy,
    identity::{identity, open_regular_nofollow, require_directory},
    paths::{bounded_read_directory, validate_component, validate_relative_path},
};
use crate::{BackupError, BackupLimits, BackupRole, ManifestEntry};
use runtrue_model::ContentDigest;
use std::{fs, path::Path};

#[derive(Debug)]
pub(crate) struct CopyState {
    pub(crate) entries: Vec<ManifestEntry>,
    pub(crate) total_bytes: u64,
    nodes: usize,
}

impl CopyState {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
            total_bytes: 0,
            nodes: 0,
        }
    }

    fn add_node(&mut self, limits: BackupLimits) -> Result<(), BackupError> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(BackupError::LimitExceeded("archive entries"))?;
        if self.nodes > limits.max_entries {
            return Err(BackupError::LimitExceeded("archive entries"));
        }
        Ok(())
    }

    pub(crate) fn add_entry(
        &mut self,
        entry: ManifestEntry,
        limits: BackupLimits,
    ) -> Result<(), BackupError> {
        self.add_node(limits)?;
        self.total_bytes = self
            .total_bytes
            .checked_add(entry.size_bytes)
            .ok_or(BackupError::LimitExceeded("archive bytes"))?;
        if self.total_bytes > limits.max_total_bytes {
            return Err(BackupError::LimitExceeded("archive bytes"));
        }
        self.entries.push(entry);
        Ok(())
    }
}

pub(crate) fn copy_source_tree(
    source: &Path,
    destination_root: &Path,
    prefix: &str,
    role: BackupRole,
    state: &mut CopyState,
    limits: BackupLimits,
) -> Result<(), BackupError> {
    require_private_real_directory(source)?;
    let destination = destination_root.join(prefix);
    create_private_subdirectory(&destination)?;
    copy_directory(source, &destination, prefix, role, 1, state, limits)
}

#[allow(clippy::too_many_arguments)]
fn copy_directory(
    source: &Path,
    destination: &Path,
    relative: &str,
    role: BackupRole,
    depth: usize,
    state: &mut CopyState,
    limits: BackupLimits,
) -> Result<(), BackupError> {
    if depth > limits.max_depth {
        return Err(BackupError::LimitExceeded("archive path depth"));
    }
    let before = fs::symlink_metadata(source).map_err(|source_error| BackupError::Io {
        operation: "inspect source directory",
        path: source.to_owned(),
        source: source_error,
    })?;
    require_directory(source, &before)?;
    let before_identity = identity(&before);
    let mut children = bounded_read_directory(source, limits)?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| BackupError::UnsafePath("non-UTF-8 source path".to_owned()))?;
        validate_component(&name)?;
        let child_relative = format!("{relative}/{name}");
        validate_relative_path(&child_relative, limits)?;
        let source_path = source.join(&name);
        let destination_path = destination.join(&name);
        let metadata =
            fs::symlink_metadata(&source_path).map_err(|source_error| BackupError::Io {
                operation: "inspect source entry",
                path: source_path.clone(),
                source: source_error,
            })?;
        if metadata.is_dir() {
            state.add_node(limits)?;
            create_private_subdirectory(&destination_path)?;
            copy_directory(
                &source_path,
                &destination_path,
                &child_relative,
                role,
                depth + 1,
                state,
                limits,
            )?;
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            let (size_bytes, digest) =
                copy_regular_file(&source_path, &destination_path, limits.max_file_bytes)?;
            state.add_entry(
                ManifestEntry {
                    path: child_relative,
                    role,
                    size_bytes,
                    digest,
                },
                limits,
            )?;
        } else {
            return Err(BackupError::UnsupportedFileType(source_path));
        }
    }
    let after = fs::symlink_metadata(source).map_err(|source_error| BackupError::Io {
        operation: "reinspect source directory",
        path: source.to_owned(),
        source: source_error,
    })?;
    if identity(&after) != before_identity || !after.is_dir() {
        return Err(BackupError::SourceChanged(source.to_owned()));
    }
    Ok(())
}

pub(crate) fn copy_regular_file(
    source: &Path,
    destination: &Path,
    limit: u64,
) -> Result<(u64, ContentDigest), BackupError> {
    let (mut input, initial) = open_regular_nofollow(source)?;
    if initial.length > limit {
        return Err(BackupError::LimitExceeded("file bytes"));
    }
    let mut output = open_new_private_file(destination)?;
    let copied = stream_hash_copy(&mut input, Some(&mut output), limit, source)?;
    output.sync_all().map_err(|source_error| BackupError::Io {
        operation: "sync copied file",
        path: destination.to_owned(),
        source: source_error,
    })?;
    let after = input.metadata().map_err(|source_error| BackupError::Io {
        operation: "reinspect copied source",
        path: source.to_owned(),
        source: source_error,
    })?;
    if identity(&after) != initial {
        let _ = fs::remove_file(destination);
        return Err(BackupError::SourceChanged(source.to_owned()));
    }
    Ok(copied)
}
