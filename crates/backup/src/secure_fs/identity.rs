use super::paths::reject_symlink_components;
use crate::BackupError;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    path::Path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    pub(super) length: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

pub(super) fn identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        length: metadata.len(),
        #[cfg(unix)]
        modified_seconds: metadata.mtime(),
        #[cfg(unix)]
        modified_nanoseconds: metadata.mtime_nsec(),
        #[cfg(unix)]
        changed_seconds: metadata.ctime(),
        #[cfg(unix)]
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

pub(super) fn open_regular_nofollow(path: &Path) -> Result<(File, FileIdentity), BackupError> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| BackupError::Io {
        operation: "inspect regular file",
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackupError::UnsupportedFileType(path.to_owned()));
    }
    let expected = identity(&metadata);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|source| BackupError::Io {
        operation: "open regular file",
        path: path.to_owned(),
        source,
    })?;
    let opened = file.metadata().map_err(|source| BackupError::Io {
        operation: "inspect opened file",
        path: path.to_owned(),
        source,
    })?;
    if !opened.is_file() || identity(&opened) != expected {
        return Err(BackupError::SourceChanged(path.to_owned()));
    }
    Ok((file, expected))
}

pub(crate) fn open_regular_guard(path: &Path) -> Result<File, BackupError> {
    open_regular_nofollow(path).map(|(file, _)| file)
}

pub(crate) fn require_private_regular_file(path: &Path) -> Result<(), BackupError> {
    let (file, _) = open_regular_nofollow(path)?;
    let metadata = file.metadata().map_err(|source| BackupError::Io {
        operation: "inspect private file",
        path: path.to_owned(),
        source,
    })?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(BackupError::InsecurePermissions(path.to_owned()));
    }
    Ok(())
}

pub(crate) fn verify_guard_identity(path: &Path, guard: &File) -> Result<(), BackupError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|source| BackupError::Io {
        operation: "reinspect guarded file",
        path: path.to_owned(),
        source,
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(BackupError::SourceChanged(path.to_owned()));
    }
    let opened = guard.metadata().map_err(|source| BackupError::Io {
        operation: "inspect guarded file",
        path: path.to_owned(),
        source,
    })?;
    #[cfg(unix)]
    if opened.dev() != path_metadata.dev() || opened.ino() != path_metadata.ino() {
        return Err(BackupError::SourceChanged(path.to_owned()));
    }
    Ok(())
}

pub(super) fn require_directory(path: &Path, metadata: &Metadata) -> Result<(), BackupError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackupError::UnsupportedFileType(path.to_owned()));
    }
    Ok(())
}

pub(super) fn require_private_permissions(
    path: &Path,
    metadata: &Metadata,
) -> Result<(), BackupError> {
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(BackupError::InsecurePermissions(path.to_owned()));
    }
    Ok(())
}

pub(super) fn set_directory_permissions(path: &Path) -> Result<(), BackupError> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        BackupError::Io {
            operation: "secure directory",
            path: path.to_owned(),
            source,
        }
    })?;
    Ok(())
}
