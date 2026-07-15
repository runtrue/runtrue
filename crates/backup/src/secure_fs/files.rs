use super::identity::{identity, open_regular_nofollow, require_directory};
use crate::BackupError;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub(crate) fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, BackupError> {
    let (mut file, initial) = open_regular_nofollow(path)?;
    if initial.length > limit {
        return Err(BackupError::LimitExceeded("manifest bytes"));
    }
    let capacity = usize::try_from(initial.length)
        .map_err(|_| BackupError::LimitExceeded("manifest bytes"))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| BackupError::Io {
            operation: "read bounded file",
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(BackupError::LimitExceeded("manifest bytes"));
    }
    let after = file.metadata().map_err(|source| BackupError::Io {
        operation: "reinspect bounded file",
        path: path.to_owned(),
        source,
    })?;
    if identity(&after) != initial {
        return Err(BackupError::SourceChanged(path.to_owned()));
    }
    Ok(bytes)
}

pub(crate) fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    let mut file = open_new_private_file(path)?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(BackupError::Io {
            operation: "write private file",
            path: path.to_owned(),
            source,
        });
    }
    Ok(())
}

pub(crate) fn create_empty_private_file(path: &Path) -> Result<File, BackupError> {
    open_new_private_file(path)
}

pub(super) fn open_new_private_file(path: &Path) -> Result<File, BackupError> {
    let parent = path
        .parent()
        .ok_or_else(|| BackupError::UnsafePath(format!("file {} has no parent", path.display())))?;
    let metadata = fs::symlink_metadata(parent).map_err(|source| BackupError::Io {
        operation: "inspect destination parent",
        path: parent.to_owned(),
        source,
    })?;
    require_directory(parent, &metadata)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path).map_err(|source| BackupError::Io {
        operation: "create private file",
        path: path.to_owned(),
        source,
    })
}
