pub(crate) fn prepare_root(requested: &Path) -> Result<PathBuf, LogError> {
    match fs::symlink_metadata(requested) {
        Ok(metadata) => require_real_directory(requested, &metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(requested)
                .map_err(|source| io_failure("create log root", requested, source))?;
            let metadata = fs::symlink_metadata(requested)
                .map_err(|source| io_failure("inspect log root", requested, source))?;
            require_real_directory(requested, &metadata)?;
        }
        Err(source) => return Err(io_failure("inspect log root", requested, source)),
    }
    requested
        .canonicalize()
        .map_err(|source| io_failure("canonicalize log root", requested, source))
}

fn require_real_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), LogError> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(LogError::UnsafeJournalPath(path.to_path_buf()));
    }
    Ok(())
}

pub(crate) fn ensure_journal_file(path: &Path) -> Result<(), LogError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(LogError::UnsafeJournalPath(path.to_path_buf()));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
                options.mode(0o600);
            }
            let file = options
                .open(path)
                .map_err(|source| io_failure("create log journal", path, source))?;
            file.sync_all()
                .map_err(|source| io_failure("sync log journal", path, source))?;
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(source) => Err(io_failure("inspect log journal", path, source)),
    }
}

pub(crate) fn open_journal_read(path: &Path) -> Result<File, LogError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|source| io_failure("open log journal", path, source))?;
    if !file
        .metadata()
        .map_err(|source| io_failure("inspect opened log journal", path, source))?
        .file_type()
        .is_file()
    {
        return Err(LogError::UnsafeJournalPath(path.to_path_buf()));
    }
    Ok(file)
}

pub(crate) fn open_journal_append(path: &Path) -> Result<File, LogError> {
    let mut options = OpenOptions::new();
    options.append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|source| io_failure("open append-only log journal", path, source))?;
    if !file
        .metadata()
        .map_err(|source| io_failure("inspect append-only log journal", path, source))?
        .file_type()
        .is_file()
    {
        return Err(LogError::UnsafeJournalPath(path.to_path_buf()));
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<(), LogError> {
    #[cfg(unix)]
    {
        let directory = File::open(path)
            .map_err(|source| io_failure("open log directory for sync", path, source))?;
        directory
            .sync_all()
            .map_err(|source| io_failure("sync log directory", path, source))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(crate) fn io_failure(operation: &'static str, path: &Path, source: io::Error) -> LogError {
    LogError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
use crate::LogError;
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};
