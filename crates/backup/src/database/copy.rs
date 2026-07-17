use crate::{
    secure_fs::{create_empty_private_file, open_regular_guard, verify_guard_identity},
    BackupError, BackupLimits,
};
use rusqlite::{
    backup::{Backup, StepResult},
    Connection, OpenFlags,
};
use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

const BACKUP_PAGES_PER_STEP: i32 = 256;
const MAX_BUSY_STEPS: usize = 1_000;
const BUSY_PAUSE: Duration = Duration::from_millis(10);

pub(crate) fn online_copy_database(
    source_path: &Path,
    destination_path: &Path,
    limits: BackupLimits,
) -> Result<(), BackupError> {
    let source_guard = open_regular_guard(source_path)?;
    if source_guard
        .metadata()
        .map_err(|source| BackupError::Io {
            operation: "inspect SQLite source",
            path: source_path.to_owned(),
            source,
        })?
        .len()
        > limits.max_database_bytes
    {
        return Err(BackupError::LimitExceeded("database bytes"));
    }
    let source = Connection::open_with_flags(
        source_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    verify_guard_identity(source_path, &source_guard)?;

    let destination_guard = create_empty_private_file(destination_path)?;
    destination_guard
        .sync_all()
        .map_err(|source| BackupError::Io {
            operation: "sync empty SQLite destination",
            path: destination_path.to_owned(),
            source,
        })?;
    drop(destination_guard);
    let mut destination = Connection::open_with_flags(
        destination_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    destination.pragma_update(None, "journal_mode", "DELETE")?;
    destination.pragma_update(None, "synchronous", "FULL")?;

    let page_size: u64 = source.pragma_query_value(None, "page_size", |row| row.get(0))?;
    if page_size == 0 {
        return Err(BackupError::InvalidDatabase("SQLite page size is zero"));
    }
    let maximum_progress_steps = limits
        .max_database_bytes
        .checked_div(page_size)
        .unwrap_or(0)
        .checked_div(BACKUP_PAGES_PER_STEP as u64)
        .unwrap_or(0)
        .saturating_add(2_048);
    let backup = Backup::new(&source, &mut destination)?;
    let mut progress_steps = 0_u64;
    let mut busy_steps = 0_usize;
    loop {
        match backup.step(BACKUP_PAGES_PER_STEP)? {
            StepResult::Done => break,
            StepResult::More => {
                progress_steps = progress_steps.saturating_add(1);
                busy_steps = 0;
                if progress_steps > maximum_progress_steps {
                    return Err(BackupError::LimitExceeded("database pages"));
                }
            }
            StepResult::Busy | StepResult::Locked => {
                busy_steps = busy_steps.saturating_add(1);
                if busy_steps > MAX_BUSY_STEPS {
                    return Err(BackupError::DatabaseBusy);
                }
                thread::sleep(BUSY_PAUSE);
            }
            _ => {
                return Err(BackupError::InvalidDatabase(
                    "SQLite online backup returned an unknown state",
                ));
            }
        }
        let progress = backup.progress();
        let page_count = u64::try_from(progress.pagecount)
            .map_err(|_| BackupError::InvalidDatabase("negative SQLite page count"))?;
        if page_count.saturating_mul(page_size) > limits.max_database_bytes {
            return Err(BackupError::LimitExceeded("database bytes"));
        }
    }
    drop(backup);
    destination.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(destination);
    force_delete_journal_mode(destination_path)?;
    verify_guard_identity(source_path, &source_guard)?;
    let copied_size = fs::metadata(destination_path)
        .map_err(|source| BackupError::Io {
            operation: "inspect copied database",
            path: destination_path.to_owned(),
            source,
        })?
        .len();
    if copied_size > limits.max_database_bytes {
        return Err(BackupError::LimitExceeded("database bytes"));
    }
    Ok(())
}

pub(crate) fn force_delete_journal_mode(path: &Path) -> Result<(), BackupError> {
    let connection = Connection::open(path)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")?;
    drop(connection);
    // Opening a restored control-plane database switches it to TRUNCATE mode.
    // SQLite may leave an empty rollback-journal sidecar behind when that
    // connection closes, even after switching the database back to DELETE.
    // A restore is an exact manifest reconstruction, so remove every SQLite
    // sidecar before validating the restored file set.
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        match fs::symlink_metadata(&sidecar) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(BackupError::UnsupportedFileType(sidecar));
            }
            Ok(_) => fs::remove_file(&sidecar).map_err(|source| BackupError::Io {
                operation: "remove SQLite sidecar",
                path: sidecar,
                source,
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(BackupError::Io {
                    operation: "inspect SQLite sidecar",
                    path: sidecar,
                    source,
                });
            }
        }
    }
    Ok(())
}
