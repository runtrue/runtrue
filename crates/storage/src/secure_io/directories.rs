use super::{io_failure, stream_verified_materialized_file, TEMP_SEQUENCE};
#[cfg(unix)]
use crate::secure_io::{confined_open, create_file_flags, secure_open_failure};
use crate::StorageError;
use runtrue_model::ContentDigest;
#[cfg(unix)]
use rustix::fs::{AtFlags, Mode};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{ffi::OsString, fs::File, io::Read, sync::atomic::Ordering};
use std::{fs, io, path::Path};

#[cfg(unix)]
pub(crate) fn create_new_directory_at(
    parent: &File,
    leaf: &str,
    display: &Path,
) -> Result<(), StorageError> {
    rustix::fs::mkdirat(parent, leaf, Mode::from_bits_truncate(0o755)).map_err(|source| {
        let source: io::Error = source.into();
        if source.kind() == io::ErrorKind::AlreadyExists {
            StorageError::DestinationCollision(display.to_path_buf())
        } else {
            secure_open_failure("create materialized directory", display, source)
        }
    })
}

#[cfg(unix)]
pub(crate) fn write_new_materialized_file_at<R: Read>(
    parent: &File,
    leaf: &std::ffi::OsStr,
    display: &Path,
    mut reader: R,
    expected_digest: &ContentDigest,
    expected_size: u64,
    executable: bool,
) -> Result<(), StorageError> {
    let (temporary, mut file) = reserve_temporary_file_at(parent, display)?;
    let result = (|| {
        stream_verified_materialized_file(
            &mut reader,
            &mut file,
            display,
            expected_digest,
            expected_size,
        )?;
        file.set_permissions(fs::Permissions::from_mode(if executable {
            0o555
        } else {
            0o444
        }))
        .map_err(|source| io_failure("set materialized file permissions", display, source))?;
        file.sync_all()
            .map_err(|source| io_failure("sync materialized file", display, source))?;
        rustix::fs::linkat(parent, &temporary, parent, leaf, AtFlags::empty()).map_err(
            |source| {
                let source: io::Error = source.into();
                if source.kind() == io::ErrorKind::AlreadyExists {
                    StorageError::DestinationCollision(display.to_path_buf())
                } else {
                    secure_open_failure("commit materialized file", display, source)
                }
            },
        )?;
        parent
            .sync_all()
            .map_err(|source| io_failure("sync materialized file parent", display, source))?;
        Ok(())
    })();
    let cleanup = rustix::fs::unlinkat(parent, &temporary, AtFlags::empty()).map_err(|source| {
        io_failure(
            "remove materialization temporary file",
            display,
            source.into(),
        )
    });
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(unix)]
pub(crate) fn reserve_temporary_file_at(
    parent: &File,
    display: &Path,
) -> Result<(OsString, File), StorageError> {
    for _ in 0..1_000 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = OsString::from(format!(
            ".materialize-{}-{sequence}.tmp",
            std::process::id()
        ));
        match confined_open(parent, Path::new(&temporary), create_file_flags()) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(secure_open_failure(
                    "create materialization temporary file",
                    display,
                    source,
                ))
            }
        }
    }
    Err(StorageError::InvalidConfiguration(
        "could not reserve a unique materialization filename".to_owned(),
    ))
}

pub(crate) fn require_real_directory(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), StorageError> {
    if metadata.file_type().is_symlink() {
        return Err(StorageError::UnsafeFilesystemEntry {
            path: path.to_path_buf(),
            kind: "symlink",
        });
    }
    if !metadata.file_type().is_dir() {
        return Err(StorageError::UnsafeFilesystemEntry {
            path: path.to_path_buf(),
            kind: "non-directory",
        });
    }
    Ok(())
}

pub(crate) fn ensure_owned_directory(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => require_real_directory(path, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(io_failure("create directory", path, source)),
            }
            let metadata = fs::symlink_metadata(path)
                .map_err(|source| io_failure("inspect created directory", path, source))?;
            require_real_directory(path, &metadata)
        }
        Err(source) => Err(io_failure("inspect directory", path, source)),
    }
}

#[cfg(not(unix))]
pub(crate) fn prepare_empty_destination(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            require_real_directory(path, &metadata)?;
            let mut entries = fs::read_dir(path)
                .map_err(|source| io_failure("read materialization destination", path, source))?;
            if entries.next().is_some() {
                return Err(StorageError::DestinationNotEmpty(path.to_path_buf()));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|source| io_failure("create materialization destination", path, source))?;
            let metadata = fs::symlink_metadata(path).map_err(|source| {
                io_failure("inspect materialization destination", path, source)
            })?;
            require_real_directory(path, &metadata)
        }
        Err(source) => Err(io_failure(
            "inspect materialization destination",
            path,
            source,
        )),
    }
}

#[cfg(not(unix))]
pub(crate) fn create_new_directory(path: &Path) -> Result<(), StorageError> {
    fs::create_dir(path).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            StorageError::DestinationCollision(path.to_path_buf())
        } else {
            io_failure("create materialized directory", path, source)
        }
    })
}
