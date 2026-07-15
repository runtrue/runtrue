use crate::{MasterKey, SensitiveError};
use std::{fmt, io, path::PathBuf};
use thiserror::Error;

/// A filesystem location containing exactly one raw 256-bit local master key.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalMasterKeyFile {
    path: PathBuf,
}

impl LocalMasterKeyFile {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Load an existing regular, non-symlink key file with exact Unix mode 0600.
    pub fn load(&self) -> Result<MasterKey, MasterKeyFileError> {
        platform::load(&self.path)
    }

    /// Load the key or atomically create it when the final path does not exist.
    pub fn load_or_create(&self) -> Result<MasterKey, MasterKeyFileError> {
        platform::load_or_create(&self.path)
    }
}

impl fmt::Debug for LocalMasterKeyFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalMasterKeyFile")
            .field("path", &self.path)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum MasterKeyFileError {
    #[error("local master-key files are unsupported on this platform")]
    UnsupportedPlatform,
    #[error("master-key path `{0}` is a symlink")]
    SymlinkNotAllowed(PathBuf),
    #[error("master-key path `{0}` is not a regular file")]
    NotRegularFile(PathBuf),
    #[error("master-key file `{path}` must have mode 0600, got {actual:#06o}")]
    InsecurePermissions { path: PathBuf, actual: u32 },
    #[error("master-key file `{path}` must contain exactly 32 bytes, got {actual}")]
    InvalidLength { path: PathBuf, actual: usize },
    #[error("could not {operation} master-key file `{path}`: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Sensitive(#[from] SensitiveError),
}

#[cfg(unix)]
mod platform {
    use super::MasterKeyFileError;
    use crate::{sensitive::KEY_BYTES, MasterKey};
    use std::{
        fs::{self, File, OpenOptions, Permissions},
        io::{self, Read, Write},
        os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _, PermissionsExt as _},
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
    };
    use zeroize::Zeroizing;

    const REQUIRED_MODE: u32 = 0o600;
    static KEY_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    pub(super) fn load(path: &Path) -> Result<MasterKey, MasterKeyFileError> {
        reject_symlink(path)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(path)
            .map_err(|source| open_failure("open", path, source))?;
        read_key(path, file)
    }

    pub(super) fn load_or_create(path: &Path) -> Result<MasterKey, MasterKeyFileError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(MasterKeyFileError::SymlinkNotAllowed(path.to_owned()));
            }
            Ok(_) => return load(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_failure("inspect", path, source)),
        }

        let parent = path.parent().ok_or_else(|| {
            io_failure(
                "locate parent of",
                path,
                io::Error::new(io::ErrorKind::InvalidInput, "master-key path has no parent"),
            )
        })?;
        let parent_metadata = fs::symlink_metadata(parent)
            .map_err(|source| io_failure("inspect parent of", path, source))?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            return Err(MasterKeyFileError::NotRegularFile(parent.to_owned()));
        }

        let key = MasterKey::generate()?;
        let (temporary_path, mut file) = reserve_temporary(parent)?;
        let write_result = (|| {
            file.set_permissions(Permissions::from_mode(REQUIRED_MODE))
                .map_err(|source| io_failure("set permissions on", &temporary_path, source))?;
            validate_handle(&temporary_path, &file)?;
            file.write_all(key.as_bytes())
                .map_err(|source| io_failure("write", &temporary_path, source))?;
            file.sync_all()
                .map_err(|source| io_failure("sync", &temporary_path, source))
        })();
        drop(file);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary_path);
            return Err(error);
        }

        match fs::hard_link(&temporary_path, path) {
            Ok(()) => {
                fs::remove_file(&temporary_path).map_err(|source| {
                    io_failure("remove temporary for", &temporary_path, source)
                })?;
                sync_directory(parent)?;
                Ok(key)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary_path).map_err(|source| {
                    io_failure("remove temporary for", &temporary_path, source)
                })?;
                load(path)
            }
            Err(source) => {
                let _ = fs::remove_file(&temporary_path);
                Err(open_failure("commit", path, source))
            }
        }
    }

    fn reserve_temporary(parent: &Path) -> Result<(std::path::PathBuf, File), MasterKeyFileError> {
        for _ in 0..1_000 {
            let sequence = KEY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                ".runtrue-master-key-{}-{sequence}.tmp",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .mode(REQUIRED_MODE)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            match options.open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(open_failure("reserve", &path, source)),
            }
        }
        Err(io_failure(
            "reserve temporary in",
            parent,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique master-key temporary",
            ),
        ))
    }

    fn sync_directory(path: &Path) -> Result<(), MasterKeyFileError> {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_failure("sync directory", path, source))
    }

    fn reject_symlink(path: &Path) -> Result<(), MasterKeyFileError> {
        let metadata =
            fs::symlink_metadata(path).map_err(|source| io_failure("inspect", path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(MasterKeyFileError::SymlinkNotAllowed(path.to_owned()));
        }
        Ok(())
    }

    fn read_key(path: &Path, mut file: File) -> Result<MasterKey, MasterKeyFileError> {
        validate_handle(path, &file)?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(KEY_BYTES + 1));
        Read::take(&mut file, (KEY_BYTES + 1) as u64)
            .read_to_end(&mut encoded)
            .map_err(|source| io_failure("read", path, source))?;
        if encoded.len() != KEY_BYTES {
            return Err(MasterKeyFileError::InvalidLength {
                path: path.to_owned(),
                actual: encoded.len(),
            });
        }
        let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
        bytes.copy_from_slice(&encoded);
        Ok(MasterKey::from_zeroizing(bytes))
    }

    fn validate_handle(path: &Path, file: &File) -> Result<(), MasterKeyFileError> {
        let metadata = file
            .metadata()
            .map_err(|source| io_failure("inspect opened", path, source))?;
        let file_type = metadata.file_type();
        if !file_type.is_file()
            || file_type.is_socket()
            || file_type.is_fifo()
            || file_type.is_block_device()
            || file_type.is_char_device()
        {
            return Err(MasterKeyFileError::NotRegularFile(path.to_owned()));
        }
        let actual = metadata.permissions().mode() & 0o7777;
        if actual != REQUIRED_MODE {
            return Err(MasterKeyFileError::InsecurePermissions {
                path: path.to_owned(),
                actual,
            });
        }
        Ok(())
    }

    fn open_failure(operation: &'static str, path: &Path, source: io::Error) -> MasterKeyFileError {
        if source.raw_os_error() == Some(libc::ELOOP) {
            MasterKeyFileError::SymlinkNotAllowed(path.to_owned())
        } else {
            io_failure(operation, path, source)
        }
    }

    fn io_failure(operation: &'static str, path: &Path, source: io::Error) -> MasterKeyFileError {
        MasterKeyFileError::Io {
            operation,
            path: path.to_owned(),
            source,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt as _},
    };

    #[test]
    fn creates_and_reloads_an_exact_mode_key_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("master.key");
        let key_file = LocalMasterKeyFile::new(&path);

        let created = key_file.load_or_create().unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.len(), 32);

        let loaded = key_file.load().unwrap();
        assert_eq!(created.as_bytes(), loaded.as_bytes());
        assert_eq!(
            key_file.load_or_create().unwrap().as_bytes(),
            loaded.as_bytes()
        );
        assert_eq!(format!("{loaded:?}"), "MasterKey([REDACTED])");
    }

    #[test]
    fn rejects_symlink_key_paths() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.key");
        LocalMasterKeyFile::new(&target).load_or_create().unwrap();
        let link = directory.path().join("linked.key");
        symlink(&target, &link).unwrap();

        assert!(matches!(
            LocalMasterKeyFile::new(&link).load(),
            Err(MasterKeyFileError::SymlinkNotAllowed(path)) if path == link
        ));
        assert!(matches!(
            LocalMasterKeyFile::new(&link).load_or_create(),
            Err(MasterKeyFileError::SymlinkNotAllowed(path)) if path == link
        ));
    }

    #[test]
    fn rejects_group_or_world_accessible_key_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("master.key");
        LocalMasterKeyFile::new(&path).load_or_create().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        assert!(matches!(
            LocalMasterKeyFile::new(&path).load(),
            Err(MasterKeyFileError::InsecurePermissions {
                path: rejected,
                actual: 0o640
            }) if rejected == path
        ));
    }

    #[test]
    fn rejects_non_regular_and_malformed_key_files() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            LocalMasterKeyFile::new(directory.path()).load(),
            Err(MasterKeyFileError::NotRegularFile(_)) | Err(MasterKeyFileError::Io { .. })
        ));

        let short = directory.path().join("short.key");
        fs::write(&short, [7_u8; 31]).unwrap();
        fs::set_permissions(&short, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            LocalMasterKeyFile::new(&short).load(),
            Err(MasterKeyFileError::InvalidLength { actual: 31, .. })
        ));
    }
}

#[cfg(not(unix))]
mod platform {
    use super::MasterKeyFileError;
    use crate::MasterKey;
    use std::path::Path;

    pub(super) fn load(_path: &Path) -> Result<MasterKey, MasterKeyFileError> {
        Err(MasterKeyFileError::UnsupportedPlatform)
    }

    pub(super) fn load_or_create(_path: &Path) -> Result<MasterKey, MasterKeyFileError> {
        Err(MasterKeyFileError::UnsupportedPlatform)
    }
}
