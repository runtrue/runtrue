use crate::CacheError;
use runtrue_model::ContentDigest;
use runtrue_storage::StorageError;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static HEAD_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn digest_hex(digest: &ContentDigest) -> Result<&str, CacheError> {
    let encoded = digest.as_str().strip_prefix("sha256:").ok_or_else(|| {
        CacheError::InvalidIdentity("only SHA-256 cache keys are supported".to_owned())
    })?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CacheError::InvalidIdentity(
            "invalid SHA-256 cache key".to_owned(),
        ));
    }
    Ok(encoded)
}

pub(crate) fn require_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), CacheError> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CacheError::UnsafeMetadataPath(path.to_path_buf()));
    }
    Ok(())
}

pub(crate) fn ensure_directory(path: &Path) -> Result<(), CacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => require_directory(path, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(io_failure("create cache directory", path, source)),
            }
            let metadata = fs::symlink_metadata(path)
                .map_err(|source| io_failure("inspect cache directory", path, source))?;
            require_directory(path, &metadata)
        }
        Err(source) => Err(io_failure("inspect cache directory", path, source)),
    }
}

pub(crate) fn read_small_regular_file(path: &Path, limit: u64) -> Result<Vec<u8>, CacheError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|source| io_failure("open cache metadata", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_failure("inspect cache metadata", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(CacheError::UnsafeMetadataPath(path.to_path_buf()));
    }
    if metadata.len() > limit {
        return Err(CacheError::MetadataLimit {
            kind: "cache head",
            limit,
            actual: metadata.len(),
        });
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_failure("read cache metadata", path, source))?;
    if bytes.len() as u64 > limit {
        return Err(CacheError::MetadataLimit {
            kind: "cache head",
            limit,
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

pub(crate) fn append_metadata(
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), CacheError> {
    let final_path = directory.join(name);
    let temporary = reserve_temporary_file(directory, "append")?;
    if let Err(error) = write_temporary_metadata(&temporary, bytes) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    match fs::hard_link(&temporary, &final_path) {
        Ok(()) => {
            fs::remove_file(&temporary)
                .map_err(|source| io_failure("remove metadata temporary", &temporary, source))?;
            sync_directory(directory)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            Err(CacheError::MetadataExists(final_path))
        }
        Err(source) => {
            let _ = fs::remove_file(&temporary);
            Err(io_failure("append cache metadata", &final_path, source))
        }
    }
}

pub(crate) fn reserve_temporary_file(
    directory: &Path,
    purpose: &str,
) -> Result<PathBuf, CacheError> {
    for _ in 0..1_000 {
        let sequence = HEAD_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".{purpose}-{}-{sequence}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                drop(file);
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_failure("reserve metadata temporary", &path, source)),
        }
    }
    Err(CacheError::InvalidConfiguration(
        "could not reserve a metadata temporary file".to_owned(),
    ))
}

pub(crate) fn write_temporary_metadata(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    let mut options = OpenOptions::new();
    options.write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut file = options
        .open(path)
        .map_err(|source| io_failure("open metadata temporary", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_failure("write metadata temporary", path, source))?;
    file.sync_all()
        .map_err(|source| io_failure("sync metadata temporary", path, source))?;
    set_read_only(path)
}

fn set_read_only(path: &Path) -> Result<(), CacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))
            .map_err(|source| io_failure("set metadata permissions", path, source))?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)
            .map_err(|source| io_failure("inspect metadata permissions", path, source))?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)
            .map_err(|source| io_failure("set metadata permissions", path, source))?;
    }
    Ok(())
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), CacheError> {
    #[cfg(unix)]
    {
        let directory = File::open(path)
            .map_err(|source| io_failure("open cache directory for sync", path, source))?;
        directory
            .sync_all()
            .map_err(|source| io_failure("sync cache directory", path, source))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(crate) fn storage_is_stored_corruption(error: &StorageError) -> bool {
    error.is_corruption()
        || matches!(
            error,
            StorageError::NotFound(_)
                | StorageError::LimitExceeded { .. }
                | StorageError::UnsafePath(_)
        )
}

pub(crate) fn io_failure(operation: &'static str, path: &Path, source: io::Error) -> CacheError {
    CacheError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
