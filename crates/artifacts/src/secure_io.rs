use crate::ArtifactError;
use runtrue_model::ContentDigest;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static METADATA_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn digest_hex(digest: &ContentDigest) -> Result<&str, ArtifactError> {
    let encoded = digest.as_str().strip_prefix("sha256:").ok_or_else(|| {
        ArtifactError::InvalidMetadata("only SHA-256 IDs are supported".to_owned())
    })?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ArtifactError::InvalidMetadata(
            "invalid SHA-256 identifier".to_owned(),
        ));
    }
    Ok(encoded)
}

pub(crate) fn require_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), ArtifactError> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(ArtifactError::UnsafeMetadataPath(path.to_path_buf()));
    }
    Ok(())
}

pub(crate) fn ensure_directory(path: &Path) -> Result<(), ArtifactError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => require_directory(path, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(io_failure("create metadata directory", path, source)),
            }
            let metadata = fs::symlink_metadata(path)
                .map_err(|source| io_failure("inspect metadata directory", path, source))?;
            require_directory(path, &metadata)
        }
        Err(source) => Err(io_failure("inspect metadata directory", path, source)),
    }
}

pub(crate) fn append_metadata(
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), ArtifactError> {
    let final_path = directory.join(name);
    let temporary = reserve_temporary_file(directory, name)?;
    if let Err(error) = write_temporary(&temporary, bytes) {
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
            Err(ArtifactError::MetadataExists(final_path))
        }
        Err(source) => {
            let _ = fs::remove_file(&temporary);
            Err(io_failure("commit immutable metadata", &final_path, source))
        }
    }
}

fn reserve_temporary_file(directory: &Path, purpose: &str) -> Result<PathBuf, ArtifactError> {
    for _ in 0..1_000 {
        let sequence = METADATA_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let safe_purpose = purpose.replace('.', "-");
        let path = directory.join(format!(
            ".{safe_purpose}-{}-{sequence}.tmp",
            std::process::id()
        ));
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
    Err(ArtifactError::InvalidConfiguration(
        "could not reserve a metadata temporary file".to_owned(),
    ))
}

fn write_temporary(path: &Path, bytes: &[u8]) -> Result<(), ArtifactError> {
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

pub(crate) fn read_small_regular(path: &Path, limit: u64) -> Result<Vec<u8>, ArtifactError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|source| io_failure("open artifact metadata", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_failure("inspect artifact metadata", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(ArtifactError::UnsafeMetadataPath(path.to_path_buf()));
    }
    if metadata.len() > limit {
        return Err(ArtifactError::MetadataLimit {
            kind: "artifact metadata",
            limit,
            actual: metadata.len(),
        });
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_failure("read artifact metadata", path, source))?;
    if bytes.len() as u64 > limit {
        return Err(ArtifactError::MetadataLimit {
            kind: "artifact metadata",
            limit,
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

fn set_read_only(path: &Path) -> Result<(), ArtifactError> {
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

pub(crate) fn sync_directory(path: &Path) -> Result<(), ArtifactError> {
    #[cfg(unix)]
    {
        let directory = File::open(path)
            .map_err(|source| io_failure("open directory for sync", path, source))?;
        directory
            .sync_all()
            .map_err(|source| io_failure("sync directory", path, source))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(crate) fn io_failure(operation: &'static str, path: &Path, source: io::Error) -> ArtifactError {
    ArtifactError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
