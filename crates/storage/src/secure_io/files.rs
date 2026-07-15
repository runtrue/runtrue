use super::ensure_owned_directory;
use crate::{cas::digest_from_hasher, StorageError, COPY_BUFFER_BYTES};
use runtrue_model::ContentDigest;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub(crate) static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct PendingFile {
    path: PathBuf,
    file: Option<File>,
}

impl PendingFile {
    pub(crate) fn create(directory: &Path, purpose: &str) -> Result<Self, StorageError> {
        ensure_owned_directory(directory)?;
        for _ in 0..1_000 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(".{purpose}-{}-{sequence}.tmp", std::process::id()));
            match create_new_file_nofollow(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(io_failure("create temporary file", &path, source)),
            }
        }
        Err(StorageError::InvalidConfiguration(
            "could not reserve a unique temporary filename".to_owned(),
        ))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("pending file is open")
    }

    pub(crate) fn discard(mut self) -> Result<(), StorageError> {
        self.file.take();
        fs::remove_file(&self.path)
            .map_err(|source| io_failure("remove temporary file", &self.path, source))
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        self.file.take();
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(not(unix))]
pub(crate) fn write_new_materialized_file<R: Read>(
    path: &Path,
    mut reader: R,
    expected_digest: &ContentDigest,
    expected_size: u64,
    executable: bool,
) -> Result<(), StorageError> {
    let parent = path.parent().ok_or_else(|| {
        StorageError::UnsafePath(format!(
            "materialized path `{}` has no parent",
            path.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|source| io_failure("inspect materialized file parent", parent, source))?;
    require_real_directory(parent, &metadata)?;
    let mut pending = PendingFile::create(parent, "materialize")?;
    let pending_path = pending.path().to_path_buf();
    stream_verified_materialized_file(
        &mut reader,
        pending.file_mut(),
        &pending_path,
        expected_digest,
        expected_size,
    )?;
    pending
        .file_mut()
        .sync_all()
        .map_err(|source| io_failure("sync materialized file", pending.path(), source))?;
    set_read_only_file(pending.path(), executable)?;
    match fs::hard_link(pending.path(), path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(StorageError::DestinationCollision(path.to_path_buf()));
        }
        Err(source) => return Err(io_failure("commit materialized file", path, source)),
    }
    pending.discard()?;
    sync_directory(parent)
}

pub(crate) fn stream_verified_materialized_file<R: Read>(
    reader: &mut R,
    output: &mut File,
    display: &Path,
    expected_digest: &ContentDigest,
    expected_size: u64,
) -> Result<(), StorageError> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).map_err(|source| {
            io_failure("read verified object for materialization", display, source)
        })?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| StorageError::Manifest("materialized file size overflow".to_owned()))?;
        if size > expected_size {
            return Err(StorageError::Manifest(format!(
                "materialized file size exceeds declared size {expected_size}"
            )));
        }
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|source| io_failure("write materialized file", display, source))?;
    }
    if size != expected_size {
        return Err(StorageError::Manifest(format!(
            "materialized file size {size} does not match declared size {expected_size}"
        )));
    }
    let actual = digest_from_hasher(hasher)?;
    if &actual != expected_digest {
        return Err(StorageError::CorruptBlob {
            expected: expected_digest.clone(),
            actual,
        });
    }
    Ok(())
}

pub(crate) fn open_regular_nofollow(
    path: &Path,
    operation: &'static str,
) -> Result<File, StorageError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            StorageError::NotFound(path.to_path_buf())
        } else {
            io_failure(operation, path, source)
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| io_failure("inspect opened file", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(StorageError::UnsafeFilesystemEntry {
            path: path.to_path_buf(),
            kind: "non-regular file",
        });
    }
    Ok(file)
}

pub(crate) fn create_new_file_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        options.mode(0o600);
    }
    options.open(path)
}

pub(crate) fn set_read_only_file(path: &Path, executable: bool) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o555 } else { 0o444 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|source| io_failure("set immutable file permissions", path, source))?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)
            .map_err(|source| io_failure("inspect file permissions", path, source))?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)
            .map_err(|source| io_failure("set immutable file permissions", path, source))?;
        let _ = executable;
    }
    Ok(())
}

pub(crate) fn file_is_executable(file: &File) -> Result<bool, StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = file
            .metadata()
            .map_err(|source| StorageError::ReadObject(source.to_string()))?;
        Ok(metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(false)
    }
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), StorageError> {
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

pub(crate) fn io_failure(operation: &'static str, path: &Path, source: io::Error) -> StorageError {
    StorageError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

pub(crate) fn read_sorted_names(
    directory: &Path,
    operation: &'static str,
) -> Result<Vec<(String, PathBuf)>, StorageError> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|source| io_failure(operation, directory, source))?
    {
        let entry = entry.map_err(|source| io_failure(operation, directory, source))?;
        let name = entry.file_name().into_string().map_err(|_| {
            StorageError::UnsafePath(format!("non-UTF-8 name below `{}`", directory.display()))
        })?;
        entries.push((name, entry.path()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}
