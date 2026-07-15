use super::{
    fs, fstat, fstatat, fsync, io, mkdirat, open_real_directory, renameat, unlinkat, AtFlags,
    AtomicU64, ContentDigest, Duration, File, GitError, Mode, OpenOptions, Ordering, OsStr,
    OsString, Path, PathBuf, SFlag, SystemTime, UnlinkatFlags, UNIX_EPOCH,
};
#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt as _,
    fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
};
use std::{
    io::{Read as _, Write as _},
    os::fd::AsRawFd as _,
};

pub(super) const IDENTITY_METADATA_FILE: &str = "identity.json";
pub(super) const MIRROR_DIRECTORY: &str = "repo.git";
pub(super) const HYDRATION_MARKER: &str = "runtrue-hydration.json";
pub(super) const MAX_IDENTITY_BYTES: usize = 1024;
pub(super) const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
pub(super) const MAX_CREDENTIAL_TTL: Duration = Duration::from_secs(60 * 60);
pub(super) const DNS_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const MAX_DNS_RESULTS: usize = 64;
pub(super) const MAX_REQUESTED_COMMITS: usize = 128;
pub(super) const MAX_METADATA_BYTES: usize = 16 * 1024;
pub(super) const FETCH_REFSPECS: [&str; 4] = [
    "+refs/heads/*:refs/heads/*",
    "+refs/tags/*:refs/tags/*",
    "+refs/pull/*/merge:refs/pull/*/merge",
    "+refs/gh-readonly-queue/*:refs/gh-readonly-queue/*",
];
static UNIQUE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(super) fn now_unix_ms() -> Result<u64, GitError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GitError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| GitError::Clock)
}

#[cfg(unix)]
pub(super) fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub(super) fn prepare_private_root(path: &Path) -> Result<PathBuf, GitError> {
    if !path.is_absolute() {
        return Err(GitError::UnsafeRepositoryRoot(path.to_owned()));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => validate_real_directory(path, 0o700)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| GitError::UnsafeRepositoryRoot(path.to_owned()))?;
            let name = path
                .file_name()
                .ok_or_else(|| GitError::UnsafeRepositoryRoot(path.to_owned()))?;
            validate_single_component(name)?;
            let (_, parent_fd) = open_real_directory(parent)?;
            mkdirat(parent_fd.as_raw_fd(), name, Mode::from_bits_truncate(0o700))
                .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
            fsync(parent_fd.as_raw_fd())
                .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
            validate_real_directory(path, 0o700)?;
        }
        Err(source) => return Err(GitError::Filesystem(path.to_owned(), source)),
    }
    open_real_directory(path).map(|(canonical, _)| canonical)
}

pub(super) fn prepare_private_child(root: &Path, child: &str) -> Result<(), GitError> {
    validate_managed_name(child)?;
    let (_, root_fd) = open_real_directory(root)?;
    let path = root.join(child);
    match fs::symlink_metadata(&path) {
        Ok(_) => validate_real_directory(&path, 0o700),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            mkdirat(root_fd.as_raw_fd(), child, Mode::from_bits_truncate(0o700))
                .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
            fsync(root_fd.as_raw_fd())
                .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
            validate_real_directory(&path, 0o700)
        }
        Err(source) => Err(GitError::Filesystem(path, source)),
    }
}

pub(super) fn validate_real_directory(path: &Path, expected_mode: u32) -> Result<(), GitError> {
    let (canonical, file) = open_real_directory(path)?;
    if canonical != path {
        return Err(GitError::UnsafeMirrorEntry(path.to_owned()));
    }
    let metadata = file
        .metadata()
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    #[cfg(unix)]
    if metadata.uid() != effective_uid() || metadata.mode() & 0o777 != expected_mode {
        return Err(GitError::UnsafeMirrorEntry(path.to_owned()));
    }
    Ok(())
}

pub(super) fn validate_descriptor_file(
    parent: &impl std::os::fd::AsRawFd,
    name: &str,
    file: &File,
    expected_mode: u32,
) -> Result<(), GitError> {
    let named = fstatat(parent.as_raw_fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
    let opened =
        fstat(file.as_raw_fd()).map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
    #[cfg(unix)]
    if SFlag::from_bits_truncate(named.st_mode) != SFlag::S_IFREG
        || SFlag::from_bits_truncate(opened.st_mode) != SFlag::S_IFREG
        || opened.st_dev != named.st_dev
        || opened.st_ino != named.st_ino
        || opened.st_nlink != 1
        || opened.st_uid != effective_uid()
        || opened.st_mode & 0o777 != expected_mode
    {
        return Err(GitError::UnsafeMirrorEntry(PathBuf::from(name)));
    }
    Ok(())
}

pub(super) fn validate_single_component(value: &OsStr) -> Result<(), GitError> {
    if value.is_empty()
        || value == OsStr::new(".")
        || value == OsStr::new("..")
        || value.as_bytes().contains(&b'/')
        || value.as_bytes().contains(&0)
    {
        return Err(GitError::InvalidConfiguration);
    }
    Ok(())
}

pub(super) fn validate_managed_name(value: &str) -> Result<(), GitError> {
    if value.is_empty()
        || value.len() > 240
        || matches!(value, "." | "..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
    {
        return Err(GitError::InvalidConfiguration);
    }
    Ok(())
}

pub(super) fn digest_name(digest: &ContentDigest) -> Result<String, GitError> {
    let value = digest.to_string();
    let hexadecimal = value
        .strip_prefix("sha256:")
        .ok_or(GitError::InvalidRepositoryIdentity)?;
    if hexadecimal.len() != 64
        || !hexadecimal
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GitError::InvalidRepositoryIdentity);
    }
    Ok(hexadecimal.to_owned())
}

pub(super) fn unique_suffix() -> Result<String, GitError> {
    let time = now_unix_ms()?;
    let sequence = UNIQUE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(format!(
        "{time:016x}-{:08x}-{sequence:016x}",
        std::process::id()
    ))
}
pub(super) fn write_atomic_private_file(path: &Path, bytes: &[u8]) -> Result<(), GitError> {
    let parent = path
        .parent()
        .ok_or_else(|| GitError::UnsafeMirrorEntry(path.to_owned()))?;
    let name = path
        .file_name()
        .ok_or_else(|| GitError::UnsafeMirrorEntry(path.to_owned()))?;
    validate_single_component(name)?;
    let (_, parent_fd) = open_real_directory(parent)?;
    let temporary = OsString::from(format!(".runtrue-write-{}", unique_suffix()?));
    let owned = rustix::fs::openat(
        &parent_fd,
        temporary.as_os_str(),
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
    let mut file = File::from(owned);
    let result = (|| {
        file.write_all(bytes)
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
        file.sync_all()
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
        validate_open_private_file(&file, path, 0o600)?;
        renameat(
            Some(parent_fd.as_raw_fd()),
            temporary.as_os_str(),
            Some(parent_fd.as_raw_fd()),
            name,
        )
        .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        fsync(parent_fd.as_raw_fd()).map_err(|error| GitError::SecureFilesystem(error.to_string()))
    })();
    if result.is_err() {
        let _ = unlinkat(
            Some(parent_fd.as_raw_fd()),
            temporary.as_os_str(),
            UnlinkatFlags::NoRemoveDir,
        );
    }
    result
}

pub(super) fn validate_open_private_file(
    file: &File,
    path: &Path,
    expected_mode: u32,
) -> Result<(), GitError> {
    let metadata = file
        .metadata()
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    #[cfg(unix)]
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o777 != expected_mode
    {
        return Err(GitError::UnsafeMirrorEntry(path.to_owned()));
    }
    Ok(())
}

pub(super) fn read_bounded_private_file(path: &Path, limit: usize) -> Result<Vec<u8>, GitError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    let mut file = options
        .open(path)
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    let metadata = file
        .metadata()
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    #[cfg(unix)]
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid()
        || metadata.len() > u64::try_from(limit).unwrap_or(u64::MAX)
    {
        return Err(GitError::UnsafeMirrorEntry(path.to_owned()));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(limit).min(limit));
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    if bytes.len() > limit {
        return Err(GitError::MirrorLimit {
            kind: "metadata bytes",
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
        });
    }
    Ok(bytes)
}
pub(super) fn sync_tree(path: &Path) -> Result<(), GitError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        let mut entries = fs::read_dir(path)
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
        entries.sort();
        for entry in entries {
            sync_tree(&entry)?;
        }
        sync_directory(path)
    } else if metadata.is_file() {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))
    } else {
        Err(GitError::UnsafeMirrorEntry(path.to_owned()))
    }
}

pub(super) fn sync_directory(path: &Path) -> Result<(), GitError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    options
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))
}
pub(super) fn make_tree_read_only(path: &Path) -> Result<(), GitError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        let mut entries = fs::read_dir(path)
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
        entries.sort();
        for entry in entries {
            make_tree_read_only(&entry)?;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o555))
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))
    } else if metadata.is_file() {
        let mode = if metadata.mode() & 0o111 == 0 {
            0o444
        } else {
            0o555
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))
    } else {
        Err(GitError::UnsafeMirrorEntry(path.to_owned()))
    }
}

pub(super) fn verify_tree_read_only(path: &Path) -> Result<(), GitError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.mode() & 0o222 != 0 {
        return Err(GitError::WritableHydrationEntry(path.to_owned()));
    }
    if metadata.is_dir() {
        let mut entries = fs::read_dir(path)
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
        entries.sort();
        for entry in entries {
            verify_tree_read_only(&entry)?;
        }
        Ok(())
    } else if metadata.is_file() {
        Ok(())
    } else {
        Err(GitError::UnsafeMirrorEntry(path.to_owned()))
    }
}

pub(super) fn verify_no_shared_objects(path: &Path) -> Result<(), GitError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    if metadata.file_type().is_symlink() {
        return Err(GitError::SharedHydrationObject(path.to_owned()));
    }
    if metadata.is_dir() {
        let entries =
            fs::read_dir(path).map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
        for entry in entries {
            let entry = entry.map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
            verify_no_shared_objects(&entry.path())?;
        }
    } else if metadata.is_file() {
        if metadata.nlink() != 1 {
            return Err(GitError::SharedHydrationObject(path.to_owned()));
        }
    } else {
        return Err(GitError::SharedHydrationObject(path.to_owned()));
    }
    Ok(())
}

pub(super) fn make_tree_owner_writable(path: &Path) -> Result<(), GitError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(GitError::Filesystem(path.to_owned(), source)),
    };
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
        let entries =
            fs::read_dir(path).map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
        for entry in entries {
            let entry = entry.map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
            make_tree_owner_writable(&entry.path())?;
        }
    } else if metadata.is_file() {
        let mode = metadata.mode() | 0o600;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    }
    Ok(())
}

pub(super) fn remove_tree_no_follow(path: &Path) -> Result<(), GitError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(GitError::Filesystem(path.to_owned(), source)),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        let entries =
            fs::read_dir(path).map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
        for entry in entries {
            let entry = entry.map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
            remove_tree_no_follow(&entry.path())?;
        }
        fs::remove_dir(path).map_err(|source| GitError::Filesystem(path.to_owned(), source))
    } else {
        fs::remove_file(path).map_err(|source| GitError::Filesystem(path.to_owned(), source))
    }
}
