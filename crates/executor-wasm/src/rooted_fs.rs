use crate::host::{
    CapabilityAdapterError, CapabilityCallContext, DirectoryGrant, FilesystemAdapter,
};
use nix::{
    fcntl::{renameat, AtFlags},
    sys::stat::{fstat, fstatat, SFlag},
    unistd::{fsync, read, unlinkat, write, UnlinkatFlags},
};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::normalize_relative_path;
use rustix::{
    fd::{AsRawFd as _, OwnedFd},
    fs::{open, openat2, Mode as RustixMode, OFlags, ResolveFlags},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, Clone)]
pub struct RootedFilesystemAdapter {
    root: PathBuf,
    root_fd: Arc<ScopedFd>,
    root_device: nix::libc::dev_t,
    root_inode: nix::libc::ino_t,
    max_file_bytes: usize,
}

impl RootedFilesystemAdapter {
    pub fn new(
        root: impl Into<PathBuf>,
        max_file_bytes: usize,
    ) -> Result<Self, CapabilityAdapterError> {
        let root = root.into();
        if !root.is_absolute() || max_file_bytes == 0 {
            return Err(CapabilityAdapterError::Denied(
                "filesystem root must be absolute and the file limit positive".to_owned(),
            ));
        }
        let root_fd = open_directory_path(&root)?;
        let root_stat = fstat(root_fd.raw()).map_err(adapter_failed)?;
        Ok(Self {
            root,
            root_fd: Arc::new(root_fd),
            root_device: root_stat.st_dev,
            root_inode: root_stat.st_ino,
            max_file_bytes,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn open_parent(
        &self,
        grant: &DirectoryGrant,
        relative_path: &str,
    ) -> Result<(ScopedFd, String, nix::libc::dev_t), CapabilityAdapterError> {
        // `contains` applies the public path byte/segment bounds before any
        // normalization allocation, including for direct adapter callers.
        if !grant.contains(relative_path) {
            return Err(denied_path());
        }
        let relative_path = normalize_relative_path(relative_path).map_err(|_| denied_path())?;
        let mut segments = relative_path.split('/').collect::<Vec<_>>();
        let file_name = segments.pop().ok_or_else(denied_path)?.to_owned();
        let parent_path = if segments.is_empty() {
            ".".to_owned()
        } else {
            segments.join("/")
        };
        let directory = openat2(
            &self.root_fd.0,
            parent_path,
            directory_flags(),
            RustixMode::empty(),
            resolution_flags(),
        )
        .map(ScopedFd)
        .map_err(|_| denied_path())?;
        let stat = fstat(directory.raw()).map_err(adapter_failed)?;
        if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR
            || stat.st_dev != self.root_device
            || (segments.is_empty() && stat.st_ino != self.root_inode)
        {
            return Err(denied_path());
        }
        Ok((directory, file_name, self.root_device))
    }
}

impl FilesystemAdapter for RootedFilesystemAdapter {
    fn read_file(
        &self,
        context: &CapabilityCallContext,
        grant: &DirectoryGrant,
        relative_path: &str,
    ) -> Result<Vec<u8>, CapabilityAdapterError> {
        context.check()?;
        let (parent, file_name, root_device) = self.open_parent(grant, relative_path)?;
        let file = openat2(
            &parent.0,
            file_name.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            RustixMode::empty(),
            resolution_flags(),
        )
        .map(ScopedFd)
        .map_err(|_| denied_path())?;
        let stat = fstat(file.raw()).map_err(adapter_failed)?;
        let file_size = usize::try_from(stat.st_size).map_err(|_| denied_path())?;
        if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
            || stat.st_dev != root_device
            || stat.st_nlink != 1
            || file_size > self.max_file_bytes.min(context.max_response_bytes())
        {
            return Err(denied_path());
        }
        let mut value = Vec::with_capacity(file_size);
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            context.check()?;
            let count = read(file.raw(), &mut buffer).map_err(adapter_failed)?;
            if count == 0 {
                break;
            }
            if value.len().saturating_add(count)
                > self.max_file_bytes.min(context.max_response_bytes())
            {
                value.fill(0);
                return Err(denied_path());
            }
            value.extend_from_slice(&buffer[..count]);
        }
        Ok(value)
    }

    fn write_file(
        &self,
        context: &CapabilityCallContext,
        grant: &DirectoryGrant,
        relative_path: &str,
        value: &[u8],
    ) -> Result<(), CapabilityAdapterError> {
        context.check()?;
        if value.len() > self.max_file_bytes.min(context.max_request_bytes()) {
            return Err(denied_path());
        }
        let (parent, file_name, root_device) = self.open_parent(grant, relative_path)?;
        let mut random = [0_u8; 16];
        OsRng.try_fill_bytes(&mut random).map_err(|_| {
            CapabilityAdapterError::Failed(
                "operating system randomness is unavailable for atomic filesystem writes"
                    .to_owned(),
            )
        })?;
        let temporary = format!(".runtrue-write-{}", hex::encode(random));
        let file = openat2(
            &parent.0,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            RustixMode::from_bits_truncate(0o600),
            resolution_flags(),
        )
        .map(ScopedFd)
        .map_err(rustix_failed)?;
        let result = (|| {
            let stat = fstat(file.raw()).map_err(adapter_failed)?;
            if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
                || stat.st_dev != root_device
                || stat.st_nlink != 1
            {
                return Err(denied_path());
            }
            let mut remaining = value;
            while !remaining.is_empty() {
                context.check()?;
                let count = write(file.raw(), remaining).map_err(adapter_failed)?;
                if count == 0 {
                    return Err(adapter_failed(nix::errno::Errno::EIO));
                }
                remaining = &remaining[count..];
            }
            fsync(file.raw()).map_err(adapter_failed)?;
            let named = fstatat(
                parent.raw(),
                temporary.as_str(),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| denied_path())?;
            if named.st_dev != stat.st_dev
                || named.st_ino != stat.st_ino
                || SFlag::from_bits_truncate(named.st_mode) != SFlag::S_IFREG
            {
                return Err(denied_path());
            }
            renameat(
                Some(parent.raw()),
                temporary.as_str(),
                Some(parent.raw()),
                file_name.as_str(),
            )
            .map_err(|_| denied_path())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = unlinkat(
                Some(parent.raw()),
                temporary.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
        }
        result
    }
}

fn open_directory_path(path: &Path) -> Result<ScopedFd, CapabilityAdapterError> {
    let fd = open(path, directory_flags(), RustixMode::empty())
        .map(ScopedFd)
        .map_err(|_| denied_path())?;
    let stat = fstat(fd.raw()).map_err(adapter_failed)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR {
        return Err(denied_path());
    }
    Ok(fd)
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn resolution_flags() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}

fn denied_path() -> CapabilityAdapterError {
    CapabilityAdapterError::Denied("filesystem path is outside the granted root".to_owned())
}

fn adapter_failed(error: nix::Error) -> CapabilityAdapterError {
    CapabilityAdapterError::Failed(format!("rooted filesystem operation failed: {error}"))
}

fn rustix_failed(error: rustix::io::Errno) -> CapabilityAdapterError {
    CapabilityAdapterError::Failed(format!("rooted filesystem operation failed: {error}"))
}

#[derive(Debug)]
struct ScopedFd(OwnedFd);

impl ScopedFd {
    fn raw(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::FilesystemAccess;
    use std::fs;
    use tempfile::tempdir;

    fn grant(scope: &str) -> DirectoryGrant {
        DirectoryGrant::new(scope.to_owned(), FilesystemAccess::ReadWrite)
    }

    fn context() -> CapabilityCallContext {
        CapabilityCallContext::new(
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            runtrue_engine::CancellationToken::default(),
            1024,
            1024,
        )
    }

    #[test]
    fn reads_and_atomically_writes_inside_granted_directory() {
        let temporary = tempdir().unwrap();
        let allowed = temporary.path().join("allowed");
        fs::create_dir(&allowed).unwrap();
        fs::write(allowed.join("input.txt"), b"input").unwrap();
        let adapter = RootedFilesystemAdapter::new(temporary.path(), 1024).unwrap();

        assert_eq!(
            adapter
                .read_file(&context(), &grant("allowed"), "allowed/input.txt")
                .unwrap(),
            b"input"
        );
        adapter
            .write_file(
                &context(),
                &grant("allowed"),
                "allowed/output.txt",
                b"output",
            )
            .unwrap();
        assert_eq!(fs::read(allowed.join("output.txt")).unwrap(), b"output");
    }

    #[test]
    fn parent_escape_and_absolute_paths_are_denied() {
        let temporary = tempdir().unwrap();
        fs::create_dir(temporary.path().join("allowed")).unwrap();
        let adapter = RootedFilesystemAdapter::new(temporary.path(), 1024).unwrap();
        assert!(adapter
            .read_file(&context(), &grant("allowed"), "../outside")
            .is_err());
        assert!(adapter
            .read_file(&context(), &grant("allowed"), "/etc/passwd")
            .is_err());
        assert!(adapter
            .write_file(&context(), &grant("allowed"), "../../outside", b"bad")
            .is_err());
    }

    #[test]
    fn symlinked_scope_and_file_are_denied() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"secret").unwrap();
        fs::create_dir(temporary.path().join("allowed")).unwrap();
        symlink(outside.path(), temporary.path().join("scope-link")).unwrap();
        symlink(
            outside.path().join("secret"),
            temporary.path().join("allowed/file-link"),
        )
        .unwrap();
        let adapter = RootedFilesystemAdapter::new(temporary.path(), 1024).unwrap();

        assert!(adapter
            .read_file(&context(), &grant("scope-link"), "scope-link/secret")
            .is_err());
        assert!(adapter
            .read_file(&context(), &grant("allowed"), "allowed/file-link")
            .is_err());
    }

    #[test]
    fn atomic_write_replaces_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let outside_file = outside.path().join("valuable");
        fs::write(&outside_file, b"unchanged").unwrap();
        let allowed = temporary.path().join("allowed");
        fs::create_dir(&allowed).unwrap();
        symlink(&outside_file, allowed.join("target")).unwrap();
        let adapter = RootedFilesystemAdapter::new(temporary.path(), 1024).unwrap();

        adapter
            .write_file(
                &context(),
                &grant("allowed"),
                "allowed/target",
                b"replacement",
            )
            .unwrap();
        assert_eq!(fs::read(&outside_file).unwrap(), b"unchanged");
        assert_eq!(fs::read(allowed.join("target")).unwrap(), b"replacement");
    }

    #[test]
    fn hard_linked_files_are_denied() {
        let temporary = tempdir().unwrap();
        let allowed = temporary.path().join("allowed");
        fs::create_dir(&allowed).unwrap();
        fs::write(allowed.join("one"), b"value").unwrap();
        fs::hard_link(allowed.join("one"), allowed.join("two")).unwrap();
        let adapter = RootedFilesystemAdapter::new(temporary.path(), 1024).unwrap();

        assert!(adapter
            .read_file(&context(), &grant("allowed"), "allowed/one")
            .is_err());
    }

    #[test]
    fn kernel_resolution_rejects_escape_symlinks_and_mount_crossings() {
        let flags = resolution_flags();
        assert!(flags.contains(ResolveFlags::BENEATH));
        assert!(flags.contains(ResolveFlags::NO_SYMLINKS));
        assert!(flags.contains(ResolveFlags::NO_MAGICLINKS));
        assert!(flags.contains(ResolveFlags::NO_XDEV));
    }
}
