use super::io_failure;
use crate::StorageError;
#[cfg(unix)]
use rustix::fs::{Dir, Mode, OFlags};
use std::fs::File;
use std::{
    ffi::OsString,
    fs, io,
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
pub(crate) fn source_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

#[cfg(unix)]
pub(crate) fn directory_open_flags() -> OFlags {
    source_open_flags() | OFlags::DIRECTORY
}

#[cfg(unix)]
pub(crate) fn create_file_flags() -> OFlags {
    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

#[cfg(unix)]
pub(crate) fn secure_path_anchor(path: &Path) -> Result<(File, PathBuf), StorageError> {
    if path.as_os_str().is_empty() {
        return Err(StorageError::UnsafePath(
            "filesystem path must not be empty".to_owned(),
        ));
    }
    let absolute = path.is_absolute();
    let anchor_path = if absolute {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let anchor = rustix::fs::open(anchor_path, directory_open_flags(), Mode::empty())
        .map(File::from)
        .map_err(|source| {
            io_failure(
                "open filesystem resolution anchor",
                anchor_path,
                source.into(),
            )
        })?;
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir if absolute => {}
            Component::CurDir => {}
            Component::Normal(segment) => relative.push(segment),
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(StorageError::UnsafePath(format!(
                    "filesystem path `{}` is not a normalized path below its anchor",
                    path.display()
                )))
            }
        }
    }
    Ok((anchor, relative))
}

#[cfg(unix)]
pub(crate) fn securely_open_existing_path(
    path: &Path,
    flags: OFlags,
) -> Result<File, StorageError> {
    let (anchor, relative) = secure_path_anchor(path)?;
    if relative.as_os_str().is_empty() {
        return Ok(anchor);
    }
    confined_open(&anchor, &relative, flags)
        .map_err(|source| secure_open_failure("open confined filesystem path", path, source))
}

#[cfg(unix)]
pub(crate) fn securely_open_parent(path: &Path) -> Result<(File, OsString), StorageError> {
    let (anchor, mut relative) = secure_path_anchor(path)?;
    let leaf = relative.file_name().map(ToOwned::to_owned).ok_or_else(|| {
        StorageError::UnsafePath(format!(
            "materialization path `{}` has no final component",
            path.display()
        ))
    })?;
    if !relative.pop() || relative.as_os_str().is_empty() {
        return Ok((anchor, leaf));
    }
    let parent = confined_open(&anchor, &relative, directory_open_flags()).map_err(|source| {
        secure_open_failure("open confined materialization parent", path, source)
    })?;
    Ok((parent, leaf))
}

#[cfg(unix)]
pub(crate) fn confined_open(root: &File, relative: &Path, final_flags: OFlags) -> io::Result<File> {
    let components = confined_components(relative)?;
    if components.is_empty() {
        return root.try_clone();
    }

    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{openat2, ResolveFlags};
        let mode = if final_flags.contains(OFlags::CREATE) {
            Mode::from_bits_truncate(0o600)
        } else {
            Mode::empty()
        };
        let resolve =
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
        match openat2(root, relative, final_flags, mode, resolve) {
            Ok(file) => return Ok(File::from(file)),
            Err(rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL) => {}
            Err(error) => return Err(error.into()),
        }
    }

    let mut directory = root.try_clone()?;
    let last = components.len().saturating_sub(1);
    for (index, component) in components.iter().enumerate() {
        let flags = if index == last {
            final_flags
        } else {
            directory_open_flags()
        };
        let mode = if flags.contains(OFlags::CREATE) {
            Mode::from_bits_truncate(0o600)
        } else {
            Mode::empty()
        };
        let opened =
            rustix::fs::openat(&directory, component, flags, mode).map_err(io::Error::from)?;
        directory = File::from(opened);
    }
    Ok(directory)
}

#[cfg(unix)]
pub(crate) fn confined_components(path: &Path) -> io::Result<Vec<OsString>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => components.push(segment.to_owned()),
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path escapes its retained directory descriptor",
                ))
            }
        }
    }
    Ok(components)
}

#[cfg(unix)]
pub(crate) fn secure_open_failure(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> StorageError {
    match source.kind() {
        io::ErrorKind::NotFound => StorageError::NotFound(path.to_path_buf()),
        io::ErrorKind::NotADirectory => StorageError::UnsafeFilesystemEntry {
            path: path.to_path_buf(),
            kind: if path_contains_symlink(path) {
                "symlink"
            } else {
                "non-directory"
            },
        },
        io::ErrorKind::InvalidInput => StorageError::UnsafePath(format!(
            "filesystem path `{}` escapes its retained root",
            path.display()
        )),
        _ if matches!(
            source.raw_os_error(),
            Some(nix::libc::ELOOP) | Some(nix::libc::EXDEV)
        ) =>
        {
            StorageError::UnsafeFilesystemEntry {
                path: path.to_path_buf(),
                kind: "symlink",
            }
        }
        _ if source.raw_os_error() == Some(nix::libc::ENXIO) => {
            StorageError::UnsafeFilesystemEntry {
                path: path.to_path_buf(),
                kind: "special file",
            }
        }
        _ => io_failure(operation, path, source),
    }
}

#[cfg(unix)]
pub(crate) fn path_contains_symlink(path: &Path) -> bool {
    let mut current = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(segment) => current.push(segment),
            Component::Prefix(_) | Component::ParentDir => return false,
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

#[cfg(unix)]
pub(crate) fn prepare_empty_destination_secure(path: &Path) -> Result<File, StorageError> {
    let (parent, leaf) = securely_open_parent(path)?;
    match confined_open(&parent, Path::new(&leaf), directory_open_flags()) {
        Ok(directory) => {
            if !directory_is_empty(&directory, path)? {
                return Err(StorageError::DestinationNotEmpty(path.to_path_buf()));
            }
            Ok(directory)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            rustix::fs::mkdirat(&parent, &leaf, Mode::from_bits_truncate(0o755)).map_err(
                |source| {
                    let source: io::Error = source.into();
                    if source.kind() == io::ErrorKind::AlreadyExists {
                        StorageError::DestinationCollision(path.to_path_buf())
                    } else {
                        secure_open_failure("create materialization destination", path, source)
                    }
                },
            )?;
            let directory = confined_open(&parent, Path::new(&leaf), directory_open_flags())
                .map_err(|source| {
                    secure_open_failure("open created materialization destination", path, source)
                })?;
            parent
                .sync_all()
                .map_err(|source| io_failure("sync materialization parent", path, source))?;
            Ok(directory)
        }
        Err(source) => Err(secure_open_failure(
            "open materialization destination",
            path,
            source,
        )),
    }
}

#[cfg(unix)]
pub(crate) fn directory_is_empty(directory: &File, display: &Path) -> Result<bool, StorageError> {
    let mut reader = Dir::read_from(directory)
        .map_err(|source| io_failure("read materialization destination", display, source.into()))?;
    while let Some(entry) = reader.read() {
        let entry = entry.map_err(|source| {
            io_failure(
                "read materialization destination entry",
                display,
                source.into(),
            )
        })?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Ok(false);
        }
    }
    Ok(true)
}
