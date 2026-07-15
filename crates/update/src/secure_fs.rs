use crate::UpdateError;
use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
};

/// Read a bounded, owner-controlled regular file without following a symlink
/// in any path component. The retained file descriptor is checked before and
/// after the read so replacement and in-place mutation races fail closed.
pub fn read_verified_file(path: impl AsRef<Path>, maximum: usize) -> Result<Vec<u8>, UpdateError> {
    let path = path.as_ref();
    if maximum == 0 {
        return Err(UpdateError::UnsafeFilePath(
            "file read bound must be nonzero".to_owned(),
        ));
    }
    let file = open_absolute_nofollow(path, read_flags(), Mode::empty())?;
    let before = file
        .metadata()
        .map_err(|source| file_io("inspect input", path, source))?;
    validate_regular(&before, path, None)?;
    let length = usize::try_from(before.len())
        .map_err(|_| UpdateError::UnsafeFilePath(format!("{} is too large", path.display())))?;
    if length == 0 || length > maximum {
        return Err(UpdateError::UnsafeFilePath(format!(
            "{} exceeds its nonzero read bound",
            path.display()
        )));
    }

    let mut bytes = Vec::with_capacity(length);
    (&file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| file_io("read input", path, source))?;
    let after = file
        .metadata()
        .map_err(|source| file_io("reinspect input", path, source))?;
    validate_regular(&after, path, Some(length as u64))?;
    if bytes.len() > maximum || !same_snapshot(&before, &after) {
        return Err(UpdateError::UnsafeFilePath(format!(
            "{} changed while it was read",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Create, sync, and publish a new mode-0644 file beneath a retained safe
/// parent descriptor. Existing destinations and ancestor symlinks are never
/// followed, and the parent directory is synced after creation.
pub fn write_new_public_file(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), UpdateError> {
    let path = path.as_ref();
    let (parent, leaf) = open_absolute_parent(path)?;
    let parent_metadata = parent
        .metadata()
        .map_err(|source| file_io("inspect output parent", path, source))?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != nix::unistd::geteuid().as_raw()
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(UpdateError::UnsafeFilePath(format!(
            "{} parent must be owner-controlled and not group/world writable",
            path.display()
        )));
    }

    let mut file = openat_confined(
        &parent,
        &leaf,
        create_public_flags(),
        Mode::from_bits_truncate(0o644),
    )
    .map_err(|source| file_io("create output", path, source))?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|source| file_io("write output", path, source))?;
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|source| file_io("set output mode", path, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| file_io("inspect output", path, source))?;
        validate_regular(&metadata, path, Some(bytes.len() as u64))?;
        file.sync_all()
            .map_err(|source| file_io("sync output", path, source))?;
        parent
            .sync_all()
            .map_err(|source| file_io("sync output parent", path, source))
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&parent, &leaf, AtFlags::empty());
        let _ = parent.sync_all();
    }
    result
}

pub(crate) fn open_absolute_nofollow(
    path: &Path,
    flags: OFlags,
    mode: Mode,
) -> Result<File, UpdateError> {
    let relative = absolute_relative(path)?;
    let root = rustix::fs::open("/", directory_flags(), Mode::empty())
        .map(File::from)
        .map_err(|source| file_io("open filesystem root", path, source.into()))?;
    openat_confined(&root, &relative, flags, mode)
        .map_err(|source| file_io("open confined path", path, source))
}

pub(crate) fn openat_confined(
    root: &File,
    path: impl AsRef<OsStr>,
    flags: OFlags,
    mode: Mode,
) -> std::io::Result<File> {
    rustix::fs::openat2(
        root,
        path.as_ref(),
        flags,
        mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(Into::into)
}

fn open_absolute_parent(path: &Path) -> Result<(File, OsString), UpdateError> {
    if !path.is_absolute() {
        return Err(UpdateError::UnsafeFilePath(format!(
            "{} must be absolute",
            path.display()
        )));
    }
    let leaf = path
        .file_name()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| UpdateError::UnsafeFilePath("missing output filename".to_owned()))?
        .to_owned();
    let parent = path
        .parent()
        .ok_or_else(|| UpdateError::UnsafeFilePath("missing output parent".to_owned()))?;
    let parent = open_absolute_nofollow(parent, directory_flags(), Mode::empty())?;
    Ok((parent, leaf))
}

fn absolute_relative(path: &Path) -> Result<PathBuf, UpdateError> {
    if !path.is_absolute() {
        return Err(UpdateError::UnsafeFilePath(format!(
            "{} must be absolute and normalized",
            path.display()
        )));
    }
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => relative.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(UpdateError::UnsafeFilePath(format!(
                    "{} must be absolute and normalized",
                    path.display()
                )))
            }
        }
    }
    if relative.as_os_str().is_empty() {
        Ok(PathBuf::from("."))
    } else {
        Ok(relative)
    }
}

fn validate_regular(
    metadata: &fs::Metadata,
    path: &Path,
    expected_length: Option<u64>,
) -> Result<(), UpdateError> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || expected_length.is_some_and(|length| metadata.len() != length)
    {
        return Err(UpdateError::UnsafeFilePath(format!(
            "{} must be a single-link regular file owned by the effective user",
            path.display()
        )));
    }
    Ok(())
}

fn same_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn create_public_flags() -> OFlags {
    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn file_io(operation: &'static str, path: &Path, source: std::io::Error) -> UpdateError {
    UpdateError::FileIo {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
