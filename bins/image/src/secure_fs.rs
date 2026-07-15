use crate::error::ImageCliError;
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

pub(crate) fn read_bounded_regular(
    path: &Path,
    max_bytes: u64,
    require_private: bool,
) -> Result<Vec<u8>, ImageCliError> {
    let mut file = open_regular_no_follow(path, require_private)?;
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes {
        return Err(ImageCliError::FileTooLarge {
            path: path.to_path_buf(),
            limit: max_bytes,
            actual: metadata.len(),
        });
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ImageCliError::SizeOverflow)?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| ImageCliError::SizeOverflow)? != metadata.len() {
        return Err(ImageCliError::FileChanged(path.to_path_buf()));
    }
    Ok(bytes)
}

pub(crate) fn open_regular_no_follow(
    path: &Path,
    require_private: bool,
) -> Result<File, ImageCliError> {
    reject_unsafe_path(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ImageCliError::NotRegularFile(path.to_path_buf()));
    }
    if require_private && metadata.mode() & 0o077 != 0 {
        return Err(ImageCliError::InsecurePrivateKeyMode {
            path: path.to_path_buf(),
            mode: metadata.mode() & 0o777,
        });
    }
    Ok(file)
}

pub(crate) fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ImageCliError> {
    reject_unsafe_path(path, true)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !fs::metadata(parent)?.is_dir() {
        return Err(ImageCliError::UnsafePath(path.to_path_buf()));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn require_new_file_target(path: &Path) -> Result<(), ImageCliError> {
    reject_unsafe_path(path, true)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(ImageCliError::OutputAlreadyExists(path.to_path_buf())),
        Err(error) => Err(ImageCliError::Io(error)),
    }
}

fn reject_unsafe_path(path: &Path, allow_missing_final: bool) -> Result<(), ImageCliError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(ImageCliError::UnsafePath(path.to_path_buf()));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    let components: Vec<OsString> = absolute
        .components()
        .filter_map(|component| match component {
            Component::RootDir => {
                current.push(Path::new("/"));
                None
            }
            Component::Normal(value) => Some(value.to_os_string()),
            Component::CurDir => None,
            Component::ParentDir | Component::Prefix(_) => Some(OsString::new()),
        })
        .collect();
    for (index, component) in components.iter().enumerate() {
        if component.is_empty() {
            return Err(ImageCliError::UnsafePath(path.to_path_buf()));
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ImageCliError::UnsafePath(path.to_path_buf()))
            }
            Ok(metadata) if index + 1 < components.len() && !metadata.is_dir() => {
                return Err(ImageCliError::UnsafePath(path.to_path_buf()))
            }
            Ok(_) => {}
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && allow_missing_final
                    && index + 1 == components.len() => {}
            Err(error) => return Err(ImageCliError::Io(error)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    #[test]
    fn writer_is_exclusive_and_rejects_symlink_ancestors() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("key");
        write_new_file(&path, b"first", 0o600).unwrap();
        assert!(write_new_file(&path, b"replace", 0o600).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        let real = temp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            write_new_file(&link.join("escape"), b"bad", 0o600),
            Err(ImageCliError::UnsafePath(_))
        ));
    }
}
