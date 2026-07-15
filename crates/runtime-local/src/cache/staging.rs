use super::{canonical_workspace, relative_path, LocalCacheConfig};
use crate::secure_io::{file_is_executable, open_regular_nofollow, set_executable};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path},
};
use tempfile::{Builder as TempBuilder, TempDir};

pub(crate) fn staging_directory(config: &LocalCacheConfig) -> Result<TempDir, String> {
    let root = config.cache_root.join("staging");
    ensure_real_directory(&root)?;
    TempBuilder::new()
        .prefix("entry-")
        .tempdir_in(root)
        .map_err(|error| error.to_string())
}

pub(crate) fn ensure_real_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(format!("{} is not a real directory", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|error| error.to_string())?;
            let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(format!("{} is not a real directory", path.display()))
            }
        }
        Err(error) => Err(error.to_string()),
    }
}

pub(crate) fn first_output_collision(workspace: &Path, outputs: &[String]) -> Option<String> {
    for relative in outputs {
        let target = workspace.join(relative_path(relative));
        match fs::symlink_metadata(target) {
            Ok(_) => return Some(relative.clone()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Some(relative.clone()),
        }
        if safe_destination_parent(workspace, relative).is_err() {
            return Some(relative.clone());
        }
    }
    None
}

pub(crate) fn safe_destination_parent(workspace: &Path, relative: &str) -> Result<(), String> {
    let workspace = canonical_workspace(workspace)?;
    let mut current = workspace;
    let path = relative_path(relative);
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    for component in parent.components() {
        let Component::Normal(segment) = component else {
            return Err(format!("unsafe output parent for {relative}"));
        };
        current.push(segment);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(format!(
                    "output parent {} is not a real directory",
                    current.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct CopyBudget {
    pub(crate) bytes: u64,
    pub(crate) limit: u64,
}

pub(crate) fn copy_to_stage(
    source: &Path,
    destination: &Path,
    budget: &mut CopyBudget,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("symlinks are not cacheable".to_owned());
    }
    if metadata.is_dir() {
        if let Some(parent) = destination.parent() {
            ensure_destination_directories(parent)?;
        }
        fs::create_dir(destination).map_err(|error| error.to_string())?;
        let mut entries = fs::read_dir(source)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            copy_to_stage(&entry.path(), &destination.join(entry.file_name()), budget)?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err("special filesystem entries are not cacheable".to_owned());
    }
    copy_file_new(source, destination, Some(budget))
}

pub(crate) fn copy_new_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("staged cache content contains a symlink".to_owned());
    }
    if metadata.is_dir() {
        if let Some(parent) = destination.parent() {
            ensure_destination_directories(parent)?;
        }
        fs::create_dir(destination).map_err(|error| error.to_string())?;
        let copy_result = (|| {
            let mut entries = fs::read_dir(source)
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            entries.sort_by_key(fs::DirEntry::file_name);
            for entry in entries {
                copy_new_tree(&entry.path(), &destination.join(entry.file_name()))?;
            }
            Ok(())
        })();
        if copy_result.is_err() {
            let _ = fs::remove_dir_all(destination);
        }
        return copy_result;
    }
    if !metadata.is_file() {
        return Err("staged cache content contains a special entry".to_owned());
    }
    copy_file_new(source, destination, None)
}

pub(crate) fn copy_file_new(
    source: &Path,
    destination: &Path,
    mut budget: Option<&mut CopyBudget>,
) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        ensure_destination_directories(parent)?;
    }
    let mut source_file = open_regular_nofollow(source)?;
    let source_metadata = source_file.metadata().map_err(|error| error.to_string())?;
    if !source_metadata.is_file() {
        return Err("source is not a regular file".to_owned());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut destination_file = options
        .open(destination)
        .map_err(|error| error.to_string())?;
    let copy_result = (|| {
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = source_file
                .read(&mut buffer)
                .map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            if let Some(limit) = budget.as_deref_mut() {
                limit.bytes = limit
                    .bytes
                    .checked_add(read as u64)
                    .ok_or("cache size overflow")?;
                if limit.bytes > limit.limit {
                    return Err(format!(
                        "declared max-size of {} bytes was exceeded",
                        limit.limit
                    ));
                }
            }
            destination_file
                .write_all(&buffer[..read])
                .map_err(|error| error.to_string())?;
        }
        destination_file
            .sync_all()
            .map_err(|error| error.to_string())?;
        set_executable(&destination_file, file_is_executable(&source_metadata))?;
        Ok(())
    })();
    if copy_result.is_err() {
        drop(destination_file);
        let _ = fs::remove_file(destination);
    }
    copy_result
}

pub(crate) fn ensure_destination_directories(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(format!("destination parent {} is unsafe", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| "destination has no parent".to_owned())?;
            ensure_destination_directories(parent)?;
            match fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
                    if metadata.is_dir() && !metadata.file_type().is_symlink() {
                        Ok(())
                    } else {
                        Err(format!("destination parent {} is unsafe", path.display()))
                    }
                }
                Err(error) => Err(error.to_string()),
            }
        }
        Err(error) => Err(error.to_string()),
    }
}
