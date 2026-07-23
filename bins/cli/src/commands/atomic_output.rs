use super::super::CliError;
use rustix::{
    fd::OwnedFd,
    fs::{
        fsync as fsync_fd, openat, openat2, renameat, unlinkat, AtFlags, Mode, OFlags,
        ResolveFlags, ABS,
    },
};
use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io::{self, Write as _},
    path::{Component, Path, PathBuf},
};

struct PreparedAtomicOutput {
    path: PathBuf,
    parent_path: PathBuf,
    parent: OwnedFd,
    temporary_name: OsString,
    destination_name: OsString,
    committed: bool,
}

impl PreparedAtomicOutput {
    fn commit(mut self) -> Result<(), CliError> {
        // Recheck the pathname before the descriptor-relative rename. The
        // held parent descriptor prevents a later symlink swap from changing
        // which directory receives the file.
        reject_output_symlink_components(&self.path)?;
        renameat(
            &self.parent,
            self.temporary_name.as_os_str(),
            &self.parent,
            self.destination_name.as_os_str(),
        )
        .map_err(|source| CliError::Write {
            path: self.path.clone(),
            source: source.into(),
        })?;
        self.committed = true;
        fsync_fd(&self.parent).map_err(|source| CliError::Write {
            path: self.parent_path.clone(),
            source: source.into(),
        })?;
        Ok(())
    }
}

impl Drop for PreparedAtomicOutput {
    fn drop(&mut self) {
        if !self.committed {
            let _ = unlinkat(
                &self.parent,
                self.temporary_name.as_os_str(),
                AtFlags::empty(),
            );
        }
    }
}

fn prepare_atomic_output(path: &Path, bytes: &[u8]) -> Result<PreparedAtomicOutput, CliError> {
    reject_output_symlink_components(path)?;
    let absolute_path = normalized_absolute_output(path)?;
    let parent = absolute_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let parent_metadata = fs::symlink_metadata(&parent).map_err(|source| CliError::Write {
        path: parent.clone(),
        source,
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(CliError::UnsafeOutputPath {
            path: absolute_path.clone(),
            reason: "the output parent must be a real directory",
        });
    }
    match fs::symlink_metadata(&absolute_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(CliError::UnsafeOutputPath {
                path: absolute_path.clone(),
                reason: "an existing output must be a regular non-symlink file",
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(CliError::Write {
                path: absolute_path.clone(),
                source,
            });
        }
    }

    let parent_fd = openat2(
        ABS,
        &parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| CliError::UnsafeOutputPath {
        path: absolute_path.clone(),
        reason: "the output parent could not be opened without following symbolic links",
    })?;
    let destination_name = absolute_path
        .file_name()
        .ok_or_else(|| CliError::UnsafeOutputPath {
            path: absolute_path.clone(),
            reason: "the output path has no file name",
        })?
        .to_os_string();

    let (temporary_name, mut temporary) = (0_u16..1000)
        .find_map(|attempt| {
            let candidate = OsString::from(format!(
                ".runtrue-output.tmp-{}-{attempt}",
                std::process::id()
            ));
            match openat(
                &parent_fd,
                candidate.as_os_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(file) => Some(Ok((candidate, File::from(file)))),
                Err(error) if error == rustix::io::Errno::EXIST => None,
                Err(source) => Some(Err(CliError::Write {
                    path: parent.join(&candidate),
                    source: source.into(),
                })),
            }
        })
        .transpose()?
        .ok_or_else(|| CliError::UnsafeOutputPath {
            path: absolute_path.clone(),
            reason: "could not reserve a same-directory output file",
        })?;
    let write_result = temporary
        .write_all(bytes)
        .and_then(|()| temporary.sync_all());
    drop(temporary);
    if let Err(source) = write_result {
        let _ = unlinkat(&parent_fd, temporary_name.as_os_str(), AtFlags::empty());
        return Err(CliError::Write {
            path: parent.join(&temporary_name),
            source,
        });
    }
    Ok(PreparedAtomicOutput {
        path: absolute_path,
        parent_path: parent,
        parent: parent_fd,
        temporary_name,
        destination_name,
        committed: false,
    })
}

/// Durably replace a user-selected output without following a symbolic link.
/// Capsule and replay files can contain event projections, so outputs are private
/// and a crash exposes either the old complete file or the new complete file.
pub(crate) fn write_atomic_output(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    prepare_atomic_output(path, bytes)?.commit()
}

fn normalized_absolute_output(path: &Path) -> Result<PathBuf, CliError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(CliError::UnsafeOutputPath {
            path: path.to_path_buf(),
            reason: "the output path contains parent traversal or a platform prefix",
        });
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(CliError::CurrentDirectory)?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(CliError::UnsafeOutputPath {
                    path: path.to_path_buf(),
                    reason: "the output path contains an unsupported component",
                });
            }
        }
    }
    Ok(normalized)
}

fn reject_output_symlink_components(path: &Path) -> Result<(), CliError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(CliError::UnsafeOutputPath {
            path: path.to_path_buf(),
            reason: "the output path contains parent traversal or a platform prefix",
        });
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(CliError::CurrentDirectory)?
            .join(path)
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
            return Err(CliError::UnsafeOutputPath {
                path: path.to_path_buf(),
                reason: "the output path contains an unsupported component",
            });
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(CliError::UnsafeOutputPath {
                    path: path.to_path_buf(),
                    reason: "the output path contains a symbolic link",
                });
            }
            Ok(metadata) if index + 1 < components.len() && !metadata.is_dir() => {
                return Err(CliError::UnsafeOutputPath {
                    path: path.to_path_buf(),
                    reason: "an output ancestor is not a directory",
                });
            }
            Ok(_) => {}
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && index + 1 == components.len() => {}
            Err(source) => {
                return Err(CliError::Write {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}
