use super::AotCacheError;
use super::{
    read::read_bounded,
    write::{atomic_write_private, Publication},
};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
const MAX_METADATA_BYTES: u64 = 64 * 1024;
pub(super) struct CachePaths {
    pub(super) metadata: PathBuf,
    pub(super) artifact: PathBuf,
}
pub(super) fn create_private_directory(path: &Path) -> Result<(), AotCacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AotCacheError::UnsafePath {
                    path: path.to_owned(),
                    reason: "path must be a non-symlink directory".to_owned(),
                });
            }
            verify_private_mode(path, &metadata)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder
                .create(path)
                .map_err(|source| cache_io(path, source))?;
            let metadata = fs::symlink_metadata(path).map_err(|source| cache_io(path, source))?;
            verify_private_mode(path, &metadata)?;
        }
        Err(source) => return Err(cache_io(path, source)),
    }
    Ok(())
}

pub(super) fn verify_private_mode(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), AotCacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(AotCacheError::UnsafePath {
                path: path.to_owned(),
                reason: "cache path must not grant group or other permissions".to_owned(),
            });
        }
        if metadata.uid() != nix::unistd::geteuid().as_raw() {
            return Err(AotCacheError::UnsafePath {
                path: path.to_owned(),
                reason: "cache path must be owned by the executor user".to_owned(),
            });
        }
    }
    Ok(())
}

pub(super) fn ensure_exact_private_file(path: &Path, expected: &[u8]) -> Result<(), AotCacheError> {
    if safe_regular_file_if_exists(path)? {
        let bytes = read_bounded(path, MAX_METADATA_BYTES)?;
        if bytes != expected {
            return Err(AotCacheError::UnsafePath {
                path: path.to_owned(),
                reason: "existing Wasmtime cache configuration is not exact".to_owned(),
            });
        }
        return Ok(());
    }
    match atomic_write_private(path, expected)? {
        Publication::Published => Ok(()),
        Publication::Existing => {
            let bytes = read_bounded(path, MAX_METADATA_BYTES)?;
            if bytes == expected {
                Ok(())
            } else {
                Err(AotCacheError::UnsafePath {
                    path: path.to_owned(),
                    reason: "concurrently published cache configuration is not exact".to_owned(),
                })
            }
        }
    }
}

pub(super) fn safe_regular_file_if_exists(path: &Path) -> Result<bool, AotCacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(AotCacheError::UnsafePath {
                    path: path.to_owned(),
                    reason: "path must be a regular non-symlink file".to_owned(),
                });
            }
            verify_private_mode(path, &metadata)?;
            verify_single_link(path, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(cache_io(path, source)),
    }
}

pub(super) fn remove_file_if_unchanged(path: &Path) -> Result<(), AotCacheError> {
    let before = fs::symlink_metadata(path).map_err(|source| cache_io(path, source))?;
    if before.file_type().is_symlink() || !before.file_type().is_file() {
        return Err(AotCacheError::UnsafePath {
            path: path.to_owned(),
            reason: "quarantine source is not a regular file".to_owned(),
        });
    }
    let identity = file_identity(&before);
    let after = fs::symlink_metadata(path).map_err(|source| cache_io(path, source))?;
    if file_identity(&after) != identity {
        return Err(AotCacheError::UnsafePath {
            path: path.to_owned(),
            reason: "quarantine source changed before removal".to_owned(),
        });
    }
    fs::remove_file(path).map_err(|source| cache_io(path, source))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    length: u64,
    #[cfg(unix)]
    device: nix::libc::dev_t,
    #[cfg(unix)]
    inode: nix::libc::ino_t,
}

fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        FileIdentity {
            length: metadata.len(),
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
    #[cfg(not(unix))]
    {
        FileIdentity {
            length: metadata.len(),
        }
    }
}

pub(super) fn verify_single_link(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), AotCacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(AotCacheError::UnsafePath {
                path: path.to_owned(),
                reason: "cache files must have exactly one hard link".to_owned(),
            });
        }
    }
    Ok(())
}

pub(super) fn cache_io(path: &Path, source: io::Error) -> AotCacheError {
    AotCacheError::Io {
        path: path.to_owned(),
        source,
    }
}
