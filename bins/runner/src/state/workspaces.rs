use super::secure_fs::set_private_directory_permissions;
use super::{
    io_error, prepare_private_directory, validate_no_symlink_components, SourceCache, StateError,
};
use runtrue_git::{GitTreeEntryKind, GitTreeManifest};
use runtrue_model::{normalize_relative_path, ContentDigest};
use sha2::{Digest as _, Sha256};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Component, Path, PathBuf},
};

const ACTIVE_DIRECTORY: &str = "active";
const SOURCE_CACHE_DIRECTORY: &str = "source-cache";
const SOURCE_CACHE_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const SOURCE_CACHE_MAX_OBJECTS: usize = 100_000;
#[derive(Clone)]
pub struct WorkspaceManager {
    root: PathBuf,
    active: PathBuf,
    source_cache: SourceCache,
}

impl WorkspaceManager {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StateError> {
        let root = prepare_private_directory(root.as_ref())?;
        let active = prepare_private_directory(&root.join(ACTIVE_DIRECTORY))?;
        let source_cache = SourceCache::open(
            root.join(SOURCE_CACHE_DIRECTORY),
            SOURCE_CACHE_MAX_BYTES,
            SOURCE_CACHE_MAX_OBJECTS,
        )?;
        let manager = Self {
            root,
            active,
            source_cache,
        };
        manager.remove_all_stale()?;
        Ok(manager)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub(crate) fn source_cache(&self) -> &SourceCache {
        &self.source_cache
    }

    pub fn create(&self, lease_id: &str, fencing_generation: u64) -> Result<PathBuf, StateError> {
        let digest = ContentDigest::sha256(format!("{lease_id}\0{fencing_generation}"));
        let name = digest.as_str().trim_start_matches("sha256:");
        let path = self.active.join(name);
        if path.exists() {
            remove_workspace_entry(&path)?;
        }
        fs::create_dir(&path).map_err(|source| io_error(&path, source))?;
        set_private_directory_permissions(&path)?;
        Ok(path)
    }

    pub fn cleanup(&self, path: &Path) -> Result<(), StateError> {
        if path.parent() != Some(self.active.as_path()) {
            return Err(StateError::UnsafePath(path.to_owned()));
        }
        if path.exists() {
            remove_workspace_entry(path)?;
        }
        Ok(())
    }

    /// Materialize an already verified source manifest into a newly-created
    /// lease workspace. Every file is create-new/no-follow and digest checked;
    /// an integrity error is terminal and never falls back to local Git.
    pub fn materialize_source<F>(
        &self,
        workspace: &Path,
        manifest: &GitTreeManifest,
        maximum_bytes: u64,
        mut open_blob: F,
    ) -> Result<u64, StateError>
    where
        F: FnMut(&ContentDigest) -> Result<Box<dyn io::Read>, StateError>,
    {
        if workspace.parent() != Some(self.active.as_path()) || maximum_bytes == 0 {
            return Err(StateError::UnsafePath(workspace.to_owned()));
        }
        let mut written = 0_u64;
        for entry in &manifest.entries {
            let relative = normalize_relative_path(&entry.path)
                .map_err(|_| StateError::UnsafeSourceEntry(entry.path.clone()))?;
            let destination = workspace.join(&relative);
            if !destination.starts_with(workspace) {
                return Err(StateError::UnsafeSourceEntry(entry.path.clone()));
            }
            match &entry.kind {
                GitTreeEntryKind::Directory => {
                    fs::create_dir(&destination)
                        .map_err(|source| io_error(&destination, source))?;
                    set_private_directory_permissions(&destination)?;
                }
                GitTreeEntryKind::File {
                    digest,
                    size_bytes,
                    executable,
                } => {
                    written = written
                        .checked_add(*size_bytes)
                        .ok_or(StateError::SourceLimit)?;
                    if written > maximum_bytes {
                        return Err(StateError::SourceLimit);
                    }
                    let parent = destination
                        .parent()
                        .ok_or_else(|| StateError::UnsafePath(destination.clone()))?;
                    validate_no_symlink_components(parent)?;
                    let mut options = OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)]
                    options
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .mode(if *executable { 0o700 } else { 0o600 });
                    let mut output = options
                        .open(&destination)
                        .map_err(|source| io_error(&destination, source))?;
                    let mut input = open_blob(digest)?;
                    let mut hasher = Sha256::new();
                    let mut remaining = *size_bytes;
                    let mut buffer = [0_u8; 64 * 1024];
                    while remaining != 0 {
                        let limit = usize::try_from(remaining.min(buffer.len() as u64))
                            .map_err(|_| StateError::SourceLimit)?;
                        let count = input
                            .read(&mut buffer[..limit])
                            .map_err(|source| io_error(&destination, source))?;
                        if count == 0 {
                            return Err(StateError::SourceIntegrity);
                        }
                        output
                            .write_all(&buffer[..count])
                            .map_err(|source| io_error(&destination, source))?;
                        hasher.update(&buffer[..count]);
                        remaining -= count as u64;
                    }
                    let mut trailing = [0_u8; 1];
                    if input
                        .read(&mut trailing)
                        .map_err(|source| io_error(&destination, source))?
                        != 0
                        || ContentDigest::parse(format!(
                            "sha256:{}",
                            hex::encode(hasher.finalize())
                        ))
                        .map_err(|_| StateError::SourceIntegrity)?
                            != *digest
                    {
                        return Err(StateError::SourceIntegrity);
                    }
                    output
                        .sync_all()
                        .map_err(|source| io_error(&destination, source))?;
                }
                GitTreeEntryKind::Symlink { target } => {
                    validate_source_symlink(&entry.path, target)?;
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(target, &destination)
                        .map_err(|source| io_error(&destination, source))?;
                    #[cfg(not(unix))]
                    return Err(StateError::UnsafeSourceEntry(entry.path.clone()));
                }
            }
        }
        Ok(written)
    }

    pub fn remove_all_stale(&self) -> Result<(), StateError> {
        for entry in fs::read_dir(&self.active).map_err(|source| io_error(&self.active, source))? {
            let entry = entry.map_err(|source| io_error(&self.active, source))?;
            remove_workspace_entry(&entry.path())?;
        }
        Ok(())
    }
}

fn validate_source_symlink(path: &str, target: &str) -> Result<(), StateError> {
    if target.is_empty() || Path::new(target).is_absolute() {
        return Err(StateError::UnsafeSourceEntry(path.to_owned()));
    }
    let mut depth = Path::new(path)
        .parent()
        .map_or(0, |parent| parent.components().count());
    for component in Path::new(target).components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            _ => return Err(StateError::UnsafeSourceEntry(path.to_owned())),
        }
    }
    Ok(())
}

fn remove_workspace_entry(path: &Path) -> Result<(), StateError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StateError::UnsafePath(path.to_owned()));
    }
    fs::remove_dir_all(path).map_err(|source| io_error(path, source))
}
