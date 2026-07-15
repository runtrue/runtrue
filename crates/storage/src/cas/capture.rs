use crate::{
    manifest::*, secure_io::*, PathSnapshot, StorageError, TreeEntry, TreeEntryKind, TreeManifest,
    TreeSnapshot, TREE_MANIFEST_VERSION,
};
#[cfg(unix)]
use rustix::fs::{Dir, FileType as RustixFileType};
#[cfg(not(unix))]
use std::{fs, io};
use std::{fs::File, io::Cursor, path::Path};

impl FsCas {
    /// Capture either one regular file or one directory tree. The root path may
    /// not be a symlink or special file. On Unix, every component is resolved
    /// from a retained directory descriptor without following symlinks.
    pub fn capture_path(&self, source: impl AsRef<Path>) -> Result<PathSnapshot, StorageError> {
        let source = source.as_ref();
        #[cfg(unix)]
        {
            let opened = securely_open_existing_path(source, source_open_flags())?;
            self.capture_opened_path(opened, source)
        }
        #[cfg(not(unix))]
        {
            self.capture_path_portable(source)
        }
    }

    /// Capture a path relative to an already trusted filesystem boundary.
    /// The root and relative path are both resolved without symlinks, and the
    /// retained root handle prevents rename races from escaping that boundary.
    pub fn capture_path_beneath(
        &self,
        root: impl AsRef<Path>,
        relative: &str,
    ) -> Result<PathSnapshot, StorageError> {
        let root = root.as_ref();
        let normalized = normalize_manifest_path(relative, self.limits)?;
        #[cfg(unix)]
        {
            let root_file = securely_open_existing_path(root, directory_open_flags())?;
            let display = root.join(path_from_manifest(&normalized));
            let opened = confined_open(&root_file, Path::new(&normalized), source_open_flags())
                .map_err(|source| {
                    secure_open_failure("open rooted capture path", &display, source)
                })?;
            self.capture_opened_path(opened, &display)
        }
        #[cfg(not(unix))]
        {
            self.capture_path_portable(&root.join(path_from_manifest(&normalized)))
        }
    }

    /// Capture a source directory without following symlinks or accepting
    /// sockets, devices, FIFOs, or other special nodes.
    pub fn capture_tree(&self, source: impl AsRef<Path>) -> Result<TreeSnapshot, StorageError> {
        let source = source.as_ref();
        #[cfg(unix)]
        let opened = securely_open_existing_path(source, directory_open_flags())?;
        #[cfg(unix)]
        return self.capture_opened_tree(opened, source);
        #[cfg(not(unix))]
        let mut state = {
            let metadata = fs::symlink_metadata(source)
                .map_err(|source_error| io_failure("inspect tree root", source, source_error))?;
            require_real_directory(source, &metadata)?;
            let mut state = CaptureState::default();
            self.capture_directory_portable(source, "", 0, &mut state)?;
            state
        };
        #[cfg(not(unix))]
        {
            self.finish_tree_capture(&mut state)
        }
    }

    #[cfg(unix)]
    fn capture_opened_path(
        &self,
        opened: File,
        display: &Path,
    ) -> Result<PathSnapshot, StorageError> {
        let metadata = opened
            .metadata()
            .map_err(|source| io_failure("inspect opened capture path", display, source))?;
        if metadata.is_dir() {
            return self.capture_opened_tree(opened, display).map(Into::into);
        }
        if !metadata.is_file() {
            return Err(StorageError::UnsafeFilesystemEntry {
                path: display.to_path_buf(),
                kind: "special file",
            });
        }
        let executable = file_is_executable(&opened)?;
        let record = self.put_reader(opened)?;
        Ok(PathSnapshot::File {
            digest: record.digest,
            size_bytes: record.size_bytes,
            executable,
        })
    }

    #[cfg(unix)]
    fn capture_opened_tree(
        &self,
        opened: File,
        display: &Path,
    ) -> Result<TreeSnapshot, StorageError> {
        let metadata = opened
            .metadata()
            .map_err(|source| io_failure("inspect opened tree root", display, source))?;
        require_real_directory(display, &metadata)?;
        let mut state = CaptureState::default();
        self.capture_directory_handle(&opened, display, "", 0, &mut state)?;
        self.finish_tree_capture(&mut state)
    }

    fn finish_tree_capture(&self, state: &mut CaptureState) -> Result<TreeSnapshot, StorageError> {
        state
            .entries
            .sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = TreeManifest {
            version: TREE_MANIFEST_VERSION,
            entries: std::mem::take(&mut state.entries),
        };
        let summary = self.validate_manifest(&manifest)?;
        let bytes = serde_json::to_vec(&manifest).map_err(StorageError::SerializeManifest)?;
        if bytes.len() as u64 > self.limits.max_manifest_bytes {
            return Err(StorageError::LimitExceeded {
                resource: "tree manifest bytes",
                limit: self.limits.max_manifest_bytes,
                actual: bytes.len() as u64,
            });
        }
        let record =
            self.put_reader_with_limit(Cursor::new(bytes), self.limits.max_manifest_bytes)?;
        Ok(TreeSnapshot {
            manifest_digest: record.digest,
            file_count: summary.file_count,
            directory_count: summary.directory_count,
            total_file_bytes: summary.total_file_bytes,
        })
    }

    #[cfg(unix)]
    fn capture_directory_handle(
        &self,
        directory: &File,
        directory_display: &Path,
        relative_parent: &str,
        depth: usize,
        state: &mut CaptureState,
    ) -> Result<(), StorageError> {
        if depth > self.limits.max_tree_depth {
            return Err(StorageError::LimitExceeded {
                resource: "tree depth",
                limit: self.limits.max_tree_depth as u64,
                actual: depth as u64,
            });
        }
        let metadata = directory.metadata().map_err(|source| {
            io_failure(
                "inspect retained source directory",
                directory_display,
                source,
            )
        })?;
        require_real_directory(directory_display, &metadata)?;

        let mut reader = Dir::read_from(directory).map_err(|source| {
            io_failure(
                "read retained source directory",
                directory_display,
                source.into(),
            )
        })?;
        let mut children = Vec::new();
        while let Some(entry) = reader.read() {
            let entry = entry.map_err(|source| {
                io_failure(
                    "read retained source directory entry",
                    directory_display,
                    source.into(),
                )
            })?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = std::str::from_utf8(bytes).map_err(|_| {
                StorageError::UnsafePath(format!(
                    "non-UTF-8 path below `{}`",
                    directory_display.display()
                ))
            })?;
            children.push((name.to_owned(), entry.file_type()));
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));

        for (name, reported_type) in children {
            let display = directory_display.join(&name);
            if reported_type == RustixFileType::Symlink {
                return Err(StorageError::UnsafeFilesystemEntry {
                    path: display,
                    kind: "symlink",
                });
            }
            if !matches!(
                reported_type,
                RustixFileType::RegularFile | RustixFileType::Directory | RustixFileType::Unknown
            ) {
                return Err(StorageError::UnsafeFilesystemEntry {
                    path: display,
                    kind: "special file",
                });
            }
            let opened = confined_open(directory, Path::new(&name), source_open_flags()).map_err(
                |source| secure_open_failure("open retained source tree entry", &display, source),
            )?;
            let metadata = opened.metadata().map_err(|source| {
                io_failure("inspect retained source tree entry", &display, source)
            })?;
            let relative = if relative_parent.is_empty() {
                name
            } else {
                format!("{relative_parent}/{name}")
            };
            let normalized = normalize_manifest_path(&relative, self.limits)?;
            state.add_entry(self.limits)?;
            if metadata.is_dir() {
                state.directory_count += 1;
                state.entries.push(TreeEntry {
                    path: normalized.clone(),
                    kind: TreeEntryKind::Directory,
                });
                self.capture_directory_handle(&opened, &display, &normalized, depth + 1, state)?;
            } else if metadata.is_file() {
                self.capture_opened_file(opened, &normalized, state)?;
            } else {
                return Err(StorageError::UnsafeFilesystemEntry {
                    path: display,
                    kind: "special file",
                });
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn capture_opened_file(
        &self,
        file: File,
        normalized: &str,
        state: &mut CaptureState,
    ) -> Result<(), StorageError> {
        let executable = file_is_executable(&file)?;
        let record = self.put_reader(file)?;
        state.total_file_bytes = state
            .total_file_bytes
            .checked_add(record.size_bytes)
            .ok_or(StorageError::LimitExceeded {
                resource: "tree file bytes",
                limit: self.limits.max_tree_total_bytes,
                actual: u64::MAX,
            })?;
        if state.total_file_bytes > self.limits.max_tree_total_bytes {
            return Err(StorageError::LimitExceeded {
                resource: "tree file bytes",
                limit: self.limits.max_tree_total_bytes,
                actual: state.total_file_bytes,
            });
        }
        state.file_count += 1;
        state.entries.push(TreeEntry {
            path: normalized.to_owned(),
            kind: TreeEntryKind::File {
                digest: record.digest,
                size_bytes: record.size_bytes,
                executable,
            },
        });
        Ok(())
    }

    #[cfg(not(unix))]
    fn capture_path_portable(&self, source: &Path) -> Result<PathSnapshot, StorageError> {
        let metadata = fs::symlink_metadata(source)
            .map_err(|source_error| io_failure("inspect capture path", source, source_error))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(StorageError::UnsafeFilesystemEntry {
                path: source.to_path_buf(),
                kind: "symlink",
            });
        }
        if file_type.is_dir() {
            return self.capture_tree(source).map(Into::into);
        }
        if !file_type.is_file() {
            return Err(StorageError::UnsafeFilesystemEntry {
                path: source.to_path_buf(),
                kind: "special file",
            });
        }
        let file = open_regular_nofollow(source, "open capture file")?;
        let executable = file_is_executable(&file)?;
        let record = self.put_reader(file)?;
        Ok(PathSnapshot::File {
            digest: record.digest,
            size_bytes: record.size_bytes,
            executable,
        })
    }

    #[cfg(not(unix))]
    fn capture_directory_portable(
        &self,
        directory: &Path,
        relative_parent: &str,
        depth: usize,
        state: &mut CaptureState,
    ) -> Result<(), StorageError> {
        if depth > self.limits.max_tree_depth {
            return Err(StorageError::LimitExceeded {
                resource: "tree depth",
                limit: self.limits.max_tree_depth as u64,
                actual: depth as u64,
            });
        }
        let metadata = fs::symlink_metadata(directory)
            .map_err(|source| io_failure("inspect source directory", directory, source))?;
        require_real_directory(directory, &metadata)?;

        let mut children = Vec::new();
        for entry in fs::read_dir(directory)
            .map_err(|source| io_failure("read source directory", directory, source))?
        {
            let entry = entry
                .map_err(|source| io_failure("read source directory entry", directory, source))?;
            let name = entry.file_name().into_string().map_err(|_| {
                StorageError::UnsafePath(format!("non-UTF-8 path below `{}`", directory.display()))
            })?;
            children.push((name, entry.path()));
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));

        for (name, path) in children {
            let relative = if relative_parent.is_empty() {
                name
            } else {
                format!("{relative_parent}/{name}")
            };
            let normalized = normalize_manifest_path(&relative, self.limits)?;
            state.add_entry(self.limits)?;
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_failure("inspect source tree entry", &path, source))?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(StorageError::UnsafeFilesystemEntry {
                    path,
                    kind: "symlink",
                });
            }
            if file_type.is_dir() {
                state.directory_count += 1;
                state.entries.push(TreeEntry {
                    path: normalized.clone(),
                    kind: TreeEntryKind::Directory,
                });
                self.capture_directory_portable(&path, &normalized, depth + 1, state)?;
            } else if file_type.is_file() {
                let file = open_regular_nofollow(&path, "open source tree file")?;
                let executable = file_is_executable(&file)?;
                let record = self.put_reader(file)?;
                state.total_file_bytes = state
                    .total_file_bytes
                    .checked_add(record.size_bytes)
                    .ok_or(StorageError::LimitExceeded {
                        resource: "tree file bytes",
                        limit: self.limits.max_tree_total_bytes,
                        actual: u64::MAX,
                    })?;
                if state.total_file_bytes > self.limits.max_tree_total_bytes {
                    return Err(StorageError::LimitExceeded {
                        resource: "tree file bytes",
                        limit: self.limits.max_tree_total_bytes,
                        actual: state.total_file_bytes,
                    });
                }
                state.file_count += 1;
                state.entries.push(TreeEntry {
                    path: normalized,
                    kind: TreeEntryKind::File {
                        digest: record.digest,
                        size_bytes: record.size_bytes,
                        executable,
                    },
                });
            } else {
                return Err(StorageError::UnsafeFilesystemEntry {
                    path,
                    kind: "special file",
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct CaptureState {
    entries: Vec<TreeEntry>,
    file_count: usize,
    directory_count: usize,
    total_file_bytes: u64,
}

impl CaptureState {
    fn add_entry(&self, limits: CasLimits) -> Result<(), StorageError> {
        if self.entries.len() >= limits.max_tree_entries {
            return Err(StorageError::LimitExceeded {
                resource: "tree entries",
                limit: limits.max_tree_entries as u64,
                actual: self.entries.len().saturating_add(1) as u64,
            });
        }
        Ok(())
    }
}
use super::{CasLimits, FsCas};
