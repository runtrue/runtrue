use crate::{
    manifest::*, secure_io::*, PathSnapshot, StorageError, TreeEntryKind, TreeManifest,
    TreeSnapshot,
};
use runtrue_model::ContentDigest;
#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(not(unix))]
use std::fs;
use std::path::Path;

impl FsCas {
    /// Materialize a verified tree into a new or empty real directory.
    /// Existing entries are never overwritten.
    pub fn materialize_tree(
        &self,
        manifest_digest: &ContentDigest,
        destination: impl AsRef<Path>,
    ) -> Result<TreeSnapshot, StorageError> {
        let manifest = self.load_tree_manifest(manifest_digest)?;
        let summary = self.validate_manifest(&manifest)?;
        let destination = destination.as_ref();
        #[cfg(unix)]
        self.materialize_tree_secure(&manifest, destination)?;
        #[cfg(not(unix))]
        self.materialize_tree_portable(&manifest, destination)?;

        Ok(TreeSnapshot {
            manifest_digest: manifest_digest.clone(),
            file_count: summary.file_count,
            directory_count: summary.directory_count,
            total_file_bytes: summary.total_file_bytes,
        })
    }

    /// Materialize a captured file or directory without following links or
    /// replacing an existing path.
    pub fn materialize_path(
        &self,
        snapshot: &PathSnapshot,
        destination: impl AsRef<Path>,
    ) -> Result<(), StorageError> {
        let destination = destination.as_ref();
        match snapshot {
            PathSnapshot::File {
                digest,
                size_bytes,
                executable,
            } => {
                let reader = self.verified_reader(digest, *size_bytes)?;
                if reader.size_bytes() != *size_bytes {
                    return Err(StorageError::Manifest(
                        "captured file size does not match verified blob".to_owned(),
                    ));
                }
                #[cfg(unix)]
                {
                    let (parent, leaf) = securely_open_parent(destination)?;
                    write_new_materialized_file_at(
                        &parent,
                        &leaf,
                        destination,
                        reader,
                        digest,
                        *size_bytes,
                        *executable,
                    )
                }
                #[cfg(not(unix))]
                {
                    match fs::symlink_metadata(destination) {
                        Ok(_) => {
                            return Err(StorageError::DestinationCollision(
                                destination.to_path_buf(),
                            ));
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(source) => {
                            return Err(io_failure(
                                "inspect materialization target",
                                destination,
                                source,
                            ));
                        }
                    }
                    write_new_materialized_file(
                        destination,
                        reader,
                        digest,
                        *size_bytes,
                        *executable,
                    )
                }
            }
            PathSnapshot::Directory {
                manifest_digest,
                file_count,
                directory_count,
                total_file_bytes,
            } => {
                let manifest = self.load_tree_manifest(manifest_digest)?;
                let summary = self.validate_manifest(&manifest)?;
                if summary.file_count != *file_count
                    || summary.directory_count != *directory_count
                    || summary.total_file_bytes != *total_file_bytes
                {
                    return Err(StorageError::Manifest(
                        "directory summary does not match its verified manifest".to_owned(),
                    ));
                }
                self.materialize_tree(manifest_digest, destination)
                    .map(|_| ())
            }
        }
    }

    #[cfg(unix)]
    pub(crate) fn materialize_tree_secure(
        &self,
        manifest: &TreeManifest,
        destination: &Path,
    ) -> Result<(), StorageError> {
        let root = prepare_empty_destination_secure(destination)?;
        let mut directories = BTreeMap::from([(String::new(), root)]);
        for entry in &manifest.entries {
            let (parent_name, leaf) = split_manifest_parent(&entry.path);
            let parent = directories.get(parent_name).ok_or_else(|| {
                StorageError::Manifest(format!(
                    "tree entry `{}` has no retained parent directory",
                    entry.path
                ))
            })?;
            let target = destination.join(path_from_manifest(&entry.path));
            match &entry.kind {
                TreeEntryKind::Directory => {
                    create_new_directory_at(parent, leaf, &target)?;
                    let opened = confined_open(parent, Path::new(leaf), directory_open_flags())
                        .map_err(|source| {
                            secure_open_failure("open materialized directory", &target, source)
                        })?;
                    directories.insert(entry.path.clone(), opened);
                }
                TreeEntryKind::File {
                    digest,
                    size_bytes,
                    executable,
                } => {
                    let reader = self.verified_reader(digest, *size_bytes)?;
                    if reader.size_bytes() != *size_bytes {
                        return Err(StorageError::Manifest(format!(
                            "file `{}` size does not match its manifest",
                            entry.path
                        )));
                    }
                    write_new_materialized_file_at(
                        parent,
                        leaf.as_ref(),
                        &target,
                        reader,
                        digest,
                        *size_bytes,
                        *executable,
                    )?;
                }
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(crate) fn materialize_tree_portable(
        &self,
        manifest: &TreeManifest,
        destination: &Path,
    ) -> Result<(), StorageError> {
        prepare_empty_destination(destination)?;
        for entry in &manifest.entries {
            let target = destination.join(path_from_manifest(&entry.path));
            match &entry.kind {
                TreeEntryKind::Directory => create_new_directory(&target)?,
                TreeEntryKind::File {
                    digest,
                    size_bytes,
                    executable,
                } => {
                    let reader = self.verified_reader(digest, *size_bytes)?;
                    if reader.size_bytes() != *size_bytes {
                        return Err(StorageError::Manifest(format!(
                            "file `{}` size does not match its manifest",
                            entry.path
                        )));
                    }
                    write_new_materialized_file(&target, reader, digest, *size_bytes, *executable)?;
                }
            }
        }
        Ok(())
    }
}
use super::FsCas;
