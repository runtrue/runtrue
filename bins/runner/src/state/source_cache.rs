use super::{prepare_private_directory, StateError};
use runtrue_git::{GitTreeEntryKind, GitTreeManifest};
use runtrue_model::ContentDigest;
use runtrue_storage::{CasLimits, FsCas, StorageError, VerifiedBlobReader};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

const SNAPSHOTS_DIRECTORY: &str = "snapshots";
const MAX_SNAPSHOTS: usize = 10_000;

#[derive(Clone)]
pub(crate) struct SourceCache {
    cas: FsCas,
    snapshots: PathBuf,
    maximum_bytes: u64,
    maximum_objects: usize,
}

impl SourceCache {
    pub(crate) fn open(
        root: impl AsRef<Path>,
        maximum_bytes: u64,
        maximum_objects: usize,
    ) -> Result<Self, StateError> {
        if maximum_bytes == 0 || maximum_objects == 0 {
            return Err(StateError::SourceCache(
                "source cache bounds must be positive".to_owned(),
            ));
        }
        let root = prepare_private_directory(root.as_ref())?;
        let snapshots = prepare_private_directory(&root.join(SNAPSHOTS_DIRECTORY))?;
        let cas = FsCas::open(
            root.join("cas"),
            CasLimits {
                max_blob_bytes: maximum_bytes,
                max_manifest_bytes: 64 * 1024 * 1024,
                max_tree_entries: maximum_objects,
                max_tree_total_bytes: maximum_bytes,
                ..CasLimits::default()
            },
        )
        .map_err(cache_error)?;
        Ok(Self {
            cas,
            snapshots,
            maximum_bytes,
            maximum_objects,
        })
    }

    pub(crate) fn reader(
        &self,
        digest: &ContentDigest,
        limit: u64,
    ) -> Result<Option<VerifiedBlobReader>, StateError> {
        match self.cas.verified_reader(digest, limit) {
            Ok(reader) => Ok(Some(reader)),
            Err(StorageError::NotFound(_)) => Ok(None),
            Err(error) => Err(cache_error(error)),
        }
    }

    pub(crate) fn store<R: Read>(
        &self,
        reader: R,
        digest: &ContentDigest,
        size_bytes: u64,
        limit: u64,
    ) -> Result<(), StateError> {
        self.cas
            .put_verified_reader(reader, digest, size_bytes, limit)
            .map(|_| ())
            .map_err(cache_error)
    }

    pub(crate) fn complete_snapshot(
        &self,
        digest: &ContentDigest,
        manifest: &GitTreeManifest,
    ) -> Result<bool, StateError> {
        if manifest
            .digest()
            .map_err(|error| StateError::SourceCache(error.to_string()))?
            != *digest
            || !self.snapshot_is_complete(digest)?
        {
            return Err(StateError::SourceIntegrity);
        }
        self.prune()?;
        if !self.snapshot_is_complete(digest)? {
            return Ok(false);
        }
        let marker = self.marker_path(digest)?;
        if marker.exists() {
            fs::remove_file(&marker).map_err(|error| {
                StateError::SourceCache(format!("refresh source snapshot marker: {error}"))
            })?;
        }
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
        {
            Ok(file) => file.sync_all().map_err(|error| {
                StateError::SourceCache(format!("sync source snapshot marker: {error}"))
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(StateError::SourceCache(format!(
                    "create source snapshot marker: {error}"
                )))
            }
        }
        self.prune_markers()?;
        Ok(true)
    }

    pub(crate) fn locality(
        &self,
        maximum_snapshots: usize,
    ) -> Result<BTreeSet<ContentDigest>, StateError> {
        if maximum_snapshots == 0 {
            return Ok(BTreeSet::new());
        }
        let mut complete = Vec::new();
        for entry in fs::read_dir(&self.snapshots)
            .map_err(|error| StateError::SourceCache(format!("read source markers: {error}")))?
        {
            let entry = entry.map_err(|error| {
                StateError::SourceCache(format!("read source marker entry: {error}"))
            })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(StateError::SourceCache(
                    "source marker name is not UTF-8".to_owned(),
                ));
            };
            let digest = ContentDigest::parse(format!("sha256:{name}"))
                .map_err(|_| StateError::SourceCache("invalid source marker name".to_owned()))?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                StateError::SourceCache(format!("inspect source marker: {error}"))
            })?;
            if !metadata.is_file() || metadata.len() != 0 {
                return Err(StateError::SourceCache(
                    "source marker is not an empty regular file".to_owned(),
                ));
            }
            if self.snapshot_is_complete(&digest)? {
                let modified = metadata.modified().map_err(|error| {
                    StateError::SourceCache(format!("inspect source marker timestamp: {error}"))
                })?;
                complete.push((modified, digest));
            } else {
                fs::remove_file(entry.path()).map_err(|error| {
                    StateError::SourceCache(format!("remove stale source marker: {error}"))
                })?;
            }
        }
        complete.sort_by(|left, right| right.cmp(left));
        Ok(complete
            .into_iter()
            .take(maximum_snapshots)
            .map(|(_, digest)| digest)
            .collect())
    }

    fn snapshot_is_complete(&self, digest: &ContentDigest) -> Result<bool, StateError> {
        let Some(reader) = self.reader(digest, 64 * 1024 * 1024)? else {
            return Ok(false);
        };
        let manifest: GitTreeManifest =
            serde_json::from_reader(reader).map_err(|_| StateError::SourceIntegrity)?;
        if manifest.digest().map_err(|_| StateError::SourceIntegrity)? != *digest {
            return Err(StateError::SourceIntegrity);
        }
        for entry in &manifest.entries {
            if let GitTreeEntryKind::File {
                digest, size_bytes, ..
            } = &entry.kind
            {
                let Some(reader) = self.reader(digest, *size_bytes)? else {
                    return Ok(false);
                };
                if reader.size_bytes() != *size_bytes {
                    return Err(StateError::SourceIntegrity);
                }
            }
        }
        Ok(true)
    }

    fn prune(&self) -> Result<(), StateError> {
        // One complete source can add at most `maximum_objects` objects to a
        // cache previously pruned to that same bound. Keep the scan bounded
        // even if the private cache directory is damaged out of band.
        let inventory_bound = self
            .maximum_objects
            .checked_mul(2)
            .and_then(|bound| bound.checked_add(1))
            .ok_or_else(|| StateError::SourceCache("source cache object bound overflow".into()))?;
        let mut objects = self
            .cas
            .inventory_objects(inventory_bound)
            .map_err(cache_error)?;
        objects.sort_by_key(|object| (object.created_unix_ms, object.digest.clone()));
        let mut bytes = objects.iter().try_fold(0_u64, |total, object| {
            total
                .checked_add(object.size_bytes)
                .ok_or_else(|| StateError::SourceCache("source cache size overflow".to_owned()))
        })?;
        let mut count = objects.len();
        for object in objects {
            if bytes <= self.maximum_bytes && count <= self.maximum_objects {
                break;
            }
            if let Some(removed) = self
                .cas
                .remove_verified_object(&object.digest)
                .map_err(cache_error)?
            {
                bytes = bytes.saturating_sub(removed);
                count = count.saturating_sub(1);
            }
        }
        Ok(())
    }

    fn prune_markers(&self) -> Result<(), StateError> {
        let mut markers = fs::read_dir(&self.snapshots)
            .map_err(|error| StateError::SourceCache(format!("read source markers: {error}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| StateError::SourceCache(format!("read source marker: {error}")))?;
        markers.sort_by_key(|entry| {
            entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok()
        });
        let remove = markers.len().saturating_sub(MAX_SNAPSHOTS);
        for marker in markers.into_iter().take(remove) {
            fs::remove_file(marker.path()).map_err(|error| {
                StateError::SourceCache(format!("remove old source marker: {error}"))
            })?;
        }
        Ok(())
    }

    fn marker_path(&self, digest: &ContentDigest) -> Result<PathBuf, StateError> {
        let name = digest
            .as_str()
            .strip_prefix("sha256:")
            .filter(|name| name.len() == 64)
            .ok_or_else(|| StateError::SourceCache("invalid source digest".to_owned()))?;
        Ok(self.snapshots.join(name))
    }
}

fn cache_error(error: StorageError) -> StateError {
    if error.is_corruption() {
        StateError::SourceIntegrity
    } else {
        StateError::SourceCache(error.to_string())
    }
}
