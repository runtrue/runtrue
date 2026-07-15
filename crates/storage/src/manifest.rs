use crate::{CasLimits, FsCas, StorageError, TreeSnapshot};
use runtrue_model::{normalize_relative_path, ContentDigest};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Cursor, path::PathBuf};

pub(crate) const TREE_MANIFEST_VERSION: u32 = 1;

/// A deterministic manifest for a directory tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeManifest {
    pub version: u32,
    pub entries: Vec<TreeEntry>,
}

impl TreeManifest {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            version: TREE_MANIFEST_VERSION,
            entries: Vec::new(),
        }
    }
}

/// One path in a tree manifest. The root itself is implicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeEntry {
    pub path: String,
    pub kind: TreeEntryKind,
}

/// Supported tree nodes. Symlinks and special files have no representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeEntryKind {
    Directory,
    File {
        digest: ContentDigest,
        size_bytes: u64,
        executable: bool,
    },
}

impl FsCas {
    /// Store a caller-created manifest after complete structural validation.
    pub fn store_tree_manifest(
        &self,
        manifest: &TreeManifest,
    ) -> Result<TreeSnapshot, StorageError> {
        let summary = self.validate_manifest(manifest)?;
        let bytes = serde_json::to_vec(manifest).map_err(StorageError::SerializeManifest)?;
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

    /// Load, digest-verify, strictly decode, and structurally validate a tree manifest.
    pub fn load_tree_manifest(&self, digest: &ContentDigest) -> Result<TreeManifest, StorageError> {
        let bytes = self.read_blob_with_limit(digest, self.limits.max_manifest_bytes)?;
        let manifest: TreeManifest =
            serde_json::from_slice(&bytes).map_err(StorageError::InvalidManifestEncoding)?;
        self.validate_manifest(&manifest)?;
        Ok(manifest)
    }

    /// Verify a manifest and return its exact bounded summary without
    /// materializing the tree.
    pub fn inspect_tree(
        &self,
        manifest_digest: &ContentDigest,
    ) -> Result<TreeSnapshot, StorageError> {
        let manifest = self.load_tree_manifest(manifest_digest)?;
        let summary = self.validate_manifest(&manifest)?;
        Ok(TreeSnapshot {
            manifest_digest: manifest_digest.clone(),
            file_count: summary.file_count,
            directory_count: summary.directory_count,
            total_file_bytes: summary.total_file_bytes,
        })
    }
}

impl FsCas {
    pub(crate) fn validate_manifest(
        &self,
        manifest: &TreeManifest,
    ) -> Result<TreeSummary, StorageError> {
        if manifest.version != TREE_MANIFEST_VERSION {
            return Err(StorageError::Manifest(format!(
                "unsupported tree manifest version {}",
                manifest.version
            )));
        }
        if manifest.entries.len() > self.limits.max_tree_entries {
            return Err(StorageError::LimitExceeded {
                resource: "tree entries",
                limit: self.limits.max_tree_entries as u64,
                actual: manifest.entries.len() as u64,
            });
        }

        let mut kinds = BTreeMap::new();
        let mut previous: Option<&str> = None;
        let mut total_file_bytes = 0_u64;
        let mut file_count = 0_usize;
        let mut directory_count = 0_usize;
        for entry in &manifest.entries {
            let normalized = normalize_manifest_path(&entry.path, self.limits)?;
            if normalized != entry.path {
                return Err(StorageError::Manifest(format!(
                    "tree path `{}` is not canonical",
                    entry.path
                )));
            }
            if previous.is_some_and(|previous| previous >= entry.path.as_str()) {
                return Err(StorageError::Manifest(
                    "tree entries must be strictly path-sorted and unique".to_owned(),
                ));
            }
            previous = Some(&entry.path);

            if let Some(parent) = parent_manifest_path(&entry.path) {
                match kinds.get(parent) {
                    Some(NodeKind::Directory) => {}
                    Some(NodeKind::File) => {
                        return Err(StorageError::Manifest(format!(
                            "file `{parent}` cannot contain `{}`",
                            entry.path
                        )));
                    }
                    None => {
                        return Err(StorageError::Manifest(format!(
                            "tree entry `{}` has undeclared parent `{parent}`",
                            entry.path
                        )));
                    }
                }
            }

            match &entry.kind {
                TreeEntryKind::Directory => {
                    directory_count += 1;
                    kinds.insert(entry.path.as_str(), NodeKind::Directory);
                }
                TreeEntryKind::File { size_bytes, .. } => {
                    if *size_bytes > self.limits.max_blob_bytes {
                        return Err(StorageError::LimitExceeded {
                            resource: "tree file bytes",
                            limit: self.limits.max_blob_bytes,
                            actual: *size_bytes,
                        });
                    }
                    total_file_bytes = total_file_bytes.checked_add(*size_bytes).ok_or(
                        StorageError::LimitExceeded {
                            resource: "tree file bytes",
                            limit: self.limits.max_tree_total_bytes,
                            actual: u64::MAX,
                        },
                    )?;
                    if total_file_bytes > self.limits.max_tree_total_bytes {
                        return Err(StorageError::LimitExceeded {
                            resource: "tree file bytes",
                            limit: self.limits.max_tree_total_bytes,
                            actual: total_file_bytes,
                        });
                    }
                    file_count += 1;
                    kinds.insert(entry.path.as_str(), NodeKind::File);
                }
            }
        }
        Ok(TreeSummary {
            file_count,
            directory_count,
            total_file_bytes,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum NodeKind {
    Directory,
    File,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TreeSummary {
    pub(crate) file_count: usize,
    pub(crate) directory_count: usize,
    pub(crate) total_file_bytes: u64,
}

pub(crate) fn normalize_manifest_path(
    path: &str,
    limits: CasLimits,
) -> Result<String, StorageError> {
    if path.len() > limits.max_relative_path_bytes {
        return Err(StorageError::LimitExceeded {
            resource: "relative path bytes",
            limit: limits.max_relative_path_bytes as u64,
            actual: path.len() as u64,
        });
    }
    let normalized = normalize_relative_path(path)
        .map_err(|error| StorageError::UnsafePath(error.to_string()))?;
    let depth = normalized.split('/').count();
    if depth > limits.max_tree_depth {
        return Err(StorageError::LimitExceeded {
            resource: "tree depth",
            limit: limits.max_tree_depth as u64,
            actual: depth as u64,
        });
    }
    Ok(normalized)
}

pub(crate) fn parent_manifest_path(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

pub(crate) fn split_manifest_parent(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

pub(crate) fn path_from_manifest(path: &str) -> PathBuf {
    path.split('/').collect()
}
