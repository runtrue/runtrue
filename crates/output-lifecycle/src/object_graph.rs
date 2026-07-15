use crate::{LifecycleError, LifecycleLimits};
use runtrue_artifacts::{verify_immutable_artifact_record, ArtifactLimits};
use runtrue_cache::CacheManifest;
use runtrue_control_plane::LifecycleGcRoot;
use runtrue_git::{GitTreeEntryKind, GitTreeManifest, GIT_TREE_MANIFEST_VERSION};
use runtrue_model::ContentDigest;
use runtrue_storage::{FsCas, PathSnapshot, TreeEntryKind, TreeManifest};
use std::collections::BTreeSet;

/// Expand every typed authoritative root and verify the digest and size of
/// every reachable CAS object. Backup/restore activation uses this stricter
/// form; unlike GC marking it rejects an expected-but-not-yet-uploaded root.
pub fn verify_authoritative_object_graph(
    cas: &FsCas,
    roots: &[LifecycleGcRoot],
    limits: LifecycleLimits,
) -> Result<Vec<LifecycleGcRoot>, LifecycleError> {
    let graph = ObjectGraph::new(cas, limits.validate()?);
    let expanded = graph.expand_roots(roots)?;
    for object in &expanded {
        cas.verify_blob(&object.digest)?;
    }
    Ok(expanded)
}

pub(crate) struct ObjectGraph<'a> {
    cas: &'a FsCas,
    limits: LifecycleLimits,
}

impl<'a> ObjectGraph<'a> {
    pub(crate) const fn new(cas: &'a FsCas, limits: LifecycleLimits) -> Self {
        Self { cas, limits }
    }

    pub(crate) fn expand_roots(
        &self,
        roots: &[LifecycleGcRoot],
    ) -> Result<Vec<LifecycleGcRoot>, LifecycleError> {
        let mut output = BTreeSet::new();
        for root in roots {
            self.insert(&mut output, root.clone())?;
            match root.root_kind.as_str() {
                "cache-manifest" => self.expand_cache_manifest(root, &mut output)?,
                "cache-tree" | "cache-promotion-source" => {
                    self.expand_tree_manifest(root, &mut output)?;
                }
                "artifact-record"
                | "artifact-pending-commit"
                | "artifact-promotion-source"
                | "artifact-promoted-record" => {
                    self.expand_artifact_manifest(root, &mut output)?;
                }
                "source-snapshot" => self.expand_source_manifest(root, &mut output)?,
                _ => {}
            }
        }
        Ok(output.into_iter().collect())
    }

    fn expand_cache_manifest(
        &self,
        root: &LifecycleGcRoot,
        output: &mut BTreeSet<LifecycleGcRoot>,
    ) -> Result<(), LifecycleError> {
        let manifest: CacheManifest = self.decode(&root.digest)?;
        if manifest.version != 1 {
            return Err(LifecycleError::UnsupportedManifestVersion {
                kind: "cache",
                version: manifest.version,
            });
        }
        let tree = LifecycleGcRoot {
            digest: manifest.tree.manifest_digest,
            root_kind: "cache-tree".to_owned(),
            root_id: root.root_id.clone(),
        };
        self.insert(output, tree.clone())?;
        self.expand_tree_manifest(&tree, output)?;
        if let Some(promotion) = manifest.promotion {
            self.insert(
                output,
                LifecycleGcRoot {
                    digest: promotion.source_manifest_digest,
                    root_kind: "cache-promotion-ancestry".to_owned(),
                    root_id: root.root_id.clone(),
                },
            )?;
            self.insert(
                output,
                LifecycleGcRoot {
                    digest: promotion.evidence.evidence_digest,
                    root_kind: "cache-promotion-evidence".to_owned(),
                    root_id: root.root_id.clone(),
                },
            )?;
        }
        Ok(())
    }

    fn expand_artifact_manifest(
        &self,
        root: &LifecycleGcRoot,
        output: &mut BTreeSet<LifecycleGcRoot>,
    ) -> Result<(), LifecycleError> {
        let artifact =
            verify_immutable_artifact_record(self.cas, &root.digest, ArtifactLimits::default())?
                .record;
        match artifact.content {
            PathSnapshot::File { digest, .. } => self.insert(
                output,
                LifecycleGcRoot {
                    digest,
                    root_kind: "artifact-file".to_owned(),
                    root_id: root.root_id.clone(),
                },
            )?,
            PathSnapshot::Directory {
                manifest_digest, ..
            } => {
                let tree = LifecycleGcRoot {
                    digest: manifest_digest,
                    root_kind: "artifact-tree".to_owned(),
                    root_id: root.root_id.clone(),
                };
                self.insert(output, tree.clone())?;
                self.expand_tree_manifest(&tree, output)?;
            }
        }
        if let Some(promotion) = artifact.promotion {
            self.insert(
                output,
                LifecycleGcRoot {
                    digest: promotion.source_record_digest,
                    root_kind: "artifact-promotion-ancestry".to_owned(),
                    root_id: root.root_id.clone(),
                },
            )?;
            self.insert(
                output,
                LifecycleGcRoot {
                    digest: promotion.evidence.evidence_digest,
                    root_kind: "artifact-promotion-evidence".to_owned(),
                    root_id: root.root_id.clone(),
                },
            )?;
        }
        Ok(())
    }

    fn expand_tree_manifest(
        &self,
        root: &LifecycleGcRoot,
        output: &mut BTreeSet<LifecycleGcRoot>,
    ) -> Result<(), LifecycleError> {
        let manifest: TreeManifest = self.cas.load_tree_manifest(&root.digest)?;
        for entry in manifest.entries {
            if let TreeEntryKind::File {
                digest, size_bytes, ..
            } = entry.kind
            {
                let actual = self.cas.verify_blob(&digest)?;
                if actual != size_bytes {
                    return Err(LifecycleError::ObjectSizeMismatch {
                        digest,
                        expected: size_bytes,
                        actual,
                    });
                }
                self.insert(
                    output,
                    LifecycleGcRoot {
                        digest,
                        root_kind: "tree-file".to_owned(),
                        root_id: root.root_id.clone(),
                    },
                )?;
            }
        }
        Ok(())
    }

    fn expand_source_manifest(
        &self,
        root: &LifecycleGcRoot,
        output: &mut BTreeSet<LifecycleGcRoot>,
    ) -> Result<(), LifecycleError> {
        let manifest: GitTreeManifest = self.decode(&root.digest)?;
        if manifest.version != GIT_TREE_MANIFEST_VERSION {
            return Err(LifecycleError::UnsupportedManifestVersion {
                kind: "source",
                version: manifest.version,
            });
        }
        for entry in manifest.entries {
            if let GitTreeEntryKind::File {
                digest, size_bytes, ..
            } = entry.kind
            {
                let actual = self.cas.verify_blob(&digest)?;
                if actual != size_bytes {
                    return Err(LifecycleError::ObjectSizeMismatch {
                        digest,
                        expected: size_bytes,
                        actual,
                    });
                }
                self.insert(
                    output,
                    LifecycleGcRoot {
                        digest,
                        root_kind: "source-file".to_owned(),
                        root_id: root.root_id.clone(),
                    },
                )?;
            }
        }
        Ok(())
    }

    fn decode<T: serde::de::DeserializeOwned>(
        &self,
        digest: &ContentDigest,
    ) -> Result<T, LifecycleError> {
        let bytes = self
            .cas
            .read_blob_limited(digest, self.limits.maximum_manifest_bytes)?;
        serde_json::from_slice(&bytes).map_err(LifecycleError::DecodeManifest)
    }

    fn insert(
        &self,
        output: &mut BTreeSet<LifecycleGcRoot>,
        root: LifecycleGcRoot,
    ) -> Result<(), LifecycleError> {
        output.insert(root);
        if output.len() > self.limits.maximum_reachable_objects {
            return Err(LifecycleError::ReachableObjectLimit);
        }
        Ok(())
    }
}
