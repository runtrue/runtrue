use crate::{
    git_object_size, parse_ls_tree_record, validate_object_id, validate_repo_path,
    validate_symlink_target, GitError, GitRepository, GitTreeEntry, GitTreeEntryKind,
    GitTreeManifest, LockedGitTreeManifest, LockedSubmoduleSources, GIT_TREE_MANIFEST_VERSION,
};
use runtrue_model::ContentDigest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSnapshotLimits {
    pub maximum_entries: usize,
    pub maximum_total_bytes: u64,
    pub maximum_symlink_bytes: usize,
}

impl Default for SourceSnapshotLimits {
    fn default() -> Self {
        Self {
            maximum_entries: 100_000,
            maximum_total_bytes: 8 * 1024 * 1024 * 1024,
            maximum_symlink_bytes: 4096,
        }
    }
}

/// Bounds for the opt-in locked-submodule graph. Keeping this separate leaves
/// the original source-manifest API and its public limit type unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockedSourceSnapshotLimits {
    pub source: SourceSnapshotLimits,
    pub maximum_submodule_depth: usize,
}

impl Default for LockedSourceSnapshotLimits {
    fn default() -> Self {
        Self {
            source: SourceSnapshotLimits::default(),
            maximum_submodule_depth: 8,
        }
    }
}

impl GitRepository {
    /// Walk an exact commit without creating a worktree and emit verified file
    /// bytes to a caller-owned CAS sink. Git hooks, remotes, and submodule
    /// network fallback are never involved.
    pub fn build_source_manifest<F>(
        &self,
        repository_id: &str,
        commit: &str,
        limits: SourceSnapshotLimits,
        mut store_blob: F,
    ) -> Result<GitTreeManifest, GitError>
    where
        F: FnMut(&ContentDigest, &[u8]) -> Result<(), GitError>,
    {
        if repository_id.is_empty()
            || repository_id.len() > 8 * 1024
            || limits.maximum_entries == 0
            || limits.maximum_total_bytes == 0
            || limits.maximum_symlink_bytes == 0
        {
            return Err(GitError::InvalidConfiguration);
        }
        let commit = self.verify_commit(commit)?;
        let output_limit = limits
            .maximum_entries
            .checked_mul(self.limits.max_path_bytes.saturating_add(160))
            .ok_or(GitError::InvalidConfiguration)?;
        let tree = self.run_git(&["ls-tree", "-r", "-t", "-z", &commit], output_limit)?;
        let mut entries = Vec::new();
        let mut total_bytes = 0_u64;
        for record in tree
            .stdout
            .split(|byte| *byte == 0)
            .filter(|row| !row.is_empty())
        {
            if entries.len() >= limits.maximum_entries {
                return Err(GitError::SourceSnapshotLimit {
                    kind: "entry count",
                    limit: limits.maximum_entries as u64,
                });
            }
            let (mode, object_kind, object_id, path) = parse_ls_tree_record(record)?;
            let path = validate_repo_path(path, self.limits)?;
            validate_object_id(object_id)?;
            let kind = match (mode, object_kind) {
                ("040000", "tree") => GitTreeEntryKind::Directory,
                ("100644" | "100755", "blob") => {
                    let size = git_object_size(self, object_id)?;
                    if size > self.limits.max_blob_bytes {
                        return Err(GitError::SourceSnapshotLimit {
                            kind: "blob bytes",
                            limit: self.limits.max_blob_bytes as u64,
                        });
                    }
                    let size_u64 =
                        u64::try_from(size).map_err(|_| GitError::InvalidGitOutput("blob size"))?;
                    total_bytes =
                        total_bytes
                            .checked_add(size_u64)
                            .ok_or(GitError::SourceSnapshotLimit {
                                kind: "total bytes",
                                limit: limits.maximum_total_bytes,
                            })?;
                    if total_bytes > limits.maximum_total_bytes {
                        return Err(GitError::SourceSnapshotLimit {
                            kind: "total bytes",
                            limit: limits.maximum_total_bytes,
                        });
                    }
                    let bytes = self
                        .run_git(&["cat-file", "blob", object_id], size.max(1))?
                        .stdout;
                    if bytes.len() != size {
                        return Err(GitError::InvalidGitOutput("blob size mismatch"));
                    }
                    let digest = ContentDigest::sha256(&bytes);
                    store_blob(&digest, &bytes)?;
                    GitTreeEntryKind::File {
                        digest,
                        size_bytes: size_u64,
                        executable: mode == "100755",
                    }
                }
                ("120000", "blob") => {
                    let size = git_object_size(self, object_id)?;
                    if size > limits.maximum_symlink_bytes {
                        return Err(GitError::SourceSnapshotLimit {
                            kind: "symlink bytes",
                            limit: limits.maximum_symlink_bytes as u64,
                        });
                    }
                    let bytes = self
                        .run_git(&["cat-file", "blob", object_id], size.max(1))?
                        .stdout;
                    let target = std::str::from_utf8(&bytes)
                        .map_err(|_| GitError::UnsafeSymlink(path.clone()))?;
                    validate_symlink_target(&path, target)?;
                    GitTreeEntryKind::Symlink {
                        target: target.to_owned(),
                    }
                }
                ("160000", "commit") => return Err(GitError::UnlockedSubmodule(path)),
                _ => {
                    return Err(GitError::UnsupportedTreeEntry {
                        path,
                        mode: mode.to_owned(),
                    })
                }
            };
            entries.push(GitTreeEntry { path, kind });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(GitTreeManifest {
            version: GIT_TREE_MANIFEST_VERSION,
            repository_id: repository_id.to_owned(),
            commit,
            entries,
        })
    }

    /// Build a source manifest from an exact root commit and an explicit tree
    /// of locked, caller-supplied local submodule repositories.
    pub fn build_source_manifest_with_locked_submodules<'repo, F>(
        &'repo self,
        repository_id: &str,
        commit: &str,
        limits: LockedSourceSnapshotLimits,
        submodules: &'repo LockedSubmoduleSources<'repo>,
        mut store_blob: F,
    ) -> Result<LockedGitTreeManifest, GitError>
    where
        F: FnMut(&ContentDigest, &[u8]) -> Result<(), GitError>,
    {
        if repository_id.is_empty()
            || repository_id.len() > 8 * 1024
            || limits.source.maximum_entries == 0
            || limits.source.maximum_total_bytes == 0
            || limits.source.maximum_symlink_bytes == 0
            || limits.maximum_submodule_depth == 0
        {
            return Err(GitError::InvalidConfiguration);
        }
        let commit = self.verify_commit(commit)?;
        let mut state = crate::LockedManifestBuildState::new(
            limits.source,
            limits.maximum_submodule_depth,
            self.limits.max_path_bytes,
        );
        state
            .active_local_repositories
            .insert(self.git_dir().to_path_buf());
        if let Ok(origin) = self.remote_origin_url() {
            state.active_origins.insert(origin);
        }
        crate::walk_locked_source_repository(
            self,
            &commit,
            "",
            &submodules.sources,
            0,
            &mut state,
        )?;
        state
            .entries
            .sort_by(|left, right| left.path.cmp(&right.path));
        if state
            .entries
            .windows(2)
            .any(|pair| pair[0].path == pair[1].path)
        {
            return Err(GitError::DuplicateSubmoduleMount(
                "source manifest path collision".to_owned(),
            ));
        }
        state
            .submodule_locks
            .sort_by(|left, right| left.path().cmp(right.path()));
        for pending in state.pending_blobs {
            let bytes = pending
                .repository
                .run_git(
                    &["cat-file", "blob", &pending.object_id],
                    pending.size.max(1),
                )?
                .stdout;
            if bytes.len() != pending.size || ContentDigest::sha256(&bytes) != pending.digest {
                return Err(GitError::SubmoduleObjectChanged(pending.path));
            }
            store_blob(&pending.digest, &bytes)?;
        }
        Ok(LockedGitTreeManifest {
            manifest: GitTreeManifest {
                version: GIT_TREE_MANIFEST_VERSION,
                repository_id: repository_id.to_owned(),
                commit,
                entries: state.entries,
            },
            submodule_locks: state.submodule_locks,
        })
    }
}
