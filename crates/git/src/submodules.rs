use crate::{
    git_object_size, parse_ls_tree_record, validate_object_id, validate_repo_path,
    validate_symlink_target, GitError, GitLimits, GitRepository, GitTreeEntry, GitTreeEntryKind,
    GitTreeManifest, NormalizedOrigin, OriginPolicy, SourceSnapshotLimits,
};
use runtrue_model::ContentDigest;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// One exact, trusted submodule identity supplied by the source-planning
/// boundary. This type never resolves a URL and never opens a repository.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitSubmoduleLock {
    path: String,
    origin: NormalizedOrigin,
    commit: String,
}

impl GitSubmoduleLock {
    pub fn new(
        path: impl Into<String>,
        origin: NormalizedOrigin,
        commit: impl Into<String>,
    ) -> Result<Self, GitError> {
        let path = path.into();
        let commit = commit.into();
        validate_repo_path(&path, GitLimits::default())?;
        validate_normalized_origin(&origin)?;
        validate_object_id(&commit)?;
        Ok(Self {
            path,
            origin,
            commit,
        })
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn origin(&self) -> &NormalizedOrigin {
        &self.origin
    }

    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }
}

/// A lock paired with an already-open local Git object database. The caller is
/// responsible for obtaining this repository through an authenticated SCM
/// path; snapshot construction performs no fetch and has no fallback.
#[derive(Debug)]
pub struct LockedSubmoduleSource<'repo> {
    lock: GitSubmoduleLock,
    repository: &'repo GitRepository,
    submodules: Vec<LockedSubmoduleSource<'repo>>,
}

impl<'repo> LockedSubmoduleSource<'repo> {
    pub fn new(
        lock: GitSubmoduleLock,
        repository: &'repo GitRepository,
        mut submodules: Vec<LockedSubmoduleSource<'repo>>,
    ) -> Result<Self, GitError> {
        sort_and_validate_submodule_sources(&mut submodules)?;
        Ok(Self {
            lock,
            repository,
            submodules,
        })
    }

    #[must_use]
    pub fn lock(&self) -> &GitSubmoduleLock {
        &self.lock
    }
}

/// Canonically sorted top-level locked submodule sources.
#[derive(Debug)]
pub struct LockedSubmoduleSources<'repo> {
    pub(crate) sources: Vec<LockedSubmoduleSource<'repo>>,
}

impl<'repo> LockedSubmoduleSources<'repo> {
    pub fn new(mut sources: Vec<LockedSubmoduleSource<'repo>>) -> Result<Self, GitError> {
        sort_and_validate_submodule_sources(&mut sources)?;
        Ok(Self { sources })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

/// Existing source-manifest bytes plus the exact sorted lock identities used
/// to admit nested repositories. The lock digest must be bound by planning and
/// approval in addition to the ordinary tree-manifest digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedGitTreeManifest {
    pub(crate) manifest: GitTreeManifest,
    pub(crate) submodule_locks: Vec<GitSubmoduleLock>,
}

impl LockedGitTreeManifest {
    #[must_use]
    pub fn manifest(&self) -> &GitTreeManifest {
        &self.manifest
    }

    #[must_use]
    pub fn submodule_locks(&self) -> &[GitSubmoduleLock] {
        &self.submodule_locks
    }

    pub fn submodule_lock_digest(&self) -> Result<ContentDigest, GitError> {
        #[derive(Serialize)]
        struct CanonicalLocks<'a> {
            domain: &'static str,
            version: u32,
            locks: &'a [GitSubmoduleLock],
        }
        let bytes = serde_json::to_vec(&CanonicalLocks {
            domain: "runtrue.git.submodule-locks",
            version: 1,
            locks: &self.submodule_locks,
        })
        .map_err(|_| GitError::InvalidGitOutput("submodule lock manifest"))?;
        Ok(ContentDigest::sha256(bytes))
    }

    #[must_use]
    pub fn into_manifest(self) -> GitTreeManifest {
        self.manifest
    }
}

pub(crate) fn sort_and_validate_submodule_sources(
    sources: &mut [LockedSubmoduleSource<'_>],
) -> Result<(), GitError> {
    for source in sources.iter() {
        validate_repo_path(source.lock.path(), GitLimits::default())?;
        validate_normalized_origin(source.lock.origin())?;
        validate_object_id(source.lock.commit())?;
    }
    sources.sort_by(|left, right| left.lock.path.cmp(&right.lock.path));
    if let Some(duplicate) = sources
        .windows(2)
        .find(|pair| pair[0].lock.path == pair[1].lock.path)
    {
        return Err(GitError::DuplicateSubmoduleMount(
            duplicate[0].lock.path.clone(),
        ));
    }
    Ok(())
}

fn validate_normalized_origin(origin: &NormalizedOrigin) -> Result<(), GitError> {
    let mut policy = OriginPolicy::new([origin.host().to_owned()])?;
    if origin.port() != 443 {
        policy.allow_nonstandard_port(origin.host().to_owned(), origin.port())?;
    }
    if policy.normalize(origin.as_str())? != *origin {
        return Err(GitError::UnsafeOrigin);
    }
    Ok(())
}

pub(crate) struct PendingSourceBlob<'repo> {
    pub(crate) repository: &'repo GitRepository,
    pub(crate) object_id: String,
    pub(crate) path: String,
    pub(crate) digest: ContentDigest,
    pub(crate) size: usize,
}

pub(crate) struct LockedManifestBuildState<'repo> {
    pub(crate) limits: SourceSnapshotLimits,
    pub(crate) maximum_submodule_depth: usize,
    pub(crate) maximum_path_bytes: usize,
    pub(crate) total_bytes: u64,
    pub(crate) entries: Vec<GitTreeEntry>,
    pub(crate) pending_blobs: Vec<PendingSourceBlob<'repo>>,
    pub(crate) submodule_locks: Vec<GitSubmoduleLock>,
    pub(crate) active_local_repositories: BTreeSet<PathBuf>,
    pub(crate) active_origins: BTreeSet<String>,
}

impl<'repo> LockedManifestBuildState<'repo> {
    pub(crate) fn new(
        limits: SourceSnapshotLimits,
        maximum_submodule_depth: usize,
        maximum_path_bytes: usize,
    ) -> Self {
        Self {
            limits,
            maximum_submodule_depth,
            maximum_path_bytes,
            total_bytes: 0,
            entries: Vec::new(),
            pending_blobs: Vec::new(),
            submodule_locks: Vec::new(),
            active_local_repositories: BTreeSet::new(),
            active_origins: BTreeSet::new(),
        }
    }

    fn add_bytes(&mut self, bytes: usize) -> Result<u64, GitError> {
        let bytes = u64::try_from(bytes).map_err(|_| GitError::InvalidGitOutput("blob size"))?;
        self.total_bytes =
            self.total_bytes
                .checked_add(bytes)
                .ok_or(GitError::SourceSnapshotLimit {
                    kind: "total bytes",
                    limit: self.limits.maximum_total_bytes,
                })?;
        if self.total_bytes > self.limits.maximum_total_bytes {
            return Err(GitError::SourceSnapshotLimit {
                kind: "total bytes",
                limit: self.limits.maximum_total_bytes,
            });
        }
        Ok(bytes)
    }

    fn push_entry(&mut self, entry: GitTreeEntry) -> Result<(), GitError> {
        if self.entries.len() >= self.limits.maximum_entries {
            return Err(GitError::SourceSnapshotLimit {
                kind: "entry count",
                limit: self.limits.maximum_entries as u64,
            });
        }
        self.entries.push(entry);
        Ok(())
    }
}

#[derive(Debug)]
struct GitSubmoduleDeclaration {
    origin: String,
}

pub(crate) fn walk_locked_source_repository<'repo>(
    repository: &'repo GitRepository,
    commit: &str,
    prefix: &str,
    submodules: &'repo [LockedSubmoduleSource<'repo>],
    depth: usize,
    state: &mut LockedManifestBuildState<'repo>,
) -> Result<(), GitError> {
    for source in submodules {
        validate_repo_path(source.lock.path(), repository.limits)?;
        validate_normalized_origin(source.lock.origin())?;
        validate_object_id(source.lock.commit())?;
    }
    let output_limit = state
        .limits
        .maximum_entries
        .checked_mul(repository.limits.max_path_bytes.saturating_add(160))
        .ok_or(GitError::InvalidConfiguration)?;
    let tree = repository.run_git(&["ls-tree", "-r", "-t", "-z", commit], output_limit)?;
    let records = tree
        .stdout
        .split(|byte| *byte == 0)
        .filter(|row| !row.is_empty())
        .collect::<Vec<_>>();
    let has_gitmodules = records.iter().any(|record| {
        matches!(
            parse_ls_tree_record(record),
            Ok(("100644" | "100755", "blob", _, ".gitmodules"))
        )
    });
    let has_gitlinks = records
        .iter()
        .any(|record| matches!(parse_ls_tree_record(record), Ok(("160000", "commit", _, _))));
    let declarations = if has_gitmodules {
        load_git_submodule_declarations(repository, commit, state.limits.maximum_entries)?
    } else {
        BTreeMap::new()
    };
    if has_gitlinks && !has_gitmodules {
        return Err(GitError::MissingSubmoduleDeclaration(prefix.to_owned()));
    }
    let mut used_locks = BTreeSet::new();
    let mut used_declarations = BTreeSet::new();
    for record in records {
        let (mode, object_kind, object_id, local_path) = parse_ls_tree_record(record)?;
        let local_path = validate_repo_path(local_path, repository.limits)?;
        validate_object_id(object_id)?;
        let path = prefixed_source_path(prefix, &local_path, state.maximum_path_bytes)?;
        match (mode, object_kind) {
            ("040000", "tree") => state.push_entry(GitTreeEntry {
                path,
                kind: GitTreeEntryKind::Directory,
            })?,
            ("100644" | "100755", "blob") => {
                let size = git_object_size(repository, object_id)?;
                if size > repository.limits.max_blob_bytes {
                    return Err(GitError::SourceSnapshotLimit {
                        kind: "blob bytes",
                        limit: repository.limits.max_blob_bytes as u64,
                    });
                }
                let size_u64 = state.add_bytes(size)?;
                let bytes = repository
                    .run_git(&["cat-file", "blob", object_id], size.max(1))?
                    .stdout;
                if bytes.len() != size {
                    return Err(GitError::InvalidGitOutput("blob size mismatch"));
                }
                let digest = ContentDigest::sha256(&bytes);
                state.pending_blobs.push(PendingSourceBlob {
                    repository,
                    object_id: object_id.to_owned(),
                    path: path.clone(),
                    digest: digest.clone(),
                    size,
                });
                state.push_entry(GitTreeEntry {
                    path,
                    kind: GitTreeEntryKind::File {
                        digest,
                        size_bytes: size_u64,
                        executable: mode == "100755",
                    },
                })?;
            }
            ("120000", "blob") => {
                let size = git_object_size(repository, object_id)?;
                if size > state.limits.maximum_symlink_bytes {
                    return Err(GitError::SourceSnapshotLimit {
                        kind: "symlink bytes",
                        limit: state.limits.maximum_symlink_bytes as u64,
                    });
                }
                state.add_bytes(size)?;
                let bytes = repository
                    .run_git(&["cat-file", "blob", object_id], size.max(1))?
                    .stdout;
                if bytes.len() != size {
                    return Err(GitError::InvalidGitOutput("symlink size mismatch"));
                }
                let target = std::str::from_utf8(&bytes)
                    .map_err(|_| GitError::UnsafeSymlink(path.clone()))?;
                validate_symlink_target(&local_path, target)?;
                state.push_entry(GitTreeEntry {
                    path,
                    kind: GitTreeEntryKind::Symlink {
                        target: target.to_owned(),
                    },
                })?;
            }
            ("160000", "commit") => {
                let source = submodules
                    .binary_search_by(|source| source.lock.path.as_str().cmp(local_path.as_str()))
                    .ok()
                    .map(|index| &submodules[index])
                    .ok_or_else(|| GitError::UnlockedSubmodule(path.clone()))?;
                used_locks.insert(local_path.clone());
                if source.lock.commit != object_id {
                    return Err(GitError::SubmoduleCommitMismatch(path));
                }
                let declaration = declarations
                    .get(&local_path)
                    .ok_or_else(|| GitError::MissingSubmoduleDeclaration(path.clone()))?;
                used_declarations.insert(local_path);
                if declaration.origin != source.lock.origin.as_str() {
                    return Err(GitError::SubmoduleOriginMismatch(path));
                }
                let supplied_origin = source
                    .repository
                    .remote_origin_url()
                    .map_err(|_| GitError::SubmoduleOriginMismatch(path.clone()))?;
                if supplied_origin != source.lock.origin.as_str() {
                    return Err(GitError::SubmoduleOriginMismatch(path));
                }
                let nested_commit = source
                    .repository
                    .verify_commit(&source.lock.commit)
                    .map_err(|_| GitError::SubmoduleObjectUnavailable(path.clone()))?;
                if nested_commit != source.lock.commit {
                    return Err(GitError::SubmoduleCommitMismatch(path));
                }
                let nested_depth = depth.saturating_add(1);
                if nested_depth > state.maximum_submodule_depth {
                    return Err(GitError::SourceSnapshotLimit {
                        kind: "submodule depth",
                        limit: state.maximum_submodule_depth as u64,
                    });
                }
                if state
                    .active_local_repositories
                    .contains(source.repository.git_dir())
                    || state.active_origins.contains(source.lock.origin.as_str())
                {
                    return Err(GitError::SubmoduleCycle(path));
                }
                state.push_entry(GitTreeEntry {
                    path: path.clone(),
                    kind: GitTreeEntryKind::Directory,
                })?;
                state.submodule_locks.push(GitSubmoduleLock {
                    path: path.clone(),
                    origin: source.lock.origin.clone(),
                    commit: source.lock.commit.clone(),
                });
                state
                    .active_local_repositories
                    .insert(source.repository.git_dir().to_path_buf());
                state
                    .active_origins
                    .insert(source.lock.origin.as_str().to_owned());
                walk_locked_source_repository(
                    source.repository,
                    &nested_commit,
                    &path,
                    &source.submodules,
                    nested_depth,
                    state,
                )?;
                state
                    .active_local_repositories
                    .remove(source.repository.git_dir());
                state.active_origins.remove(source.lock.origin.as_str());
            }
            _ => {
                return Err(GitError::UnsupportedTreeEntry {
                    path,
                    mode: mode.to_owned(),
                })
            }
        }
    }
    if let Some(unused) = submodules
        .iter()
        .find(|source| !used_locks.contains(source.lock.path()))
    {
        return Err(GitError::UnusedSubmoduleLock(prefixed_source_path(
            prefix,
            unused.lock.path(),
            state.maximum_path_bytes,
        )?));
    }
    if let Some(unused) = declarations
        .keys()
        .find(|path| !used_declarations.contains(*path))
    {
        return Err(GitError::UnusedSubmoduleDeclaration(prefixed_source_path(
            prefix,
            unused,
            state.maximum_path_bytes,
        )?));
    }
    Ok(())
}

fn prefixed_source_path(
    prefix: &str,
    local_path: &str,
    maximum_path_bytes: usize,
) -> Result<String, GitError> {
    let path = if prefix.is_empty() {
        local_path.to_owned()
    } else {
        format!("{prefix}/{local_path}")
    };
    validate_repo_path(
        &path,
        GitLimits {
            max_path_bytes: maximum_path_bytes,
            ..GitLimits::default()
        },
    )
}

fn load_git_submodule_declarations(
    repository: &GitRepository,
    commit: &str,
    maximum_entries: usize,
) -> Result<BTreeMap<String, GitSubmoduleDeclaration>, GitError> {
    let expression = format!("{commit}:.gitmodules");
    let output_limit = repository.limits.max_blob_bytes.saturating_add(64 * 1024);
    let output = match repository.run_git(
        &[
            "config",
            "--blob",
            &expression,
            "-z",
            "--get-regexp",
            "^submodule\\..*\\.(path|url)$",
        ],
        output_limit,
    ) {
        Ok(output) => output,
        Err(GitError::CommandFailed {
            exit_code: Some(1), ..
        }) => return Ok(BTreeMap::new()),
        Err(_) => return Err(GitError::InvalidSubmoduleDeclaration),
    };
    let mut by_name = BTreeMap::<String, (Option<String>, Option<String>)>::new();
    for record in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let record =
            std::str::from_utf8(record).map_err(|_| GitError::InvalidSubmoduleDeclaration)?;
        let (key, value) = record
            .split_once('\n')
            .ok_or(GitError::InvalidSubmoduleDeclaration)?;
        if value.is_empty()
            || value.len() > 4_096
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(GitError::InvalidSubmoduleDeclaration);
        }
        let key = key
            .strip_prefix("submodule.")
            .ok_or(GitError::InvalidSubmoduleDeclaration)?;
        let (name, is_path) = if let Some(name) = key.strip_suffix(".path") {
            (name, true)
        } else if let Some(name) = key.strip_suffix(".url") {
            (name, false)
        } else {
            return Err(GitError::InvalidSubmoduleDeclaration);
        };
        if name.is_empty() || name.len() > 1_024 || name.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(GitError::InvalidSubmoduleDeclaration);
        }
        let fields = by_name.entry(name.to_owned()).or_default();
        let slot = if is_path {
            &mut fields.0
        } else {
            &mut fields.1
        };
        if slot.replace(value.to_owned()).is_some() {
            return Err(GitError::InvalidSubmoduleDeclaration);
        }
    }
    if by_name.len() > maximum_entries {
        return Err(GitError::SourceSnapshotLimit {
            kind: "entry count",
            limit: maximum_entries as u64,
        });
    }
    let mut by_path = BTreeMap::new();
    for (path, origin) in by_name.into_values() {
        let path = path.ok_or(GitError::InvalidSubmoduleDeclaration)?;
        let origin = origin.ok_or(GitError::InvalidSubmoduleDeclaration)?;
        let path = validate_repo_path(&path, repository.limits)?;
        if by_path
            .insert(path, GitSubmoduleDeclaration { origin })
            .is_some()
        {
            return Err(GitError::InvalidSubmoduleDeclaration);
        }
    }
    Ok(by_path)
}
