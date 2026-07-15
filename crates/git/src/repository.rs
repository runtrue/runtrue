use crate::{
    find_git, open_null_directory_placeholder, open_real_directory, parse_changed_paths,
    parse_ls_tree, parse_ls_tree_record, parse_one_line, validate_object_id, validate_repo_path,
    GitBlob, GitError, GitLimits, TrustedWorkflowSources,
};
use runtrue_model::ContentDigest;
use std::{
    fmt,
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
pub struct GitRepository {
    root: PathBuf,
    git_dir: PathBuf,
    kind: GitRepositoryKind,
    // Retaining descriptors makes later path identity checks independent of
    // caller-controlled renames and gives mirror/hydration code a safe anchor.
    _root_fd: Arc<File>,
    git_dir_fd: Arc<File>,
    pub(crate) git_program: PathBuf,
    pub(crate) limits: GitLimits,
}

impl fmt::Debug for GitRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitRepository")
            .field("root", &self.root)
            .field("git_dir", &self.git_dir)
            .field("kind", &self.kind)
            .field("git_program", &self.git_program)
            .field("limits", &self.limits)
            .finish()
    }
}

impl GitRepository {
    pub fn open(root: impl AsRef<Path>, limits: GitLimits) -> Result<Self, GitError> {
        let limits = limits.validate()?;
        let requested = root.as_ref();
        let (root, root_fd) = open_real_directory(requested)?;
        let git_program = find_git()?;
        let mut repository = Self {
            root,
            git_dir: PathBuf::new(),
            kind: GitRepositoryKind::Worktree,
            _root_fd: Arc::new(root_fd),
            // Replaced only after Git proves the exact repository layout.
            git_dir_fd: Arc::new(open_null_directory_placeholder()?),
            git_program,
            limits,
        };
        let bare = repository.run_git(&["rev-parse", "--is-bare-repository"], 1024)?;
        let bare = parse_one_line(&bare.stdout, "bare repository flag")?;
        repository.kind = match bare {
            "true" => GitRepositoryKind::Bare,
            "false" => GitRepositoryKind::Worktree,
            _ => return Err(GitError::InvalidGitOutput("bare repository flag")),
        };
        let git_dir = repository.run_git(&["rev-parse", "--absolute-git-dir"], 16 * 1024)?;
        let git_dir = parse_one_line(&git_dir.stdout, "absolute Git directory")?;
        let (git_dir, git_dir_fd) = open_real_directory(Path::new(git_dir))?;
        repository.git_dir = git_dir;
        repository.git_dir_fd = Arc::new(git_dir_fd);
        match repository.kind {
            GitRepositoryKind::Bare if repository.git_dir != repository.root => {
                return Err(GitError::RepositoryRootMismatch {
                    expected: repository.root.clone(),
                    actual: repository.git_dir.clone(),
                });
            }
            GitRepositoryKind::Worktree => {
                let result = repository.run_git(&["rev-parse", "--show-toplevel"], 16 * 1024)?;
                let reported = parse_one_line(&result.stdout, "repository root")?;
                let (reported, _) = open_real_directory(Path::new(reported))?;
                if reported != repository.root {
                    return Err(GitError::RepositoryRootMismatch {
                        expected: repository.root.clone(),
                        actual: reported,
                    });
                }
            }
            GitRepositoryKind::Bare => {}
        }
        Ok(repository)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    #[must_use]
    pub const fn kind(&self) -> GitRepositoryKind {
        self.kind
    }

    /// Verify that an exact full object ID names a commit and return Git's
    /// canonical object ID (SHA-1 or SHA-256 repository format).
    pub fn verify_commit(&self, commit: &str) -> Result<String, GitError> {
        validate_object_id(commit)?;
        let expression = format!("{commit}^{{commit}}");
        let result = self.run_git(
            &["rev-parse", "--verify", "--end-of-options", &expression],
            1024,
        )?;
        let resolved = parse_one_line(&result.stdout, "commit object id")?;
        validate_object_id(resolved)?;
        Ok(resolved.to_owned())
    }

    /// Read one regular blob without checking out or executing repository data.
    pub fn read_blob(&self, commit: &str, path: &str) -> Result<GitBlob, GitError> {
        let commit = self.verify_commit(commit)?;
        let path = validate_repo_path(path, self.limits)?;
        let tree = self.run_git(
            &["ls-tree", "-z", &commit, "--", path.as_str()],
            self.limits.max_path_bytes.saturating_add(256),
        )?;
        if tree.stdout.is_empty() {
            return Err(GitError::PathNotFound);
        }
        let (mode, object_kind, object_id, listed_path) = parse_ls_tree(&tree.stdout)?;
        if listed_path != path {
            return Err(GitError::PathMismatch);
        }
        if object_kind != "blob" || !matches!(mode, "100644" | "100755") {
            return Err(GitError::UnsupportedBlobMode(mode.to_owned()));
        }
        validate_object_id(object_id)?;
        let size_result = self.run_git(&["cat-file", "-s", object_id], 1024)?;
        let size = parse_one_line(&size_result.stdout, "blob size")?
            .parse::<usize>()
            .map_err(|_| GitError::InvalidGitOutput("blob size"))?;
        if size > self.limits.max_blob_bytes {
            return Err(GitError::OutputLimit {
                kind: "blob bytes",
                limit: self.limits.max_blob_bytes,
            });
        }
        let contents = self
            .run_git(&["cat-file", "blob", object_id], size.max(1))?
            .stdout;
        if contents.len() != size {
            return Err(GitError::InvalidGitOutput("blob size mismatch"));
        }
        Ok(GitBlob {
            commit,
            path,
            executable: mode == "100755",
            digest: ContentDigest::sha256(&contents),
            bytes: contents,
        })
    }

    pub fn changed_paths(&self, base: &str, source: &str) -> Result<Vec<String>, GitError> {
        let base = self.verify_commit(base)?;
        let source = self.verify_commit(source)?;
        let result = self.run_git(
            &[
                "diff",
                "--no-ext-diff",
                "--no-renames",
                "--name-only",
                "-z",
                "--diff-filter=ACDMRTUXB",
                &base,
                &source,
                "--",
            ],
            self.limits.max_diff_bytes,
        )?;
        parse_changed_paths(&result.stdout, self.limits)
    }

    /// List bounded regular files below one repository-relative directory at
    /// an exact commit. Tree objects, symlinks, submodules, and unusual blob
    /// modes are ignored; malformed or oversized Git output fails closed.
    pub fn regular_files_under(
        &self,
        commit: &str,
        directory: &str,
        max_files: usize,
    ) -> Result<Vec<String>, GitError> {
        if max_files == 0 {
            return Err(GitError::InvalidConfiguration);
        }
        let commit = self.verify_commit(commit)?;
        let directory = validate_repo_path(directory, self.limits)?;
        let output_limit = max_files
            .saturating_add(1)
            .saturating_mul(self.limits.max_path_bytes.saturating_add(128));
        let tree = self.run_git(
            &[
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                &commit,
                "--",
                directory.as_str(),
            ],
            output_limit,
        )?;
        if tree.stdout.last().is_some_and(|byte| *byte != 0) {
            return Err(GitError::InvalidGitOutput("tree entry terminator"));
        }
        let mut files = std::collections::BTreeSet::new();
        for record in tree
            .stdout
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
        {
            let (mode, kind, object_id, path) = parse_ls_tree_record(record)?;
            validate_object_id(object_id)?;
            let path = validate_repo_path(path, self.limits)?;
            if kind == "blob" && matches!(mode, "100644" | "100755") {
                if files.len() >= max_files {
                    return Err(GitError::OutputLimit {
                        kind: "regular file count",
                        limit: max_files,
                    });
                }
                files.insert(path);
            }
        }
        Ok(files.into_iter().collect())
    }

    /// Return the one exact repository-local `remote.origin.url`. This reads
    /// configuration only; it never contacts the remote. Missing, repeated,
    /// non-UTF-8, multiline, or control-bearing values fail closed.
    pub fn remote_origin_url(&self) -> Result<String, GitError> {
        let result = self.run_git(
            &[
                "config",
                "--local",
                "--no-includes",
                "--get-all",
                "remote.origin.url",
            ],
            16 * 1024,
        )?;
        let text = std::str::from_utf8(&result.stdout)
            .map_err(|_| GitError::InvalidGitOutput("remote origin UTF-8"))?;
        let value = text
            .strip_suffix('\n')
            .ok_or(GitError::InvalidGitOutput("remote origin terminator"))?;
        if value.is_empty()
            || value.contains(['\n', '\r', '\0'])
            || value.chars().any(char::is_whitespace)
        {
            return Err(GitError::InvalidGitOutput("remote origin value"));
        }
        Ok(value.to_owned())
    }

    /// Load the base workflow for execution. Proposed workflow bytes are
    /// returned only when that exact path changed and only through the
    /// explicitly named risk-analysis accessor.
    pub fn trusted_workflow_sources(
        &self,
        base_commit: &str,
        source_commit: &str,
        workflow_path: &str,
    ) -> Result<TrustedWorkflowSources, GitError> {
        let workflow_path = validate_repo_path(workflow_path, self.limits)?;
        let base_commit = self.verify_commit(base_commit)?;
        let source_commit = self.verify_commit(source_commit)?;
        let execution = self.read_blob(&base_commit, &workflow_path)?;
        let changed = self
            .changed_paths(&base_commit, &source_commit)?
            .binary_search(&workflow_path)
            .is_ok();
        let proposed_for_risk = if changed {
            match self.read_blob(&source_commit, &workflow_path) {
                Ok(blob) => Some(blob),
                Err(GitError::PathNotFound) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        Ok(TrustedWorkflowSources {
            execution,
            proposed_for_risk,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitRepositoryKind {
    Worktree,
    Bare,
}
