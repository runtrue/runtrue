use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("invalid Git limits")]
    InvalidConfiguration,
    #[error("invalid Git origin policy")]
    InvalidOriginPolicy,
    #[error("unsafe Git origin")]
    UnsafeOrigin,
    #[error("Git origin host `{0}` is not allowlisted")]
    OriginHostDenied(String),
    #[error("Git origin port `{0}` is not administratively allowlisted")]
    OriginPortDenied(u16),
    #[error("Git origin IP literals are denied")]
    OriginIpLiteralDenied,
    #[error("Git origin DNS resolution was empty, timed out, or included a non-public address")]
    UnsafeOriginResolution,
    #[error("installed Git does not expose libcurl DNS pinning support")]
    GitResolvePinningUnavailable,
    #[error("invalid repository mirror identity")]
    InvalidRepositoryIdentity,
    #[error("invalid or expired repository credential")]
    InvalidCredential,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("Git executable is unavailable on PATH")]
    GitUnavailable,
    #[error("unsafe Git repository root `{0}`")]
    UnsafeRepositoryRoot(PathBuf),
    #[error("repository root mismatch: expected `{expected}`, Git reported `{actual}`")]
    RepositoryRootMismatch { expected: PathBuf, actual: PathBuf },
    #[error("filesystem error at `{0}`: {1}")]
    Filesystem(PathBuf, io::Error),
    #[error("secure filesystem operation failed: {0}")]
    SecureFilesystem(String),
    #[error("unsafe mirror entry `{0}`")]
    UnsafeMirrorEntry(PathBuf),
    #[error("mirror writer lock failed: {0}")]
    WriterLock(String),
    #[error("mirror identity metadata changed")]
    MirrorIdentityChanged,
    #[error("mirror origin changed")]
    MirrorOriginChanged,
    #[error("mirror is corrupt: {0}")]
    MirrorCorrupt(String),
    #[error("mirror {kind} exceeds limit {limit}")]
    MirrorLimit { kind: &'static str, limit: u64 },
    #[error("unsafe hydration destination `{0}`")]
    UnsafeHydrationDestination(PathBuf),
    #[error("hydrated workspace does not match its exact mirror and commit")]
    HydrationMismatch,
    #[error("hydrated workspace entry remains writable: `{0}`")]
    WritableHydrationEntry(PathBuf),
    #[error("hydrated object is still linked to another inode: `{0}`")]
    SharedHydrationObject(PathBuf),
    #[error("repository credential appeared in Git process output")]
    CredentialLeakDetected,
    #[error("Git process could not start: {0}")]
    Spawn(String),
    #[error("Git process wait failed: {0}")]
    Wait(String),
    #[error("Git process exceeded its deadline")]
    Timeout,
    #[error("Git output capture failed: {0}")]
    Capture(io::Error),
    #[error("Git output capture thread panicked")]
    CaptureThread,
    #[error("Git command failed with exit code {exit_code:?}: {stderr}")]
    CommandFailed {
        exit_code: Option<i32>,
        stderr: String,
    },
    #[error("Git {kind} exceeds limit {limit}")]
    OutputLimit { kind: &'static str, limit: usize },
    #[error("mutable or invalid Git revision; a full lowercase object id is required")]
    MutableOrInvalidRevision,
    #[error("unsafe repository-relative path `{0}`")]
    UnsafePath(String),
    #[error("Git path was not found")]
    PathNotFound,
    #[error("Git returned an unsupported blob mode `{0}`")]
    UnsupportedBlobMode(String),
    #[error("Git returned another path than requested")]
    PathMismatch,
    #[error("Git returned invalid {0}")]
    InvalidGitOutput(&'static str),
    #[error("source snapshot {kind} exceeds limit {limit}")]
    SourceSnapshotLimit { kind: &'static str, limit: u64 },
    #[error("unsafe source symlink `{0}`")]
    UnsafeSymlink(String),
    #[error("submodule `{0}` has no exact source-manifest lock")]
    UnlockedSubmodule(String),
    #[error("submodule lock `{0}` does not name a Git link")]
    UnusedSubmoduleLock(String),
    #[error("submodule declaration `{0}` does not name a Git link")]
    UnusedSubmoduleDeclaration(String),
    #[error("submodule mount `{0}` is duplicated")]
    DuplicateSubmoduleMount(String),
    #[error("submodule `{0}` has no exact committed .gitmodules declaration")]
    MissingSubmoduleDeclaration(String),
    #[error("committed .gitmodules content is invalid or ambiguous")]
    InvalidSubmoduleDeclaration,
    #[error("submodule `{0}` does not match its locked commit")]
    SubmoduleCommitMismatch(String),
    #[error("submodule `{0}` does not match its locked normalized origin")]
    SubmoduleOriginMismatch(String),
    #[error("submodule `{0}` exact commit is absent from its supplied local object database")]
    SubmoduleObjectUnavailable(String),
    #[error("submodule `{0}` creates a recursive repository graph")]
    SubmoduleCycle(String),
    #[error("source object `{0}` changed between validation and publication")]
    SubmoduleObjectChanged(String),
    #[error("unsupported Git tree entry `{path}` with mode `{mode}`")]
    UnsupportedTreeEntry { path: String, mode: String },
}
