//! Bounded, non-interactive Git reads for trusted workflow discovery.
//!
//! Only full lowercase object IDs are accepted as revisions. Pull-request
//! planning can therefore read the target/base workflow for execution while
//! retaining the proposed workflow bytes strictly for risk analysis. Blob
//! modes, path traversal, output sizes, command duration, and inherited Git
//! configuration are all constrained.

mod benchmark;
mod blob;
mod command;
mod error;
mod mirror;
mod origin;
mod repository;
mod snapshot;
mod submodules;
#[cfg(test)]
mod tests;
mod tree;
mod validation;

pub use benchmark::{MirrorBenchmarkInput, MirrorBenchmarkReport, MirrorBenchmarkSample};
pub use blob::{GitBlob, GitLimits, TrustedWorkflowSources};
pub use error::GitError;
pub use mirror::{
    CredentialRequest, GitCredential, GitCredentialProvider, HydratedWorkspace, HydrationOutcome,
    MaintenanceOutcome, MirrorHandle, MirrorLimits, MirrorManager, MirrorMiss, MirrorSyncOutcome,
    RepositoryIdentity,
};
pub use origin::{NormalizedOrigin, OriginPolicy};
pub use repository::{GitRepository, GitRepositoryKind};
pub use snapshot::{LockedSourceSnapshotLimits, SourceSnapshotLimits};
pub use submodules::{
    GitSubmoduleLock, LockedGitTreeManifest, LockedSubmoduleSource, LockedSubmoduleSources,
};
pub use tree::{GitTreeEntry, GitTreeEntryKind, GitTreeManifest, GIT_TREE_MANIFEST_VERSION};

pub(crate) use command::{
    bounded_diagnostic, capture, git_hardening_arguments, null_device, safe_path, wait_bounded,
};
pub(crate) use submodules::{walk_locked_source_repository, LockedManifestBuildState};
pub(crate) use validation::{
    find_git, git_object_size, open_null_directory_placeholder, open_real_directory,
    parse_changed_paths, parse_ls_tree, parse_ls_tree_record, parse_one_line, validate_object_id,
    validate_repo_path, validate_symlink_target,
};
