use crate::ReusableWorkflowProviderError;
use runtrue_compiler::ReusableSourceBundleError;
use runtrue_git::GitError;
use runtrue_lock::LockError;
use runtrue_scm::WorkflowSourceError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustedPlannerError {
    #[error("authenticated SCM event is invalid")]
    InvalidEvent,
    #[error("SCM event has no executable revision")]
    NoExecutableRevision,
    #[error("required {kind} is absent at the exact Git revision")]
    RequiredPathMissing { kind: &'static str },
    #[error("Git source read failed: {0}")]
    Git(#[from] GitError),
    #[error("reusable workflow lock entries require an authenticated source provider")]
    ReusableSourceProviderRequired,
    #[error(transparent)]
    ReusableSource(#[from] ReusableWorkflowProviderError),
    #[error("reusable workflow source bundle is invalid: {0}")]
    ReusableBundle(#[from] ReusableSourceBundleError),
    #[error("{kind} is invalid: {source}")]
    InvalidLockfile {
        kind: &'static str,
        source: LockError,
    },
    #[error("workflow at revision {revision} is not UTF-8")]
    WorkflowNotUtf8 { revision: String },
    #[error("workflow source frontend rejected the input: {0}")]
    WorkflowFrontend(String),
    #[error("workflow compilation failed: {0}")]
    Compile(#[from] runtrue_compiler::CompileError),
    #[error("workflow source trust decision failed: {0}")]
    Source(#[from] WorkflowSourceError),
    #[error("approved workflow definition cannot be compiled from the exact source")]
    ApprovedDefinitionInvalid,
    #[error("policy version identifiers are invalid")]
    InvalidPolicyVersions,
    #[error("durable repository default branch is invalid")]
    InvalidDefaultBranch,
    #[error("normalized SCM event could not be encoded: {0}")]
    EventEncoding(#[from] serde_json::Error),
}
