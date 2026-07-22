//! Trusted SCM-to-capsule assembly.
//!
//! Workflow and lockfile bytes are loaded only from exact Git object IDs. For
//! pull requests the target/base definition is always the executable default;
//! proposed bytes are compiled separately for semantic risk analysis and may
//! replace the base definition only with approval evidence bound to the full
//! compiler approval-subject digest.

mod analysis;
mod error;
mod locks;
mod planner;
mod provider;
mod secrets;
mod source_trust;

pub use analysis::{ProposedAnalysisFailure, ProposedWorkflowAnalysis, TrustedCapsuleResult};
pub use error::TrustedPlannerError;
pub use planner::TrustedPlanner;
pub use provider::{ReusableWorkflowProviderError, ReusableWorkflowSourceProvider};
pub use runtrue_workflow_frontend::{
    PreparedWorkflowSource, WorkflowFrontendOptions, WorkflowFrontendReport, WorkflowSourceFrontend,
};
pub use secrets::{SecretMetadataResolver, SecretResolutionError};
pub use source_trust::derive_source_trust;

pub const DEFAULT_LOCKFILE_PATH: &str = ".runtrue.lock";
