//! Trusted SCM-to-capsule assembly.
//!
//! Workflow and lockfile bytes are loaded only from exact Git object IDs. For
//! pull requests the target/base definition is always the executable default;
//! proposed bytes are compiled separately for semantic risk analysis and may
//! replace the base definition only with approval evidence bound to the full
//! compiler approval-subject digest.

mod analysis;
mod error;
mod limits;
mod locks;
mod planner;
mod provider;
mod source_trust;

pub use analysis::{ProposedAnalysisFailure, ProposedWorkflowAnalysis, TrustedCapsuleResult};
pub use error::TrustedPlannerError;
pub use limits::TrustedPlannerLimits;
pub use planner::TrustedPlanner;
pub use provider::{ReusableWorkflowProviderError, ReusableWorkflowSourceProvider};
pub use source_trust::derive_source_trust;

pub const DEFAULT_LOCKFILE_PATH: &str = ".runtrue.lock";
