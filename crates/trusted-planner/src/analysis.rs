use runtrue_compiler::{Compilation, RiskReport};
use runtrue_model::ContentDigest;
use runtrue_scm::{TrustedWorkflowSelection, WorkflowSourceInputs};

const ABSENT_WORKFLOW_DOMAIN: &[u8] = b"runtrue.trusted-planner.absent-workflow.v1\0";

pub(crate) fn absent_workflow_digest() -> ContentDigest {
    ContentDigest::sha256(ABSENT_WORKFLOW_DOMAIN)
}

#[derive(Debug, Clone)]
pub struct TrustedCapsuleResult {
    pub execution: Compilation,
    pub selection: TrustedWorkflowSelection,
    pub proposed_analysis: ProposedWorkflowAnalysis,
    /// Exact Git and policy identities used for source selection. Callers may
    /// persist this bounded snapshot and require an exact match when a gated
    /// execution is re-planned after approval.
    pub source_inputs: WorkflowSourceInputs,
}

#[derive(Debug, Clone)]
pub enum ProposedWorkflowAnalysis {
    NotApplicable,
    Deleted {
        workflow_digest: ContentDigest,
    },
    Invalid {
        workflow_digest: ContentDigest,
        failure: ProposedAnalysisFailure,
    },
    Valid {
        compilation: Box<Compilation>,
        semantic_risk: RiskReport,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposedAnalysisFailure {
    WorkflowNotUtf8,
    LockfileInvalid,
    WorkflowInvalid,
}
