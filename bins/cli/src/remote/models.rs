use super::super::reusable::TransportReusableWorkflow;
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{ExecutionCapsule, ParityGrade};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateCapsuleRequest {
    pub(super) source_commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) base_commit: Option<String>,
    pub(super) workflow_path: String,
    pub(super) workflow_yaml: String,
    pub(super) event: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) lockfile_toml: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) reusable_workflows: Vec<TransportReusableWorkflow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) selected_job: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedCapsuleResponse {
    pub(super) id: String,
    pub(super) repository_id: String,
    pub(super) digest: ContentDigest,
    pub(super) status: String,
    pub(super) workflow_digest: ContentDigest,
    pub(super) lock_digest: Option<ContentDigest>,
    pub(super) risk_score: u32,
    pub(super) approval_required: bool,
    pub(super) approval_requests: Vec<CapsuleApprovalResponse>,
    pub(super) parity_grade: Value,
    pub(super) created_at: String,
    pub(super) signature: Value,
    pub(super) capsule: ExecutionCapsule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CapsuleApprovalResponse {
    pub(super) id: String,
    pub(super) approval_kind: String,
    pub(super) subject_digest: ContentDigest,
    pub(super) status: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateRunRequest {
    pub(super) priority: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RunResponse {
    pub(super) id: String,
    pub(super) capsule_id: String,
    pub(super) status: Value,
    pub(super) created_at: String,
    pub(super) started_at: Option<String>,
    pub(super) completed_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SubmitReport {
    pub(super) run_created: bool,
    pub(super) run_id: String,
    pub(super) run_status: Value,
    pub(super) capsule_id: String,
    pub(super) capsule_digest: ContentDigest,
    pub(super) parity: &'static str,
    pub(super) expected_parity: ParityGrade,
    pub(super) risk_score: u32,
    pub(super) approval_required: bool,
    pub(super) approval_subject_digest: ContentDigest,
    pub(super) approval_requests: Vec<CapsuleApprovalResponse>,
    pub(super) capsule_idempotency_replayed: bool,
    pub(super) run_idempotency_replayed: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingApprovalReport {
    pub(super) run_created: bool,
    pub(super) status: &'static str,
    pub(super) capsule_id: String,
    pub(super) capsule_digest: ContentDigest,
    pub(super) approval_subject_digest: ContentDigest,
    pub(super) approval_requests: Vec<CapsuleApprovalResponse>,
    pub(super) capsule_idempotency_replayed: bool,
}
