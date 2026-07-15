use crate::DeploymentSubject;
use runtrue_model::ContentDigest;
use runtrue_policy::ApprovalRequest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentRequestStatus {
    PendingApproval,
    Waiting,
    Ready,
    InProgress,
    Succeeded,
    Failed,
    Denied,
    Expired,
    Canceled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRequest {
    pub id: String,
    pub idempotency_key: String,
    pub subject: DeploymentSubject,
    pub subject_digest: ContentDigest,
    pub status: DeploymentRequestStatus,
    pub approval: ApprovalRequest,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateDeploymentRequest {
    pub id: String,
    pub idempotency_key: String,
    pub approval_request_id: String,
    pub subject: DeploymentSubject,
    pub risk_score: u32,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateDeploymentResult {
    pub request: DeploymentRequest,
    pub replayed: bool,
}
