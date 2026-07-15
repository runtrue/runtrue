use runtrue_lifecycle::JobState;
use runtrue_lifecycle::RunState;
use runtrue_model::ContentDigest;
use runtrue_scheduler::SchedulingRequirements;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewJob {
    pub id: String,
    pub job_key: String,
    pub attempt: u32,
    pub requirements: SchedulingRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRunRequest {
    pub id: String,
    pub repository_id: String,
    pub capsule_id: String,
    pub priority: i32,
    pub remote: bool,
    pub created_unix_ms: u64,
    pub jobs: Vec<NewJob>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    pub id: String,
    pub repository_id: String,
    pub capsule_id: String,
    pub status: RunState,
    pub priority: i32,
    pub remote: bool,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSnapshotState {
    Building,
    Ready,
    Failed,
    Retired,
}

impl SourceSnapshotState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotRecord {
    pub id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub commit_sha: String,
    pub tree_manifest_digest: ContentDigest,
    pub state: SourceSnapshotState,
    pub created_unix_ms: u64,
    pub verified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSourceSnapshotRecord {
    pub run_id: String,
    pub source_snapshot_id: String,
    pub capsule_digest: ContentDigest,
    pub bound_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRunnerSourceTicket {
    pub id: String,
    pub tenant_id: String,
    pub runner_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub job_id: String,
    pub job_attempt: u32,
    pub maximum_bytes: u64,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerSourceTicketRecord {
    pub id: String,
    pub tenant_id: String,
    pub runner_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub job_id: String,
    pub job_attempt: u32,
    pub source_snapshot_id: String,
    pub tree_manifest_digest: ContentDigest,
    pub maximum_bytes: u64,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerSourceDownload {
    pub ticket_id: String,
    pub object_digest: ContentDigest,
    pub runner_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub job_id: String,
    pub job_attempt: u32,
    pub size_bytes: u64,
    pub recorded_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    pub id: String,
    pub run_id: String,
    pub job_key: String,
    pub attempt: u32,
    pub status: JobState,
    pub requirements: SchedulingRequirements,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotentResult<T> {
    pub value: T,
    pub replayed: bool,
}
