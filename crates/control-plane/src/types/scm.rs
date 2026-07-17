use crate::types::capsules::{CapsuleApiMetadata, SignedCapsuleRecord};
use crate::types::runs::{CreateRunRequest, IdempotentResult, RunRecord, SourceSnapshotRecord};
use runtrue_model::ContentDigest;
use runtrue_policy::ApprovalRequest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScmSourceFetchState {
    Reserved,
    Fetched,
    SnapshotReady,
    Committed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmSourceFetchRecord {
    pub id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub installation_id: String,
    pub origin_task_id: String,
    pub normalized_event_digest: ContentDigest,
    pub source_commit: String,
    pub base_commit: Option<String>,
    pub origin_digest: ContentDigest,
    pub token_scope_digest: Option<ContentDigest>,
    pub mirror_identity_digest: Option<ContentDigest>,
    pub tree_manifest_digest: Option<ContentDigest>,
    pub source_snapshot_id: Option<String>,
    pub state: ScmSourceFetchState,
    pub attempts: u32,
    pub last_error_code: Option<String>,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveScmSourceFetch {
    pub id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub installation_id: String,
    pub origin_task_id: String,
    pub normalized_event_digest: ContentDigest,
    pub source_commit: String,
    pub base_commit: Option<String>,
    pub origin_digest: ContentDigest,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordScmFetchSnapshotReady {
    pub tenant_id: String,
    pub fetch_id: String,
    pub token_scope_digest: ContentDigest,
    pub mirror_identity_digest: ContentDigest,
    pub tree_manifest_digest: ContentDigest,
    pub source_snapshot_id: String,
    pub now_unix_ms: u64,
}

/// Provider-neutral durable payload for one GitHub check projection. It
/// contains only public projection data and immutable control-plane ids;
/// installation tokens and signer material never enter the task table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmCheckAction {
    pub label: String,
    pub description: String,
    pub identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmCheckPublishTask {
    pub publication_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub installation_id: String,
    pub installation_external_id: String,
    pub run_id: String,
    pub commit_sha: String,
    pub owner: String,
    pub repository: String,
    pub external_repository_id: String,
    pub logical_name: String,
    pub external_id: String,
    pub check_name: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conclusion: Option<String>,
    pub title: String,
    pub summary: String,
    /// Render the backend-generated summary as Markdown. Dynamic values must
    /// already be escaped by the producer before this flag is set.
    #[serde(default)]
    pub render_markdown: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ScmCheckAction>,
    pub trusted_base_workflow: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScmCheckPublicationState {
    Reserved,
    Reconciling,
    Published,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmCheckPublicationRecord {
    pub id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub installation_id: String,
    pub run_id: String,
    pub task_id: String,
    pub provider: String,
    pub commit_sha: String,
    pub logical_name: String,
    pub external_id: String,
    pub request_digest: ContentDigest,
    pub annotation_count: u32,
    pub provider_check_run_id: Option<u64>,
    pub confirmed_annotations: u32,
    pub state: ScmCheckPublicationState,
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveScmCheckPublication {
    pub id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub installation_id: String,
    pub run_id: String,
    pub task_id: String,
    pub worker_id: String,
    pub commit_sha: String,
    pub logical_name: String,
    pub external_id: String,
    pub request_digest: ContentDigest,
    pub annotation_count: u32,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordScmCheckProgress {
    pub tenant_id: String,
    pub publication_id: String,
    pub task_id: String,
    pub worker_id: String,
    pub provider_check_run_id: u64,
    pub confirmed_annotations: u32,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordScmCheckFailure {
    pub tenant_id: String,
    pub publication_id: String,
    pub task_id: String,
    pub worker_id: String,
    pub error_code: String,
    pub terminal: bool,
    pub now_unix_ms: u64,
}

/// Which trusted SCM selection produced a durable execution candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScmExecutionRole {
    Direct,
    TrustedBase,
    ProposedDefinition,
}

/// Exact Git/compiler identities which must still match when an approved SCM
/// execution is re-planned. Repository bytes are deliberately not embedded;
/// the continuation reads only the named immutable objects from its trusted
/// mirror and compares all of these identities before committing a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmSourceIdentity {
    pub normalized_event_digest: ContentDigest,
    pub source_commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_commit: Option<String>,
    pub workflow_path: String,
    pub proposed_workflow_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_workflow_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_lockfile_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_lockfile_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_approval_subject_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reusable_workflow_digests: Vec<String>,
    pub policy_version_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmContinuationContext {
    pub pending_execution_id: String,
    pub event: Value,
    pub role: ScmExecutionRole,
    pub source_identity: ScmSourceIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_snapshot_id: Option<String>,
    /// Repository-scoped identity for the static privileged capability
    /// envelope. Unlike the Capsule approval subject, this intentionally
    /// excludes the triggering event and source commit so an unchanged
    /// workflow can reuse a durable capability grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged_capability_digest: Option<ContentDigest>,
    /// Exact repository-action Programs prepared before approval. The worker
    /// reuses these immutable resolutions during continuation and still must
    /// reproduce the byte-identical signed Capsule before approval is
    /// consumed.
    #[serde(default = "empty_object", skip_serializing_if = "is_empty_object")]
    pub resolved_repository_actions: Value,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

fn is_empty_object(value: &Value) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

/// A signed SCM capsule plus its exact future run request. Empty approvals mean
/// it is safe to create immediately; otherwise `continuation` is mandatory and
/// the whole candidate is persisted without creating a run or jobs.
#[derive(Clone)]
pub struct PreparedScmExecution {
    pub capsule: SignedCapsuleRecord,
    pub metadata: CapsuleApiMetadata,
    pub approvals: Vec<ApprovalRequest>,
    pub run: CreateRunRequest,
    pub continuation: Option<ScmContinuationContext>,
    pub source_snapshot: Option<SourceSnapshotRecord>,
    pub scm_fetch_id: Option<String>,
}

impl fmt::Debug for PreparedScmExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedScmExecution")
            .field("capsule", &self.capsule)
            .field("metadata", &self.metadata)
            .field("approval_count", &self.approvals.len())
            .field("run", &self.run)
            .field("continuation", &self.continuation)
            .field("source_snapshot", &self.source_snapshot)
            .field("scm_fetch_id", &self.scm_fetch_id)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScmProposedAnalysisStatus {
    Valid,
    Invalid,
    Deleted,
}

/// Durable proposed-workflow analysis. For a valid definition `analysis`
/// carries the bounded semantic-risk report and `proposed_capsule_id` names the
/// signed, never-yet-executed capsule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmProposedAnalysisRecord {
    pub id: String,
    pub origin_task_id: String,
    pub repository_id: String,
    pub status: ScmProposedAnalysisStatus,
    pub source_identity: ScmSourceIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_capsule_id: Option<String>,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScmPendingExecutionState {
    AwaitingApproval,
    ContinuationPending,
    RunCreated,
    Denied,
    Expired,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmPendingExecution {
    pub id: String,
    pub origin_task_id: String,
    pub repository_id: String,
    pub capsule_id: String,
    pub role: ScmExecutionRole,
    pub state: ScmPendingExecutionState,
    pub context: ScmContinuationContext,
    pub run: CreateRunRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_approval_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged_approval_id: Option<String>,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmTaskCompletion {
    pub task_id: String,
    pub run_ids: Vec<String>,
    pub pending_execution_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_analysis_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScmContinuationResolution {
    Ready(ScmPendingExecution),
    Waiting(ScmPendingExecution),
    Closed(ScmPendingExecution),
    RunCreated(RunRecord),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScmContinuationCommit {
    Run(IdempotentResult<RunRecord>),
    Waiting(ScmPendingExecution),
    Closed(ScmPendingExecution),
}
