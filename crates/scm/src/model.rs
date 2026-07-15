use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    GitHub,
    GitLab,
    Gitea,
    Forgejo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryIdentity {
    pub external_id: String,
    pub owner: String,
    pub name: String,
    pub full_name: String,
    pub private: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorIdentity {
    pub external_id: String,
    pub login: String,
    pub is_bot: bool,
}

/// Bounded, redaction-safe metadata for an authenticated GitHub delivery.
/// This is intentionally separate from [`EventEnvelope`]: observing a
/// delivery does not make its event type executable by the workflow planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubDeliveryMetadata {
    pub installation_id: String,
    pub repository: RepositoryIdentity,
    pub actor: ActorIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    pub normalized_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitRevision {
    pub commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_full_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestAction {
    Opened,
    Synchronize,
    Reopened,
    Edited,
    Labeled,
    Unlabeled,
    ReadyForReview,
    ConvertedToDraft,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueCommentAction {
    Created,
    Edited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckRunEventAction {
    Completed,
    Rerequested,
    RequestedAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventType {
    Push,
    PullRequest { action: PullRequestAction },
    IssueComment { action: IssueCommentAction },
    CheckRun { action: CheckRunEventAction },
    MergeGroup,
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestEvent {
    pub number: u64,
    pub draft: bool,
    pub merged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueCommentEvent {
    pub issue_number: u64,
    pub issue_is_pull_request: bool,
    pub comment_id: u64,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRunPullRequest {
    pub number: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRunEvent {
    pub check_run_id: u64,
    pub pull_requests: Vec<CheckRunPullRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_action_identifier: Option<String>,
}

/// Stable event contract consumed by planning and expression projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub version: u32,
    pub provider: ProviderKind,
    pub installation_id: String,
    pub repository: RepositoryIdentity,
    pub event_id: String,
    pub event_type: EventType,
    pub actor: ActorIdentity,
    pub source: GitRevision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<GitRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<PullRequestEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_comment: Option<IssueCommentEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_run: Option<CheckRunEvent>,
    pub changed_paths: Vec<String>,
    pub received_unix_ms: u64,
    pub raw_payload_digest: ContentDigest,
    pub normalized_digest: ContentDigest,
}
