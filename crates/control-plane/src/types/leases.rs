use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialTaintState {
    #[default]
    Unknown,
    None,
    CredentialReleased,
}

impl CredentialTaintState {
    #[must_use]
    pub const fn permits_replay_or_checkpoint(self) -> bool {
        matches!(self, Self::None)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::None => "none",
            Self::CredentialReleased => "credential_released",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "none" => Ok(Self::None),
            "credential_released" => Ok(Self::CredentialReleased),
            _ => Err("invalid credential taint state"),
        }
    }
}

/// Durable, plaintext-free record of one secret value delivered to one
/// running step. A repeated request for the same binding is rejected rather
/// than replaying the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerSecretLeaseRecord {
    pub id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub runner_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub secret_metadata_id: String,
    pub secret_version: u64,
    pub purpose: String,
    pub guest_key_fingerprint: ContentDigest,
    pub runner_posture_digest: ContentDigest,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRunnerSecretRequest {
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub runner_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub secret_metadata_id: String,
    pub purpose: String,
    pub guest_key_fingerprint: ContentDigest,
    pub runner_posture_digest: ContentDigest,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeRunnerOidcRequest {
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub runner_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub audience: String,
    pub runner_posture_digest: ContentDigest,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRunnerOidcIssuance {
    pub grant_id: String,
    pub audience: String,
    pub jti: String,
    pub runner_id: String,
    pub runner_posture_digest: ContentDigest,
    pub job_attempt: u32,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerLogFrameRecord {
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub job_attempt: u32,
    pub step_id: String,
    pub stream: String,
    pub sequence: u64,
    pub monotonic_nanoseconds: u64,
    pub wall_time_unix_ms: u64,
    pub payload: Vec<u8>,
    pub redaction_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendRunnerLogsRequest {
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub runner_id: String,
    pub frames: Vec<RunnerLogFrameRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRunnerBlobUpload {
    pub ticket_id: String,
    pub blob_digest: ContentDigest,
    pub ticket_kind: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub job_attempt: u32,
    pub size_bytes: u64,
    pub maximum_ticket_bytes: u64,
    pub recorded_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerDataCommitKind {
    Cache,
    Artifact,
}

impl RunnerDataCommitKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Artifact => "artifact",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerDataCommit {
    pub kind: RunnerDataCommitKind,
    pub object_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub output_name: Option<String>,
    pub lease_id: String,
    pub fencing_generation: u64,
    pub ticket_id: String,
    pub committed_unix_ms: u64,
}
