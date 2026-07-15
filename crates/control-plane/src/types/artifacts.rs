use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactCatalogRecord {
    pub artifact_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub output_name: String,
    pub content_digest: ContentDigest,
    pub manifest_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
    pub size_bytes: u64,
    pub media_type: String,
    pub classification: String,
    pub scan_state: String,
    pub retention_until_unix_seconds: u64,
    pub legal_hold: bool,
    pub state: String,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDownloadTicketRecord {
    pub token_hash: ContentDigest,
    pub artifact_id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub classification: String,
    pub manifest_digest: ContentDigest,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub used_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactMetrics {
    pub cataloged: u64,
    pub quarantined: u64,
    pub download_tickets_issued: u64,
    pub download_tickets_consumed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactScanState {
    Pending,
    Claimed,
    Passed,
    Failed,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactScanJournalRecord {
    pub id: String,
    pub tenant_id: String,
    pub artifact_id: String,
    pub scanner: String,
    pub subject_digest: ContentDigest,
    pub state: ArtifactScanState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_unix_ms: Option<u64>,
    pub attempts: u32,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPromotionIntent {
    pub id: String,
    pub subject_digest: ContentDigest,
    pub tenant_id: String,
    pub source_artifact_id: String,
    pub source_manifest_digest: ContentDigest,
    pub source_provenance_digest: ContentDigest,
    pub source_classification: String,
    pub target_classification: String,
    pub evidence_digest: ContentDigest,
    pub evidence: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_evidence_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_evidence_digest: Option<ContentDigest>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_manifest_digest: Option<ContentDigest>,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
}
