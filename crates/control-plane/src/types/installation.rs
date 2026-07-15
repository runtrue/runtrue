use crate::types::repositories::RepositoryRecord;
use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmInstallationRecord {
    pub id: String,
    pub tenant_id: String,
    pub provider: String,
    pub external_id: String,
    pub credential_reference: String,
    pub permissions: Value,
    pub status: String,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmRepositoryLinkRecord {
    pub repository_id: String,
    pub tenant_id: String,
    pub installation_id: String,
    pub external_repository_id: String,
    pub clone_url: String,
    pub status: String,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitHubSetupStatus {
    Pending,
    Exchanging,
    Completed,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSetupTransactionRecord {
    pub id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub idempotency_key: String,
    pub request_digest: ContentDigest,
    pub state_digest: ContentDigest,
    pub github_web_origin: String,
    pub github_api_origin: String,
    pub return_path: String,
    pub status: GitHubSetupStatus,
    pub attempts: u32,
    pub expires_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_external_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGitHubSetupTransaction {
    pub id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub idempotency_key: String,
    pub request_digest: ContentDigest,
    pub state_digest: ContentDigest,
    pub github_web_origin: String,
    pub github_api_origin: String,
    pub return_path: String,
    pub expires_unix_ms: u64,
    pub created_unix_ms: u64,
}

impl CreateGitHubSetupTransaction {
    pub fn expected_request_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        #[derive(Serialize)]
        struct Material<'a> {
            version: u32,
            tenant_id: &'a str,
            principal_id: &'a str,
            idempotency_key: &'a str,
            github_web_origin: &'a str,
            github_api_origin: &'a str,
            return_path: &'a str,
            ttl_ms: u64,
        }

        let mut bytes = b"runtrue.github-app.setup-request.v2\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&Material {
            version: 2,
            tenant_id: &self.tenant_id,
            principal_id: &self.principal_id,
            idempotency_key: &self.idempotency_key,
            github_web_origin: &self.github_web_origin,
            github_api_origin: &self.github_api_origin,
            return_path: &self.return_path,
            ttl_ms: self.expires_unix_ms.saturating_sub(self.created_unix_ms),
        })?);
        Ok(ContentDigest::sha256(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginGitHubSetupTransaction {
    pub tenant_id: String,
    pub principal_id: String,
    pub transaction_id: String,
    pub state_digest: ContentDigest,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitHubAccountKind {
    Organization,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitHubRepositorySelection {
    All,
    Selected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubInstallationRecord {
    pub installation: ScmInstallationRecord,
    pub web_origin: String,
    pub api_origin: String,
    pub account_external_id: String,
    pub account_login: String,
    pub account_kind: GitHubAccountKind,
    pub repository_selection: GitHubRepositorySelection,
    pub lifecycle_generation: u64,
    pub synchronized_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_unix_ms: Option<u64>,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSelectedRepository {
    pub external_repository_id: String,
    pub owner: String,
    pub name: String,
    pub full_name: String,
    pub clone_url: String,
    pub visibility: String,
    pub default_branch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubRepositoryCatalogRecord {
    pub installation_id: String,
    pub external_repository_id: String,
    pub tenant_id: String,
    pub web_origin: String,
    pub api_origin: String,
    pub owner: String,
    pub name: String,
    pub full_name: String,
    pub clone_url: String,
    pub visibility: String,
    pub default_branch: String,
    pub status: String,
    pub selection_generation: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_unix_ms: Option<u64>,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileGitHubInstallation {
    pub installation: GitHubInstallationRecord,
    pub selected_repositories: Vec<GitHubSelectedRepository>,
    pub expected_version: Option<u64>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteGitHubSetupTransaction {
    pub tenant_id: String,
    pub principal_id: String,
    pub transaction_id: String,
    pub state_digest: ContentDigest,
    pub reconciliation: ReconcileGitHubInstallation,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetGitHubInstallationStatus {
    pub tenant_id: String,
    pub installation_id: String,
    pub expected_version: u64,
    pub status: String,
    pub lifecycle_generation: u64,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSelectedGitHubRepository {
    pub tenant_id: String,
    pub installation_id: String,
    pub external_repository_id: String,
    pub repository: RepositoryRecord,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubRepositoryReconciliationSummary {
    pub selected: u64,
    pub inserted: u64,
    pub updated: u64,
    pub removed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubInstallationReconciliationResult {
    pub installation: GitHubInstallationRecord,
    pub repositories: GitHubRepositoryReconciliationSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitHubLifecycleDeliveryState {
    Pending,
    Leased,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubLifecycleDeliveryRecord {
    pub delivery_id: String,
    pub tenant_id: String,
    pub installation_id: String,
    pub installation_external_id: String,
    pub event_name: String,
    pub action: String,
    pub payload_digest: ContentDigest,
    pub state: GitHubLifecycleDeliveryState,
    pub attempts: u32,
    pub available_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_owner: Option<String>,
    pub lease_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_lease_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_lease_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure_lease_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_retry_unix_ms: Option<u64>,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveGitHubLifecycleDelivery {
    pub delivery_id: String,
    pub tenant_id: String,
    pub installation_id: String,
    pub installation_external_id: String,
    pub event_name: String,
    pub action: String,
    pub payload_digest: ContentDigest,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimGitHubLifecycleDelivery {
    pub tenant_id: String,
    pub delivery_id: String,
    pub worker_id: String,
    pub now_unix_ms: u64,
    pub lease_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteGitHubLifecycleDelivery {
    pub tenant_id: String,
    pub delivery_id: String,
    pub worker_id: String,
    pub lease_generation: u64,
    pub completion_digest: ContentDigest,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailGitHubLifecycleDelivery {
    pub tenant_id: String,
    pub delivery_id: String,
    pub worker_id: String,
    pub lease_generation: u64,
    pub error_digest: ContentDigest,
    pub retry_unix_ms: Option<u64>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRecoveryState {
    pub fencing_epoch: u64,
    pub safe_mode: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_restore_unix_ms: Option<u64>,
}
