use crate::types::leases::RunnerSecretLeaseRecord;
use runtrue_model::ContentDigest;
use runtrue_secrets::SecretPlaintext;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

/// One-shot result returned only by the in-process secret broker adapter.
/// Its diagnostic representation never exposes the released value.
pub struct DeliveredRunnerSecret {
    pub lease: RunnerSecretLeaseRecord,
    pub plaintext: SecretPlaintext,
}

impl fmt::Debug for DeliveredRunnerSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveredRunnerSecret")
            .field("lease", &self.lease)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

/// Secret reference metadata only. There is intentionally no value/ciphertext field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretMetadataReference {
    pub id: String,
    pub tenant_id: String,
    pub scope: String,
    pub name: String,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_reference: Option<String>,
    pub secret_type: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<u64>,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

/// Provider-neutral scope kind. Provider vocabulary belongs in frontend adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScopeKind {
    Workspace,
    ScmAccount,
    Project,
    Repository,
}

impl SecretScopeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::ScmAccount => "scm_account",
            Self::Project => "project",
            Self::Repository => "repository",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretScope {
    pub kind: SecretScopeKind,
    pub id: String,
}

impl SecretScope {
    /// Retains the original tenant scope so existing secrets remain defaults.
    pub fn workspace(tenant_id: impl Into<String>) -> Self {
        Self {
            kind: SecretScopeKind::Workspace,
            id: tenant_id.into(),
        }
    }

    pub fn durable_key(&self) -> String {
        let prefix = match self.kind {
            SecretScopeKind::Workspace => "tenant",
            SecretScopeKind::ScmAccount => "scm-account",
            SecretScopeKind::Project => "project",
            SecretScopeKind::Repository => "repository",
        };
        format!("{prefix}:{}", self.id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationProjectTargetKind {
    ScmAccount,
    Repository,
}

impl ConfigurationProjectTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScmAccount => "scm_account",
            Self::Repository => "repository",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationProjectTarget {
    pub kind: ConfigurationProjectTargetKind,
    pub id: String,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationProjectRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    pub status: String,
    pub version: u64,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    #[serde(default)]
    pub targets: Vec<ConfigurationProjectTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutConfigurationProject {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub status: String,
    /// Zero creates the project; otherwise this must equal the durable version.
    pub expected_version: u64,
    #[serde(default)]
    pub targets: Vec<ConfigurationProjectTarget>,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretResolutionCandidate {
    pub scope: SecretScope,
    pub metadata_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretResolutionRecord {
    pub tenant_id: String,
    pub repository_id: String,
    pub scm_account_id: String,
    pub name: String,
    pub selected: SecretResolutionCandidate,
    #[serde(default)]
    pub shadowed: Vec<SecretResolutionCandidate>,
    pub project_versions: Vec<(String, u64)>,
    pub resolution_digest: ContentDigest,
}
