use crate::types::leases::RunnerSecretLeaseRecord;
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
