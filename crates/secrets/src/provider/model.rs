//! Provider-facing release contracts and sensitive lease values.
use super::validation::{validate_identifier, validate_lease_metadata, validate_provider_id};
use crate::SecretPlaintext;
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
pub const MAX_PROVIDER_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROVIDER_REFERENCE_BYTES: usize = 4_096;
pub const MAX_PROVIDER_IDENTIFIER_BYTES: usize = 1_024;
pub const MAX_VAULT_PATH_SEGMENTS: usize = 128;
pub const MAX_VAULT_TOKEN_BYTES: usize = 64 * 1024;
pub const MAX_VAULT_CA_BUNDLE_BYTES: usize = 1024 * 1024;
pub const MAX_VAULT_CA_CERTIFICATES: usize = 64;
pub const MAX_VAULT_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_VAULT_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_EXTERNAL_SECRET_PROVIDERS: usize = 128;
const EXTERNAL_SECRET_RELEASE_SUBJECT_DOMAIN: &[u8] =
    b"runtrue.external-secret-release-subject.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSecretLeaseRequest {
    pub release_id: String,
    pub release_subject_digest: ContentDigest,
    pub provider_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub runner_id: String,
    pub secret_metadata_id: String,
    pub provider_reference: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub purpose: String,
    pub expires_unix_ms: u64,
}

impl ExternalSecretLeaseRequest {
    /// Compute the immutable release subject without trusting the digest field
    /// carried alongside the request.
    pub fn expected_release_subject_digest(&self) -> Result<ContentDigest, ProviderError> {
        #[derive(Serialize)]
        struct ReleaseSubject<'a> {
            release_id: &'a str,
            provider_id: &'a str,
            tenant_id: &'a str,
            repository_id: &'a str,
            run_id: &'a str,
            runner_id: &'a str,
            secret_metadata_id: &'a str,
            provider_reference: &'a str,
            execution_lease_id: &'a str,
            fencing_generation: u64,
            installation_fencing_epoch: u64,
            job_id: &'a str,
            job_attempt: u32,
            step_id: &'a str,
            purpose: &'a str,
            expires_unix_ms: u64,
        }

        let subject = ReleaseSubject {
            release_id: &self.release_id,
            provider_id: &self.provider_id,
            tenant_id: &self.tenant_id,
            repository_id: &self.repository_id,
            run_id: &self.run_id,
            runner_id: &self.runner_id,
            secret_metadata_id: &self.secret_metadata_id,
            provider_reference: &self.provider_reference,
            execution_lease_id: &self.execution_lease_id,
            fencing_generation: self.fencing_generation,
            installation_fencing_epoch: self.installation_fencing_epoch,
            job_id: &self.job_id,
            job_attempt: self.job_attempt,
            step_id: &self.step_id,
            purpose: &self.purpose,
            expires_unix_ms: self.expires_unix_ms,
        };
        let canonical = serde_json::to_vec(&subject)?;
        let mut bytes =
            Vec::with_capacity(EXTERNAL_SECRET_RELEASE_SUBJECT_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(EXTERNAL_SECRET_RELEASE_SUBJECT_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(ContentDigest::sha256(bytes))
    }

    pub fn validate(&self, now_unix_ms: u64) -> Result<(), ProviderError> {
        validate_identifier("external secret release id", &self.release_id)?;
        validate_provider_id(&self.provider_id)?;
        validate_identifier("tenant id", &self.tenant_id)?;
        validate_identifier("repository id", &self.repository_id)?;
        validate_identifier("run id", &self.run_id)?;
        validate_identifier("runner id", &self.runner_id)?;
        validate_identifier("secret metadata id", &self.secret_metadata_id)?;
        validate_identifier("execution lease id", &self.execution_lease_id)?;
        validate_identifier("job id", &self.job_id)?;
        validate_identifier("step id", &self.step_id)?;
        validate_identifier("secret purpose", &self.purpose)?;
        if self.provider_reference.is_empty()
            || self.provider_reference.len() > MAX_PROVIDER_REFERENCE_BYTES
            || self
                .provider_reference
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || self.fencing_generation == 0
            || self.installation_fencing_epoch == 0
            || self.job_attempt == 0
            || now_unix_ms >= self.expires_unix_ms
        {
            return Err(ProviderError::InvalidLeaseRequest);
        }
        if self.release_subject_digest != self.expected_release_subject_digest()? {
            return Err(ProviderError::ReleaseSubjectMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSecretLeaseMetadata {
    pub release_id: String,
    pub release_subject_digest: ContentDigest,
    pub provider: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub runner_id: String,
    pub secret_metadata_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_version: Option<u64>,
    pub renewable: bool,
    pub expires_unix_ms: u64,
}

impl ExternalSecretLeaseMetadata {
    pub fn validate_against(
        &self,
        request: &ExternalSecretLeaseRequest,
    ) -> Result<(), ProviderError> {
        validate_lease_metadata(self, &request.provider_id)?;
        if self.release_id != request.release_id
            || self.release_subject_digest != request.release_subject_digest
            || self.provider != request.provider_id
            || self.tenant_id != request.tenant_id
            || self.repository_id != request.repository_id
            || self.run_id != request.run_id
            || self.runner_id != request.runner_id
            || self.secret_metadata_id != request.secret_metadata_id
            || self.execution_lease_id != request.execution_lease_id
            || self.fencing_generation != request.fencing_generation
            || self.installation_fencing_epoch != request.installation_fencing_epoch
            || self.job_id != request.job_id
            || self.job_attempt != request.job_attempt
            || self.step_id != request.step_id
            || self.purpose != request.purpose
            || self.expires_unix_ms > request.expires_unix_ms
        {
            return Err(ProviderError::ReleaseSubjectMismatch);
        }
        Ok(())
    }
}

pub struct ExternalSecretLease {
    pub metadata: ExternalSecretLeaseMetadata,
    plaintext: SecretPlaintext,
}

impl ExternalSecretLease {
    pub fn from_parts(
        metadata: ExternalSecretLeaseMetadata,
        plaintext: SecretPlaintext,
    ) -> Result<Self, ProviderError> {
        let provider = metadata.provider.clone();
        validate_lease_metadata(&metadata, &provider)?;
        Ok(Self {
            metadata,
            plaintext,
        })
    }

    #[must_use]
    pub fn plaintext(&self) -> &SecretPlaintext {
        &self.plaintext
    }

    #[must_use]
    pub fn into_plaintext(self) -> SecretPlaintext {
        self.plaintext
    }

    #[must_use]
    pub fn into_parts(self) -> (ExternalSecretLeaseMetadata, SecretPlaintext) {
        (self.metadata, self.plaintext)
    }
}

impl fmt::Debug for ExternalSecretLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalSecretLease")
            .field("metadata", &self.metadata)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

pub trait ExternalSecretProvider: Send + Sync {
    fn provider_id(&self) -> &str;

    fn lease(
        &self,
        request: &ExternalSecretLeaseRequest,
        now_unix_ms: u64,
    ) -> Result<ExternalSecretLease, ProviderError>;

    fn revoke(
        &self,
        metadata: &ExternalSecretLeaseMetadata,
        now_unix_ms: u64,
    ) -> Result<(), ProviderError>;
}
#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("invalid external secret lease request")]
    InvalidLeaseRequest,
    #[error("invalid external secret lease metadata")]
    InvalidLeaseMetadata,
    #[error("invalid external secret provider configuration")]
    InvalidProviderConfiguration,
    #[error("Vault/OpenBao address violates the selected HTTPS or test-loopback policy")]
    InvalidProviderAddress,
    #[error("reviewed Vault/OpenBao CA bundle is empty, malformed, or too large")]
    InvalidCaBundle,
    #[error("Vault/OpenBao transport request escaped its configured origin or resource bounds")]
    InvalidTransportRequest,
    #[error("external secret provider identifier is not registered")]
    UnknownProvider,
    #[error("external secret provider identifier was registered more than once")]
    DuplicateProviderRegistration,
    #[error("external secret provider registry reached its fixed capacity")]
    ProviderRegistryFull,
    #[error("external secret provider returned metadata for another provider identifier")]
    ProviderIdentityMismatch,
    #[error("external secret release subject digest does not match its immutable binding")]
    ReleaseSubjectMismatch,
    #[error("invalid Vault/OpenBao token")]
    InvalidProviderToken,
    #[error("invalid Vault/OpenBao KV v2 provider reference")]
    InvalidProviderReference,
    #[error("Vault/OpenBao transport failed without exposing provider response data")]
    Transport,
    #[error("Vault/OpenBao returned HTTP status {0}")]
    ProviderStatus(u16),
    #[error("Vault/OpenBao response exceeded its bounded size")]
    ProviderResponseTooLarge,
    #[error("Vault/OpenBao response was malformed or ambiguous")]
    InvalidProviderResponse,
    #[error("configured secret field was absent from the Vault/OpenBao response")]
    SecretFieldMissing,
    #[error("Vault/OpenBao secret field did not use the configured encoding")]
    InvalidSecretEncoding,
    #[error("external secret exceeds {limit} bytes (observed {actual})")]
    SecretTooLarge { limit: usize, actual: usize },
    #[error("external provider lease duration overflow")]
    ProviderLeaseOverflow,
    #[error("external provider returned an already-expired lease")]
    ProviderLeaseExpired,
    #[error("external provider request encoding failed")]
    RequestEncoding(#[from] serde_json::Error),
}
