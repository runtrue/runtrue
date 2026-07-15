//! Public runner request, authorized release, and revocation models.
use crate::ProviderError;
use thiserror::Error;

pub(super) const MAX_BROKER_IDENTIFIER_BYTES: usize = 1_024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerExternalSecretRequest {
    pub runner_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub secret_metadata_id: String,
    pub purpose: String,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedExternalSecretRelease {
    pub release_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub runner_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub secret_metadata_id: String,
    pub purpose: String,
    pub provider_id: String,
    pub provider_reference: String,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSecretRevocationRequest {
    pub release_id: String,
    pub runner_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
}

#[derive(Debug, Error)]
pub enum ExternalSecretBrokerError {
    #[error("invalid external secret broker request")]
    InvalidRequest,
    #[error("external secret release was denied")]
    AuthorizationDenied,
    #[error("external secret authorization did not match the active runner binding")]
    AuthorizationBindingMismatch,
    #[error("external secret release ID was replayed with a different immutable subject")]
    SubjectConflict,
    #[error("external secret plaintext was already delivered and cannot be replayed")]
    AlreadyDelivered,
    #[error("external secret release requires explicit durable reconciliation")]
    IndeterminateRecoveryRequired,
    #[error("external secret durable journal failed")]
    Journal,
    #[error("external secret provider operation failed: {0}")]
    Provider(#[source] ProviderError),
}
