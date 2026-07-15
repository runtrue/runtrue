//! Plaintext-free durable release reservation and audit journal contracts.
use super::model::{ExternalSecretBrokerError, ExternalSecretRevocationRequest};
use crate::{ExternalSecretLeaseMetadata, ExternalSecretLeaseRequest};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSecretReleaseReservation {
    pub release_id: String,
    pub release_subject_digest: ContentDigest,
    pub provider_id: String,
    pub provider_reference_digest: ContentDigest,
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
    pub expires_unix_ms: u64,
}

impl ExternalSecretReleaseReservation {
    pub(super) fn from_provider_request(request: &ExternalSecretLeaseRequest) -> Self {
        Self {
            release_id: request.release_id.clone(),
            release_subject_digest: request.release_subject_digest.clone(),
            provider_id: request.provider_id.clone(),
            provider_reference_digest: ContentDigest::sha256(request.provider_reference.as_bytes()),
            tenant_id: request.tenant_id.clone(),
            repository_id: request.repository_id.clone(),
            run_id: request.run_id.clone(),
            runner_id: request.runner_id.clone(),
            execution_lease_id: request.execution_lease_id.clone(),
            fencing_generation: request.fencing_generation,
            installation_fencing_epoch: request.installation_fencing_epoch,
            job_id: request.job_id.clone(),
            job_attempt: request.job_attempt,
            step_id: request.step_id.clone(),
            secret_metadata_id: request.secret_metadata_id.clone(),
            purpose: request.purpose.clone(),
            expires_unix_ms: request.expires_unix_ms,
        }
    }

    pub(super) fn matches_revocation(&self, request: &ExternalSecretRevocationRequest) -> bool {
        self.release_id == request.release_id
            && self.runner_id == request.runner_id
            && self.execution_lease_id == request.execution_lease_id
            && self.fencing_generation == request.fencing_generation
            && self.installation_fencing_epoch == request.installation_fencing_epoch
            && self.job_id == request.job_id
            && self.job_attempt == request.job_attempt
            && self.step_id == request.step_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ExternalSecretReleaseState {
    Reserved,
    Delivered {
        provider_metadata: ExternalSecretLeaseMetadata,
    },
    Revoking {
        provider_metadata: ExternalSecretLeaseMetadata,
    },
    Revoked {
        provider_metadata: ExternalSecretLeaseMetadata,
        revoked_unix_ms: u64,
    },
    Indeterminate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_metadata: Option<ExternalSecretLeaseMetadata>,
        observed_unix_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSecretReleaseJournalEntry {
    pub reservation: ExternalSecretReleaseReservation,
    pub state: ExternalSecretReleaseState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSecretReserveOutcome {
    /// True only when this call durably created the reservation.
    pub created: bool,
    pub entry: ExternalSecretReleaseJournalEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSecretRevokeOutcome {
    /// True only when this call durably transitioned delivered -> revoking.
    pub started: bool,
    pub entry: ExternalSecretReleaseJournalEntry,
}

/// Migration-24 persistence contract. Every method must use an exact compare
/// against the reservation subject and perform its transition atomically.
pub trait ExternalSecretReleaseJournal: Send + Sync {
    fn reserve(
        &self,
        reservation: &ExternalSecretReleaseReservation,
    ) -> Result<ExternalSecretReserveOutcome, ExternalSecretBrokerError>;

    fn mark_delivered(
        &self,
        reservation: &ExternalSecretReleaseReservation,
        provider_metadata: &ExternalSecretLeaseMetadata,
    ) -> Result<(), ExternalSecretBrokerError>;

    fn mark_indeterminate(
        &self,
        reservation: &ExternalSecretReleaseReservation,
        provider_metadata: Option<&ExternalSecretLeaseMetadata>,
        observed_unix_ms: u64,
    ) -> Result<(), ExternalSecretBrokerError>;

    fn load(
        &self,
        release_id: &str,
    ) -> Result<ExternalSecretReleaseJournalEntry, ExternalSecretBrokerError>;

    fn begin_revoke(
        &self,
        reservation: &ExternalSecretReleaseReservation,
    ) -> Result<ExternalSecretRevokeOutcome, ExternalSecretBrokerError>;

    fn mark_revoked(
        &self,
        reservation: &ExternalSecretReleaseReservation,
        revoked_unix_ms: u64,
    ) -> Result<(), ExternalSecretBrokerError>;
}
