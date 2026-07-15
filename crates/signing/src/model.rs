use crate::{canonical_bytes, SigningError};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningOperation {
    SignDigest,
    SignAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub step_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub requester_identity: String,
    pub capsule_digest: ContentDigest,
    pub artifact_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
    pub purpose: String,
    pub operation: SigningOperation,
    pub approval_id: String,
    pub policy_version_ids: Vec<String>,
    pub requested_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

impl SigningRequest {
    pub fn request_digest(&self) -> Result<ContentDigest, SigningError> {
        Ok(ContentDigest::sha256(canonical_bytes(self)?))
    }

    pub fn approval_subject(&self) -> Result<SigningApprovalSubject, SigningError> {
        Ok(SigningApprovalSubject {
            tenant_id: self.tenant_id.clone(),
            repository_id: self.repository_id.clone(),
            run_id: self.run_id.clone(),
            job_id: self.job_id.clone(),
            step_id: self.step_id.clone(),
            execution_lease_id: self.execution_lease_id.clone(),
            fencing_generation: self.fencing_generation,
            installation_fencing_epoch: self.installation_fencing_epoch,
            requester_identity: self.requester_identity.clone(),
            capsule_digest: self.capsule_digest.clone(),
            artifact_digest: self.artifact_digest.clone(),
            provenance_digest: self.provenance_digest.clone(),
            purpose: self.purpose.clone(),
            operation: self.operation,
            policy_version_ids: self.policy_version_ids.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningApprovalSubject {
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub step_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub requester_identity: String,
    pub capsule_digest: ContentDigest,
    pub artifact_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
    pub purpose: String,
    pub operation: SigningOperation,
    pub policy_version_ids: Vec<String>,
}

impl SigningApprovalSubject {
    pub fn digest(&self) -> Result<ContentDigest, SigningError> {
        Ok(ContentDigest::sha256(canonical_bytes(self)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningApproval {
    pub approval_id: String,
    pub subject_digest: ContentDigest,
    pub approver_identities: Vec<String>,
    pub policy_version_ids: Vec<String>,
    pub approved_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningGrant {
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub step_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub requester_identity: String,
    pub capsule_digest: ContentDigest,
    pub artifact_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
    pub purpose: String,
    pub operation: SigningOperation,
    pub policy_version_ids: Vec<String>,
    pub expires_at_unix_seconds: u64,
}
