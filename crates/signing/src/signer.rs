use crate::{canonical_bytes, SigningError, SigningOperation, SIGNING_DOMAIN};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerPayload {
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
    pub subject_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub artifact_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
    pub capsule_digest: ContentDigest,
    pub purpose: String,
    pub operation: SigningOperation,
    pub approval_id: String,
    pub policy_version_ids: Vec<String>,
}

impl SignerPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, SigningError> {
        let canonical = canonical_bytes(self)?;
        let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(SIGNING_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSignature {
    pub key_id: String,
    pub algorithm: String,
    pub bytes: Vec<u8>,
}

pub trait NonExportableSigner: Send {
    fn key_id(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn purpose(&self) -> &str;
    fn sign(
        &mut self,
        request_id: &str,
        domain_separated_payload: &[u8],
    ) -> Result<RawSignature, SigningError>;
}
