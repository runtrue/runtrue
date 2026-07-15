use crate::{canonical_bytes, SigningError, SigningOperation};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

pub(crate) const ENVELOPE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub version: u32,
    pub request_id: String,
    pub request_digest: ContentDigest,
    pub subject_digest: ContentDigest,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub step_id: String,
    pub artifact_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
    pub capsule_digest: ContentDigest,
    pub purpose: String,
    pub operation: SigningOperation,
    pub signer_key_id: String,
    pub algorithm: String,
    pub signature: Vec<u8>,
    pub approval_id: String,
    pub approver_identities: Vec<String>,
    pub policy_version_ids: Vec<String>,
    pub signed_at_unix_seconds: u64,
}

impl SignatureEnvelope {
    pub fn digest(&self) -> Result<ContentDigest, SigningError> {
        Ok(ContentDigest::sha256(canonical_bytes(self)?))
    }
}
