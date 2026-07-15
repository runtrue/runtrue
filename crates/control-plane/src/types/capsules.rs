use runtrue_attest::CapsuleSignature;
use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct SignedCapsuleRecord {
    pub id: String,
    pub repository_id: String,
    pub digest: ContentDigest,
    pub canonical_capsule: Vec<u8>,
    pub signature: CapsuleSignature,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleApiMetadata {
    pub capsule_id: String,
    pub approval_subject_digest: ContentDigest,
    pub risk_score: u32,
}

impl fmt::Debug for SignedCapsuleRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedCapsuleRecord")
            .field("id", &self.id)
            .field("repository_id", &self.repository_id)
            .field("digest", &self.digest)
            .field("canonical_capsule_bytes", &self.canonical_capsule.len())
            .field("signature", &self.signature)
            .field("created_unix_ms", &self.created_unix_ms)
            .finish()
    }
}
