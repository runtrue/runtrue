use crate::{
    canonical, validation, ApprovalSubject, CapsuleKind, ContentDigest, ExecutionModelError,
};
use serde::{Deserialize, Serialize};

pub const SEAL_SCHEMA_VERSION: u32 = 1;
pub const MIN_SEAL_SIGNATURE_BYTES: usize = 32;
pub const MAX_SEAL_SIGNATURE_BYTES: usize = 16 * 1024;
pub const MAX_SEAL_LIFETIME_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

/// A domain-neutral authorization artifact over one exact ApprovalSubject.
///
/// The Seal is deliberately separate from workflow approvals. Its signing
/// payload binds both the ApprovalSubject digest and the Capsule identity so a
/// subject or Capsule cannot be substituted while retaining the same envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub schema_version: u32,
    pub approval_subject_digest: ContentDigest,
    pub capsule_kind: CapsuleKind,
    pub capsule_digest: ContentDigest,
    pub signer_identity: String,
    pub authority_identity: String,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub revocation_generation: u64,
    pub signature_algorithm: String,
    pub signing_key_id: ContentDigest,
    pub signature: Vec<u8>,
}

impl Seal {
    /// Validate canonical shape and intrinsic time bounds. Cryptographic
    /// signature verification is performed by an algorithm-specific verifier
    /// over [`Self::signing_bytes`].
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        self.validate_unsigned()?;
        if !(MIN_SEAL_SIGNATURE_BYTES..=MAX_SEAL_SIGNATURE_BYTES).contains(&self.signature.len()) {
            return Err(ExecutionModelError::InvalidField {
                field: "Seal signature",
                reason: "must be present and within the canonical byte bound",
            });
        }
        Ok(())
    }

    fn validate_unsigned(&self) -> Result<(), ExecutionModelError> {
        validation::schema(
            "Seal schema version",
            self.schema_version,
            SEAL_SCHEMA_VERSION,
        )?;
        validation::identifier("Seal signer identity", &self.signer_identity)?;
        validation::identifier("Seal authority identity", &self.authority_identity)?;
        validation::identifier("Seal signature algorithm", &self.signature_algorithm)?;
        if self.issued_unix_ms >= self.expires_unix_ms
            || self.expires_unix_ms.saturating_sub(self.issued_unix_ms) > MAX_SEAL_LIFETIME_MS
        {
            return Err(ExecutionModelError::InvalidField {
                field: "Seal validity window",
                reason: "expiry must follow issuance within the maximum lifetime",
            });
        }
        if self.revocation_generation == 0 {
            return Err(ExecutionModelError::InvalidField {
                field: "Seal revocation generation",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }

    /// Revalidate this Seal for one exact subject at admission time. Revocation
    /// generation is exact: advancing the authority generation invalidates all
    /// Seals issued under the prior generation.
    pub fn validate_for_subject(
        &self,
        subject: &ApprovalSubject,
        now_unix_ms: u64,
        current_revocation_generation: u64,
    ) -> Result<(), ExecutionModelError> {
        self.validate()?;
        subject.validate()?;
        if self.approval_subject_digest != subject.digest()?
            || self.capsule_kind != subject.capsule_kind
            || self.capsule_digest != subject.capsule_digest
        {
            return Err(ExecutionModelError::SealSubjectMismatch);
        }
        if now_unix_ms < self.issued_unix_ms {
            return Err(ExecutionModelError::SealNotYetValid);
        }
        if now_unix_ms >= self.expires_unix_ms {
            return Err(ExecutionModelError::SealExpired);
        }
        if self.revocation_generation != current_revocation_generation {
            return Err(ExecutionModelError::SealRevoked {
                expected: current_revocation_generation,
                actual: self.revocation_generation,
            });
        }
        Ok(())
    }

    /// Canonical bytes covered by the external signature. The signature itself
    /// is excluded to avoid a circular signing input.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        self.validate_unsigned()?;
        canonical::canonical_bytes(&SealSigningPayload::from(self))
    }

    /// Canonical signed Seal envelope, including signature bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<ContentDigest, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_digest(self)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SealSigningPayload<'a> {
    schema_version: u32,
    approval_subject_digest: &'a ContentDigest,
    capsule_kind: CapsuleKind,
    capsule_digest: &'a ContentDigest,
    signer_identity: &'a str,
    authority_identity: &'a str,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
    revocation_generation: u64,
    signature_algorithm: &'a str,
    signing_key_id: &'a ContentDigest,
}

impl<'a> From<&'a Seal> for SealSigningPayload<'a> {
    fn from(seal: &'a Seal) -> Self {
        Self {
            schema_version: seal.schema_version,
            approval_subject_digest: &seal.approval_subject_digest,
            capsule_kind: seal.capsule_kind,
            capsule_digest: &seal.capsule_digest,
            signer_identity: &seal.signer_identity,
            authority_identity: &seal.authority_identity,
            issued_unix_ms: seal.issued_unix_ms,
            expires_unix_ms: seal.expires_unix_ms,
            revocation_generation: seal.revocation_generation,
            signature_algorithm: &seal.signature_algorithm,
            signing_key_id: &seal.signing_key_id,
        }
    }
}
