use super::{validation::validate_identifier, ImageAttestError, ImageVerifyingKey};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::canonicalize_value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const UPDATE_METADATA_MEDIA_TYPE: &str =
    "application/vnd.runtrue.update-metadata+canonical-json;version=1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTarget {
    pub manifest_digest: ContentDigest,
    pub payload_digest: ContentDigest,
    pub payload_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMetadata {
    pub metadata_version: u32,
    pub channel: String,
    /// Strictly increasing per channel; clients persist the highest accepted
    /// generation and reject rollback even if an old signature is valid.
    pub generation: u64,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub targets: BTreeMap<String, UpdateTarget>,
}

impl UpdateMetadata {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ImageAttestError> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        Ok(serde_json::to_vec(&canonicalize_value(value))?)
    }

    pub fn digest(&self) -> Result<ContentDigest, ImageAttestError> {
        Ok(ContentDigest::sha256(self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSignature {
    pub key_id: ContentDigest,
    pub metadata_digest: ContentDigest,
    pub media_type: String,
    pub algorithm: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedUpdateMetadata {
    pub metadata: UpdateMetadata,
    pub signatures: Vec<UpdateSignature>,
}

/// Persist this state outside the update directory. Accepting metadata is a
/// mutating operation so callers cannot accidentally verify without recording
/// the rollback fence.
#[derive(Debug, Clone)]
pub struct TrustedUpdateState {
    channel: String,
    highest_generation: u64,
    threshold: usize,
    trusted_keys: BTreeMap<ContentDigest, ImageVerifyingKey>,
}

impl TrustedUpdateState {
    pub fn new(
        channel: impl Into<String>,
        highest_generation: u64,
        threshold: usize,
        trusted_keys: impl IntoIterator<Item = ImageVerifyingKey>,
    ) -> Result<Self, ImageAttestError> {
        let channel = channel.into();
        validate_identifier("trusted update channel", &channel)?;
        let trusted_keys: BTreeMap<_, _> = trusted_keys
            .into_iter()
            .map(|key| (key.key_id(), key))
            .collect();
        if threshold == 0 || threshold > trusted_keys.len() {
            return Err(ImageAttestError::InvalidTrustThreshold);
        }
        Ok(Self {
            channel,
            highest_generation,
            threshold,
            trusted_keys,
        })
    }

    #[must_use]
    pub const fn highest_generation(&self) -> u64 {
        self.highest_generation
    }

    pub fn verify_and_advance(
        &mut self,
        signed: &SignedUpdateMetadata,
        now_unix_ms: u64,
    ) -> Result<ContentDigest, ImageAttestError> {
        signed.metadata.validate()?;
        if signed.metadata.channel != self.channel {
            return Err(ImageAttestError::WrongUpdateChannel);
        }
        if now_unix_ms < signed.metadata.issued_unix_ms
            || now_unix_ms >= signed.metadata.expires_unix_ms
        {
            return Err(ImageAttestError::UpdateMetadataExpired);
        }
        if signed.metadata.generation <= self.highest_generation {
            return Err(ImageAttestError::UpdateRollback {
                highest: self.highest_generation,
                offered: signed.metadata.generation,
            });
        }
        if signed.signatures.len() > self.trusted_keys.len().saturating_mul(2).max(16) {
            return Err(ImageAttestError::SignatureLimitExceeded);
        }
        let expected_digest = signed.metadata.digest()?;
        let mut verified = BTreeMap::new();
        for signature in &signed.signatures {
            if signature.metadata_digest != expected_digest {
                return Err(ImageAttestError::ObjectDigestMismatch);
            }
            let Some(key) = self.trusted_keys.get(&signature.key_id) else {
                continue;
            };
            if verified.contains_key(&signature.key_id) {
                return Err(ImageAttestError::DuplicateUpdateSignature);
            }
            key.verify_update(&signed.metadata, signature)?;
            verified.insert(signature.key_id.clone(), ());
        }
        if verified.len() < self.threshold {
            return Err(ImageAttestError::UpdateSignatureThreshold {
                required: self.threshold,
                verified: verified.len(),
            });
        }
        self.highest_generation = signed.metadata.generation;
        Ok(expected_digest)
    }
}
