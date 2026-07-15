use crate::{canonical::canonical_bytes, AuditCheckpoint, AuditError, AuditEvent};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroize;

const SIGNATURE_DOMAIN: &[u8] = b"runtrue.audit.checkpoint.signature.v1\0";
pub const AUDIT_CHECKPOINT_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const AUDIT_CHECKPOINT_MEDIA_TYPE: &str =
    "application/vnd.runtrue.audit-checkpoint+canonical-json;version=1";

/// A purpose-separated installation key for periodic audit checkpoints.
pub struct AuditCheckpointSigningKey {
    seed: [u8; 32],
}

impl AuditCheckpointSigningKey {
    pub fn generate() -> Result<Self, AuditSignatureError> {
        let mut seed = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| AuditSignatureError::RandomnessUnavailable)?;
        Ok(Self { seed })
    }

    #[must_use]
    pub const fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    #[must_use]
    pub fn verifying_key(&self) -> AuditCheckpointVerifyingKey {
        AuditCheckpointVerifyingKey(SigningKey::from_bytes(&self.seed).verifying_key())
    }

    pub fn sign(
        &self,
        checkpoint: &AuditCheckpoint,
    ) -> Result<SignedAuditCheckpoint, AuditSignatureError> {
        let canonical = canonical_bytes(checkpoint)?;
        let signature =
            SigningKey::from_bytes(&self.seed).sign(&signature_message(checkpoint, &canonical));
        Ok(SignedAuditCheckpoint {
            signature_version: 1,
            media_type: AUDIT_CHECKPOINT_MEDIA_TYPE.to_owned(),
            algorithm: AUDIT_CHECKPOINT_SIGNATURE_ALGORITHM.to_owned(),
            key_id: self.verifying_key().key_id(),
            checkpoint: checkpoint.clone(),
            signature: signature.to_bytes().to_vec(),
        })
    }
}

impl Drop for AuditCheckpointSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl fmt::Debug for AuditCheckpointSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditCheckpointSigningKey(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuditCheckpointVerifyingKey(VerifyingKey);

impl AuditCheckpointVerifyingKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuditSignatureError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AuditSignatureError::InvalidPublicKeyLength(bytes.len()))?;
        Ok(Self(VerifyingKey::from_bytes(&bytes)?))
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    #[must_use]
    pub fn key_id(&self) -> ContentDigest {
        ContentDigest::sha256(self.to_bytes())
    }

    pub fn verify(
        &self,
        signed: &SignedAuditCheckpoint,
        events: &[AuditEvent],
    ) -> Result<(), AuditSignatureError> {
        if signed.signature_version != 1
            || signed.media_type != AUDIT_CHECKPOINT_MEDIA_TYPE
            || signed.algorithm != AUDIT_CHECKPOINT_SIGNATURE_ALGORITHM
            || signed.key_id != self.key_id()
        {
            return Err(AuditSignatureError::SignatureMetadataMismatch);
        }
        let canonical = canonical_bytes(&signed.checkpoint)?;
        let signature_bytes: [u8; 64] = signed
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AuditSignatureError::InvalidSignatureLength(signed.signature.len()))?;
        self.0.verify(
            &signature_message(&signed.checkpoint, &canonical),
            &Signature::from_bytes(&signature_bytes),
        )?;
        signed.checkpoint.verify(events)?;
        Ok(())
    }
}

impl fmt::Debug for AuditCheckpointVerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditCheckpointVerifyingKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditCheckpoint {
    pub signature_version: u32,
    pub media_type: String,
    pub algorithm: String,
    pub key_id: ContentDigest,
    pub checkpoint: AuditCheckpoint,
    pub signature: Vec<u8>,
}

fn signature_message(checkpoint: &AuditCheckpoint, canonical: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical.len() + 160);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(AUDIT_CHECKPOINT_MEDIA_TYPE.as_bytes());
    message.push(0);
    message.extend_from_slice(checkpoint.checkpoint_hash.as_str().as_bytes());
    message.push(0);
    message.extend_from_slice(canonical);
    message
}

#[derive(Debug, Error)]
pub enum AuditSignatureError {
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid audit checkpoint public key length {0}; expected 32 bytes")]
    InvalidPublicKeyLength(usize),
    #[error("invalid audit checkpoint signature length {0}; expected 64 bytes")]
    InvalidSignatureLength(usize),
    #[error("audit checkpoint signature metadata does not match its verification key")]
    SignatureMetadataMismatch,
    #[error("audit checkpoint signature verification failed: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("audit checkpoint validation failed: {0}")]
    Audit(#[from] AuditError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{checkpoint, AuditEventData, AuditPrincipal, AuditResource};
    use std::collections::BTreeMap;

    fn events() -> Vec<AuditEvent> {
        let data = AuditEventData {
            observed_unix_ms: 1,
            tenant_id: "tenant".to_owned(),
            actor: AuditPrincipal {
                kind: "service".to_owned(),
                id: "server".to_owned(),
            },
            action: "policy.activate".to_owned(),
            resource: AuditResource {
                kind: "policy".to_owned(),
                id: "policy-1".to_owned(),
            },
            result: "success".to_owned(),
            request_id: "request-1".to_owned(),
            decision_id: None,
            metadata: BTreeMap::new(),
        };
        vec![AuditEvent::create(1, "installation".to_owned(), None, data).unwrap()]
    }

    #[test]
    fn checkpoint_signature_binds_key_chain_and_exact_checkpoint() {
        let events = events();
        let checkpoint = checkpoint(&events).unwrap();
        let key = AuditCheckpointSigningKey::from_seed([7; 32]);
        let signed = key.sign(&checkpoint).unwrap();
        key.verifying_key().verify(&signed, &events).unwrap();
        assert_eq!(format!("{key:?}"), "AuditCheckpointSigningKey(<redacted>)");

        let mut tampered = signed.clone();
        tampered.checkpoint.through_sequence += 1;
        assert!(key.verifying_key().verify(&tampered, &events).is_err());
        let other = AuditCheckpointSigningKey::from_seed([8; 32]).verifying_key();
        assert!(matches!(
            other.verify(&signed, &events),
            Err(AuditSignatureError::SignatureMetadataMismatch)
        ));
    }

    #[test]
    fn a_valid_signature_cannot_hide_chain_tampering() {
        let mut events = events();
        let key = AuditCheckpointSigningKey::from_seed([9; 32]);
        let signed = key.sign(&checkpoint(&events).unwrap()).unwrap();
        events[0].data.result = "tampered".to_owned();
        assert!(matches!(
            key.verifying_key().verify(&signed, &events),
            Err(AuditSignatureError::Audit(_))
        ));
    }
}
