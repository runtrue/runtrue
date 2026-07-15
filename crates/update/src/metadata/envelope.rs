pub trait RoleMetadata: Serialize + Clone {
    fn role(&self) -> RoleType;
    fn validate_structure(&self) -> Result<(), UpdateError>;
}

impl RoleMetadata for RootMetadata {
    fn role(&self) -> RoleType {
        RoleType::Root
    }

    fn validate_structure(&self) -> Result<(), UpdateError> {
        Self::validate_structure(self)
    }
}

impl RoleMetadata for TargetsMetadata {
    fn role(&self) -> RoleType {
        RoleType::Targets
    }

    fn validate_structure(&self) -> Result<(), UpdateError> {
        Self::validate_structure(self)
    }
}

impl RoleMetadata for SnapshotMetadata {
    fn role(&self) -> RoleType {
        RoleType::Snapshot
    }

    fn validate_structure(&self) -> Result<(), UpdateError> {
        Self::validate_structure(self)
    }
}

impl RoleMetadata for TimestampMetadata {
    fn role(&self) -> RoleType {
        RoleType::Timestamp
    }

    fn validate_structure(&self) -> Result<(), UpdateError> {
        Self::validate_structure(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataSignature {
    pub key_id: ContentDigest,
    pub algorithm: String,
    pub signature_hex: String,
}

impl MetadataSignature {
    pub(crate) fn signature(&self) -> Result<Signature, UpdateError> {
        if self.algorithm != UPDATE_SIGNATURE_ALGORITHM
            || self.signature_hex.len() != 128
            || !is_lower_hex(&self.signature_hex)
        {
            return Err(UpdateError::InvalidSignatureEncoding);
        }
        let bytes =
            hex::decode(&self.signature_hex).map_err(|_| UpdateError::InvalidSignatureEncoding)?;
        let bytes: [u8; 64] = bytes
            .try_into()
            .map_err(|_| UpdateError::InvalidSignatureEncoding)?;
        Ok(Signature::from_bytes(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope<T> {
    pub signed: T,
    pub signatures: Vec<MetadataSignature>,
}

impl<T: RoleMetadata> SignedEnvelope<T> {
    pub fn unsigned(signed: T) -> Result<Self, UpdateError> {
        signed.validate_structure()?;
        Ok(Self {
            signed,
            signatures: Vec::new(),
        })
    }

    pub fn sign(mut self, key: &UpdateSigningKey) -> Result<Self, UpdateError> {
        self.signed.validate_structure()?;
        if self.signatures.len() >= MAX_SIGNATURES
            || self
                .signatures
                .iter()
                .any(|signature| signature.key_id == key.key_id())
        {
            return Err(UpdateError::DuplicateOrExcessSignature);
        }
        let message = signature_message(self.signed.role(), &self.signed)?;
        let signature = SigningKey::from_bytes(key.seed()).sign(&message);
        self.signatures.push(MetadataSignature {
            key_id: key.key_id(),
            algorithm: UPDATE_SIGNATURE_ALGORITHM.to_owned(),
            signature_hex: hex::encode(signature.to_bytes()),
        });
        self.signatures
            .sort_by(|left, right| left.key_id.cmp(&right.key_id));
        Ok(self)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        canonical_bytes(self)
    }
}

use crate::{
    canonical_bytes, is_lower_hex, signature_message, RoleType, RootMetadata, SnapshotMetadata,
    TargetsMetadata, TimestampMetadata, UpdateError, UpdateSigningKey, MAX_SIGNATURES,
    UPDATE_SIGNATURE_ALGORITHM,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
