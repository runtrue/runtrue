#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePublicKey {
    pub algorithm: String,
    pub public_key_hex: String,
}

impl UpdatePublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            algorithm: UPDATE_SIGNATURE_ALGORITHM.to_owned(),
            public_key_hex: hex::encode(bytes),
        }
    }

    pub fn key_id(&self) -> Result<ContentDigest, UpdateError> {
        Ok(ContentDigest::sha256(self.verifying_key()?.to_bytes()))
    }

    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey, UpdateError> {
        if self.algorithm != UPDATE_SIGNATURE_ALGORITHM
            || self.public_key_hex.len() != 64
            || !is_lower_hex(&self.public_key_hex)
        {
            return Err(UpdateError::InvalidPublicKey);
        }
        let bytes = hex::decode(&self.public_key_hex).map_err(|_| UpdateError::InvalidPublicKey)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| UpdateError::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| UpdateError::InvalidPublicKey)
    }
}

impl fmt::Debug for UpdatePublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdatePublicKey")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id().ok())
            .finish()
    }
}

pub struct UpdateSigningKey {
    seed: [u8; 32],
}

impl UpdateSigningKey {
    pub fn generate() -> Result<Self, UpdateError> {
        let mut seed = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| UpdateError::RandomnessUnavailable)?;
        Ok(Self { seed })
    }

    #[must_use]
    pub const fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    #[must_use]
    pub fn public_key(&self) -> UpdatePublicKey {
        UpdatePublicKey::from_bytes(
            SigningKey::from_bytes(&self.seed)
                .verifying_key()
                .to_bytes(),
        )
    }

    #[must_use]
    pub fn key_id(&self) -> ContentDigest {
        ContentDigest::sha256(
            SigningKey::from_bytes(&self.seed)
                .verifying_key()
                .to_bytes(),
        )
    }

    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

impl Drop for UpdateSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl fmt::Debug for UpdateSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UpdateSigningKey(<redacted>)")
    }
}
use crate::{is_lower_hex, UpdateError, UPDATE_SIGNATURE_ALGORITHM};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;
