use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use std::fmt;
use zeroize::Zeroize;

use crate::{Jwk, OidcError, JWT_ALGORITHM};

pub struct OidcSigningKey {
    seed: [u8; 32],
}

impl OidcSigningKey {
    pub fn generate() -> Result<Self, OidcError> {
        let mut seed = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| OidcError::RandomnessUnavailable)?;
        Ok(Self { seed })
    }

    #[must_use]
    pub const fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    #[must_use]
    pub fn verifying_key(&self) -> OidcVerifyingKey {
        OidcVerifyingKey(SigningKey::from_bytes(&self.seed).verifying_key())
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed).sign(message).to_bytes()
    }
}

impl Drop for OidcSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl fmt::Debug for OidcSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OidcSigningKey([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct OidcVerifyingKey(VerifyingKey);

impl OidcVerifyingKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OidcError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| OidcError::InvalidPublicKeyLength(bytes.len()))?;
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

    #[must_use]
    pub fn jwk(&self) -> Jwk {
        Jwk {
            key_type: "OKP".to_owned(),
            curve: "Ed25519".to_owned(),
            algorithm: JWT_ALGORITHM.to_owned(),
            key_use: "sig".to_owned(),
            key_id: self.key_id().to_string(),
            x: Base64UrlUnpadded::encode_string(&self.to_bytes()),
        }
    }

    pub fn from_jwk(jwk: &Jwk) -> Result<Self, OidcError> {
        if jwk.key_type != "OKP"
            || jwk.curve != "Ed25519"
            || jwk.algorithm != JWT_ALGORITHM
            || jwk.key_use != "sig"
        {
            return Err(OidcError::InvalidJwk);
        }
        let key_id = ContentDigest::parse(jwk.key_id.clone()).map_err(|_| OidcError::InvalidJwk)?;
        let bytes = Base64UrlUnpadded::decode_vec(&jwk.x).map_err(OidcError::Base64)?;
        let key = Self::from_bytes(&bytes)?;
        if key.key_id() != key_id {
            return Err(OidcError::InvalidJwk);
        }
        Ok(key)
    }

    pub(crate) fn verify(
        &self,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), ed25519_dalek::SignatureError> {
        self.0.verify(message, &Signature::from_bytes(signature))
    }
}

impl fmt::Debug for OidcVerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcVerifyingKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}
