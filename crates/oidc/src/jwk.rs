use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{OidcError, OidcVerifyingKey, MAX_JWKS_BYTES, MAX_RETAINED_SIGNING_KEYS};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jwk {
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "crv")]
    pub curve: String,
    #[serde(rename = "alg")]
    pub algorithm: String,
    #[serde(rename = "use")]
    pub key_use: String,
    #[serde(rename = "kid")]
    pub key_id: String,
    pub x: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn from_json(bytes: &[u8]) -> Result<Self, OidcError> {
        if bytes.is_empty() || bytes.len() > MAX_JWKS_BYTES {
            return Err(OidcError::JwksTooLarge);
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validating_keys()?;
        Ok(value)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, OidcError> {
        self.validating_keys()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_JWKS_BYTES {
            return Err(OidcError::JwksTooLarge);
        }
        Ok(bytes)
    }

    pub fn verifying_key(&self, key_id: &ContentDigest) -> Result<OidcVerifyingKey, OidcError> {
        self.validating_keys()?
            .remove(key_id)
            .ok_or(OidcError::UnknownSigningKey)
    }

    pub(crate) fn validating_keys(
        &self,
    ) -> Result<BTreeMap<ContentDigest, OidcVerifyingKey>, OidcError> {
        if self.keys.is_empty() || self.keys.len() > MAX_RETAINED_SIGNING_KEYS.saturating_add(1) {
            return Err(OidcError::InvalidJwks);
        }
        let mut keys = BTreeMap::new();
        for jwk in &self.keys {
            let key = OidcVerifyingKey::from_jwk(jwk)?;
            if keys.insert(key.key_id(), key).is_some() {
                return Err(OidcError::DuplicateSigningKey);
            }
        }
        Ok(keys)
    }
}
