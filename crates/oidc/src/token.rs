use base64ct::{Base64UrlUnpadded, Encoding as _};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::OidcError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintTokenRequest {
    pub audience: String,
    pub ttl_seconds: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintedOidcToken {
    pub token: String,
    pub expires_unix_seconds: u64,
    pub jti: String,
    pub key_id: ContentDigest,
}

impl fmt::Debug for MintedOidcToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MintedOidcToken")
            .field("token", &"[REDACTED]")
            .field("expires_unix_seconds", &self.expires_unix_seconds)
            .field("jti", &self.jti)
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl fmt::Display for MintedOidcToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MintedOidcToken([REDACTED])")
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JwtHeader {
    #[serde(rename = "alg")]
    pub(crate) algorithm: String,
    #[serde(rename = "typ")]
    pub(crate) token_type: String,
    #[serde(rename = "kid")]
    pub(crate) key_id: String,
}

pub(crate) fn random_jti() -> Result<String, OidcError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| OidcError::RandomnessUnavailable)?;
    Ok(Base64UrlUnpadded::encode_string(&bytes))
}
