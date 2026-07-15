use crate::DebugSessionError;
use hmac::{Hmac, Mac as _};
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const TOKEN_DOMAIN: &[u8] = b"runtrue.debug-session.token.v1\0";
const TOKEN_BYTES: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct TunnelTokenDigest(pub(crate) [u8; 32]);

impl fmt::Debug for TunnelTokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TunnelTokenDigest([REDACTED])")
    }
}

impl Serialize for TunnelTokenDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("hmac-sha256:{}", hex::encode(self.0)))
    }
}

impl<'de> Deserialize<'de> for TunnelTokenDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let encoded = value
            .strip_prefix("hmac-sha256:")
            .ok_or_else(|| serde::de::Error::custom("invalid tunnel token digest"))?;
        let decoded = hex::decode(encoded).map_err(serde::de::Error::custom)?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid tunnel token digest"))?;
        Ok(Self(bytes))
    }
}

pub struct TunnelTokenKey(Zeroizing<[u8; 32]>);

impl TunnelTokenKey {
    pub fn generate() -> Result<Self, DebugSessionError> {
        let mut key = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(&mut *key)
            .map_err(|_| DebugSessionError::RandomnessUnavailable)?;
        Ok(Self(key))
    }

    #[must_use]
    pub fn from_key(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }

    pub(crate) fn digest(&self, session_id: &str, token: &str) -> TunnelTokenDigest {
        let mut mac = HmacSha256::new_from_slice(&*self.0).expect("HMAC accepts a 32-byte key");
        mac.update(TOKEN_DOMAIN);
        mac.update(session_id.as_bytes());
        mac.update(&[0]);
        mac.update(token.as_bytes());
        TunnelTokenDigest(mac.finalize().into_bytes().into())
    }

    pub(crate) fn verify(&self, session_id: &str, token: &str, digest: &TunnelTokenDigest) -> bool {
        let mut mac = HmacSha256::new_from_slice(&*self.0).expect("HMAC accepts a 32-byte key");
        mac.update(TOKEN_DOMAIN);
        mac.update(session_id.as_bytes());
        mac.update(&[0]);
        mac.update(token.as_bytes());
        mac.verify_slice(&digest.0).is_ok()
    }
}

impl fmt::Debug for TunnelTokenKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TunnelTokenKey([REDACTED])")
    }
}

pub struct OneUseTunnelToken(Zeroizing<String>);

impl OneUseTunnelToken {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OneUseTunnelToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OneUseTunnelToken([REDACTED])")
    }
}

pub(crate) fn generate_tunnel_token() -> Result<OneUseTunnelToken, DebugSessionError> {
    let mut bytes = Zeroizing::new([0_u8; TOKEN_BYTES]);
    OsRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|_| DebugSessionError::RandomnessUnavailable)?;
    Ok(OneUseTunnelToken(Zeroizing::new(hex::encode(
        bytes.as_slice(),
    ))))
}

pub(crate) fn valid_token_text(value: &str) -> bool {
    value.len() == TOKEN_BYTES * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
