use crate::AuthError;
use hmac::{Hmac, Mac as _};
use rand_core::{OsRng, RngCore as _};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const TOKEN_DOMAIN: &[u8] = b"runtrue.authentication.token.v1\0";
const TOKEN_BYTES: usize = 32;
/// A browser session is deliberately bounded instead of forgetting old
/// refresh credentials. Forgetting a consumed credential would turn an old
/// replay into an indistinguishable random failure and leave the family live.
/// At the bound the family is revoked and the user must authenticate again.
pub const MAX_USED_REFRESH_DIGESTS: usize = 1024;

/// One-time plaintext token material.
pub struct SecretToken(Zeroizing<String>);

impl SecretToken {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretToken([REDACTED])")
    }
}

/// Persistable keyed digest of a token. This is not a content digest.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenDigest([u8; 32]);

impl fmt::Debug for TokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenDigest([REDACTED])")
    }
}

impl TokenDigest {
    /// Canonical keyed lookup value suitable for a unique database column.
    ///
    /// This is deliberately not a content digest and remains installation-key
    /// specific. It cannot be used to authenticate without the installation
    /// token-hashing key.
    #[must_use]
    pub fn storage_key(&self) -> String {
        format!("hmac-sha256:{}", hex::encode(self.0))
    }
}

impl Serialize for TokenDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("hmac-sha256:{}", hex::encode(self.0)))
    }
}

impl<'de> Deserialize<'de> for TokenDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let encoded = value
            .strip_prefix("hmac-sha256:")
            .ok_or_else(|| D::Error::custom("token digest must use hmac-sha256"))?;
        let decoded = hex::decode(encoded).map_err(D::Error::custom)?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| D::Error::custom("token digest must contain exactly 32 bytes"))?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenKind {
    Api,
    Access,
    Refresh,
    Csrf,
    OidcState,
    OidcNonce,
    OidcPkceVerifier,
}

impl TokenKind {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Api => b"api",
            Self::Access => b"access",
            Self::Refresh => b"refresh",
            Self::Csrf => b"csrf",
            Self::OidcState => b"oidc-state",
            Self::OidcNonce => b"oidc-nonce",
            Self::OidcPkceVerifier => b"oidc-pkce-verifier",
        }
    }
}

/// Installation-owned key used to make database token hashes non-portable.
pub struct TokenHasher {
    key: Zeroizing<[u8; 32]>,
}

impl TokenHasher {
    pub fn generate() -> Result<Self, AuthError> {
        let mut key = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(&mut *key)
            .map_err(|_| AuthError::RandomnessUnavailable)?;
        Ok(Self { key })
    }

    #[must_use]
    pub fn from_key(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    pub(crate) fn digest(&self, kind: TokenKind, token: &str) -> TokenDigest {
        let mut mac = HmacSha256::new_from_slice(&*self.key).expect("HMAC accepts a 32-byte key");
        mac.update(TOKEN_DOMAIN);
        mac.update(kind.label());
        mac.update(&[0]);
        mac.update(token.as_bytes());
        TokenDigest(mac.finalize().into_bytes().into())
    }

    /// Derive the indexed keyed digest for an opaque API bearer token.
    #[must_use]
    pub fn api_token_digest(&self, token: &str) -> TokenDigest {
        self.digest(TokenKind::Api, token)
    }

    pub(crate) fn verify(&self, kind: TokenKind, token: &str, expected: &TokenDigest) -> bool {
        let mut mac = HmacSha256::new_from_slice(&*self.key).expect("HMAC accepts a 32-byte key");
        mac.update(TOKEN_DOMAIN);
        mac.update(kind.label());
        mac.update(&[0]);
        mac.update(token.as_bytes());
        mac.verify_slice(&expected.0).is_ok()
    }
}

impl fmt::Debug for TokenHasher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenHasher([REDACTED])")
    }
}

pub(crate) fn generate_token() -> Result<SecretToken, AuthError> {
    let mut bytes = Zeroizing::new([0_u8; TOKEN_BYTES]);
    OsRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|_| AuthError::RandomnessUnavailable)?;
    let encoded = hex::encode(bytes.as_slice());
    Ok(SecretToken(Zeroizing::new(encoded)))
}
