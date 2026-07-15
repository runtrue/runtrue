use crate::ModelError;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{fmt, str::FromStr};

/// The digest algorithm used by the v0.x Capsule identity contract.
pub const DIGEST_ALGORITHM: &str = "sha256";

/// An algorithm-qualified, lowercase content digest.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContentDigest(String);

impl ContentDigest {
    #[must_use]
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = Sha256::digest(bytes.as_ref());
        Self(format!("{DIGEST_ALGORITHM}:{}", hex::encode(bytes)))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let Some(encoded) = value.strip_prefix("sha256:") else {
            return Err(ModelError::UnsupportedDigestAlgorithm);
        };
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ContentDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ContentDigest {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for ContentDigest {
    type Error = ModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<ContentDigest> for String {
    fn from(value: ContentDigest) -> Self {
        value.0
    }
}
