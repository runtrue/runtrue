use rand_core::{OsRng, RngCore};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

pub(crate) const KEY_BYTES: usize = 32;

/// Plaintext secret bytes which are redacted from diagnostics and zeroized.
pub struct SecretPlaintext(Zeroizing<Vec<u8>>);

impl SecretPlaintext {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretPlaintext {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl fmt::Debug for SecretPlaintext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretPlaintext([REDACTED])")
    }
}

/// A 256-bit key-encryption key, redacted from diagnostics and zeroized.
pub struct MasterKey(Zeroizing<[u8; KEY_BYTES]>);

impl MasterKey {
    /// Generate a key from the operating system CSPRNG.
    pub fn generate() -> Result<Self, SensitiveError> {
        let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
        OsRng
            .try_fill_bytes(&mut *bytes)
            .map_err(|_| SensitiveError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Wrap caller-provided key bytes in the redacted, zeroizing key type.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }

    /// Explicitly duplicate key material for a second in-process crypto
    /// boundary. This remains non-`Clone` so accidental copies are rejected.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self::from_bytes(*self.as_bytes())
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    pub(crate) fn from_zeroizing(bytes: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKey([REDACTED])")
    }
}

/// Failure to initialize a sensitive wrapper safely.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SensitiveError {
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
}
