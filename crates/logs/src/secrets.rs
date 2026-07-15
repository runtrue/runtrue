/// Installation-supplied key used only for exact input-frame replay digests.
///
/// The journal stores HMAC output, never this key. Key bytes are zeroized when
/// the value is dropped and are intentionally unavailable through `Debug`.
pub struct InputDigestKey(Zeroizing<Vec<u8>>);

impl InputDigestKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, LogError> {
        let bytes = Zeroizing::new(bytes);
        if !(MIN_INPUT_DIGEST_KEY_BYTES..=MAX_INPUT_DIGEST_KEY_BYTES).contains(&bytes.len()) {
            return Err(LogError::InvalidInputDigestKey);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for InputDigestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputDigestKey(<redacted>)")
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SecretPattern(Vec<u8>);

impl SecretPattern {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretPattern {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct SecretMaterial {
    patterns: Vec<SecretPattern>,
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        // `SecretPattern::drop` zeroizes every allocation. Clearing here also
        // ensures that happens before the enclosing allocation is released.
        self.patterns.clear();
    }
}

/// Secret patterns are shared without copying and are intentionally opaque to
/// `Debug` and error messages. Their backing allocations are zeroized on drop.
pub struct SecretSet {
    material: Arc<SecretMaterial>,
    pub(crate) max_pattern_bytes: usize,
}

impl Clone for SecretSet {
    fn clone(&self) -> Self {
        Self {
            material: Arc::clone(&self.material),
            max_pattern_bytes: self.max_pattern_bytes,
        }
    }
}

impl SecretSet {
    pub fn new(patterns: Vec<Vec<u8>>, limits: LogLimits) -> Result<Self, LogError> {
        let patterns = patterns.into_iter().map(SecretPattern).collect::<Vec<_>>();
        if patterns.len() > limits.max_secrets {
            return Err(LogError::InvalidSecrets);
        }
        let mut unique = BTreeSet::new();
        for pattern in patterns {
            if pattern.is_empty() || pattern.len() > limits.max_secret_bytes {
                return Err(LogError::InvalidSecrets);
            }
            unique.insert(pattern);
        }
        let mut patterns = unique.into_iter().collect::<Vec<_>>();
        patterns.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        let max_pattern_bytes = patterns.iter().map(SecretPattern::len).max().unwrap_or(0);
        Ok(Self {
            material: Arc::new(SecretMaterial { patterns }),
            max_pattern_bytes,
        })
    }

    #[must_use]
    pub fn empty() -> Self {
        Self {
            material: Arc::new(SecretMaterial {
                patterns: Vec::new(),
            }),
            max_pattern_bytes: 0,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.material.patterns.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.material.patterns.is_empty()
    }

    pub(crate) fn patterns(&self) -> &[SecretPattern] {
        &self.material.patterns
    }
}

impl fmt::Debug for SecretSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretSet")
            .field("pattern_count", &self.material.patterns.len())
            .field("max_pattern_bytes", &self.max_pattern_bytes)
            .finish()
    }
}
use crate::{
    pipeline::{MAX_INPUT_DIGEST_KEY_BYTES, MIN_INPUT_DIGEST_KEY_BYTES},
    LogError, LogLimits,
};
use std::{collections::BTreeSet, fmt, sync::Arc};
use zeroize::{Zeroize as _, Zeroizing};
