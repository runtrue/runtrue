use crate::RunnerAdmissionError;
use runtrue_attest::CapsuleVerifyingKey;
use runtrue_model::ContentDigest;
use std::collections::BTreeMap;

/// Public-key set trusted to authorize execution capsules.
#[derive(Debug, Clone, Default)]
pub struct CapsuleTrustStore {
    keys: BTreeMap<ContentDigest, CapsuleVerifyingKey>,
}

impl CapsuleTrustStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        key: CapsuleVerifyingKey,
    ) -> Result<ContentDigest, RunnerAdmissionError> {
        let key_id = key.key_id();
        if self.keys.insert(key_id.clone(), key).is_some() {
            return Err(RunnerAdmissionError::DuplicateSigningKey(key_id));
        }
        Ok(key_id)
    }

    #[must_use]
    pub fn contains(&self, key_id: &ContentDigest) -> bool {
        self.keys.contains_key(key_id)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub(crate) fn get(
        &self,
        key_id: &ContentDigest,
    ) -> Result<&CapsuleVerifyingKey, RunnerAdmissionError> {
        self.keys
            .get(key_id)
            .ok_or_else(|| RunnerAdmissionError::UntrustedSigningKey(key_id.clone()))
    }
}
