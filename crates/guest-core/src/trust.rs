use crate::GuestError;
use runtrue_attest::CapsuleVerifyingKey;
use runtrue_model::ContentDigest;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct GuestCapsuleTrustStore {
    keys: BTreeMap<ContentDigest, CapsuleVerifyingKey>,
}

impl GuestCapsuleTrustStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: CapsuleVerifyingKey) -> Result<(), GuestError> {
        let key_id = key.key_id();
        if self.keys.insert(key_id.clone(), key).is_some() {
            return Err(GuestError::DuplicateCapsuleKey(key_id));
        }
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub(crate) fn get(&self, key_id: &ContentDigest) -> Result<&CapsuleVerifyingKey, GuestError> {
        self.keys
            .get(key_id)
            .ok_or_else(|| GuestError::UntrustedCapsuleKey(key_id.clone()))
    }
}
