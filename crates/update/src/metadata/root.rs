#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleAssignment {
    pub key_ids: BTreeSet<ContentDigest>,
    pub threshold: u16,
}

impl RoleAssignment {
    pub(crate) fn validate(
        &self,
        keys: &BTreeMap<ContentDigest, UpdatePublicKey>,
    ) -> Result<(), UpdateError> {
        if self.key_ids.is_empty()
            || self.threshold == 0
            || usize::from(self.threshold) > self.key_ids.len()
            || !self.key_ids.iter().all(|key| keys.contains_key(key))
        {
            return Err(UpdateError::InvalidRoleAssignment);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootMetadata {
    pub header: MetadataHeader,
    pub keys: BTreeMap<ContentDigest, UpdatePublicKey>,
    pub roles: BTreeMap<RoleType, RoleAssignment>,
}

impl RootMetadata {
    pub fn validate_structure(&self) -> Result<(), UpdateError> {
        self.header.validate_structure(RoleType::Root)?;
        if self.keys.is_empty()
            || self.keys.len() > MAX_ROOT_KEYS
            || self.roles.len() != RoleType::ALL.len()
        {
            return Err(UpdateError::InvalidRootMetadata);
        }
        for (key_id, key) in &self.keys {
            if &key.key_id()? != key_id {
                return Err(UpdateError::KeyIdMismatch);
            }
        }
        let mut assigned = BTreeSet::new();
        for role in RoleType::ALL {
            let assignment = self
                .roles
                .get(&role)
                .ok_or(UpdateError::MissingRoleAssignment(role))?;
            assignment.validate(&self.keys)?;
            for key_id in &assignment.key_ids {
                if !assigned.insert(key_id.clone()) {
                    return Err(UpdateError::RoleKeyReuse);
                }
            }
        }
        if assigned.len() != self.keys.len() {
            return Err(UpdateError::UnassignedRootKey);
        }
        Ok(())
    }

    pub(crate) fn validate_at(&self, now_unix_seconds: u64) -> Result<(), UpdateError> {
        self.validate_structure()?;
        self.header.validate_at(RoleType::Root, now_unix_seconds)
    }
}
use crate::{MetadataHeader, RoleType, UpdateError, UpdatePublicKey, MAX_ROOT_KEYS};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
