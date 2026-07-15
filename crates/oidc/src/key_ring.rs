use base64ct::{Base64UrlUnpadded, Encoding as _};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{
    validation::validate_issuer, OidcError, OidcVerifyingKey, KEY_RING_SNAPSHOT_VERSION,
    MAX_KEY_RING_SNAPSHOT_BYTES, MAX_RETAINED_SIGNING_KEYS, MAX_REVOKED_SIGNING_KEY_IDS,
    MAX_SIGNING_KEY_OVERLAP_SECONDS, MAX_TOKEN_TTL_SECONDS,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcActiveSigningKeyRecord {
    pub key_id: ContentDigest,
    pub public_key: String,
    pub activated_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcRetiredSigningKeyRecord {
    pub key_id: ContentDigest,
    pub public_key: String,
    pub activated_unix_seconds: u64,
    pub retired_unix_seconds: u64,
    pub publish_until_unix_seconds: u64,
    pub maximum_token_ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcRevokedSigningKeyRecord {
    pub key_id: ContentDigest,
    pub revoked_unix_seconds: u64,
}

/// Durable public lifecycle state. Active private signing material is
/// intentionally stored and recovered through a separate secret/KMS boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcKeyRingSnapshot {
    pub schema_version: u32,
    pub issuer: String,
    pub generation: u64,
    pub maximum_ttl_seconds: u64,
    pub updated_unix_seconds: u64,
    pub active: OidcActiveSigningKeyRecord,
    pub retired: Vec<OidcRetiredSigningKeyRecord>,
    pub revoked: Vec<OidcRevokedSigningKeyRecord>,
}

impl OidcKeyRingSnapshot {
    pub fn from_json(bytes: &[u8]) -> Result<Self, OidcError> {
        if bytes.is_empty() || bytes.len() > MAX_KEY_RING_SNAPSHOT_BYTES {
            return Err(OidcError::KeyRingSnapshotTooLarge);
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        if serde_json::to_vec(&value)? != bytes {
            return Err(OidcError::NonCanonicalKeyRingSnapshot);
        }
        Ok(value)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, OidcError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_KEY_RING_SNAPSHOT_BYTES {
            return Err(OidcError::KeyRingSnapshotTooLarge);
        }
        Ok(bytes)
    }

    pub(crate) fn validate(&self) -> Result<(), OidcError> {
        validate_issuer(&self.issuer)?;
        if self.schema_version != KEY_RING_SNAPSHOT_VERSION {
            return Err(OidcError::UnsupportedKeyRingSnapshotVersion);
        }
        if self.generation == 0
            || self.maximum_ttl_seconds == 0
            || self.maximum_ttl_seconds > MAX_TOKEN_TTL_SECONDS
            || self.active.activated_unix_seconds > self.updated_unix_seconds
            || self.retired.len() > MAX_RETAINED_SIGNING_KEYS
            || self.revoked.len() > MAX_REVOKED_SIGNING_KEY_IDS
        {
            return Err(OidcError::InvalidKeyRingSnapshot);
        }

        let active = verifying_key_from_record(&self.active.key_id, &self.active.public_key)?;
        let mut seen = BTreeSet::from([active.key_id()]);
        let mut previous_retired = None;
        let mut newer_key_activated_unix_seconds = self.active.activated_unix_seconds;
        for retired in &self.retired {
            let key = verifying_key_from_record(&retired.key_id, &retired.public_key)?;
            retired
                .publish_until_unix_seconds
                .checked_sub(retired.retired_unix_seconds)
                .filter(|overlap| {
                    retired.maximum_token_ttl_seconds != 0
                        && retired.maximum_token_ttl_seconds <= MAX_TOKEN_TTL_SECONDS
                        && *overlap >= retired.maximum_token_ttl_seconds
                        && *overlap <= MAX_SIGNING_KEY_OVERLAP_SECONDS
                })
                .ok_or(OidcError::InvalidKeyRingSnapshot)?;
            if retired.retired_unix_seconds > newer_key_activated_unix_seconds
                || retired.activated_unix_seconds > retired.retired_unix_seconds
                || retired.retired_unix_seconds > self.updated_unix_seconds
                || !seen.insert(key.key_id())
            {
                return Err(OidcError::InvalidKeyRingSnapshot);
            }
            newer_key_activated_unix_seconds = retired.activated_unix_seconds;
            let order = (retired.retired_unix_seconds, retired.key_id.clone());
            if previous_retired
                .as_ref()
                .is_some_and(|previous| previous < &order)
            {
                return Err(OidcError::InvalidKeyRingSnapshot);
            }
            previous_retired = Some(order);
        }

        let mut previous_revoked = None;
        for revoked in &self.revoked {
            if revoked.revoked_unix_seconds > self.updated_unix_seconds
                || !seen.insert(revoked.key_id.clone())
            {
                return Err(OidcError::InvalidKeyRingSnapshot);
            }
            let order = (revoked.revoked_unix_seconds, revoked.key_id.clone());
            if previous_revoked
                .as_ref()
                .is_some_and(|previous| previous < &order)
            {
                return Err(OidcError::InvalidKeyRingSnapshot);
            }
            previous_revoked = Some(order);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcSigningKeyRotation {
    pub generation: u64,
    pub previous_key_id: ContentDigest,
    pub active_key_id: ContentDigest,
    pub rotated_unix_seconds: u64,
    pub previous_key_publish_until_unix_seconds: Option<u64>,
    pub emergency: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcSigningKeyRevocation {
    pub generation: u64,
    pub key_id: ContentDigest,
    pub revoked_unix_seconds: u64,
}

#[derive(Clone)]
pub(crate) struct RetiredSigningKey {
    pub(crate) key: OidcVerifyingKey,
    pub(crate) activated_unix_seconds: u64,
    pub(crate) retired_unix_seconds: u64,
    pub(crate) publish_until_unix_seconds: u64,
    pub(crate) maximum_token_ttl_seconds: u64,
}

pub(crate) fn verifying_key_from_record(
    expected_key_id: &ContentDigest,
    public_key: &str,
) -> Result<OidcVerifyingKey, OidcError> {
    let bytes = Base64UrlUnpadded::decode_vec(public_key).map_err(OidcError::Base64)?;
    let key = OidcVerifyingKey::from_bytes(&bytes)?;
    if &key.key_id() != expected_key_id {
        return Err(OidcError::SigningKeyContinuityMismatch);
    }
    Ok(key)
}

pub(crate) fn sort_retired_keys(keys: &mut [RetiredSigningKey]) {
    keys.sort_by(|left, right| {
        right
            .retired_unix_seconds
            .cmp(&left.retired_unix_seconds)
            .then_with(|| right.key.key_id().cmp(&left.key.key_id()))
    });
}

pub(crate) fn sort_revoked_keys(keys: &mut [OidcRevokedSigningKeyRecord]) {
    keys.sort_by(|left, right| {
        right
            .revoked_unix_seconds
            .cmp(&left.revoked_unix_seconds)
            .then_with(|| right.key_id.cmp(&left.key_id))
    });
}
