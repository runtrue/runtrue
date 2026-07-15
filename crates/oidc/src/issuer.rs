use base64ct::{Base64UrlUnpadded, Encoding as _};
use runtrue_model::ContentDigest;
use std::fmt;

use crate::{
    claims::JwtClaims,
    discovery::OidcDiscoveryDocument,
    grant::OidcGrant,
    jwk::JwkSet,
    key_ring::{
        sort_retired_keys, sort_revoked_keys, verifying_key_from_record, RetiredSigningKey,
    },
    token::{random_jti, JwtHeader, MintTokenRequest, MintedOidcToken},
    validation::{validate_identifier, validate_issuer},
    verification::{token_key_id, verify_token},
    OidcActiveSigningKeyRecord, OidcError, OidcKeyRingSnapshot, OidcRetiredSigningKeyRecord,
    OidcRevokedSigningKeyRecord, OidcSigningKey, OidcSigningKeyRevocation, OidcSigningKeyRotation,
    JWT_ALGORITHM, JWT_TYPE, KEY_RING_SNAPSHOT_VERSION, MAX_RETAINED_SIGNING_KEYS,
    MAX_REVOKED_SIGNING_KEY_IDS, MAX_SIGNING_KEY_OVERLAP_SECONDS, MAX_TOKEN_BYTES,
    MAX_TOKEN_TTL_SECONDS,
};

pub struct OidcIssuer {
    issuer: String,
    pub(crate) signing_key: OidcSigningKey,
    maximum_ttl_seconds: u64,
    active_key_activated_unix_seconds: u64,
    retired_signing_keys: Vec<RetiredSigningKey>,
    revoked_signing_keys: Vec<OidcRevokedSigningKeyRecord>,
    key_ring_generation: u64,
    key_ring_updated_unix_seconds: u64,
}

impl OidcIssuer {
    pub fn new(issuer: String, signing_key: OidcSigningKey) -> Result<Self, OidcError> {
        Self::new_at(issuer, signing_key, 0)
    }

    pub fn new_at(
        issuer: String,
        signing_key: OidcSigningKey,
        activated_unix_seconds: u64,
    ) -> Result<Self, OidcError> {
        validate_issuer(&issuer)?;
        Ok(Self {
            issuer,
            signing_key,
            maximum_ttl_seconds: MAX_TOKEN_TTL_SECONDS,
            active_key_activated_unix_seconds: activated_unix_seconds,
            retired_signing_keys: Vec::new(),
            revoked_signing_keys: Vec::new(),
            key_ring_generation: 1,
            key_ring_updated_unix_seconds: activated_unix_seconds,
        })
    }

    pub fn from_key_ring_snapshot(
        signing_key: OidcSigningKey,
        snapshot: OidcKeyRingSnapshot,
    ) -> Result<Self, OidcError> {
        snapshot.validate()?;
        let active_key = signing_key.verifying_key();
        let snapshot_active =
            verifying_key_from_record(&snapshot.active.key_id, &snapshot.active.public_key)?;
        if active_key != snapshot_active {
            return Err(OidcError::SigningKeyContinuityMismatch);
        }
        let retired_signing_keys = snapshot
            .retired
            .iter()
            .map(|record| {
                Ok(RetiredSigningKey {
                    key: verifying_key_from_record(&record.key_id, &record.public_key)?,
                    activated_unix_seconds: record.activated_unix_seconds,
                    retired_unix_seconds: record.retired_unix_seconds,
                    publish_until_unix_seconds: record.publish_until_unix_seconds,
                    maximum_token_ttl_seconds: record.maximum_token_ttl_seconds,
                })
            })
            .collect::<Result<Vec<_>, OidcError>>()?;
        Ok(Self {
            issuer: snapshot.issuer,
            signing_key,
            maximum_ttl_seconds: snapshot.maximum_ttl_seconds,
            active_key_activated_unix_seconds: snapshot.active.activated_unix_seconds,
            retired_signing_keys,
            revoked_signing_keys: snapshot.revoked,
            key_ring_generation: snapshot.generation,
            key_ring_updated_unix_seconds: snapshot.updated_unix_seconds,
        })
    }

    pub fn set_maximum_ttl_seconds(&mut self, value: u64) -> Result<(), OidcError> {
        if value == 0 || value > MAX_TOKEN_TTL_SECONDS {
            return Err(OidcError::InvalidTtl);
        }
        if value == self.maximum_ttl_seconds {
            return Ok(());
        }
        let generation = self.next_key_ring_generation()?;
        self.maximum_ttl_seconds = value;
        self.key_ring_generation = generation;
        Ok(())
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn discovery_document(&self) -> OidcDiscoveryDocument {
        OidcDiscoveryDocument::for_issuer(&self.issuer)
    }

    #[must_use]
    pub const fn key_ring_generation(&self) -> u64 {
        self.key_ring_generation
    }

    #[must_use]
    pub fn active_key_id(&self) -> ContentDigest {
        self.signing_key.verifying_key().key_id()
    }

    #[must_use]
    pub fn key_ring_snapshot(&self) -> OidcKeyRingSnapshot {
        let active_key = self.signing_key.verifying_key();
        OidcKeyRingSnapshot {
            schema_version: KEY_RING_SNAPSHOT_VERSION,
            issuer: self.issuer.clone(),
            generation: self.key_ring_generation,
            maximum_ttl_seconds: self.maximum_ttl_seconds,
            updated_unix_seconds: self.key_ring_updated_unix_seconds,
            active: OidcActiveSigningKeyRecord {
                key_id: active_key.key_id(),
                public_key: Base64UrlUnpadded::encode_string(&active_key.to_bytes()),
                activated_unix_seconds: self.active_key_activated_unix_seconds,
            },
            retired: self
                .retired_signing_keys
                .iter()
                .map(|retired| OidcRetiredSigningKeyRecord {
                    key_id: retired.key.key_id(),
                    public_key: Base64UrlUnpadded::encode_string(&retired.key.to_bytes()),
                    activated_unix_seconds: retired.activated_unix_seconds,
                    retired_unix_seconds: retired.retired_unix_seconds,
                    publish_until_unix_seconds: retired.publish_until_unix_seconds,
                    maximum_token_ttl_seconds: retired.maximum_token_ttl_seconds,
                })
                .collect(),
            revoked: self.revoked_signing_keys.clone(),
        }
    }

    pub fn key_ring_snapshot_json(&self) -> Result<Vec<u8>, OidcError> {
        self.key_ring_snapshot().to_json()
    }

    pub fn jwks_at(&self, now_unix_seconds: u64) -> Result<JwkSet, OidcError> {
        self.ensure_lifecycle_time(now_unix_seconds)?;
        let mut keys = Vec::with_capacity(self.retired_signing_keys.len().saturating_add(1));
        keys.push(self.signing_key.verifying_key().jwk());
        keys.extend(
            self.retired_signing_keys
                .iter()
                .filter(|retired| now_unix_seconds < retired.publish_until_unix_seconds)
                .map(|retired| retired.key.jwk()),
        );
        let jwks = JwkSet { keys };
        jwks.validating_keys()?;
        Ok(jwks)
    }

    /// Backwards-compatible view at the latest recorded lifecycle time. HTTP
    /// handlers participating in rotation should use [`Self::jwks_at`].
    #[must_use]
    pub fn jwks(&self) -> JwkSet {
        self.jwks_at(self.key_ring_updated_unix_seconds)
            .expect("validated OIDC key-ring invariants")
    }

    pub fn rotate_signing_key(
        &mut self,
        new_signing_key: OidcSigningKey,
        now_unix_seconds: u64,
        overlap_seconds: u64,
    ) -> Result<OidcSigningKeyRotation, OidcError> {
        self.validate_new_signing_key(&new_signing_key)?;
        self.ensure_lifecycle_time(now_unix_seconds)?;
        if overlap_seconds < self.maximum_ttl_seconds
            || overlap_seconds > MAX_SIGNING_KEY_OVERLAP_SECONDS
        {
            return Err(OidcError::InvalidSigningKeyOverlap);
        }
        let publish_until_unix_seconds = now_unix_seconds
            .checked_add(overlap_seconds)
            .ok_or(OidcError::InvalidSigningKeyOverlap)?;
        let retained_key_count = self
            .retired_signing_keys
            .iter()
            .filter(|key| now_unix_seconds < key.publish_until_unix_seconds)
            .count();
        if retained_key_count >= MAX_RETAINED_SIGNING_KEYS {
            return Err(OidcError::SigningKeyHistoryFull);
        }
        let generation = self.next_key_ring_generation()?;
        let previous_key_id = self.signing_key.verifying_key().key_id();
        let active_key_id = new_signing_key.verifying_key().key_id();
        let previous_key_activated_unix_seconds = self.active_key_activated_unix_seconds;
        self.retired_signing_keys
            .retain(|key| now_unix_seconds < key.publish_until_unix_seconds);
        let previous_signing_key = std::mem::replace(&mut self.signing_key, new_signing_key);
        self.retired_signing_keys.push(RetiredSigningKey {
            key: previous_signing_key.verifying_key(),
            activated_unix_seconds: previous_key_activated_unix_seconds,
            retired_unix_seconds: now_unix_seconds,
            publish_until_unix_seconds,
            maximum_token_ttl_seconds: self.maximum_ttl_seconds,
        });
        sort_retired_keys(&mut self.retired_signing_keys);
        self.active_key_activated_unix_seconds = now_unix_seconds;
        self.key_ring_generation = generation;
        self.key_ring_updated_unix_seconds = now_unix_seconds;
        Ok(OidcSigningKeyRotation {
            generation,
            previous_key_id,
            active_key_id,
            rotated_unix_seconds: now_unix_seconds,
            previous_key_publish_until_unix_seconds: Some(publish_until_unix_seconds),
            emergency: false,
        })
    }

    pub fn emergency_rotate_signing_key(
        &mut self,
        new_signing_key: OidcSigningKey,
        now_unix_seconds: u64,
    ) -> Result<OidcSigningKeyRotation, OidcError> {
        self.validate_new_signing_key(&new_signing_key)?;
        self.ensure_lifecycle_time(now_unix_seconds)?;
        if self.revoked_signing_keys.len() >= MAX_REVOKED_SIGNING_KEY_IDS {
            return Err(OidcError::SigningKeyRevocationHistoryFull);
        }
        let generation = self.next_key_ring_generation()?;
        let previous_key_id = self.signing_key.verifying_key().key_id();
        let active_key_id = new_signing_key.verifying_key().key_id();
        self.signing_key = new_signing_key;
        self.revoked_signing_keys.push(OidcRevokedSigningKeyRecord {
            key_id: previous_key_id.clone(),
            revoked_unix_seconds: now_unix_seconds,
        });
        sort_revoked_keys(&mut self.revoked_signing_keys);
        self.retired_signing_keys
            .retain(|key| now_unix_seconds < key.publish_until_unix_seconds);
        self.active_key_activated_unix_seconds = now_unix_seconds;
        self.key_ring_generation = generation;
        self.key_ring_updated_unix_seconds = now_unix_seconds;
        Ok(OidcSigningKeyRotation {
            generation,
            previous_key_id,
            active_key_id,
            rotated_unix_seconds: now_unix_seconds,
            previous_key_publish_until_unix_seconds: None,
            emergency: true,
        })
    }

    pub fn revoke_retired_signing_key(
        &mut self,
        key_id: &ContentDigest,
        now_unix_seconds: u64,
    ) -> Result<OidcSigningKeyRevocation, OidcError> {
        self.ensure_lifecycle_time(now_unix_seconds)?;
        if &self.active_key_id() == key_id {
            return Err(OidcError::CannotRevokeActiveSigningKey);
        }
        if self
            .revoked_signing_keys
            .iter()
            .any(|revoked| &revoked.key_id == key_id)
        {
            return Err(OidcError::SigningKeyRevoked);
        }
        let position = self
            .retired_signing_keys
            .iter()
            .position(|retired| &retired.key.key_id() == key_id)
            .ok_or(OidcError::UnknownSigningKey)?;
        if self.revoked_signing_keys.len() >= MAX_REVOKED_SIGNING_KEY_IDS {
            return Err(OidcError::SigningKeyRevocationHistoryFull);
        }
        let generation = self.next_key_ring_generation()?;
        self.retired_signing_keys.remove(position);
        self.revoked_signing_keys.push(OidcRevokedSigningKeyRecord {
            key_id: key_id.clone(),
            revoked_unix_seconds: now_unix_seconds,
        });
        sort_revoked_keys(&mut self.revoked_signing_keys);
        self.key_ring_generation = generation;
        self.key_ring_updated_unix_seconds = now_unix_seconds;
        Ok(OidcSigningKeyRevocation {
            generation,
            key_id: key_id.clone(),
            revoked_unix_seconds: now_unix_seconds,
        })
    }

    pub fn prune_expired_signing_keys(
        &mut self,
        now_unix_seconds: u64,
    ) -> Result<usize, OidcError> {
        self.ensure_lifecycle_time(now_unix_seconds)?;
        let before = self.retired_signing_keys.len();
        let retained = self
            .retired_signing_keys
            .iter()
            .filter(|key| now_unix_seconds < key.publish_until_unix_seconds)
            .count();
        let removed = before.saturating_sub(retained);
        if removed != 0 {
            let generation = self.next_key_ring_generation()?;
            self.retired_signing_keys
                .retain(|key| now_unix_seconds < key.publish_until_unix_seconds);
            self.key_ring_generation = generation;
            self.key_ring_updated_unix_seconds = now_unix_seconds;
        }
        Ok(removed)
    }

    pub fn verify(
        &self,
        token: &str,
        expected_grant: &OidcGrant,
        expected_audience: &str,
        now_unix_seconds: u64,
    ) -> Result<JwtClaims, OidcError> {
        self.ensure_lifecycle_time(now_unix_seconds)?;
        let key_id = token_key_id(token)?;
        if self
            .revoked_signing_keys
            .iter()
            .any(|revoked| revoked.key_id == key_id)
        {
            return Err(OidcError::SigningKeyRevoked);
        }
        let active_key = self.signing_key.verifying_key();
        if active_key.key_id() == key_id {
            let claims = verify_token(
                token,
                &active_key,
                &self.issuer,
                expected_grant,
                expected_audience,
                now_unix_seconds,
            )?;
            if claims.issued_unix_seconds < self.active_key_activated_unix_seconds {
                return Err(OidcError::SigningKeyOutsideValidityWindow);
            }
            return Ok(claims);
        }
        let retired = self
            .retired_signing_keys
            .iter()
            .find(|retired| retired.key.key_id() == key_id)
            .ok_or(OidcError::UnknownSigningKey)?;
        if now_unix_seconds >= retired.publish_until_unix_seconds {
            return Err(OidcError::SigningKeyOutsideValidityWindow);
        }
        let claims = verify_token(
            token,
            &retired.key,
            &self.issuer,
            expected_grant,
            expected_audience,
            now_unix_seconds,
        )?;
        if claims.issued_unix_seconds < retired.activated_unix_seconds
            || claims.issued_unix_seconds > retired.retired_unix_seconds
            || claims.expires_unix_seconds > retired.publish_until_unix_seconds
        {
            return Err(OidcError::SigningKeyOutsideValidityWindow);
        }
        Ok(claims)
    }

    fn validate_new_signing_key(&self, key: &OidcSigningKey) -> Result<(), OidcError> {
        let key_id = key.verifying_key().key_id();
        if key_id == self.active_key_id()
            || self
                .retired_signing_keys
                .iter()
                .any(|retired| retired.key.key_id() == key_id)
            || self
                .revoked_signing_keys
                .iter()
                .any(|revoked| revoked.key_id == key_id)
        {
            return Err(OidcError::DuplicateSigningKey);
        }
        Ok(())
    }

    fn ensure_lifecycle_time(&self, now_unix_seconds: u64) -> Result<(), OidcError> {
        if now_unix_seconds < self.key_ring_updated_unix_seconds
            || now_unix_seconds < self.active_key_activated_unix_seconds
        {
            return Err(OidcError::SigningKeyClockRollback);
        }
        Ok(())
    }

    fn next_key_ring_generation(&self) -> Result<u64, OidcError> {
        self.key_ring_generation
            .checked_add(1)
            .ok_or(OidcError::SigningKeyGenerationExhausted)
    }

    pub fn mint(
        &self,
        grant: &OidcGrant,
        request: &MintTokenRequest,
        now_unix_seconds: u64,
    ) -> Result<MintedOidcToken, OidcError> {
        self.ensure_lifecycle_time(now_unix_seconds)?;
        grant.validate()?;
        validate_identifier("OIDC audience", &request.audience)?;
        if !grant.allowed_audiences.contains(&request.audience) {
            return Err(OidcError::AudienceNotGranted);
        }
        if request.ttl_seconds == 0 || request.ttl_seconds > self.maximum_ttl_seconds {
            return Err(OidcError::InvalidTtl);
        }
        if now_unix_seconds >= grant.expires_unix_seconds {
            return Err(OidcError::GrantExpired);
        }
        let expires_unix_seconds = now_unix_seconds
            .checked_add(request.ttl_seconds)
            .map(|expires| expires.min(grant.expires_unix_seconds))
            .filter(|expires| *expires > now_unix_seconds)
            .ok_or(OidcError::InvalidTtl)?;
        let key_id = self.signing_key.verifying_key().key_id();
        let header = JwtHeader {
            algorithm: JWT_ALGORITHM.to_owned(),
            token_type: JWT_TYPE.to_owned(),
            key_id: key_id.to_string(),
        };
        let jti = random_jti()?;
        let claims = JwtClaims::from_grant(
            &self.issuer,
            grant,
            request.audience.clone(),
            now_unix_seconds,
            expires_unix_seconds,
            jti.clone(),
        );
        let header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header)?);
        let claims = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&claims)?);
        let signing_input = format!("{header}.{claims}");
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let signature = Base64UrlUnpadded::encode_string(&signature);
        let token = format!("{signing_input}.{signature}");
        if token.len() > MAX_TOKEN_BYTES {
            return Err(OidcError::TokenTooLarge);
        }
        Ok(MintedOidcToken {
            token,
            expires_unix_seconds,
            jti,
            key_id,
        })
    }
}

impl fmt::Debug for OidcIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcIssuer")
            .field("issuer", &self.issuer)
            .field("signing_key", &"[REDACTED]")
            .field("maximum_ttl_seconds", &self.maximum_ttl_seconds)
            .finish()
    }
}
