//! Encrypted secret storage operations, key rotation, and lease redemption.
use super::crypto::random_array;
use super::{
    lease::{LeaseState, SecretLeaseMetadata, SecretLeaseRequest},
    model::{EncryptedSecretVersion, SecretIdentity, SecretMetadata, SecretStatus},
    snapshot::{SecretSnapshotRecord, SecretVaultSnapshot},
    validation::{current_version, metadata, require_active, require_binding, validate_component},
};
use super::{SecretsError, VAULT_SNAPSHOT_VERSION};
use crate::{MasterKey, SecretPlaintext};
use std::{collections::BTreeMap, fmt};
const LEASE_ID_BYTES: usize = 16;
pub(super) struct SecretRecord {
    pub(super) status: SecretStatus,
    pub(super) versions: BTreeMap<u64, EncryptedSecretVersion>,
}

/// Persistable encrypted vault state. The snapshot contains ciphertext and
/// public metadata only; plaintext and the master key have no serialization
pub struct SecretVault {
    kek_id: String,
    master_key: MasterKey,
    secrets: BTreeMap<SecretIdentity, SecretRecord>,
    active_fences: BTreeMap<String, u64>,
    leases: BTreeMap<String, SecretLeaseMetadata>,
}

impl SecretVault {
    pub fn new(kek_id: impl Into<String>, master_key: MasterKey) -> Result<Self, SecretsError> {
        let kek_id = kek_id.into();
        validate_component("kek_id", &kek_id)?;
        Ok(Self {
            kek_id,
            master_key,
            secrets: BTreeMap::new(),
            active_fences: BTreeMap::new(),
            leases: BTreeMap::new(),
        })
    }

    /// Restore a vault from encrypted local persistence and authenticate every
    /// encrypted version before making the vault available to callers.
    pub fn from_snapshot(
        snapshot: SecretVaultSnapshot,
        master_key: MasterKey,
    ) -> Result<Self, SecretsError> {
        if snapshot.snapshot_version != VAULT_SNAPSHOT_VERSION {
            return Err(SecretsError::UnsupportedVaultSnapshotVersion(
                snapshot.snapshot_version,
            ));
        }
        validate_component("kek_id", &snapshot.kek_id)?;
        let mut secrets = BTreeMap::new();
        for persisted in snapshot.secrets {
            persisted.identity.validate()?;
            if persisted.versions.is_empty() {
                return Err(SecretsError::MissingVersions);
            }
            let mut versions = BTreeMap::new();
            for encrypted in persisted.versions {
                encrypted.validate_storage_shape()?;
                if encrypted.identity() != &persisted.identity {
                    return Err(SecretsError::SnapshotIdentityMismatch);
                }
                if encrypted.wrapped_dek.kek_id != snapshot.kek_id {
                    return Err(SecretsError::UnexpectedKekId {
                        expected: snapshot.kek_id.clone(),
                        actual: encrypted.wrapped_dek.kek_id.clone(),
                    });
                }
                let version = encrypted.version();
                if versions.insert(version, encrypted).is_some() {
                    return Err(SecretsError::ImmutableVersionConflict(version));
                }
            }
            for (expected, actual) in (1_u64..).zip(versions.keys().copied()) {
                if expected != actual {
                    return Err(SecretsError::NonContiguousVersions);
                }
            }
            for encrypted in versions.values() {
                // Authenticate persisted ciphertext eagerly. The redacted,
                // zeroizing plaintext is dropped immediately.
                drop(encrypted.decrypt(&master_key)?);
            }
            if secrets
                .insert(
                    persisted.identity,
                    SecretRecord {
                        status: persisted.status,
                        versions,
                    },
                )
                .is_some()
            {
                return Err(SecretsError::DuplicateSnapshotIdentity);
            }
        }
        Ok(Self {
            kek_id: snapshot.kek_id,
            master_key,
            secrets,
            active_fences: BTreeMap::new(),
            leases: BTreeMap::new(),
        })
    }

    /// Export ciphertext and public metadata for durable persistence.
    #[must_use]
    pub fn snapshot(&self) -> SecretVaultSnapshot {
        SecretVaultSnapshot {
            snapshot_version: VAULT_SNAPSHOT_VERSION,
            kek_id: self.kek_id.clone(),
            secrets: self
                .secrets
                .iter()
                .map(|(identity, record)| SecretSnapshotRecord {
                    identity: identity.clone(),
                    status: record.status,
                    versions: record.versions.values().cloned().collect(),
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn kek_id(&self) -> &str {
        &self.kek_id
    }

    pub fn create_secret(
        &mut self,
        identity: SecretIdentity,
        plaintext: &SecretPlaintext,
    ) -> Result<SecretMetadata, SecretsError> {
        identity.validate()?;
        if self.secrets.contains_key(&identity) {
            return Err(SecretsError::SecretAlreadyExists(identity));
        }
        let version = EncryptedSecretVersion::encrypt(
            identity.clone(),
            1,
            plaintext,
            &self.kek_id,
            &self.master_key,
        )?;
        let mut versions = BTreeMap::new();
        versions.insert(1, version);
        self.secrets.insert(
            identity.clone(),
            SecretRecord {
                status: SecretStatus::Active,
                versions,
            },
        );
        Ok(SecretMetadata {
            identity,
            status: SecretStatus::Active,
            current_version: 1,
        })
    }

    pub fn add_version(
        &mut self,
        identity: &SecretIdentity,
        plaintext: &SecretPlaintext,
    ) -> Result<SecretMetadata, SecretsError> {
        identity.validate()?;
        let record = self
            .secrets
            .get(identity)
            .ok_or_else(|| SecretsError::SecretNotFound(identity.clone()))?;
        require_active(identity, record.status)?;
        let current = current_version(record)?;
        let version = current
            .checked_add(1)
            .ok_or(SecretsError::VersionOverflow)?;
        let encrypted = EncryptedSecretVersion::encrypt(
            identity.clone(),
            version,
            plaintext,
            &self.kek_id,
            &self.master_key,
        )?;
        let record = self
            .secrets
            .get_mut(identity)
            .ok_or_else(|| SecretsError::SecretNotFound(identity.clone()))?;
        if record.versions.insert(version, encrypted).is_some() {
            return Err(SecretsError::ImmutableVersionConflict(version));
        }
        metadata(identity, record)
    }

    pub fn metadata(&self, identity: &SecretIdentity) -> Result<SecretMetadata, SecretsError> {
        let record = self
            .secrets
            .get(identity)
            .ok_or_else(|| SecretsError::SecretNotFound(identity.clone()))?;
        metadata(identity, record)
    }

    #[must_use]
    pub fn list_metadata(&self) -> Vec<SecretMetadata> {
        self.secrets
            .iter()
            .filter_map(|(identity, record)| metadata(identity, record).ok())
            .collect()
    }

    pub fn encrypted_version(
        &self,
        identity: &SecretIdentity,
        version: u64,
    ) -> Result<&EncryptedSecretVersion, SecretsError> {
        let record = self
            .secrets
            .get(identity)
            .ok_or_else(|| SecretsError::SecretNotFound(identity.clone()))?;
        record
            .versions
            .get(&version)
            .ok_or_else(|| SecretsError::SecretVersionNotFound {
                identity: identity.clone(),
                version,
            })
    }

    /// Return one active secret version to an administrative caller. The
    /// returned wrapper is redacted in diagnostics and zeroizes on drop.
    pub fn reveal_for_administration(
        &self,
        identity: &SecretIdentity,
        version: Option<u64>,
    ) -> Result<SecretPlaintext, SecretsError> {
        identity.validate()?;
        let record = self
            .secrets
            .get(identity)
            .ok_or_else(|| SecretsError::SecretNotFound(identity.clone()))?;
        require_active(identity, record.status)?;
        let version = version.unwrap_or(current_version(record)?);
        let encrypted =
            record
                .versions
                .get(&version)
                .ok_or_else(|| SecretsError::SecretVersionNotFound {
                    identity: identity.clone(),
                    version,
                })?;
        encrypted.decrypt(&self.master_key)
    }

    /// Permanently disable new versions and releases while retaining encrypted history.
    pub fn tombstone(&mut self, identity: &SecretIdentity) -> Result<SecretMetadata, SecretsError> {
        let record = self
            .secrets
            .get_mut(identity)
            .ok_or_else(|| SecretsError::SecretNotFound(identity.clone()))?;
        record.status = SecretStatus::Tombstoned;
        for lease in self.leases.values_mut() {
            if lease.identity == *identity && lease.state == LeaseState::Issued {
                lease.state = LeaseState::Revoked;
            }
        }
        metadata(identity, record)
    }

    /// Re-encrypt every DEK under a new KEK without rewriting payload ciphertext.
    pub fn rotate_kek(
        &mut self,
        new_kek_id: impl Into<String>,
        new_master_key: MasterKey,
    ) -> Result<(), SecretsError> {
        let new_kek_id = new_kek_id.into();
        validate_component("kek_id", &new_kek_id)?;
        if new_kek_id == self.kek_id {
            return Err(SecretsError::KekIdNotAdvanced(new_kek_id));
        }

        let mut replacements = Vec::new();
        for (identity, record) in &self.secrets {
            for (version, encrypted) in &record.versions {
                if encrypted.wrapped_dek.kek_id != self.kek_id {
                    return Err(SecretsError::UnexpectedKekId {
                        expected: self.kek_id.clone(),
                        actual: encrypted.wrapped_dek.kek_id.clone(),
                    });
                }
                replacements.push((
                    identity.clone(),
                    *version,
                    encrypted.rewrap(&self.master_key, &new_kek_id, &new_master_key)?,
                ));
            }
        }

        for (identity, version, replacement) in replacements {
            let encrypted = self
                .secrets
                .get_mut(&identity)
                .and_then(|record| record.versions.get_mut(&version))
                .ok_or_else(|| SecretsError::SecretVersionNotFound {
                    identity: identity.clone(),
                    version,
                })?;
            encrypted.wrapped_dek = replacement;
        }
        self.kek_id = new_kek_id;
        self.master_key = new_master_key;
        Ok(())
    }

    /// Record the authoritative generation and revoke older outstanding leases.
    pub fn set_active_fencing_generation(
        &mut self,
        execution_lease_id: impl Into<String>,
        generation: u64,
    ) -> Result<(), SecretsError> {
        let execution_lease_id = execution_lease_id.into();
        validate_component("execution_lease_id", &execution_lease_id)?;
        if generation == 0 {
            return Err(SecretsError::InvalidFencingGeneration);
        }
        if let Some(current) = self.active_fences.get(&execution_lease_id).copied() {
            if generation < current {
                return Err(SecretsError::FencingGenerationRegression {
                    current,
                    proposed: generation,
                });
            }
            if generation == current {
                return Ok(());
            }
        }
        self.active_fences
            .insert(execution_lease_id.clone(), generation);
        for lease in self.leases.values_mut() {
            if lease.execution_lease_id == execution_lease_id
                && lease.fencing_generation < generation
                && lease.state == LeaseState::Issued
            {
                lease.state = LeaseState::Revoked;
            }
        }
        Ok(())
    }

    pub fn issue_lease(
        &mut self,
        request: SecretLeaseRequest,
        now_unix_ms: u64,
    ) -> Result<SecretLeaseMetadata, SecretsError> {
        request.identity.validate()?;
        validate_component("execution_lease_id", &request.execution_lease_id)?;
        validate_component("step_id", &request.step_id)?;
        validate_component("purpose", &request.purpose)?;
        if request.fencing_generation == 0 {
            return Err(SecretsError::InvalidFencingGeneration);
        }
        if request.expires_at_unix_ms <= now_unix_ms {
            return Err(SecretsError::InvalidLeaseExpiry);
        }
        let active = self
            .active_fences
            .get(&request.execution_lease_id)
            .copied()
            .ok_or_else(|| {
                SecretsError::FencingGenerationNotRegistered(request.execution_lease_id.clone())
            })?;
        if active != request.fencing_generation {
            return Err(SecretsError::StaleFencingGeneration {
                active,
                provided: request.fencing_generation,
            });
        }

        let record = self
            .secrets
            .get(&request.identity)
            .ok_or_else(|| SecretsError::SecretNotFound(request.identity.clone()))?;
        require_active(&request.identity, record.status)?;
        let secret_version = request.version.unwrap_or(current_version(record)?);
        if !record.versions.contains_key(&secret_version) {
            return Err(SecretsError::SecretVersionNotFound {
                identity: request.identity.clone(),
                version: secret_version,
            });
        }

        let id = self.unique_lease_id()?;
        let metadata = SecretLeaseMetadata {
            id: id.clone(),
            identity: request.identity,
            secret_version,
            execution_lease_id: request.execution_lease_id,
            fencing_generation: request.fencing_generation,
            step_id: request.step_id,
            purpose: request.purpose,
            expires_at_unix_ms: request.expires_at_unix_ms,
            state: LeaseState::Issued,
        };
        self.leases.insert(id, metadata.clone());
        Ok(metadata)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn redeem_lease(
        &mut self,
        lease_id: &str,
        execution_lease_id: &str,
        fencing_generation: u64,
        step_id: &str,
        purpose: &str,
        now_unix_ms: u64,
    ) -> Result<SecretPlaintext, SecretsError> {
        let lease = self
            .leases
            .get(lease_id)
            .cloned()
            .ok_or_else(|| SecretsError::LeaseNotFound(lease_id.to_owned()))?;
        require_binding(
            "execution_lease_id",
            &lease.execution_lease_id,
            execution_lease_id,
        )?;
        require_binding("step_id", &lease.step_id, step_id)?;
        require_binding("purpose", &lease.purpose, purpose)?;

        let active = self
            .active_fences
            .get(execution_lease_id)
            .copied()
            .ok_or_else(|| {
                SecretsError::FencingGenerationNotRegistered(execution_lease_id.to_owned())
            })?;
        if fencing_generation != active {
            return Err(SecretsError::StaleFencingGeneration {
                active,
                provided: fencing_generation,
            });
        }
        if lease.fencing_generation != active {
            return Err(SecretsError::StaleFencingGeneration {
                active,
                provided: lease.fencing_generation,
            });
        }
        if now_unix_ms >= lease.expires_at_unix_ms {
            if let Some(stored) = self.leases.get_mut(lease_id) {
                if stored.state == LeaseState::Issued {
                    stored.state = LeaseState::Expired;
                }
            }
            return Err(SecretsError::LeaseExpired(lease_id.to_owned()));
        }
        match lease.state {
            LeaseState::Issued => {}
            LeaseState::Consumed => {
                return Err(SecretsError::LeaseAlreadyConsumed(lease_id.to_owned()));
            }
            LeaseState::Revoked => return Err(SecretsError::LeaseRevoked(lease_id.to_owned())),
            LeaseState::Expired => return Err(SecretsError::LeaseExpired(lease_id.to_owned())),
        }

        let record = self
            .secrets
            .get(&lease.identity)
            .ok_or_else(|| SecretsError::SecretNotFound(lease.identity.clone()))?;
        require_active(&lease.identity, record.status)?;
        let encrypted = record.versions.get(&lease.secret_version).ok_or_else(|| {
            SecretsError::SecretVersionNotFound {
                identity: lease.identity.clone(),
                version: lease.secret_version,
            }
        })?;
        let plaintext = match encrypted.decrypt(&self.master_key) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                if let Some(stored) = self.leases.get_mut(lease_id) {
                    stored.state = LeaseState::Revoked;
                }
                return Err(error);
            }
        };
        self.leases
            .get_mut(lease_id)
            .ok_or_else(|| SecretsError::LeaseNotFound(lease_id.to_owned()))?
            .state = LeaseState::Consumed;
        Ok(plaintext)
    }

    pub fn revoke_lease(&mut self, lease_id: &str) -> Result<(), SecretsError> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| SecretsError::LeaseNotFound(lease_id.to_owned()))?;
        match lease.state {
            LeaseState::Issued => lease.state = LeaseState::Revoked,
            LeaseState::Revoked => {}
            LeaseState::Consumed => {
                return Err(SecretsError::LeaseAlreadyConsumed(lease_id.to_owned()));
            }
            LeaseState::Expired => return Err(SecretsError::LeaseExpired(lease_id.to_owned())),
        }
        Ok(())
    }

    pub fn expire_leases(&mut self, now_unix_ms: u64) -> usize {
        let mut expired = 0;
        for lease in self.leases.values_mut() {
            if lease.state == LeaseState::Issued && now_unix_ms >= lease.expires_at_unix_ms {
                lease.state = LeaseState::Expired;
                expired += 1;
            }
        }
        expired
    }

    pub fn lease_metadata(&self, lease_id: &str) -> Result<SecretLeaseMetadata, SecretsError> {
        self.leases
            .get(lease_id)
            .cloned()
            .ok_or_else(|| SecretsError::LeaseNotFound(lease_id.to_owned()))
    }

    fn unique_lease_id(&self) -> Result<String, SecretsError> {
        for _ in 0..4 {
            let candidate = hex::encode(random_array::<LEASE_ID_BYTES>()?);
            if !self.leases.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(SecretsError::LeaseIdCollision)
    }
}

impl fmt::Debug for SecretVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretVault")
            .field("kek_id", &self.kek_id)
            .field("master_key", &self.master_key)
            .field("secret_count", &self.secrets.len())
            .field("active_fence_count", &self.active_fences.len())
            .field("lease_count", &self.leases.len())
            .finish()
    }
}
