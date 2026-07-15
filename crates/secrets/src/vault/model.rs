//! Public secret identities, metadata, and encrypted-version representation.
use super::crypto::{
    associated_data, decrypt_aead, encrypt_aead, random_array, unwrap_dek, wrap_dek,
    DataEncryptionKey,
};
use super::validation::{validate_component, validate_plaintext, validate_version};
use super::SecretsError;
use crate::{MasterKey, SecretPlaintext};
use serde::{Deserialize, Serialize};
use std::fmt;
pub(super) const NONCE_BYTES: usize = 24;
pub(super) const MAX_IDENTITY_BYTES: usize = 1_024;
pub const MAX_SECRET_BYTES: usize = 16 * 1024 * 1024;
pub(super) const PAYLOAD_AAD_DOMAIN: &[u8] = b"runtrue.secret.payload.v1\0";
pub(super) const DEK_AAD_DOMAIN: &[u8] = b"runtrue.secret.dek-wrap.v1\0";
pub(super) const ENCRYPTION_ALGORITHM: &str = "xchacha20poly1305";

/// Stable coordinates used in encryption associated data and storage lookup.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretIdentity {
    pub(crate) tenant_id: String,
    pub(crate) scope: String,
    pub(crate) name: String,
}

impl SecretIdentity {
    pub fn new(
        tenant_id: impl Into<String>,
        scope: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, SecretsError> {
        let identity = Self {
            tenant_id: tenant_id.into(),
            scope: scope.into(),
            name: name.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn validate(&self) -> Result<(), SecretsError> {
        validate_component("tenant_id", &self.tenant_id)?;
        validate_component("scope", &self.scope)?;
        validate_component("name", &self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStatus {
    Active,
    Tombstoned,
}

/// Safe public metadata. It contains neither plaintext nor encrypted payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretMetadata {
    pub identity: SecretIdentity,
    pub status: SecretStatus,
    pub current_version: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EncryptedPayload {
    pub(super) nonce: [u8; NONCE_BYTES],
    pub(super) ciphertext: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WrappedDek {
    pub(super) kek_id: String,
    pub(super) nonce: [u8; NONCE_BYTES],
    pub(super) ciphertext: Vec<u8>,
}

/// Persistable encrypted version. Fields are immutable outside this crate.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSecretVersion {
    pub(crate) identity: SecretIdentity,
    pub(crate) version: u64,
    algorithm: String,
    pub(super) payload: EncryptedPayload,
    pub(super) wrapped_dek: WrappedDek,
}

impl EncryptedSecretVersion {
    #[must_use]
    pub fn identity(&self) -> &SecretIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    #[must_use]
    pub fn kek_id(&self) -> &str {
        &self.wrapped_dek.kek_id
    }

    #[must_use]
    pub fn payload_nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.payload.nonce
    }

    #[must_use]
    pub fn payload_ciphertext(&self) -> &[u8] {
        &self.payload.ciphertext
    }

    pub(super) fn encrypt(
        identity: SecretIdentity,
        version: u64,
        plaintext: &SecretPlaintext,
        kek_id: &str,
        master_key: &MasterKey,
    ) -> Result<Self, SecretsError> {
        identity.validate()?;
        validate_version(version)?;
        validate_plaintext(plaintext)?;
        validate_component("kek_id", kek_id)?;

        let dek = DataEncryptionKey::generate()?;
        let payload_nonce = random_array()?;
        let payload_aad = associated_data(PAYLOAD_AAD_DOMAIN, &identity, version, None);
        let payload_ciphertext = encrypt_aead(
            dek.as_bytes(),
            &payload_nonce,
            plaintext.as_bytes(),
            &payload_aad,
        )?;
        let wrapped_dek = wrap_dek(&dek, &identity, version, kek_id, master_key)?;

        Ok(Self {
            identity,
            version,
            algorithm: ENCRYPTION_ALGORITHM.to_owned(),
            payload: EncryptedPayload {
                nonce: payload_nonce,
                ciphertext: payload_ciphertext,
            },
            wrapped_dek,
        })
    }

    pub(super) fn decrypt(&self, master_key: &MasterKey) -> Result<SecretPlaintext, SecretsError> {
        self.validate_storage_shape()?;
        let dek = unwrap_dek(&self.wrapped_dek, &self.identity, self.version, master_key)?;
        let aad = associated_data(PAYLOAD_AAD_DOMAIN, &self.identity, self.version, None);
        let plaintext = SecretPlaintext::new(decrypt_aead(
            dek.as_bytes(),
            &self.payload.nonce,
            &self.payload.ciphertext,
            &aad,
        )?);
        if plaintext.len() > MAX_SECRET_BYTES {
            return Err(SecretsError::SecretTooLarge {
                limit: MAX_SECRET_BYTES,
                actual: plaintext.len(),
            });
        }
        Ok(plaintext)
    }

    pub(super) fn rewrap(
        &self,
        old_master_key: &MasterKey,
        new_kek_id: &str,
        new_master_key: &MasterKey,
    ) -> Result<WrappedDek, SecretsError> {
        self.validate_storage_shape()?;
        let dek = unwrap_dek(
            &self.wrapped_dek,
            &self.identity,
            self.version,
            old_master_key,
        )?;
        wrap_dek(
            &dek,
            &self.identity,
            self.version,
            new_kek_id,
            new_master_key,
        )
    }

    pub(super) fn validate_storage_shape(&self) -> Result<(), SecretsError> {
        self.identity.validate()?;
        validate_version(self.version)?;
        validate_component("kek_id", &self.wrapped_dek.kek_id)?;
        if self.algorithm != ENCRYPTION_ALGORITHM {
            return Err(SecretsError::UnsupportedEncryptionAlgorithm(
                self.algorithm.clone(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for EncryptedSecretVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedSecretVersion")
            .field("identity", &self.identity)
            .field("version", &self.version)
            .field("algorithm", &self.algorithm)
            .field("kek_id", &self.wrapped_dek.kek_id)
            .field("payload_ciphertext_bytes", &self.payload.ciphertext.len())
            .field("wrapped_dek_bytes", &self.wrapped_dek.ciphertext.len())
            .finish()
    }
}
