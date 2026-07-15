//! Ciphertext-only vault snapshot representation.
use super::model::{EncryptedSecretVersion, SecretIdentity, SecretStatus};
use serde::{Deserialize, Serialize};
use std::fmt;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretVaultSnapshot {
    pub(super) snapshot_version: u32,
    pub(super) kek_id: String,
    pub(super) secrets: Vec<SecretSnapshotRecord>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecretSnapshotRecord {
    pub(super) identity: SecretIdentity,
    pub(super) status: SecretStatus,
    pub(super) versions: Vec<EncryptedSecretVersion>,
}

impl fmt::Debug for SecretVaultSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let version_count = self
            .secrets
            .iter()
            .map(|record| record.versions.len())
            .sum::<usize>();
        formatter
            .debug_struct("SecretVaultSnapshot")
            .field("snapshot_version", &self.snapshot_version)
            .field("kek_id", &self.kek_id)
            .field("secret_count", &self.secrets.len())
            .field("encrypted_version_count", &version_count)
            .finish()
    }
}
