//! Encrypted local secret versions and fenced one-use release leases.
pub mod crypto;
pub mod error;
pub mod lease;
pub mod model;
pub mod snapshot;
pub mod store;
pub mod validation;
pub use error::SecretsError;
pub use lease::{LeaseState, SecretLeaseMetadata, SecretLeaseRequest};
pub use model::{
    EncryptedSecretVersion, SecretIdentity, SecretMetadata, SecretStatus, MAX_SECRET_BYTES,
};
pub use snapshot::SecretVaultSnapshot;
pub use store::SecretVault;
pub(super) const VAULT_SNAPSHOT_VERSION: u32 = 1;
#[cfg(test)]
mod tests;
