//! Encrypted local secret versions and fenced, one-use release leases.
//!
//! Secret payloads are encrypted with independent random data-encryption keys.
//! A local master key wraps those keys, allowing KEK rotation without touching
//! payload ciphertext. Public metadata types never contain plaintext or key
//! material; the few sensitive wrapper types are redacted and zeroized.

mod key_file;
pub mod provider;
pub mod runner_broker;
mod sensitive;
pub mod vault;

pub use key_file::{LocalMasterKeyFile, MasterKeyFileError};
pub use provider::{
    ExternalSecretLease, ExternalSecretLeaseMetadata, ExternalSecretLeaseRequest,
    ExternalSecretProvider, ExternalSecretProviderRegistry, HardenedVaultTransport, ProviderError,
    ProviderRegistryMetrics, StaticVaultTokenSource, VaultEndpointPolicy, VaultHttpMethod,
    VaultHttpRequest, VaultHttpResponse, VaultKvV2Provider, VaultToken, VaultTokenSource,
    VaultTransport, VaultTransportLimits, VaultValueEncoding, MAX_EXTERNAL_SECRET_PROVIDERS,
    MAX_PROVIDER_IDENTIFIER_BYTES, MAX_PROVIDER_REFERENCE_BYTES, MAX_PROVIDER_RESPONSE_BYTES,
    MAX_VAULT_CA_BUNDLE_BYTES, MAX_VAULT_CA_CERTIFICATES, MAX_VAULT_PATH_SEGMENTS,
    MAX_VAULT_REQUEST_BYTES, MAX_VAULT_RESPONSE_HEADER_BYTES, MAX_VAULT_TOKEN_BYTES,
};
pub use runner_broker::{
    AuthorizedExternalSecretRelease, ExternalSecretBrokerError, ExternalSecretBrokerMetrics,
    ExternalSecretReleaseAuthority, ExternalSecretReleaseJournal,
    ExternalSecretReleaseJournalEntry, ExternalSecretReleaseReservation,
    ExternalSecretReleaseState, ExternalSecretReserveOutcome, ExternalSecretRevocationRequest,
    ExternalSecretRevokeOutcome, ExternalSecretRunnerBroker, RunnerExternalSecretRequest,
};
pub use sensitive::{MasterKey, SecretPlaintext, SensitiveError};
pub use vault::{
    EncryptedSecretVersion, LeaseState, SecretIdentity, SecretLeaseMetadata, SecretLeaseRequest,
    SecretMetadata, SecretStatus, SecretVault, SecretVaultSnapshot, SecretsError, MAX_SECRET_BYTES,
};
