//! External secret-provider contracts and hardened implementations.
pub mod model;
pub mod registry;
pub mod validation;
pub mod vault;
pub use model::{
    ExternalSecretLease, ExternalSecretLeaseMetadata, ExternalSecretLeaseRequest,
    ExternalSecretProvider, ProviderError, MAX_EXTERNAL_SECRET_PROVIDERS,
    MAX_PROVIDER_IDENTIFIER_BYTES, MAX_PROVIDER_REFERENCE_BYTES, MAX_PROVIDER_RESPONSE_BYTES,
    MAX_VAULT_CA_BUNDLE_BYTES, MAX_VAULT_CA_CERTIFICATES, MAX_VAULT_PATH_SEGMENTS,
    MAX_VAULT_REQUEST_BYTES, MAX_VAULT_RESPONSE_HEADER_BYTES, MAX_VAULT_TOKEN_BYTES,
};
pub use registry::{ExternalSecretProviderRegistry, ProviderRegistryMetrics};
pub use vault::*;
#[cfg(test)]
mod tests;
