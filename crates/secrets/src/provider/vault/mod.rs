//! Vault/OpenBao-specific provider components.
pub mod kv;
pub mod reference;
pub mod token;
pub mod transport;
pub use kv::VaultKvV2Provider;
pub use reference::VaultValueEncoding;
pub use token::{StaticVaultTokenSource, VaultToken, VaultTokenSource};
pub use transport::{
    HardenedVaultTransport, VaultEndpointPolicy, VaultHttpMethod, VaultHttpRequest,
    VaultHttpResponse, VaultTransport, VaultTransportLimits,
};
