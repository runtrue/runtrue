//! Redacted, zeroizing Vault/OpenBao token sources.
use super::super::model::{ProviderError, MAX_VAULT_TOKEN_BYTES};
use std::fmt;
use zeroize::Zeroizing;
pub struct VaultToken(Zeroizing<String>);

impl VaultToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_VAULT_TOKEN_BYTES
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ProviderError::InvalidProviderToken);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VaultToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultToken(<redacted>)")
    }
}

pub trait VaultTokenSource {
    fn token(&self, now_unix_ms: u64) -> Result<VaultToken, ProviderError>;
}

/// Primarily for isolated installations. Dynamic workload or AppRole token
/// sources are preferred because they can rotate without rebuilding a provider.
pub struct StaticVaultTokenSource {
    token: Zeroizing<String>,
}

impl StaticVaultTokenSource {
    pub fn new(token: VaultToken) -> Self {
        Self { token: token.0 }
    }
}

impl VaultTokenSource for StaticVaultTokenSource {
    fn token(&self, _now_unix_ms: u64) -> Result<VaultToken, ProviderError> {
        VaultToken::new(self.token.as_str())
    }
}

impl fmt::Debug for StaticVaultTokenSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticVaultTokenSource(<redacted>)")
    }
}
