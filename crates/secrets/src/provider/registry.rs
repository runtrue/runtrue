//! Explicit provider registration and dispatch.
use super::model::{
    ExternalSecretLease, ExternalSecretLeaseMetadata, ExternalSecretLeaseRequest,
    ExternalSecretProvider, ProviderError, MAX_EXTERNAL_SECRET_PROVIDERS,
};
use super::validation::validate_provider_id;
use std::{
    collections::BTreeMap,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProviderRegistryMetrics {
    pub lease_attempts: u64,
    pub lease_successes: u64,
    pub revoke_attempts: u64,
    pub revoke_successes: u64,
    pub provider_failures: u64,
    pub rejected_requests: u64,
}

#[derive(Default)]
struct ProviderRegistryCounters {
    lease_attempts: AtomicU64,
    lease_successes: AtomicU64,
    revoke_attempts: AtomicU64,
    revoke_successes: AtomicU64,
    provider_failures: AtomicU64,
    rejected_requests: AtomicU64,
}

/// Explicit provider dispatch. There is deliberately no default-provider
/// fallback: the caller must select a registered identifier and the returned
/// lease metadata must name that same identifier.
#[derive(Default)]
pub struct ExternalSecretProviderRegistry {
    providers: BTreeMap<String, Box<dyn ExternalSecretProvider>>,
    counters: ProviderRegistryCounters,
}

impl fmt::Debug for ExternalSecretProviderRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalSecretProviderRegistry")
            .field("provider_ids", &self.providers.keys().collect::<Vec<_>>())
            .field("metrics", &self.metrics())
            .finish()
    }
}

impl ExternalSecretProviderRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<P>(
        &mut self,
        provider_id: impl Into<String>,
        provider: P,
    ) -> Result<(), ProviderError>
    where
        P: ExternalSecretProvider + 'static,
    {
        let provider_id = provider_id.into();
        validate_provider_id(&provider_id)?;
        if provider.provider_id() != provider_id {
            return Err(ProviderError::ProviderIdentityMismatch);
        }
        if self.providers.len() >= MAX_EXTERNAL_SECRET_PROVIDERS {
            return Err(ProviderError::ProviderRegistryFull);
        }
        if self.providers.contains_key(&provider_id) {
            return Err(ProviderError::DuplicateProviderRegistration);
        }
        self.providers.insert(provider_id, Box::new(provider));
        Ok(())
    }

    pub fn lease(
        &self,
        provider_id: &str,
        request: &ExternalSecretLeaseRequest,
        now_unix_ms: u64,
    ) -> Result<ExternalSecretLease, ProviderError> {
        saturating_increment(&self.counters.lease_attempts);
        let Some(provider) = self.providers.get(provider_id) else {
            saturating_increment(&self.counters.rejected_requests);
            return Err(ProviderError::UnknownProvider);
        };
        let lease = match provider.lease(request, now_unix_ms) {
            Ok(lease) => lease,
            Err(error) => {
                saturating_increment(&self.counters.provider_failures);
                return Err(error);
            }
        };
        if lease.metadata.provider != provider_id {
            saturating_increment(&self.counters.rejected_requests);
            return Err(ProviderError::ProviderIdentityMismatch);
        }
        saturating_increment(&self.counters.lease_successes);
        Ok(lease)
    }

    pub fn revoke(
        &self,
        metadata: &ExternalSecretLeaseMetadata,
        now_unix_ms: u64,
    ) -> Result<(), ProviderError> {
        saturating_increment(&self.counters.revoke_attempts);
        let Some(provider) = self.providers.get(&metadata.provider) else {
            saturating_increment(&self.counters.rejected_requests);
            return Err(ProviderError::UnknownProvider);
        };
        match provider.revoke(metadata, now_unix_ms) {
            Ok(()) => {
                saturating_increment(&self.counters.revoke_successes);
                Ok(())
            }
            Err(error) => {
                saturating_increment(&self.counters.provider_failures);
                Err(error)
            }
        }
    }

    #[must_use]
    pub fn metrics(&self) -> ProviderRegistryMetrics {
        ProviderRegistryMetrics {
            lease_attempts: self.counters.lease_attempts.load(Ordering::Relaxed),
            lease_successes: self.counters.lease_successes.load(Ordering::Relaxed),
            revoke_attempts: self.counters.revoke_attempts.load(Ordering::Relaxed),
            revoke_successes: self.counters.revoke_successes.load(Ordering::Relaxed),
            provider_failures: self.counters.provider_failures.load(Ordering::Relaxed),
            rejected_requests: self.counters.rejected_requests.load(Ordering::Relaxed),
        }
    }
}

fn saturating_increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}
