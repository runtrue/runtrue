use crate::{
    AutoscalerError, FleetRequest, FleetView, LaunchClaim, OwnershipLease, PlannedReplacement,
    PoolTemplate, PreparedInstance, ProviderIdentity, ProviderInstance,
};
use async_trait::async_trait;
use std::time::{SystemTime, UNIX_EPOCH};

#[async_trait]
pub trait Provider: Send + Sync {
    /// Return the number of additional instances the provider can safely fit.
    ///
    /// Providers without a meaningful local capacity signal remain unbounded;
    /// the control-plane policy still enforces its maximum worker count.
    async fn available_capacity(&self) -> Result<u64, AutoscalerError> {
        Ok(u64::MAX)
    }

    async fn prepare(&self, request: &FleetRequest) -> Result<PreparedInstance, AutoscalerError>;
    async fn create(
        &self,
        request: &FleetRequest,
        prepared: &PreparedInstance,
    ) -> Result<ProviderInstance, AutoscalerError>;
    async fn publish_claim(
        &self,
        instance: &ProviderInstance,
        prepared: &PreparedInstance,
        claim: &LaunchClaim,
    ) -> Result<(), AutoscalerError>;
    async fn start(&self, instance: &ProviderInstance) -> Result<(), AutoscalerError>;
    async fn destroy(&self, instance: &ProviderInstance) -> Result<(), AutoscalerError>;
    async fn cleanup_claim(&self, request: &FleetRequest) -> Result<(), AutoscalerError>;
}

#[async_trait]
pub trait ControlPlaneClient: Send + Sync {
    async fn acquire_lease(
        &self,
        pool: &str,
        owner: &str,
        expires_in_ms: u64,
    ) -> Result<OwnershipLease, AutoscalerError>;
    async fn fleet(&self, pool: &str) -> Result<FleetView, AutoscalerError>;
    async fn create_request(
        &self,
        pool: &str,
        generation: u64,
        template: &PoolTemplate,
    ) -> Result<FleetRequest, AutoscalerError>;
    async fn transition(
        &self,
        request: &FleetRequest,
        next: &str,
        generation: u64,
        detail: &str,
    ) -> Result<FleetRequest, AutoscalerError>;
    async fn create_launch_claim(
        &self,
        request: &FleetRequest,
        generation: u64,
        identity: &ProviderIdentity,
    ) -> Result<LaunchClaim, AutoscalerError>;
    async fn plan_replacement(
        &self,
        pool: &str,
        generation: u64,
    ) -> Result<Option<PlannedReplacement>, AutoscalerError>;
    async fn activate_replacement(
        &self,
        pool: &str,
        replacement: &str,
        generation: u64,
    ) -> Result<(), AutoscalerError>;
}

#[async_trait]
impl<T> Provider for &T
where
    T: Provider + Sync + ?Sized,
{
    async fn available_capacity(&self) -> Result<u64, AutoscalerError> {
        (**self).available_capacity().await
    }

    async fn prepare(&self, request: &FleetRequest) -> Result<PreparedInstance, AutoscalerError> {
        (**self).prepare(request).await
    }

    async fn create(
        &self,
        request: &FleetRequest,
        prepared: &PreparedInstance,
    ) -> Result<ProviderInstance, AutoscalerError> {
        (**self).create(request, prepared).await
    }

    async fn publish_claim(
        &self,
        instance: &ProviderInstance,
        prepared: &PreparedInstance,
        claim: &LaunchClaim,
    ) -> Result<(), AutoscalerError> {
        (**self).publish_claim(instance, prepared, claim).await
    }

    async fn start(&self, instance: &ProviderInstance) -> Result<(), AutoscalerError> {
        (**self).start(instance).await
    }

    async fn destroy(&self, instance: &ProviderInstance) -> Result<(), AutoscalerError> {
        (**self).destroy(instance).await
    }

    async fn cleanup_claim(&self, request: &FleetRequest) -> Result<(), AutoscalerError> {
        (**self).cleanup_claim(request).await
    }
}

#[async_trait]
impl<T> ControlPlaneClient for &T
where
    T: ControlPlaneClient + Sync + ?Sized,
{
    async fn acquire_lease(
        &self,
        pool: &str,
        owner: &str,
        expires_in_ms: u64,
    ) -> Result<OwnershipLease, AutoscalerError> {
        (**self).acquire_lease(pool, owner, expires_in_ms).await
    }

    async fn fleet(&self, pool: &str) -> Result<FleetView, AutoscalerError> {
        (**self).fleet(pool).await
    }

    async fn create_request(
        &self,
        pool: &str,
        generation: u64,
        template: &PoolTemplate,
    ) -> Result<FleetRequest, AutoscalerError> {
        (**self).create_request(pool, generation, template).await
    }

    async fn transition(
        &self,
        request: &FleetRequest,
        next: &str,
        generation: u64,
        detail: &str,
    ) -> Result<FleetRequest, AutoscalerError> {
        (**self).transition(request, next, generation, detail).await
    }

    async fn create_launch_claim(
        &self,
        request: &FleetRequest,
        generation: u64,
        identity: &ProviderIdentity,
    ) -> Result<LaunchClaim, AutoscalerError> {
        (**self)
            .create_launch_claim(request, generation, identity)
            .await
    }

    async fn plan_replacement(
        &self,
        pool: &str,
        generation: u64,
    ) -> Result<Option<PlannedReplacement>, AutoscalerError> {
        (**self).plan_replacement(pool, generation).await
    }

    async fn activate_replacement(
        &self,
        pool: &str,
        replacement: &str,
        generation: u64,
    ) -> Result<(), AutoscalerError> {
        (**self)
            .activate_replacement(pool, replacement, generation)
            .await
    }
}

pub trait Clock: Send + Sync {
    fn now_unix_ms(&self) -> Result<u64, AutoscalerError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> Result<u64, AutoscalerError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AutoscalerError::InvalidConfiguration("system clock precedes Unix epoch"))?
            .as_millis()
            .try_into()
            .map_err(|_| AutoscalerError::InvalidConfiguration("system clock is out of range"))
    }
}
