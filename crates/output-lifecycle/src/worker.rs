use crate::LifecycleError;
use runtrue_artifacts::ArtifactStore;
use runtrue_control_plane::ControlPlane;
use runtrue_storage::FsCas;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleLimits {
    pub maximum_roots: usize,
    pub maximum_reachable_objects: usize,
    pub maximum_inventory_objects: usize,
    pub maximum_manifest_bytes: u64,
    pub maximum_scan_evidence_bytes: u64,
    pub safety_horizon_ms: u64,
    pub gc_lease_duration_ms: u64,
    pub ledger_retention_ms: u64,
}

impl Default for LifecycleLimits {
    fn default() -> Self {
        Self {
            maximum_roots: 250_000,
            maximum_reachable_objects: 1_000_000,
            maximum_inventory_objects: 1_000_000,
            maximum_manifest_bytes: 16 * 1024 * 1024,
            maximum_scan_evidence_bytes: 4 * 1024 * 1024,
            safety_horizon_ms: 24 * 60 * 60 * 1_000,
            gc_lease_duration_ms: 30 * 60 * 1_000,
            ledger_retention_ms: 30 * 24 * 60 * 60 * 1_000,
        }
    }
}

impl LifecycleLimits {
    pub(crate) fn validate(self) -> Result<Self, LifecycleError> {
        if self.maximum_roots == 0
            || self.maximum_reachable_objects == 0
            || self.maximum_inventory_objects == 0
            || self.maximum_manifest_bytes == 0
            || self.maximum_scan_evidence_bytes == 0
            || self.safety_horizon_ms == 0
            || self.gc_lease_duration_ms == 0
            || self.ledger_retention_ms == 0
            || self.maximum_roots > self.maximum_reachable_objects
        {
            return Err(LifecycleError::InvalidConfiguration);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcSummary {
    pub generation: u64,
    pub marked_objects: usize,
    pub swept_objects: usize,
    pub swept_bytes: u64,
}

pub struct OutputLifecycleWorker<'a> {
    pub(crate) control: &'a ControlPlane,
    pub(crate) artifacts: &'a ArtifactStore,
    pub(crate) cas: &'a FsCas,
    pub(crate) limits: LifecycleLimits,
}

impl<'a> OutputLifecycleWorker<'a> {
    pub fn new(
        control: &'a ControlPlane,
        artifacts: &'a ArtifactStore,
        limits: LifecycleLimits,
    ) -> Result<Self, LifecycleError> {
        Ok(Self {
            control,
            artifacts,
            cas: artifacts.cas(),
            limits: limits.validate()?,
        })
    }
}
