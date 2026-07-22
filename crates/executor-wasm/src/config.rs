use crate::{
    AotCacheConfig, HandleAuthenticationKey, WasmComponentArtifact, WasmError, WasmLimits,
    WasmTarget,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmPackageCacheConfig {
    /// Maximum number of fully compiled components retained in memory.
    pub max_warm_components: usize,
    /// Maximum number of immutable AOT artifacts retained in memory.
    pub max_warmish_entries: usize,
    /// Maximum combined payload bytes retained by the warmish tier.
    pub max_warmish_bytes: usize,
}

impl Default for WasmPackageCacheConfig {
    fn default() -> Self {
        Self {
            max_warm_components: 64,
            max_warmish_entries: 1_024,
            max_warmish_bytes: 512 * 1024 * 1024,
        }
    }
}

pub struct WasmExecutorConfig {
    pub target: WasmTarget,
    pub limits: WasmLimits,
    pub cache: AotCacheConfig,
    pub package_cache: WasmPackageCacheConfig,
    pub handle_authentication_key: HandleAuthenticationKey,
    pub(crate) components: BTreeMap<String, WasmComponentArtifact>,
}

impl WasmExecutorConfig {
    #[must_use]
    pub fn new(
        target: WasmTarget,
        cache: AotCacheConfig,
        handle_authentication_key: HandleAuthenticationKey,
    ) -> Self {
        Self {
            target,
            limits: WasmLimits::default(),
            cache,
            package_cache: WasmPackageCacheConfig::default(),
            handle_authentication_key,
            components: BTreeMap::new(),
        }
    }

    pub fn register_component(&mut self, artifact: WasmComponentArtifact) -> Result<(), WasmError> {
        let reference = artifact.reference.clone();
        match self.components.entry(reference.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(artifact);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(WasmError::DuplicateComponent(reference))
            }
        }
    }

    #[must_use]
    pub fn components(&self) -> &BTreeMap<String, WasmComponentArtifact> {
        &self.components
    }
}
