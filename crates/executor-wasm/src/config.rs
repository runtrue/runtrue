use crate::{
    AotCacheConfig, HandleAuthenticationKey, WasmComponentArtifact, WasmError, WasmLimits,
    WasmTarget,
};
use std::collections::BTreeMap;
pub struct WasmExecutorConfig {
    pub target: WasmTarget,
    pub limits: WasmLimits,
    pub cache: AotCacheConfig,
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
