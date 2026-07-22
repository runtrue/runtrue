use crate::{
    cache::{engine_compatibility_digest, AuthenticatedAotArtifact},
    AotCacheError, AotCacheKey, WasmError, WasmPackageCacheConfig,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use wasmtime::{component::Component, Engine, Precompiled};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackagePreparationTier {
    Cold,
    Warmish,
    Warm,
}

pub(crate) struct WarmComponent {
    pub engine: Engine,
    pub component: Component,
}

pub(crate) struct AdmittedAot {
    key: AotCacheKey,
    bytes: Arc<[u8]>,
}

impl AdmittedAot {
    pub(crate) fn from_authenticated_cache(
        engine: &Engine,
        expected_key: &AotCacheKey,
        artifact: AuthenticatedAotArtifact,
    ) -> Result<Self, WasmError> {
        Self::from_engine_output(engine, expected_key, artifact.into_bytes())
    }

    pub(crate) fn from_component(
        engine: &Engine,
        expected_key: &AotCacheKey,
        component: &Component,
    ) -> Result<Self, WasmError> {
        let bytes = component
            .serialize()
            .map_err(|error| WasmError::Compile(error.to_string()))?;
        Self::from_engine_output(engine, expected_key, bytes)
    }

    fn from_engine_output(
        engine: &Engine,
        expected_key: &AotCacheKey,
        bytes: Vec<u8>,
    ) -> Result<Self, WasmError> {
        if expected_key.engine_compatibility_digest != engine_compatibility_digest(engine) {
            return Err(WasmError::AotCache(AotCacheError::Incompatible));
        }
        if !matches!(
            Engine::detect_precompiled(&bytes),
            Some(Precompiled::Component)
        ) {
            return Err(WasmError::AotCache(AotCacheError::CorruptArtifact));
        }
        Ok(Self {
            key: expected_key.clone(),
            bytes: bytes.into(),
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn key(&self) -> &AotCacheKey {
        &self.key
    }

    #[allow(unsafe_code)]
    pub(crate) fn deserialize(&self, engine: &Engine) -> Result<Component, WasmError> {
        // SAFETY: constructors accept only opaque bytes from the authenticated
        // disk cache or bytes produced directly by `Component::serialize` for
        // the exact engine compatibility digest. The private `Arc<[u8]>` is immutable for the
        // lifetime of this value. This type and method are crate-private; the
        // executor that admitted the entry owns the compatible engine used
        // here, so compatibility does not need to be recomputed on every hit.
        unsafe { Component::deserialize(engine, &self.bytes) }
            .map_err(|error| WasmError::Compile(error.to_string()))
    }
}

struct CacheEntry<T> {
    value: Arc<T>,
    last_used: u64,
}

pub(crate) struct PackageMemoryCache {
    config: WasmPackageCacheConfig,
    sequence: u64,
    warm: BTreeMap<ContentDigest, CacheEntry<WarmComponent>>,
    warmish: BTreeMap<ContentDigest, CacheEntry<AdmittedAot>>,
    warmish_bytes: usize,
}

impl PackageMemoryCache {
    pub(crate) fn new(config: WasmPackageCacheConfig) -> Result<Self, WasmError> {
        if config.max_warm_components == 0
            || config.max_warmish_entries == 0
            || config.max_warmish_bytes == 0
            || config.max_warmish_entries < config.max_warm_components
        {
            return Err(WasmError::InvalidConfiguration(
                "package cache limits must be positive and warmish entries must cover warm entries"
                    .to_owned(),
            ));
        }
        Ok(Self {
            config,
            sequence: 0,
            warm: BTreeMap::new(),
            warmish: BTreeMap::new(),
            warmish_bytes: 0,
        })
    }

    pub(crate) fn warm(&mut self, digest: &ContentDigest) -> Option<Arc<WarmComponent>> {
        let tick = self.tick();
        let entry = self.warm.get_mut(digest)?;
        entry.last_used = tick;
        Some(entry.value.clone())
    }

    pub(crate) fn warmish(&mut self, digest: &ContentDigest) -> Option<Arc<AdmittedAot>> {
        let tick = self.tick();
        let entry = self.warmish.get_mut(digest)?;
        entry.last_used = tick;
        Some(entry.value.clone())
    }

    pub(crate) fn insert_warm(&mut self, digest: ContentDigest, component: Arc<WarmComponent>) {
        let tick = self.tick();
        self.warm.insert(
            digest,
            CacheEntry {
                value: component,
                last_used: tick,
            },
        );
        while self.warm.len() > self.config.max_warm_components {
            let Some(evicted) = least_recent(&self.warm) else {
                break;
            };
            self.warm.remove(&evicted);
        }
    }

    pub(crate) fn insert_warmish(&mut self, digest: ContentDigest, aot: Arc<AdmittedAot>) {
        if aot.len() > self.config.max_warmish_bytes {
            return;
        }
        let tick = self.tick();
        if let Some(previous) = self.warmish.insert(
            digest,
            CacheEntry {
                value: aot.clone(),
                last_used: tick,
            },
        ) {
            self.warmish_bytes = self.warmish_bytes.saturating_sub(previous.value.len());
        }
        self.warmish_bytes = self.warmish_bytes.saturating_add(aot.len());
        while self.warmish.len() > self.config.max_warmish_entries
            || self.warmish_bytes > self.config.max_warmish_bytes
        {
            let Some(evicted) = least_recent(&self.warmish) else {
                break;
            };
            if let Some(entry) = self.warmish.remove(&evicted) {
                self.warmish_bytes = self.warmish_bytes.saturating_sub(entry.value.len());
            }
        }
    }

    pub(crate) fn remove_warmish(&mut self, digest: &ContentDigest) {
        if let Some(entry) = self.warmish.remove(digest) {
            self.warmish_bytes = self.warmish_bytes.saturating_sub(entry.value.len());
        }
    }

    pub(crate) fn tiers(&self) -> BTreeMap<ContentDigest, PackagePreparationTier> {
        let mut tiers = self
            .warmish
            .keys()
            .cloned()
            .map(|digest| (digest, PackagePreparationTier::Warmish))
            .collect::<BTreeMap<_, _>>();
        for digest in self.warm.keys() {
            tiers.insert(digest.clone(), PackagePreparationTier::Warm);
        }
        tiers
    }

    fn tick(&mut self) -> u64 {
        self.sequence = self.sequence.checked_add(1).unwrap_or_else(|| {
            for entry in self.warm.values_mut() {
                entry.last_used = 0;
            }
            for entry in self.warmish.values_mut() {
                entry.last_used = 0;
            }
            1
        });
        self.sequence
    }
}

fn least_recent<T>(entries: &BTreeMap<ContentDigest, CacheEntry<T>>) -> Option<ContentDigest> {
    entries
        .iter()
        .min_by_key(|(digest, entry)| (entry.last_used, *digest))
        .map(|(digest, _)| digest.clone())
}
