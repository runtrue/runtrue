mod authentication;
mod error;
mod read;
mod validation;
mod write;
use read::read_bounded;
pub(crate) use validation::engine_compatibility_digest;
use write::{atomic_write_private, Publication};
mod metadata;
mod model;
mod secure_fs;
pub use authentication::AotAuthenticationKey;
pub use error::AotCacheError;
use hmac::{Hmac, Mac as _};
use metadata::{AuthenticatedMetadata, UnsignedMetadata};
pub use model::{AotCacheConfig, AotCacheEvent, AotCacheEventKind, AotCacheKey, AotCacheStatus};
use runtrue_model::ContentDigest;
use secure_fs::{
    cache_io, create_private_directory, ensure_exact_private_file, remove_file_if_unchanged,
    safe_regular_file_if_exists, CachePaths,
};
use sha2::Sha256;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use wasmtime::{Engine, Precompiled};

const CACHE_DOMAIN: &[u8] = b"runtrue.wasm-aot-cache.v1\0";
const MAX_METADATA_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct AotCache {
    authenticated_root: PathBuf,
    quarantine_root: PathBuf,
    authentication_key: AotAuthenticationKey,
    max_entries: usize,
    max_total_bytes: u64,
    max_entry_bytes: usize,
}

pub(crate) struct PreparedAotCache {
    pub cache: AotCache,
    pub wasmtime_config_path: PathBuf,
}

pub(crate) struct AotCacheInspection {
    pub status: AotCacheStatus,
    pub authenticated_artifact: Option<Vec<u8>>,
}

impl AotCache {
    pub(crate) fn prepare(config: AotCacheConfig) -> Result<PreparedAotCache, AotCacheError> {
        #[cfg(not(unix))]
        return Err(AotCacheError::UnsupportedPlatform);

        if !config.root.is_absolute() {
            return Err(AotCacheError::RelativeRoot);
        }
        if config.max_entries == 0
            || config.max_total_bytes == 0
            || config.max_entry_bytes == 0
            || u64::try_from(config.max_entry_bytes).unwrap_or(u64::MAX) > config.max_total_bytes
        {
            return Err(AotCacheError::InvalidLimits);
        }
        create_private_directory(&config.root)?;
        let authenticated_root = config.root.join("authenticated");
        let quarantine_root = config.root.join("quarantine");
        let wasmtime_root = config.root.join("wasmtime");
        create_private_directory(&authenticated_root)?;
        create_private_directory(&quarantine_root)?;
        create_private_directory(&wasmtime_root)?;

        let wasmtime_config_path = config.root.join("wasmtime-cache.toml");
        let directory = wasmtime_root.to_string_lossy();
        let directory = serde_json::to_string(directory.as_ref())?;
        let cache_config = format!(
            "[cache]\ndirectory = {directory}\nfile-count-soft-limit = \"{}\"\nfiles-total-size-soft-limit = \"{}\"\n",
            config.max_entries,
            config.max_total_bytes,
        );
        ensure_exact_private_file(&wasmtime_config_path, cache_config.as_bytes())?;

        Ok(PreparedAotCache {
            cache: Self {
                authenticated_root,
                quarantine_root,
                authentication_key: config.authentication_key,
                max_entries: config.max_entries,
                max_total_bytes: config.max_total_bytes,
                max_entry_bytes: config.max_entry_bytes,
            },
            wasmtime_config_path,
        })
    }

    pub(crate) fn inspect(
        &self,
        _engine: &Engine,
        expected_key: &AotCacheKey,
    ) -> Result<AotCacheInspection, AotCacheError> {
        let paths = self.paths(expected_key)?;
        let metadata_exists = safe_regular_file_if_exists(&paths.metadata)?;
        let artifact_exists = safe_regular_file_if_exists(&paths.artifact)?;
        match (metadata_exists, artifact_exists) {
            (false, false) => {
                return Ok(AotCacheInspection {
                    status: AotCacheStatus::Miss,
                    authenticated_artifact: None,
                })
            }
            (true, true) => {}
            _ => return Err(AotCacheError::CorruptArtifact),
        }

        let metadata_bytes = read_bounded(&paths.metadata, MAX_METADATA_BYTES)?;
        let metadata: AuthenticatedMetadata = serde_json::from_slice(&metadata_bytes)?;
        if serde_json::to_vec(&metadata)? != metadata_bytes {
            return Err(AotCacheError::CorruptArtifact);
        }
        if metadata.schema_version != 1 || &metadata.key != expected_key {
            return Err(AotCacheError::Incompatible);
        }
        let artifact_size =
            usize::try_from(metadata.artifact_size).map_err(|_| AotCacheError::EntryTooLarge)?;
        if artifact_size > self.max_entry_bytes {
            return Err(AotCacheError::EntryTooLarge);
        }
        let artifact = read_bounded(
            &paths.artifact,
            u64::try_from(self.max_entry_bytes).unwrap_or(u64::MAX),
        )?;
        if artifact.len() != artifact_size
            || ContentDigest::sha256(&artifact) != metadata.artifact_digest
        {
            return Err(AotCacheError::CorruptArtifact);
        }
        self.verify_tag(&metadata, &artifact)?;
        if !matches!(
            Engine::detect_precompiled(&artifact),
            Some(Precompiled::Component)
        ) {
            return Err(AotCacheError::CorruptArtifact);
        }
        Ok(AotCacheInspection {
            status: AotCacheStatus::Hit,
            authenticated_artifact: Some(artifact),
        })
    }

    pub(crate) fn record(&self, key: &AotCacheKey, artifact: &[u8]) -> Result<(), AotCacheError> {
        if artifact.is_empty() || artifact.len() > self.max_entry_bytes {
            return Err(AotCacheError::EntryTooLarge);
        }
        let paths = self.paths(key)?;
        if safe_regular_file_if_exists(&paths.metadata)?
            || safe_regular_file_if_exists(&paths.artifact)?
        {
            return Err(AotCacheError::CorruptArtifact);
        }
        self.enforce_budget(artifact.len())?;
        let artifact_digest = ContentDigest::sha256(artifact);
        let artifact_size =
            u64::try_from(artifact.len()).map_err(|_| AotCacheError::EntryTooLarge)?;
        let unsigned = UnsignedMetadata {
            schema_version: 1,
            key,
            artifact_digest: &artifact_digest,
            artifact_size,
        };
        let unsigned_bytes = serde_json::to_vec(&unsigned)?;
        let authentication_tag = self.authentication_tag(&unsigned_bytes, artifact)?;
        let metadata = AuthenticatedMetadata {
            schema_version: 1,
            key: key.clone(),
            artifact_digest,
            artifact_size,
            authentication_tag,
        };
        let metadata_bytes = serde_json::to_vec(&metadata)?;
        if atomic_write_private(&paths.artifact, artifact)? == Publication::Existing {
            return Err(AotCacheError::EntryAlreadyExists);
        }
        if atomic_write_private(&paths.metadata, &metadata_bytes)? == Publication::Existing {
            // Never remove the artifact here: another publisher or a damaged
            // cache may own the destination name. The partial pair will be
            // detected and quarantined on the next inspection.
            return Err(AotCacheError::EntryAlreadyExists);
        }
        Ok(())
    }

    pub(crate) fn quarantine(&self, key: &AotCacheKey) -> Result<(), AotCacheError> {
        let paths = self.paths(key)?;
        let key_digest = key.digest()?;
        let stem = key_digest
            .as_str()
            .strip_prefix("sha256:")
            .ok_or(AotCacheError::Incompatible)?;
        for (source, kind) in [(&paths.metadata, "metadata"), (&paths.artifact, "artifact")] {
            if !safe_regular_file_if_exists(source)? {
                continue;
            }
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let destination = self.quarantine_root.join(format!(
                "{stem}-{kind}-{}-{sequence}.quarantine",
                std::process::id()
            ));
            fs::hard_link(source, &destination).map_err(|error| cache_io(&destination, error))?;
            remove_file_if_unchanged(source)?;
        }
        Ok(())
    }

    fn verify_tag(
        &self,
        metadata: &AuthenticatedMetadata,
        artifact: &[u8],
    ) -> Result<(), AotCacheError> {
        let unsigned = UnsignedMetadata {
            schema_version: metadata.schema_version,
            key: &metadata.key,
            artifact_digest: &metadata.artifact_digest,
            artifact_size: metadata.artifact_size,
        };
        let unsigned_bytes = serde_json::to_vec(&unsigned)?;
        let tag = hex::decode(&metadata.authentication_tag)
            .map_err(|_| AotCacheError::AuthenticationFailed)?;
        let mut mac = HmacSha256::new_from_slice(&self.authentication_key.0)
            .map_err(|_| AotCacheError::AuthenticationFailed)?;
        mac.update(CACHE_DOMAIN);
        mac.update(&unsigned_bytes);
        mac.update(artifact);
        mac.verify_slice(&tag)
            .map_err(|_| AotCacheError::AuthenticationFailed)
    }

    fn authentication_tag(
        &self,
        unsigned_metadata: &[u8],
        artifact: &[u8],
    ) -> Result<String, AotCacheError> {
        let mut mac = HmacSha256::new_from_slice(&self.authentication_key.0)
            .map_err(|_| AotCacheError::AuthenticationFailed)?;
        mac.update(CACHE_DOMAIN);
        mac.update(unsigned_metadata);
        mac.update(artifact);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn paths(&self, key: &AotCacheKey) -> Result<CachePaths, AotCacheError> {
        let digest = key.digest()?;
        let stem = digest
            .as_str()
            .strip_prefix("sha256:")
            .ok_or(AotCacheError::Incompatible)?;
        Ok(CachePaths {
            metadata: self.authenticated_root.join(format!("{stem}.json")),
            artifact: self.authenticated_root.join(format!("{stem}.aot")),
        })
    }

    fn enforce_budget(&self, new_artifact_bytes: usize) -> Result<(), AotCacheError> {
        let mut entries = 0_usize;
        let mut scanned_files = 0_usize;
        let mut total = 0_u64;
        let scan_limit = self.max_entries.saturating_mul(2).saturating_add(64);
        for entry in fs::read_dir(&self.authenticated_root)
            .map_err(|source| cache_io(&self.authenticated_root, source))?
        {
            let entry = entry.map_err(|source| cache_io(&self.authenticated_root, source))?;
            scanned_files = scanned_files.saturating_add(1);
            if scanned_files > scan_limit {
                return Err(AotCacheError::BudgetExceeded);
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| cache_io(&path, source))?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(AotCacheError::UnsafePath {
                    path,
                    reason: "cache entries must be regular non-symlink files".to_owned(),
                });
            }
            total = total
                .checked_add(metadata.len())
                .ok_or(AotCacheError::BudgetExceeded)?;
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "aot")
            {
                entries = entries.saturating_add(1);
            }
        }
        let new_bytes = u64::try_from(new_artifact_bytes)
            .map_err(|_| AotCacheError::BudgetExceeded)?
            .saturating_add(MAX_METADATA_BYTES);
        if entries >= self.max_entries || total.saturating_add(new_bytes) > self.max_total_bytes {
            return Err(AotCacheError::BudgetExceeded);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
