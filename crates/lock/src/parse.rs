use crate::model::{ComponentEntry, ImageEntry, LockFile, WorkflowEntry, MAX_LOCKFILE_BYTES};
use crate::raw::RawLockFile;
use crate::LockError;

impl LockFile {
    pub fn parse(bytes: &[u8]) -> Result<Self, LockError> {
        if bytes.len() > MAX_LOCKFILE_BYTES {
            return Err(LockError::TooLarge {
                limit: MAX_LOCKFILE_BYTES,
                actual: bytes.len(),
            });
        }
        let source = std::str::from_utf8(bytes).map_err(LockError::Utf8)?;
        let raw: RawLockFile = toml::from_str(source).map_err(LockError::Toml)?;
        let mut lock = Self {
            lock_version: raw.lock_version,
            components: raw
                .components
                .into_iter()
                .map(|entry| ComponentEntry {
                    source: entry.source,
                    resolved: entry.resolved,
                    signature_identity: entry.signature_identity,
                    wit_world: entry.wit_world,
                })
                .collect(),
            images: raw
                .images
                .into_iter()
                .map(|entry| ImageEntry {
                    source: entry.source,
                    resolved: entry.resolved,
                    platform: entry.platform,
                })
                .collect(),
            workflows: raw
                .workflows
                .into_iter()
                .map(|entry| WorkflowEntry {
                    source: entry.source,
                    commit: entry.commit,
                    digest: entry.digest,
                })
                .collect(),
        };
        lock.normalize_and_validate()?;
        Ok(lock)
    }
}
