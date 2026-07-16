use crate::error::ImportError;
use runtrue_lock::LockFile;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedImageLock {
    pub(crate) source: String,
    pub(crate) resolved: String,
    pub(crate) platform: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedComponentLock {
    pub(crate) source: String,
    pub(crate) resolved: String,
    pub(crate) signature_identity: String,
    pub(crate) wit_world: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedLockfile {
    pub(crate) lock_version: u32,
    #[serde(rename = "image")]
    pub(crate) images: Vec<GeneratedImageLock>,
    #[serde(rename = "component")]
    pub(crate) components: Vec<GeneratedComponentLock>,
}

pub(crate) fn build_lockfile(
    images: BTreeSet<GeneratedImageLock>,
    components: BTreeSet<GeneratedComponentLock>,
) -> Result<Option<(LockFile, String)>, ImportError> {
    if images.is_empty() && components.is_empty() {
        return Ok(None);
    }
    let generated = GeneratedLockfile {
        lock_version: 1,
        images: images.into_iter().collect(),
        components: components.into_iter().collect(),
    };
    let text =
        toml::to_string(&generated).map_err(|error| ImportError::Serialize(error.to_string()))?;
    let lock = LockFile::parse(text.as_bytes())
        .map_err(|error| ImportError::GeneratedLockfile(error.to_string()))?;
    Ok(Some((lock, text)))
}
