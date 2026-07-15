use crate::LockError;
use runtrue_model::ContentDigest;
use serde::Serialize;

pub const LOCK_VERSION: u32 = 1;
pub const MAX_LOCKFILE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_ENTRIES_PER_KIND: usize = 16_384;
pub(crate) const MAX_SOURCE_BYTES: usize = 4_096;
pub(crate) const MAX_METADATA_BYTES: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockFile {
    pub(crate) lock_version: u32,
    #[serde(default, rename = "component")]
    pub(crate) components: Vec<ComponentEntry>,
    #[serde(default, rename = "image")]
    pub(crate) images: Vec<ImageEntry>,
    #[serde(default, rename = "workflow")]
    pub(crate) workflows: Vec<WorkflowEntry>,
}

impl LockFile {
    #[must_use]
    pub const fn lock_version(&self) -> u32 {
        self.lock_version
    }

    #[must_use]
    pub fn components(&self) -> &[ComponentEntry] {
        &self.components
    }

    #[must_use]
    pub fn images(&self) -> &[ImageEntry] {
        &self.images
    }

    #[must_use]
    pub fn workflows(&self) -> &[WorkflowEntry] {
        &self.workflows
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.components.is_empty() && self.images.is_empty() && self.workflows.is_empty()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LockError> {
        serde_json::to_vec(self).map_err(LockError::Canonical)
    }

    pub fn digest(&self) -> Result<ContentDigest, LockError> {
        Ok(ContentDigest::sha256(self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentEntry {
    pub(crate) source: String,
    pub(crate) resolved: ContentDigest,
    pub(crate) signature_identity: String,
    pub(crate) wit_world: String,
}

impl ComponentEntry {
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub const fn resolved(&self) -> &ContentDigest {
        &self.resolved
    }

    #[must_use]
    pub fn signature_identity(&self) -> &str {
        &self.signature_identity
    }

    #[must_use]
    pub fn wit_world(&self) -> &str {
        &self.wit_world
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageEntry {
    pub(crate) source: String,
    pub(crate) resolved: String,
    pub(crate) platform: String,
}

impl ImageEntry {
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub fn resolved(&self) -> &str {
        &self.resolved
    }

    #[must_use]
    pub fn platform(&self) -> &str {
        &self.platform
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowEntry {
    pub(crate) source: String,
    pub(crate) commit: String,
    pub(crate) digest: ContentDigest,
}

impl WorkflowEntry {
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Component,
    Image,
    Workflow,
}

impl std::fmt::Display for EntryKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Component => "component",
            Self::Image => "image",
            Self::Workflow => "workflow",
        })
    }
}
