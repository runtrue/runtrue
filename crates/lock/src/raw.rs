use runtrue_model::ContentDigest;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLockFile {
    pub(crate) lock_version: u32,
    #[serde(default, rename = "component")]
    pub(crate) components: Vec<RawComponentEntry>,
    #[serde(default, rename = "image")]
    pub(crate) images: Vec<RawImageEntry>,
    #[serde(default, rename = "workflow")]
    pub(crate) workflows: Vec<RawWorkflowEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawComponentEntry {
    pub(crate) source: String,
    pub(crate) resolved: ContentDigest,
    pub(crate) signature_identity: String,
    pub(crate) wit_world: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawImageEntry {
    pub(crate) source: String,
    pub(crate) resolved: String,
    pub(crate) platform: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawWorkflowEntry {
    pub(crate) source: String,
    pub(crate) commit: String,
    pub(crate) digest: ContentDigest,
}
