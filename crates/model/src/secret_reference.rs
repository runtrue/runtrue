use crate::ContentDigest;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Exact project membership revision that participated in secret resolution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretProjectVersion {
    pub project_id: String,
    pub version: u64,
}

/// Trusted, metadata-only resolution proof sealed into an execution capsule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretResolutionBinding {
    /// Exact durable scope key selected by the trusted resolver.
    pub scope: String,
    /// Built-in version selected at planning time. External providers may omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_version: Option<u64>,
    pub resolution_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub project_versions: Vec<SecretProjectVersion>,
}

/// Metadata-only secret reference. This type intentionally has no value field.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    pub metadata_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Absent only for compiler-local references and reserved provider grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<SecretResolutionBinding>,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("metadata_id", &self.metadata_id)
            .field("name", &self.name)
            .field("purpose", &self.purpose)
            .field("resolution", &self.resolution)
            .finish()
    }
}
