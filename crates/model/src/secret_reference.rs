use serde::{Deserialize, Serialize};
use std::fmt;

/// Metadata-only secret reference. This type intentionally has no value field.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    pub metadata_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("metadata_id", &self.metadata_id)
            .field("name", &self.name)
            .field("purpose", &self.purpose)
            .finish()
    }
}
