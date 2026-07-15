use crate::StorageError;

/// Resource limits enforced before untrusted content is retained or expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CasLimits {
    pub max_blob_bytes: u64,
    pub max_manifest_bytes: u64,
    pub max_tree_entries: usize,
    pub max_tree_total_bytes: u64,
    pub max_relative_path_bytes: usize,
    pub max_tree_depth: usize,
}

impl Default for CasLimits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 4 * 1024 * 1024 * 1024,
            max_manifest_bytes: 16 * 1024 * 1024,
            max_tree_entries: 100_000,
            max_tree_total_bytes: 16 * 1024 * 1024 * 1024,
            max_relative_path_bytes: 4 * 1024,
            max_tree_depth: 128,
        }
    }
}

impl CasLimits {
    pub(crate) fn validate(self) -> Result<Self, StorageError> {
        if self.max_blob_bytes == 0
            || self.max_manifest_bytes == 0
            || self.max_tree_entries == 0
            || self.max_tree_total_bytes == 0
            || self.max_relative_path_bytes == 0
            || self.max_tree_depth == 0
        {
            return Err(StorageError::InvalidConfiguration(
                "all CAS limits must be greater than zero".to_owned(),
            ));
        }
        Ok(self)
    }
}
