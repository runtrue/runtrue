use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

pub const BACKUP_FORMAT_VERSION: u32 = 1;
pub const MANIFEST_FILE_NAME: &str = "manifest.json";
pub const DATABASE_RELATIVE_PATH: &str = "control-plane.sqlite";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupLimits {
    pub max_manifest_bytes: u64,
    pub max_entries: usize,
    pub max_file_bytes: u64,
    pub max_database_bytes: u64,
    pub max_total_bytes: u64,
    pub max_relative_path_bytes: usize,
    pub max_depth: usize,
    pub max_database_records: usize,
    pub max_database_record_bytes: u64,
}

impl Default for BackupLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 32 * 1024 * 1024,
            max_entries: 250_000,
            max_file_bytes: 8 * 1024 * 1024 * 1024,
            max_database_bytes: 64 * 1024 * 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024 * 1024 * 1024,
            max_relative_path_bytes: 4 * 1024,
            max_depth: 128,
            max_database_records: 2_000_000,
            max_database_record_bytes: 32 * 1024 * 1024,
        }
    }
}

impl BackupLimits {
    pub(crate) fn validate(self) -> Result<Self, &'static str> {
        if self.max_manifest_bytes == 0
            || self.max_entries == 0
            || self.max_file_bytes == 0
            || self.max_database_bytes == 0
            || self.max_total_bytes == 0
            || self.max_relative_path_bytes == 0
            || self.max_depth == 0
            || self.max_database_records == 0
            || self.max_database_record_bytes == 0
            || self.max_database_bytes > self.max_total_bytes
            || self.max_file_bytes > self.max_total_bytes
        {
            return Err("backup limits must be non-zero and internally consistent");
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupRole {
    Database,
    Blob,
    Config,
    KeyCiphertext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub path: String,
    pub role: BackupRole,
    pub size_bytes: u64,
    pub digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalKeyContinuity {
    pub capsule_signing_key_id: ContentDigest,
    pub oidc_signing_key_id: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub format_version: u32,
    pub created_unix_ms: u64,
    pub installation_id: String,
    pub source_schema_version: u32,
    pub source_fencing_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_key_continuity: Option<LocalKeyContinuity>,
    pub entries: Vec<ManifestEntry>,
    pub total_bytes: u64,
}
