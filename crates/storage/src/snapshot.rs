use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

/// Summary of an immutable tree snapshot stored in the CAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeSnapshot {
    pub manifest_digest: ContentDigest,
    pub file_count: usize,
    pub directory_count: usize,
    pub total_file_bytes: u64,
}

/// A captured regular file or directory tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PathSnapshot {
    File {
        digest: ContentDigest,
        size_bytes: u64,
        executable: bool,
    },
    Directory {
        manifest_digest: ContentDigest,
        file_count: usize,
        directory_count: usize,
        total_file_bytes: u64,
    },
}

impl From<TreeSnapshot> for PathSnapshot {
    fn from(snapshot: TreeSnapshot) -> Self {
        Self::Directory {
            manifest_digest: snapshot.manifest_digest,
            file_count: snapshot.file_count,
            directory_count: snapshot.directory_count,
            total_file_bytes: snapshot.total_file_bytes,
        }
    }
}
