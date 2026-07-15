use crate::GitError;
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

pub const GIT_TREE_MANIFEST_VERSION: u32 = 1;

/// A canonical description of an exact Git tree. Entries are always sorted by
/// repository-relative byte path before this value is returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitTreeManifest {
    pub version: u32,
    pub repository_id: String,
    pub commit: String,
    pub entries: Vec<GitTreeEntry>,
}

impl GitTreeManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GitError> {
        serde_json::to_vec(self).map_err(|_| GitError::InvalidGitOutput("source manifest"))
    }

    pub fn digest(&self) -> Result<ContentDigest, GitError> {
        Ok(ContentDigest::sha256(self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitTreeEntry {
    pub path: String,
    pub kind: GitTreeEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GitTreeEntryKind {
    Directory,
    File {
        digest: ContentDigest,
        size_bytes: u64,
        executable: bool,
    },
    Symlink {
        target: String,
    },
}
