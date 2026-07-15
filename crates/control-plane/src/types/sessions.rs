use runtrue_model::ContentDigest;
use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct ReplayBundleRecord {
    pub id: String,
    pub run_id: String,
    pub digest: ContentDigest,
    pub canonical_bundle: Vec<u8>,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
}

impl fmt::Debug for ReplayBundleRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayBundleRecord")
            .field("id", &self.id)
            .field("run_id", &self.run_id)
            .field("digest", &self.digest)
            .field("canonical_bundle_bytes", &self.canonical_bundle.len())
            .field("created_unix_ms", &self.created_unix_ms)
            .field("expires_unix_ms", &self.expires_unix_ms)
            .finish()
    }
}
