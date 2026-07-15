mod memory;
mod sqlite;
mod validation;

use crate::{SignatureEnvelope, SigningError};
use runtrue_model::ContentDigest;

pub use memory::MemorySigningLedger;
pub use sqlite::SqliteSigningLedger;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerState {
    Reserved {
        request_digest: ContentDigest,
    },
    Signed {
        request_digest: ContentDigest,
        envelope: SignatureEnvelope,
    },
    Complete {
        request_digest: ContentDigest,
        envelope: SignatureEnvelope,
    },
}

pub trait SigningLedger: Send + Sync {
    fn reserve(
        &self,
        request_id: &str,
        request_digest: &ContentDigest,
    ) -> Result<Option<LedgerState>, SigningError>;
    fn store_signed(
        &self,
        request_id: &str,
        request_digest: &ContentDigest,
        envelope: &SignatureEnvelope,
    ) -> Result<(), SigningError>;
    fn complete(
        &self,
        request_id: &str,
        request_digest: &ContentDigest,
    ) -> Result<(), SigningError>;
    fn abort(&self, request_id: &str, request_digest: &ContentDigest) -> Result<(), SigningError>;
}
