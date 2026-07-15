use crate::MAX_REPLAY_BUNDLE_BYTES;
use runtrue_model::ContentDigest;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("unsupported replay schema version {0}")]
    UnsupportedSchema(u32),
    #[error("replay bundle exceeds the {MAX_REPLAY_BUNDLE_BYTES}-byte limit: {0} bytes")]
    TooLarge(usize),
    #[error("replay bundle is not in its exact canonical representation")]
    NonCanonical,
    #[error("replay field `{0}` must be sorted and duplicate-free")]
    NonCanonicalSet(&'static str),
    #[error("replay capsule digest mismatch: expected {expected}, found {actual}")]
    CapsuleDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("replay bundle digest mismatch: expected {expected}, found {actual}")]
    BundleDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error(transparent)]
    Capsule(#[from] runtrue_workflow_ir::CapsuleError),
    #[error("invalid replay JSON: {0}")]
    Json(#[from] serde_json::Error),
}
