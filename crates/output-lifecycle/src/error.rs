use runtrue_control_plane::ControlPlaneError;
use runtrue_model::ContentDigest;
use runtrue_storage::StorageError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("invalid lifecycle worker limits")]
    InvalidConfiguration,
    #[error("control-plane lifecycle operation failed: {0}")]
    ControlPlane(#[from] ControlPlaneError),
    #[error("CAS lifecycle operation failed: {0}")]
    Storage(#[from] StorageError),
    #[error("immutable manifest decoding failed: {0}")]
    DecodeManifest(serde_json::Error),
    #[error("reachable-object bound was exceeded")]
    ReachableObjectLimit,
    #[error("CAS inventory changed during verified deletion")]
    InventoryChanged,
    #[error("lifecycle counter overflow")]
    IntegerOverflow,
    #[error("artifact store operation failed: {0}")]
    Artifact(#[from] runtrue_artifacts::ArtifactError),
    #[error("artifact promotion source metadata changed")]
    PromotionSourceMismatch,
    #[error("artifact catalog id is not a content digest")]
    ArtifactRecordIdentity,
    #[error("artifact catalog does not match its immutable artifact record")]
    ArtifactCatalogMismatch,
    #[error("scanner evidence is empty or exceeds its configured byte limit")]
    ScanEvidenceLimit,
    #[error("artifact promotion evidence digest changed")]
    PromotionEvidenceMismatch,
    #[error("artifact promotion is not pending")]
    PromotionNotPending,
    #[error("completed artifact promotion has no exact result")]
    PromotionResultMissing,
    #[error("lifecycle JSON conversion failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("durable GC lease has an invalid phase")]
    InvalidGcPhase,
    #[error("unsupported {kind} manifest version {version}")]
    UnsupportedManifestVersion { kind: &'static str, version: u32 },
    #[error("CAS object {digest} has {actual} bytes, expected {expected}")]
    ObjectSizeMismatch {
        digest: ContentDigest,
        expected: u64,
        actual: u64,
    },
}
