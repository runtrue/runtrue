#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid {0:?} metadata header")]
    InvalidMetadataHeader(RoleType),
    #[error("{0:?} metadata was issued in the future")]
    MetadataFromFuture(RoleType),
    #[error("{0:?} metadata is expired")]
    MetadataExpired(RoleType),
    #[error("invalid update public key")]
    InvalidPublicKey,
    #[error("update key id does not match its public key")]
    KeyIdMismatch,
    #[error("invalid root metadata")]
    InvalidRootMetadata,
    #[error("missing role assignment for {0:?}")]
    MissingRoleAssignment(RoleType),
    #[error("invalid role assignment")]
    InvalidRoleAssignment,
    #[error("one update key may not be assigned to multiple roles")]
    RoleKeyReuse,
    #[error("root contains an unassigned key")]
    UnassignedRootKey,
    #[error("invalid target description")]
    InvalidTargetDescription,
    #[error("targets metadata is empty or exceeds its bound")]
    InvalidTargetsMetadata,
    #[error("unsafe update target path `{0}`")]
    UnsafeTargetPath(String),
    #[error("update target exceeds its size bound")]
    TargetTooLarge,
    #[error("update target length does not match signed metadata")]
    TargetLengthMismatch,
    #[error("update target digest does not match signed metadata")]
    TargetDigestMismatch,
    #[error("update target `{0}` is absent from signed targets")]
    TargetNotFound(String),
    #[error("invalid snapshot metadata")]
    InvalidSnapshotMetadata,
    #[error("invalid timestamp metadata")]
    InvalidTimestampMetadata,
    #[error("referenced metadata version does not match")]
    ReferencedVersionMismatch,
    #[error("referenced metadata digest or length does not match")]
    MetadataReferenceMismatch,
    #[error("metadata exceeds its encoded bound")]
    MetadataTooLarge,
    #[error("invalid signature encoding or algorithm")]
    InvalidSignatureEncoding,
    #[error("duplicate or excessive metadata signature")]
    DuplicateOrExcessSignature,
    #[error("metadata signature set is not strictly unique and canonical")]
    InvalidSignatureSet,
    #[error("metadata signature key is not authorized for the role")]
    SignatureKeyNotAuthorized,
    #[error("metadata signature is invalid")]
    InvalidSignature,
    #[error("signature threshold for {role:?} requires {required}, found {valid}")]
    SignatureThresholdNotMet {
        role: RoleType,
        required: u16,
        valid: usize,
    },
    #[error("non-sequential root rotation: expected {expected}, got {actual}")]
    NonSequentialRootRotation { expected: u64, actual: u64 },
    #[error("release bundle contains too many sequential root rotations")]
    TooManyRootRotations,
    #[error("metadata version overflow")]
    VersionOverflow,
    #[error("{0:?} metadata rollback was rejected")]
    MetadataRollback(RoleType),
    #[error("same-version {0:?} metadata changed bytes")]
    SameVersionMetadataChanged(RoleType),
    #[error("metadata issue/expiry order is incoherent")]
    IncoherentMetadataTimes,
    #[error("invalid trusted update state")]
    InvalidTrustedState,
    #[error("trusted update state is already initialized")]
    TrustStateAlreadyInitialized,
    #[error("trusted update state changed concurrently")]
    ConcurrentTrustStateChange,
    #[error("bootstrap root does not match the out-of-band expected digest")]
    UnpinnedBootstrapRoot,
    #[error("invalid release provenance statement")]
    InvalidReleaseProvenance,
    #[error("invalid CycloneDX release SBOM")]
    InvalidCycloneDxBom,
    #[error("metadata JSON contains duplicate keys")]
    DuplicateJsonKey,
    #[error("metadata JSON exceeds structural bounds")]
    JsonBoundsExceeded,
    #[error("metadata JSON is not canonical")]
    NonCanonicalMetadata,
    #[error("could not serialize update metadata: {0}")]
    Serialize(serde_json::Error),
    #[error("could not decode update metadata: {0}")]
    Deserialize(serde_json::Error),
    #[error("update trust store path is unsafe: {0}")]
    UnsafeTrustStore(String),
    #[error("release file path is unsafe: {0}")]
    UnsafeFilePath(String),
    #[error("release file I/O during {operation} at {}: {source}", path.display())]
    FileIo {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("update trust store I/O during {operation}: {source}")]
    TrustStoreIo {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}
use crate::RoleType;
use std::path::PathBuf;
use thiserror::Error;
