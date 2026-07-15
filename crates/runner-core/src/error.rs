use runtrue_model::ContentDigest;
use runtrue_protocol::DigestConversionError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RunnerAdmissionError {
    #[error("invalid runner profile: {0}")]
    InvalidProfile(String),
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("capsule trust store cannot be empty")]
    EmptyTrustStore,
    #[error("duplicate capsule signing key `{0}`")]
    DuplicateSigningKey(ContentDigest),
    #[error("untrusted capsule signing key `{0}`")]
    UntrustedSigningKey(ContentDigest),
    #[error("installation fencing epoch must be greater than zero")]
    InvalidInstallationEpoch,
    #[error("capsule byte limit must be greater than zero")]
    InvalidCapsuleLimit,
    #[error("offer targets runner `{actual}`, expected `{expected}`")]
    WrongRunner { expected: String, actual: String },
    #[error("lease fencing generation must be greater than zero")]
    InvalidFencingGeneration,
    #[error("stale installation epoch {actual}; expected {expected}")]
    StaleInstallationEpoch { expected: u64, actual: u64 },
    #[error("missing protobuf timestamp `{0}`")]
    MissingTimestamp(&'static str),
    #[error("invalid protobuf timestamp `{0}`")]
    InvalidTimestamp(&'static str),
    #[error("invalid lease time window")]
    InvalidLeaseWindow,
    #[error("lease offer is outside its acceptance window")]
    OfferOutsideAcceptanceWindow,
    #[error("missing digest `{0}")]
    MissingDigest(&'static str),
    #[error(transparent)]
    WireDigest(#[from] DigestConversionError),
    #[error("offer and fetched capsule digests disagree")]
    CapsuleDigestDisagreement,
    #[error("canonical capsule size {actual} is outside 1..={limit} bytes")]
    CapsuleSize { limit: usize, actual: usize },
    #[error("canonical capsule bytes do not match their digest")]
    CapsuleDigestMismatch,
    #[error("unsupported capsule media type `{0}`")]
    UnsupportedCapsuleMediaType(String),
    #[error("lease offer and fetched signature envelopes disagree")]
    SignatureEnvelopeDisagreement,
    #[error("invalid execution capsule JSON: {0}")]
    InvalidCapsuleJson(serde_json::Error),
    #[error("cannot canonicalize execution capsule: {0}")]
    CanonicalCapsule(runtrue_workflow_ir::CapsuleError),
    #[error("execution capsule bytes are not exact canonical JSON")]
    NonCanonicalCapsule,
    #[error("invalid capsule signing key id")]
    InvalidSigningKeyId,
    #[error("execution capsule signature verification failed: {0}")]
    InvalidCapsuleSignature(runtrue_attest::AttestError),
    #[error("unsupported capsule schema version {actual}; expected {expected}")]
    UnsupportedCapsuleSchemaVersion { expected: u32, actual: u32 },
    #[error("unsupported engine compatibility version `{actual}`; expected `{expected}`")]
    UnsupportedEngineCompatibilityVersion {
        expected: &'static str,
        actual: String,
    },
    #[error("job `{0}` is not present in the signed capsule")]
    JobNotInCapsule(String),
    #[error("lease offer omits runner requirements")]
    MissingRequirements,
    #[error("lease requirements do not exactly match the signed capsule")]
    RequirementsDoNotMatchCapsule,
    #[error("verified runner profile cannot satisfy the signed capsule")]
    VerifiedProfileCannotSatisfyCapsule,
    #[error("lease operation carries a stale or mismatched fence")]
    StaleLeaseFence,
    #[error("lease has expired")]
    LeaseExpired,
    #[error("operation is not valid in the current lease state")]
    InvalidLeaseState,
    #[error("repeated completion conflicts with the accepted result")]
    ConflictingCompletion,
}
