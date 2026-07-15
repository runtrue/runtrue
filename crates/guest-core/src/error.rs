use runtrue_model::ContentDigest;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GuestError {
    #[error("invalid guest boot configuration")]
    InvalidBootConfiguration,
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("unsupported guest protocol version {0}")]
    UnsupportedProtocol(u32),
    #[error("invalid or expired guest bootstrap")]
    InvalidBootstrap,
    #[error("guest session expired")]
    SessionExpired,
    #[error("guest session authenticator is unavailable")]
    AuthenticationUnavailable,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("guest message authentication failed")]
    AuthenticationFailed,
    #[error("guest message is for another session")]
    WrongSession,
    #[error("unexpected message sequence: expected {expected}, found {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
    #[error("message sequence space is exhausted")]
    SequenceExhausted,
    #[error("guest message has invalid size {0}")]
    MessageSize(usize),
    #[error("guest message is not in canonical JSON form")]
    NonCanonicalMessage,
    #[error("guest capsule has invalid size {0}")]
    InvalidCapsuleSize(usize),
    #[error("guest capsule digest does not match the boot configuration")]
    CapsuleDigestMismatch,
    #[error("guest capsule is not canonical")]
    NonCanonicalCapsule,
    #[error("guest capsule trust store is empty")]
    EmptyCapsuleTrustStore,
    #[error("guest capsule trust store already contains key `{0}`")]
    DuplicateCapsuleKey(ContentDigest),
    #[error("guest does not trust capsule key `{0}`")]
    UntrustedCapsuleKey(ContentDigest),
    #[error("execution capsule signature failed: {0}")]
    InvalidCapsuleSignature(runtrue_attest::AttestError),
    #[error("execution capsule canonicalization failed: {0}")]
    CanonicalCapsule(runtrue_workflow_ir::CapsuleError),
    #[error("job `{0}` is not in the signed capsule")]
    JobNotInCapsule(String),
    #[error("execution capsule has not been admitted")]
    CapsuleNotAdmitted,
    #[error("guest session state violation: {0}")]
    InvalidState(&'static str),
    #[error("guest mount limit exceeded")]
    MountLimitExceeded,
    #[error("unsafe guest mount path `{0}`")]
    UnsafeMountPath(String),
    #[error("duplicate guest mount id or path")]
    DuplicateMount,
    #[error("guest mount path `{0}` is not declared by any step capability")]
    UndeclaredMountCapability(String),
    #[error("step `{0}` is not in the signed job")]
    StepNotInCapsule(String),
    #[error("step `{0}` has already completed")]
    StepAlreadyCompleted(String),
    #[error("step capability digest does not match the signed capsule")]
    CapabilityDigestMismatch,
    #[error("there is no active guest step")]
    NoActiveStep,
    #[error("message does not target the active guest step")]
    WrongActiveStep,
    #[error("guest step result has an invalid outcome combination")]
    InvalidStepResult,
    #[error("guest job cannot finish until every signed-capsule step has a terminal result")]
    IncompleteJob,
    #[error("invalid or expired secret envelope")]
    InvalidSecretEnvelope,
    #[error("secret is not declared for the active step")]
    UndeclaredSecret,
    #[error("invalid or expired OIDC envelope")]
    InvalidOidcEnvelope,
    #[error("OIDC audience is not declared for the active step")]
    UndeclaredOidcAudience,
    #[error("guest log frame exceeds its bounded size")]
    LogFrameTooLarge,
    #[error("guest JSON failed: {0}")]
    Json(serde_json::Error),
}
