use runtrue_model::ContentDigest;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderContractError {
    #[error("invalid or oversized {0}")]
    InvalidText(&'static str),
    #[error("invalid contract generation range")]
    InvalidGenerationRange,
    #[error("no compatible Provider contract generation")]
    NoCompatibleGeneration,
    #[error(
        "contract negotiation attempted to downgrade authenticated generation {authenticated} to {selected}"
    )]
    DowngradeRejected { authenticated: u32, selected: u32 },
    #[error("Provider contract collection exceeds its bound")]
    CollectionLimit,
    #[error("Provider contract numeric value is invalid: {0}")]
    InvalidNumber(&'static str),
    #[error("Provider descriptor is inconsistent: {0}")]
    InvalidDescriptor(&'static str),
    #[error("required Provider feature profile is unsupported: {0}")]
    UnsupportedProfile(String),
    #[error("runtime inventory is inconsistent: {0}")]
    InvalidInventory(&'static str),
    #[error("capacity observation is invalid or expired")]
    InvalidCapacityObservation,
    #[error("portable failure cause is invalid: {0}")]
    InvalidFailureCause(&'static str),
    #[error("retry decision is inconsistent")]
    InvalidRetryDecision,
    #[error("Evidence event is invalid: {0}")]
    InvalidEvidence(&'static str),
    #[error("Evidence event digest mismatch: expected {expected}, computed {actual}")]
    EvidenceDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("Evidence chain scope or subject changed")]
    EvidenceSubjectChanged,
    #[error("Evidence chain expected sequence {expected}, found {actual}")]
    EvidenceSequence { expected: u64, actual: u64 },
    #[error("Evidence chain previous-event digest mismatch at sequence {0}")]
    EvidencePreviousDigest(u64),
    #[error("invalid logical object contract: {0}")]
    InvalidObjectContract(&'static str),
    #[error("invalid pool member transition")]
    InvalidPoolTransition,
    #[error("external-effect transition is invalid: {0}")]
    InvalidEffectTransition(&'static str),
    #[error("external-effect transition digest mismatch")]
    EffectDigestMismatch,
    #[error("Provider operation contract is invalid: {0}")]
    InvalidOperation(&'static str),
    #[error("Invocation capability contract is invalid: {0}")]
    InvalidInvocation(&'static str),
    #[error("conformance metadata is invalid: {0}")]
    InvalidConformance(&'static str),
    #[error("canonical Provider contract JSON failed: {0}")]
    Json(String),
}

impl From<serde_json::Error> for ProviderContractError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}
