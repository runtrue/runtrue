use crate::{MAX_BISIM_CANARIES, MAX_BISIM_CANARY_BYTES, MIN_BISIM_CANARY_BYTES};
use runtrue_engine::EngineError;
use runtrue_workflow_ir::{Isolation, ParityGrade};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BisimError {
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error(
        "secret canary has {0} bytes; expected {MIN_BISIM_CANARY_BYTES}..={MAX_BISIM_CANARY_BYTES}"
    )]
    InvalidCanarySize(usize),
    #[error("Bisim request has {0} secret canaries; maximum is {MAX_BISIM_CANARIES}")]
    TooManyCanaries(usize),
    #[error("job `{job_id}` requests {requested:?}, but Bisim backend is {backend:?}")]
    BackendIsolationMismatch {
        job_id: String,
        requested: Isolation,
        backend: Isolation,
    },
    #[error("backend parity {backend:?} cannot satisfy capsule parity {capsule:?}")]
    BackendParityInsufficient {
        capsule: ParityGrade,
        backend: ParityGrade,
    },
    #[error("Capsule changed during the Bisim run")]
    CapsuleDigestChanged,
    #[error("secret canary appeared on {surface}")]
    SecretCanaryLeak { surface: &'static str },
    #[error("unsupported Bisim observation version {0}")]
    UnsupportedObservationVersion(u32),
    #[error("Bisim observation still contains nondeterministic timing")]
    ObservationContainsTiming,
    #[error("Bisim observation has {0} canonical bytes and exceeds its bound")]
    ObservationTooLarge(usize),
    #[error("normalized execution-result digest mismatch")]
    ResultDigestMismatch,
    #[error("lifecycle-event digest mismatch")]
    EventDigestMismatch,
    #[error("invalid Bisim Evidence binding: {0}")]
    InvalidEvidenceBinding(&'static str),
    #[error("portable Provider lifecycle or output claim differs from the engine result")]
    PortableResultMismatch,
    #[error("execution engine failed: {0}")]
    Engine(#[from] EngineError),
    #[error("execution capsule failed: {0}")]
    Capsule(#[from] runtrue_workflow_ir::CapsuleError),
    #[error("Bisim JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("portable Provider observation is invalid: {0}")]
    ProviderContract(#[from] runtrue_provider_contract::ProviderContractError),
}
