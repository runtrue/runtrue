use crate::AotCacheError;
use runtrue_attest::ImageAttestError;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum WasmError {
    #[error("invalid Wasm executor configuration: {0}")]
    InvalidConfiguration(String),
    #[error("this host platform is unsupported by the Wasm executor")]
    UnsupportedHostPlatform,
    #[error("unsupported CPU feature floor `{0}`")]
    UnsupportedCpuFeatureFloor(String),
    #[error("Wasmtime configuration failed: {0}")]
    RuntimeConfiguration(String),
    #[error("duplicate component registration `{0}`")]
    DuplicateComponent(String),
    #[error("unknown component `{0}`")]
    UnknownComponent(String),
    #[error("component reference is not an exact digest reference")]
    MutableComponentReference,
    #[error("component signer does not match the expected signer")]
    SignerMismatch,
    #[error("component manifest does not match the exact payload")]
    ManifestMismatch,
    #[error("component manifest compatibility metadata is not exact")]
    ManifestCompatibilityMismatch,
    #[error("component manifest is not currently valid")]
    ManifestExpired,
    #[error("component image attestation failed: {0}")]
    ImageAttestation(#[from] ImageAttestError),
    #[error("AOT cache failed: {0}")]
    AotCache(#[from] AotCacheError),
    #[error("Wasm executor cannot run isolation mode `{0}`")]
    UnsupportedIsolation(String),
    #[error("Wasm runner target does not match the embedded runtime target")]
    PlatformMismatch,
    #[error("unsupported Wasm capability: {0}")]
    UnsupportedCapability(String),
    #[error("Wasm components receive no ambient environment")]
    AmbientEnvironmentDenied,
    #[error("Wasm executor has no command, script, or native fallback")]
    NoFallback,
    #[error("Wasm limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("invalid Wasm execution request: {0}")]
    InvalidRequest(String),
    #[error("invalid component input: {0}")]
    InvalidInput(String),
    #[error("component compilation failed: {0}")]
    Compile(String),
    #[error("component linking failed: {0}")]
    Link(String),
    #[error("Wasm watchdog failed")]
    Watchdog,
    #[error("Wasm executor internal error: {0}")]
    Internal(String),
}
