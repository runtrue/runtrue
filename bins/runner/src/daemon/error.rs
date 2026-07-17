use crate::{enrollment::EnrollmentError, state::StateError, transport::TransportError};
use runtrue_model::ContentDigest;
use runtrue_runner_core::RunnerAdmissionError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("invalid runner id")]
    InvalidRunnerId,
    #[error("verified inventory belongs to another runner")]
    InventoryRunnerMismatch,
    #[error("verified inventory protocol version differs from negotiated protocol")]
    InventoryProtocolMismatch,
    #[error("control hello connection id does not match this stream")]
    ConnectionIdMismatch,
    #[error("invalid control-plane heartbeat interval")]
    InvalidHeartbeatInterval,
    #[error("invalid control-plane server time")]
    InvalidServerTime,
    #[error("system clock is outside the supported range")]
    ClockRange,
    #[error("control-plane deadline has already elapsed")]
    DeadlineElapsed,
    #[error("control stream closed")]
    ControlStreamClosed,
    #[error("unexpected control message")]
    UnexpectedControlMessage,
    #[error("certificate rotation requires credentials managed by --credential-directory")]
    CertificateRotationUnavailable,
    #[error("runner certificate rotated; reconnect with the installed credential generation")]
    CertificateRotated,
    #[error("control plane rejected the exact lease completion")]
    CompletionRejected,
    #[error("native execution requires explicit trusted-native configuration")]
    NativeExecutionDisabled,
    #[error("the active runner transport has no authenticated capability broker channel")]
    BrokerUnavailable,
    #[error("runner data-plane operation failed: {0}")]
    DataPlane(String),
    #[error("secret and OIDC grants are unsupported by the {0} execution backend")]
    BrokerUnsupportedBackend(String),
    #[error("network allow is unsupported by the {0} execution backend without an external enforcement provider")]
    NetworkEnforcementUnavailable(String),
    #[error("remote protocol v1 does not bind step transitions to a job attempt")]
    RemoteRetriesUnsupported,
    #[error("engine step lifecycle event does not match the offered job")]
    StepLifecycleBinding,
    #[error("terminal step lifecycle delivery did not drain within its bound")]
    StepLifecycleDrainTimeout,
    #[error("unsupported isolation backend `{0}`; isolation is never downgraded")]
    UnsupportedIsolation(String),
    #[error("invalid OCI runner configuration: {0}")]
    OciConfiguration(String),
    #[error("missing signed OCI assignment for job `{job_id}` service {service_id:?}")]
    MissingOciManifest {
        job_id: String,
        service_id: Option<String>,
    },
    #[error("signed OCI assignment mismatch: {0}")]
    OciManifestMismatch(String),
    #[error("signed OCI assignment has expired")]
    OciManifestExpired,
    #[error("signed OCI assignment uses untrusted image key `{0}`")]
    UntrustedOciImageKey(ContentDigest),
    #[error("invalid Wasm runner configuration: {0}")]
    WasmConfiguration(String),
    #[error("missing signed Wasm component assignment for `{0}`")]
    MissingWasmComponent(String),
    #[error("signed Wasm component assignment mismatch: {0}")]
    WasmManifestMismatch(String),
    #[error("signed Wasm component assignment uses untrusted image key `{0}")]
    UntrustedWasmComponentKey(ContentDigest),
    #[error("Wasm AOT state failed its integrity probe: {0}")]
    WasmAotState(String),
    #[error("invalid Firecracker runner configuration: {0}")]
    FirecrackerConfiguration(String),
    #[error("signed Firecracker assignment mismatch: {0}")]
    FirecrackerAssignment(String),
    #[error("signed Firecracker image set has expired")]
    FirecrackerImageExpired,
    #[error("offered job `{0}` is absent from the admitted capsule")]
    OfferedJobMissing(String),
    #[error("invalid workspace path `{0}`")]
    InvalidWorkspace(PathBuf),
    #[error("log sequence overflow")]
    LogSequenceOverflow,
    #[error("execution result encoding failed: {0}")]
    ResultEncoding(serde_json::Error),
    #[error("execution result exceeds byte limit {limit} (actual {actual})")]
    ResultLimitExceeded { limit: usize, actual: usize },
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Credentials(#[from] crate::CredentialError),
    #[error(transparent)]
    Enrollment(#[from] EnrollmentError),
    #[error(transparent)]
    Admission(#[from] RunnerAdmissionError),
    #[error(transparent)]
    Digest(#[from] runtrue_protocol::DigestConversionError),
    #[error(transparent)]
    Protocol(#[from] runtrue_protocol::ProtocolVersionError),
    #[error(transparent)]
    Engine(#[from] runtrue_engine::EngineError),
    #[error(transparent)]
    Oci(#[from] runtrue_executor_oci::OciError),
    #[error(transparent)]
    Wasm(#[from] runtrue_executor_wasm::WasmError),
    #[error(transparent)]
    Firecracker(#[from] runtrue_executor_firecracker::FirecrackerError),
    #[error(transparent)]
    ImageAttestation(#[from] runtrue_attest::ImageAttestError),
}

impl RunnerError {
    /// Return the stable control-plane rejection code for a failed executor
    /// preflight. Assignment failures are deterministic for the offered plan
    /// and must not be collapsed into the retryable generic code.
    pub const fn preflight_rejection_code(&self) -> &'static str {
        match self {
            Self::MissingWasmComponent(_) => "wasm_component_assignment_missing",
            Self::WasmManifestMismatch(_) | Self::UntrustedWasmComponentKey(_) => {
                "wasm_component_assignment_invalid"
            }
            Self::MissingOciManifest { .. } => "oci_image_assignment_missing",
            Self::OciManifestMismatch(_)
            | Self::OciManifestExpired
            | Self::UntrustedOciImageKey(_) => "oci_image_assignment_invalid",
            _ => "executor_preflight_rejected",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RunnerError;

    #[test]
    fn preflight_rejection_codes_preserve_permanent_assignment_failures() {
        assert_eq!(
            RunnerError::MissingWasmComponent("wasm://example.invalid/action@sha256:00".to_owned())
                .preflight_rejection_code(),
            "wasm_component_assignment_missing"
        );
        assert_eq!(
            RunnerError::WasmConfiguration("temporary runtime failure".to_owned())
                .preflight_rejection_code(),
            "executor_preflight_rejected"
        );
    }
}
