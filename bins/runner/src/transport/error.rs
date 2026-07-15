use crate::state::StateError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("invalid control-plane endpoint: {0}")]
    Endpoint(#[from] tonic::transport::Error),
    #[error("control-plane endpoint has no supported URI scheme")]
    EndpointScheme,
    #[error("control-plane endpoint has no host")]
    EndpointHost,
    #[error("non-loopback or non-opted-in plaintext control-plane endpoint is forbidden")]
    InsecureEndpoint,
    #[error("--insecure-loopback cannot be combined with an HTTPS endpoint")]
    InsecureFlagWithTls,
    #[error("runner data plane is unavailable")]
    DataPlaneUnavailable,
    #[error("runner blob stream is malformed")]
    InvalidBlobStream,
    #[error("runner object transfer was cancelled")]
    TransferCancelled,
    #[error("runner enrollment requires an HTTPS endpoint")]
    EnrollmentRequiresTls,
    #[error("HTTPS requires CA, client certificate, and client private key files")]
    MissingMutualTls,
    #[error("configured certificate or private-key file is not PEM encoded")]
    InvalidPem,
    #[error("TLS files cannot be supplied to an insecure HTTP endpoint")]
    TlsMaterialWithInsecureEndpoint,
    #[error("runner stream is already open")]
    AlreadyOpen,
    #[error("runner stream is not open")]
    NotOpen,
    #[error("runner stream closed")]
    StreamClosed,
    #[error("runner stream remained backpressured beyond its send deadline")]
    StreamBackpressure,
    #[error("control plane did not send ControlHello first")]
    MissingControlHello,
    #[error("runner RPC failed with gRPC code {code:?}: {message}")]
    Status { code: tonic::Code, message: String },
    #[error(transparent)]
    State(#[from] StateError),
}

impl From<tonic::Status> for TransportError {
    fn from(status: tonic::Status) -> Self {
        Self::Status {
            code: status.code(),
            message: status.message().to_owned(),
        }
    }
}

impl TransportError {
    #[must_use]
    pub fn is_running_step_not_observed(&self) -> bool {
        matches!(
            self,
            Self::Status {
                code: tonic::Code::FailedPrecondition,
                message,
            } if message == "broker request requires the declared step to be currently running"
        )
    }

    #[must_use]
    pub fn is_data_plane_state_not_observed(&self) -> bool {
        self.is_running_step_not_observed()
            || matches!(
                self,
                Self::Status {
                    code: tonic::Code::FailedPrecondition,
                    message,
                } if message == "artifact finalization requires a completed current attempt"
            )
    }
}
