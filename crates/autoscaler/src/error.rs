use std::{io, path::PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum AutoscalerError {
    #[error("invalid autoscaler configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("autoscaler configuration `{0}` is missing")]
    MissingConfiguration(&'static str),
    #[error("autoscaler randomness is unavailable")]
    RandomnessUnavailable,
    #[error("control-plane transport failed during {operation}: {detail}")]
    ControlPlaneTransport {
        operation: &'static str,
        detail: String,
    },
    #[error("control plane rejected {operation} with HTTP {status}: {detail}")]
    ControlPlaneStatus {
        operation: &'static str,
        status: u16,
        detail: String,
    },
    #[error("control plane returned malformed data during {0}")]
    MalformedControlPlaneResponse(&'static str),
    #[error("Docker API transport failed during {operation}: {source}")]
    DockerTransport {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Docker API rejected {operation} with HTTP {status}: {detail}")]
    DockerStatus {
        operation: &'static str,
        status: u16,
        detail: String,
    },
    #[error("Docker API returned malformed data during {0}")]
    MalformedDockerResponse(&'static str),
    #[error("provider rejected the operation: {0}")]
    Provider(String),
    #[error("autoscaler reconciliation failed: {0}")]
    Reconcile(String),
    #[error("autoscaler file operation `{operation}` failed for `{path}`: {source}")]
    File {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("autoscaler JSON processing failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("autoscaler task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

impl AutoscalerError {
    pub(crate) fn file(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: io::Error,
    ) -> Self {
        Self::File {
            operation,
            path: path.into(),
            source,
        }
    }
}
