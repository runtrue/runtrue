//! Signed-image, jailer, and authenticated guest boundary for Firecracker.
//!
//! Nothing in this crate treats the presence of a kernel, root filesystem, or
//! guest agent on disk as admission. Callers first verify a complete signed
//! image set, then stage immutable bytes into a private per-job directory.

mod config_state;
mod image;
mod platform;
mod process;
mod session;
mod snapshot;
mod transport;

pub use config_state::{
    FirecrackerVmConfig, JobState, JobStateManager, JobStatePaths, ProcessReflinkProvisioner,
    ReflinkProvisioner, SnapshotStatePaths,
};
pub use image::{
    FirecrackerImageSet, ImageArtifact, ImageTrustStore, SnapshotImageSet,
    SnapshotRuntimeCompatibility, SnapshotRuntimeRequirements, VerifiedArtifact, VerifiedImageSet,
    VerifiedSnapshotImageSet,
};
pub use platform::{
    FirecrackerPaths, HostCapabilityProbe, HostRequirements, JailerInvocation,
    LinuxHostCapabilityProbe,
};
pub use process::{ProcessVmLauncher, RunningVm, VmControl, VmExit, VmInvocation, VmLauncher};
pub use session::{OneJobReport, OneJobSession};
pub use snapshot::{
    FirecrackerLaunchPlan, SnapshotApi, SnapshotLoadRequest, UnixSnapshotApiClient,
};
pub use transport::{
    EnvelopeTransport, FirecrackerVsockConnector, FramedTransport, GuestConnector,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FirecrackerError {
    #[error("invalid Firecracker configuration: {0}")]
    InvalidConfiguration(String),
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("untrusted image signing key {0}")]
    UntrustedImageKey(runtrue_model::ContentDigest),
    #[error("duplicate image signing key {0}")]
    DuplicateImageKey(runtrue_model::ContentDigest),
    #[error("image signature or manifest is invalid: {0}")]
    ImageAttestation(#[from] runtrue_attest::ImageAttestError),
    #[error("image artifact {path} is unsafe: {reason}")]
    UnsafeArtifact {
        path: std::path::PathBuf,
        reason: String,
    },
    #[error("cannot read image artifact {path}: {source}")]
    ArtifactIo {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("image artifact size mismatch for {path}: expected {expected}, got {actual}")]
    ArtifactSizeMismatch {
        path: std::path::PathBuf,
        expected: u64,
        actual: u64,
    },
    #[error("image artifact digest mismatch for {path}")]
    ArtifactDigestMismatch { path: std::path::PathBuf },
    #[error("image component binding {component} is missing or incorrect")]
    ComponentBinding { component: &'static str },
    #[error("host preflight failed: {0}")]
    Preflight(String),
    #[error("cannot spawn Firecracker jailer: {0}")]
    Spawn(String),
    #[error("cannot wait for Firecracker jailer: {0}")]
    Wait(String),
    #[error("Firecracker process-group cleanup failed: {0}")]
    ProcessCleanup(String),
    #[error("Firecracker state operation failed for {path}: {source}")]
    StateIo {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Firecracker JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("guest transport failed: {0}")]
    Transport(String),
    #[error("authenticated guest protocol failed: {0}")]
    GuestProtocol(#[from] runtrue_guest_core::GuestError),
    #[error("guest protocol state violation: {0}")]
    Protocol(String),
    #[error("Firecracker snapshot API failed: {0}")]
    SnapshotApi(String),
}

pub(crate) fn artifact_io(path: &std::path::Path, source: std::io::Error) -> FirecrackerError {
    FirecrackerError::ArtifactIo {
        path: path.to_owned(),
        source,
    }
}

pub(crate) fn state_io(path: &std::path::Path, source: std::io::Error) -> FirecrackerError {
    FirecrackerError::StateIo {
        path: path.to_owned(),
        source,
    }
}
