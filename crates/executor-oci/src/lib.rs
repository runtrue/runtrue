//! Rootless, digest-pinned OCI execution through an external runtime.
//!
//! The runtime boundary is split by responsibility while preserving the
//! crate-root API and the executor's security and cleanup contracts.

mod admission;
mod config;
mod environment;
mod error;
mod executor;
mod image;
mod invocation;
mod limits;
mod mounts;
mod process;
mod recovery;
mod runtime;
mod security;
mod services;

pub use admission::{ImageAdmissionError, ImageAdmissionProvider};
pub use config::{OciExecutorConfig, OciPlatform};
pub use error::OciError;
pub use executor::OciExecutor;
pub use image::{AdmittedImage, LockedImage};
pub use invocation::{
    RuntimeCommandRunner, RuntimeControl, RuntimeInvocation, RuntimeInvocationKind, RuntimeResult,
};
pub use limits::OciLimits;
pub use mounts::OciMount;
pub use process::ProcessCommandRunner;
pub use recovery::{recover_abandoned_job_state, verify_preloaded_images, OciRecoveryConfig};

pub(crate) use environment::*;
pub(crate) use executor::PreparedService;
pub(crate) use runtime::*;
pub(crate) use security::*;

use runtrue_engine::{
    CancellationToken, Executor, ExecutorError, ExecutorOutput, JobAttemptOutcome, PreparedAction,
    StepExecutionRequest,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{
    Architecture, ExecutionCapsule, Healthcheck, Isolation, NetworkPermission, NetworkProtocol,
    OperatingSystem, PlannedJob, PlannedService, ScalarValue, Shell, StepAction, ValueBinding,
};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(crate) const MAX_SECCOMP_PROFILE_BYTES: u64 = 1024 * 1024;
pub(crate) const CONTAINER_WORKSPACE: &str = "/workspace";
pub(crate) const CONTAINER_SCRIPT: &str = "/runtrue/step/script";
pub(crate) const DEFAULT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_SERVICE_STARTUP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub(crate) const FORBIDDEN_SOCKET_NAMES: [&str; 5] = [
    "docker.sock",
    "containerd.sock",
    "podman.sock",
    "crio.sock",
    "buildkitd.sock",
];
pub(crate) const FORBIDDEN_SOCKET_ENV: [&str; 5] = [
    "DOCKER_HOST",
    "CONTAINER_HOST",
    "BUILDKIT_HOST",
    "KUBECONFIG",
    "SSH_AUTH_SOCK",
];

/// Validate and canonicalize an installed default-deny seccomp profile without
/// constructing an executor. Runners use this before advertising OCI support.
pub fn validate_seccomp_profile_file(path: &Path) -> Result<PathBuf, OciError> {
    let path = canonical_regular_file(path, "seccomp profile", MAX_SECCOMP_PROFILE_BYTES)?;
    validate_seccomp_profile(&path)?;
    Ok(path)
}

/// Validate Podman's explicitly configured environment using the same bounds
/// and allowlist enforced for every runtime invocation.
pub fn validate_runtime_environment(
    environment: &BTreeMap<String, String>,
) -> Result<(), OciError> {
    validate_environment(environment, OciLimits::default(), EnvironmentScope::Runtime)
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
