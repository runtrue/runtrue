//! Fail-closed Firecracker execution for authenticated remote leases.
//!
//! There is deliberately no network, registry, or isolation fallback.

mod config;
mod driver;
mod execution;
mod host;
mod images;
mod recovery;

pub use config::FirecrackerRuntimePaths;
pub use driver::FirecrackerJobExecutor;

use crate::{
    daemon::{JobExecution, RunnerError},
    oci::strict_json,
    state::{prepare_private_directory, read_bounded_private_file, validate_no_symlink_components},
};
use nix::fcntl::{flock, FlockArg};
use runtrue_attest::{ImageKind, ImageVerifyingKey, SignedImageManifest};
use runtrue_engine::{CancellationToken, StepStateObserver};
use runtrue_executor_firecracker::{
    FirecrackerImageSet, FirecrackerLaunchPlan, FirecrackerPaths, FirecrackerVsockConnector,
    GuestConnector, HostCapabilityProbe, HostRequirements, ImageArtifact, ImageTrustStore,
    JailerInvocation, JobStateManager, LinuxHostCapabilityProbe, OneJobReport, OneJobSession,
    ProcessReflinkProvisioner, ProcessVmLauncher, ReflinkProvisioner, SnapshotImageSet,
    SnapshotRuntimeCompatibility, SnapshotRuntimeRequirements, UnixSnapshotApiClient, VmControl,
    VmInvocation, VmLauncher,
};
use runtrue_guest_core::{GuestBootstrap, GuestStepResult, LogStream, GUEST_PROTOCOL_VERSION};
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_runner_core::AdmittedLease;
use runtrue_workflow_ir::{
    Architecture, Isolation, OperatingSystem, PermissionSet, Shell, StepAction, StepCapabilitySet,
    ValueBinding,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    fmt, fs,
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_PROFILE_BYTES: u64 = 1024 * 1024;
const MAX_RUNTIME_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CPUINFO_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MITIGATION_FILE_BYTES: u64 = 64 * 1024;
const MAX_IMAGE_MANIFESTS: usize = 5;
const MAX_LOG_FRAMES: usize = 256;
const MAX_RESULT_BYTES: usize = 32 * 1024 * 1024;
const VSOCK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const VSOCK_IO_TIMEOUT: Duration = Duration::from_secs(5);
const SNAPSHOT_API_TIMEOUT: Duration = Duration::from_secs(5);
const VM_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const SNAPSHOT_STATE_ROLE: &str = "state";
const SNAPSHOT_MEMORY_ROLE: &str = "memory";
const SNAPSHOT_ROLE_KEY: &str = "snapshot-role";

use config::RuntimeProfile;
use execution::{
    canceled_job_execution, job_execution_from_report, now_unix_ms, session_id, validate_guest_job,
};
use host::{
    acquire_cid_lock, cpu_feature_digest, host_memory_bytes, mitigation_profile_digest,
    probe_cgroup_lifecycle, probe_reflink, require_absolute, validate_executable,
    validate_host_architecture, validate_image_payload, validate_private_directory,
    validate_runtime_binary,
};
use images::{image_expiry, image_set_digest, load_image_set, load_image_trust};
use recovery::{recover_abandoned_jails, verify_cgroup_clean};

#[cfg(test)]
mod tests;
