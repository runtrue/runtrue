//! Signed OCI assignment loading and per-lease executor construction.

mod admission;
mod assignments;
mod config;
mod execution;
mod validation;

pub use config::{OciRuntimeFactory, OciRuntimePaths};
pub use execution::OciJobExecutor;
pub(crate) use validation::strict_json;

use crate::{
    daemon::RunnerError,
    state::{prepare_private_directory, read_bounded_private_file, validate_no_symlink_components},
};
use runtrue_attest::{ImageKind, ImageVerifyingKey, SignedImageManifest};
use runtrue_engine::{CancellationToken, Engine, ExecutionResult, StepStateObserver};
use runtrue_executor_dispatch::ExecutorDispatcher;
use runtrue_executor_oci::{
    recover_abandoned_job_state, validate_runtime_environment, validate_seccomp_profile_file,
    verify_preloaded_images, AdmittedImage, ImageAdmissionError, ImageAdmissionProvider,
    LockedImage, OciExecutor, OciExecutorConfig, OciPlatform, OciRecoveryConfig,
    ProcessCommandRunner, RuntimeCommandRunner,
};
use runtrue_model::ContentDigest;
use runtrue_runner_core::AdmittedLease;
use runtrue_workflow_ir::{Architecture, Isolation, OperatingSystem};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_RUNTIME_ENVIRONMENT_BYTES: u64 = 1024 * 1024;
const MAX_ASSIGNMENTS: usize = 4096;
const JOB_ROLE: &str = "$job";
const COMPAT_CAPSULE_DIGEST: &str = "runtrue-capsule-digest";
const COMPAT_JOB_ID: &str = "runtrue-job-id";
const COMPAT_SERVICE_ID: &str = "runtrue-service-id";
const COMPAT_OCI_REFERENCE: &str = "runtrue-oci-reference";
const COMPAT_SIGNATURE_IDENTITY: &str = "runtrue-signature-identity";
const COMPAT_ASSIGNMENT_SCOPE: &str = "runtrue-assignment-scope";
const REUSABLE_IMAGE_SCOPE: &str = "reusable-image";

use admission::SelectedManifestAdmission;
use assignments::{
    load_assignments, load_image_keys, AssignmentKey, AssignmentRecord, LoadedAssignments,
    SelectedAssignments,
};
use config::{LoadedOciConfiguration, ProcessRuntimeFactory};
use validation::{
    decode_key, load_runtime_environment, now_unix_ms, sorted_directory_files, validate_podman,
    validate_private_directory, validate_private_regular_file,
};

#[cfg(test)]
mod tests;
