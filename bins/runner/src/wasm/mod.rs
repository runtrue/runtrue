//! Preloaded, signed WebAssembly Component execution for remote leases.

mod adapters;
mod components;
mod config;
mod execution;
mod network;
mod validation;

pub use config::WasmRuntimePaths;
pub use execution::WasmJobExecutor;

use crate::{
    broker::{wasm_broker_adapters, BrokerExecutionBinding, RunnerBrokerClient},
    daemon::RunnerError,
    oci::strict_json,
    state::{read_bounded_private_file, validate_no_symlink_components},
};
use runtrue_attest::{ImageVerifyingKey, SignedImageManifest};
use runtrue_engine::{
    CancellationToken, Engine, ExecutionResult, Executor, ExecutorError, ExecutorOutput,
    JobAttemptOutcome, PreparedAction, StepStateObserver,
};
use runtrue_executor_dispatch::ExecutorDispatcher;
use runtrue_executor_wasm::{
    AotAuthenticationKey, AotCacheConfig, CapabilityAdapterError, CapabilityAdapters,
    CapabilityCallContext, DirectoryGrant, FilesystemAdapter, HandleAuthenticationKey,
    PackagePreparationTier as WasmPackagePreparationTier, RootedFilesystemAdapter,
    WasmComponentArtifact, WasmExecutor, WasmTarget,
};
use runtrue_model::ContentDigest;
use runtrue_runner_core::AdmittedLease;
use runtrue_workflow_ir::{ExecutionCapsule, Isolation, PlannedJob, StepAction};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_RUNTIME_KEY_BYTES: u64 = 16 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_COMPONENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMPONENT_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_COMPONENTS: usize = 256;
const MAX_WORKSPACE_FILE_BYTES: usize = 64 * 1024 * 1024;

use adapters::{adapters_for_lease, adapters_for_workspace, reject_aot_events};
use components::{exact_component_digest, load_component_keys, load_components};
use validation::{decode_runtime_keys, validate_private_directory};

#[cfg(test)]
mod tests;
