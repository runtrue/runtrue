//! Explicitly opted-in local process execution.

use crate::bindings::is_valid_environment_name;
use crate::{
    Executor, ExecutorError, ExecutorOutput, JobAttemptOutcome, PreparedAction,
    StepExecutionRequest, DEFAULT_MAX_CAPTURE_BYTES,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{
    Architecture, ExecutionCapsule, Isolation, OperatingSystem, PlannedJob, Shell, StepAction,
};
use std::{
    collections::BTreeMap,
    fmt,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
const NATIVE_PROCESS_GROUP_TERMINATION_GRACE: Duration = Duration::from_millis(100);
#[cfg(unix)]
const NATIVE_PROCESS_GROUP_VERIFY_TIMEOUT: Duration = Duration::from_secs(1);

mod capture;
mod executor;
mod process;

use capture::{capture_stream, duration_millis, snapshot_capture};
use process::{
    cleanup_and_verify_native_process_group, kill_and_wait, native_command,
    resolve_working_directory, validate_command, validate_executor_environment,
};

pub use executor::{LocalProcessExecutor, NativeExecutor, NativeProcessExecutor};
pub(crate) use process::host_platform;
