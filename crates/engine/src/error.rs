//! Engine and executor failures.

use crate::MAX_JOB_RETRIES;
use runtrue_lifecycle::{JobState, StepState};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutorError {
    #[error("native process execution is disabled; explicit allow_native is required")]
    NativeExecutionDisabled,
    #[error("native process executor cannot run isolation mode `{0}`")]
    UnsupportedIsolation(String),
    #[error("native process executor cannot run target platform `{requested}` on host `{host}`")]
    PlatformMismatch { requested: String, host: String },
    #[error("native process executor does not support host platform `{os}/{arch}`")]
    UnsupportedHostPlatform { os: String, arch: String },
    #[error("native process executor does not support component action `{0}`")]
    UnsupportedComponent(String),
    #[error("native process executor cannot honor capsule feature: {0}")]
    UnsupportedCapsuleFeature(String),
    #[error("unsafe working directory `{0}`")]
    UnsafeWorkingDirectory(String),
    #[error("working directory is unavailable: {0}")]
    WorkingDirectory(String),
    #[error("invalid environment variable name `{0}`")]
    InvalidEnvironmentName(String),
    #[error("environment variable `{0}` contains a NUL byte")]
    InvalidEnvironmentValue(String),
    #[error("invalid command: {0}")]
    InvalidCommand(String),
    #[error("could not spawn process: {0}")]
    Spawn(String),
    #[error("could not query or wait for process: {0}")]
    Wait(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EngineError {
    #[error("execution capsule has schema version {found}; expected {expected}")]
    IncompatibleSchemaVersion { found: u32, expected: u32 },
    #[error("execution capsule has incompatible engine version `{found}`; expected `{expected}`")]
    IncompatibleEngineVersion { found: String, expected: String },
    #[error("execution capsule contains duplicate job id `{0}`")]
    DuplicateJob(String),
    #[error("scheduler-offered job `{0}` is not present in the execution capsule")]
    SelectedJobNotFound(String),
    #[error("execution capsule contains an empty job id")]
    EmptyJobId,
    #[error("job `{job_id}` depends on unknown job `{dependency}`")]
    UnknownDependency { job_id: String, dependency: String },
    #[error("job `{job_id}` lists dependency `{dependency}` more than once")]
    DuplicateDependency { job_id: String, dependency: String },
    #[error("execution capsule job graph contains a cycle")]
    DependencyCycle,
    #[error("job `{job_id}` contains duplicate step id `{step_id}`")]
    DuplicateStep { job_id: String, step_id: String },
    #[error("job `{job_id}` contains an empty step id")]
    EmptyStepId { job_id: String },
    #[error("job `{job_id}` requests {retries} retries; the engine limit is {MAX_JOB_RETRIES}")]
    TooManyRetries { job_id: String, retries: u32 },
    #[error("{scope} timeout must be greater than zero")]
    InvalidTimeout { scope: String },
    #[error("script digest mismatch in `{job_id}.{step_id}`")]
    ScriptDigestMismatch { job_id: String, step_id: String },
    #[error("invalid condition `{expression}`: {message}")]
    InvalidCondition { expression: String, message: String },
    #[error("context value `{path}` is unavailable")]
    MissingContextValue { path: String },
    #[error("runtime event context does not match the immutable context bound into the capsule")]
    RuntimeContextMismatch,
    #[error("execution capsule contains an invalid scalar at `{0}`")]
    InvalidScalarValue(String),
    #[error("untrusted context is injected through the process environment at `{0}`")]
    UnsafeDynamicEnvironment(String),
    #[error("untrusted context is passed through process arguments at `{0}`")]
    UnsafeDynamicArgument(String),
    #[error("structured output from `{job_id}.{step_id}` is invalid: {message}")]
    InvalidStructuredOutput {
        job_id: String,
        step_id: String,
        message: String,
    },
    #[error("dynamic matrix `{template_id}` cannot be expanded: {message}")]
    DynamicMatrix {
        template_id: String,
        message: String,
    },
    #[error("execution backend rejected the complete capsule before execution: {0}")]
    ExecutorPreflight(String),
    #[error("execution backend failed to finalize job `{job_id}` attempt {attempt}: {message}")]
    ExecutorFinalization {
        job_id: String,
        attempt: u32,
        message: String,
    },
    #[error("invalid environment variable name `{0}`")]
    InvalidEnvironmentName(String),
    #[error("environment variable `{0}` contains a NUL byte")]
    InvalidEnvironmentValue(String),
    #[error("invalid job state transition from {from:?} to {to:?}")]
    InvalidJobTransition { from: JobState, to: JobState },
    #[error("invalid step state transition from {from:?} to {to:?}")]
    InvalidStepTransition { from: StepState, to: StepState },
    #[error(
        "step lifecycle observer rejected `{job_id}.{step_id}` transition to {to:?}: {message}"
    )]
    StepStateObserver {
        job_id: String,
        step_id: String,
        to: StepState,
        message: String,
    },
}
