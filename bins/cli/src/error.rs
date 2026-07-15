use super::{admin, remote, reusable, EXIT_EXECUTION, EXIT_INTERNAL, EXIT_VALIDATION};
use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub(super) enum CliError {
    #[error("cannot determine the current directory: {0}")]
    CurrentDirectory(io::Error),
    #[error("workflow already exists at {}; pass --force to replace it", .0.display())]
    AlreadyExists(PathBuf),
    #[error("refusing unsafe init path {}: {reason}", path.display())]
    UnsafeInitPath { path: PathBuf, reason: &'static str },
    #[error("refusing unsafe output path {}: {reason}", path.display())]
    UnsafeOutputPath { path: PathBuf, reason: &'static str },
    #[error("cannot read {}: {source}", path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("{kind} {} must be a regular file and cannot be a symlink", path.display())]
    NonRegularInput { kind: &'static str, path: PathBuf },
    #[error("{kind} {} exceeds the {limit}-byte input limit", path.display())]
    InputTooLarge {
        kind: &'static str,
        path: PathBuf,
        limit: u64,
    },
    #[error("{} is not valid UTF-8: {source}", path.display())]
    Utf8 {
        path: PathBuf,
        source: std::string::FromUtf8Error,
    },
    #[error("cannot write {}: {source}", path.display())]
    Write { path: PathBuf, source: io::Error },
    #[error("cannot discover workflows in {}: {source}; run `runtrue init` or pass --workflow", path.display())]
    Discover { path: PathBuf, source: io::Error },
    #[error("no .yaml or .yml workflows found in {}; run `runtrue init` or pass --workflow", .0.display())]
    NoWorkflows(PathBuf),
    #[error("discovered {0} workflows; pass --workflow to select exactly one")]
    AmbiguousWorkflows(usize),
    #[error("event fixture {} is not valid JSON: {source}", path.display())]
    EventJson {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error(transparent)]
    Compile(#[from] runtrue_compiler::CompileError),
    #[error(transparent)]
    Import(#[from] runtrue_gha_import::ImportError),
    #[error(transparent)]
    Submit(#[from] remote::SubmitError),
    #[error("invalid .runtrue.lock: {0}")]
    Lock(#[from] runtrue_lock::LockError),
    #[error(transparent)]
    ReusableHydration(#[from] reusable::ReusableHydrationError),
    #[error(transparent)]
    Engine(#[from] runtrue_engine::EngineError),
    #[error(transparent)]
    Replay(#[from] runtrue_replay::ReplayError),
    #[error(transparent)]
    Bisim(#[from] runtrue_bisim::BisimError),
    #[error(transparent)]
    Artifact(#[from] runtrue_runtime_local::LocalArtifactError),
    #[error(transparent)]
    Admin(#[from] admin::AdminError),
    #[error("local execution requires explicit --allow-native acknowledgement")]
    NativeAcknowledgementRequired,
    #[error("local execution does not support this capsule: {0}")]
    UnsupportedLocalFeature(String),
    #[error("cannot serialize JSON output: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cannot write output: {0}")]
    Output(io::Error),
}

impl CliError {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::CurrentDirectory(_) => "current_directory",
            Self::AlreadyExists(_) => "already_exists",
            Self::UnsafeInitPath { .. } => "unsafe_init_path",
            Self::UnsafeOutputPath { .. } => "unsafe_output_path",
            Self::Read { .. } => "read_failed",
            Self::NonRegularInput { .. } => "non_regular_input",
            Self::InputTooLarge { .. } => "input_too_large",
            Self::Utf8 { .. } => "invalid_utf8",
            Self::Write { .. } => "write_failed",
            Self::Discover { .. } => "discovery_failed",
            Self::NoWorkflows(_) => "no_workflows",
            Self::AmbiguousWorkflows(_) => "ambiguous_workflows",
            Self::EventJson { .. } => "invalid_event_json",
            Self::Compile(_) => "workflow_invalid",
            Self::Import(_) => "github_import_invalid",
            Self::Submit(error) => error.code(),
            Self::Lock(_) => "invalid_lockfile",
            Self::ReusableHydration(_) => "reusable_workflow_source_invalid",
            Self::Engine(_) => "execution_engine_error",
            Self::Replay(_) => "invalid_replay_bundle",
            Self::Bisim(_) => "bisim_invalid",
            Self::Artifact(_) => "artifact_capture_failed",
            Self::Admin(error) => error.code(),
            Self::NativeAcknowledgementRequired => "native_acknowledgement_required",
            Self::UnsupportedLocalFeature(_) => "unsupported_local_feature",
            Self::Json(_) => "json_failed",
            Self::Output(_) => "output_failed",
        }
    }

    pub(super) const fn exit_code(&self) -> u8 {
        match self {
            Self::Compile(_)
            | Self::Import(_)
            | Self::Submit(_)
            | Self::Lock(_)
            | Self::ReusableHydration(_)
            | Self::AlreadyExists(_)
            | Self::UnsafeInitPath { .. }
            | Self::UnsafeOutputPath { .. }
            | Self::Read { .. }
            | Self::NonRegularInput { .. }
            | Self::InputTooLarge { .. }
            | Self::Utf8 { .. }
            | Self::Discover { .. }
            | Self::NoWorkflows(_)
            | Self::AmbiguousWorkflows(_)
            | Self::EventJson { .. }
            | Self::Replay(_)
            | Self::Bisim(_)
            | Self::NativeAcknowledgementRequired
            | Self::UnsupportedLocalFeature(_) => EXIT_VALIDATION,
            Self::Engine(_) | Self::Artifact(_) => EXIT_EXECUTION,
            Self::Admin(error) => error.exit_code(),
            Self::CurrentDirectory(_) | Self::Write { .. } | Self::Json(_) | Self::Output(_) => {
                EXIT_INTERNAL
            }
        }
    }
}
