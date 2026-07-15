mod secrets;
mod secure_fs;
mod variables;

use secrets::{secret_delete, secret_get, secret_rotate, secret_set};
use variables::{var_delete, var_get, var_set};

use clap::{Args, Subcommand};
use runtrue_secrets::{MasterKeyFileError, SecretsError};
use std::{
    convert::Infallible,
    fmt, io,
    path::{Path, PathBuf},
    sync::atomic::AtomicU64,
};
use thiserror::Error;
use zeroize::Zeroizing;

const LOCAL_TENANT_ID: &str = "local-tenant";
const LOCAL_SCOPE: &str = "workspace";
const LOCAL_KEK_ID: &str = "local-kek-v1";
const VARIABLE_STATE_VERSION: u32 = 1;
const MAX_ADMIN_NAME_BYTES: usize = 128;
const MAX_SECRET_INPUT_BYTES: u64 = 1024 * 1024;
const MAX_SECRET_STATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_VARIABLE_VALUE_BYTES: usize = 1024 * 1024;
const MAX_VARIABLE_STATE_BYTES: u64 = 16 * 1024 * 1024;
static PRIVATE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Args)]
pub(crate) struct SecretsArgs {
    #[command(subcommand)]
    command: SecretCommand,
}

impl SecretsArgs {
    pub(crate) const fn wants_json(&self) -> bool {
        match &self.command {
            SecretCommand::Set(args) => args.json,
            SecretCommand::Get(args) => args.json,
            SecretCommand::Delete(args) => args.json,
            SecretCommand::Rotate(args) => args.json,
        }
    }
}

#[derive(Debug, Subcommand)]
enum SecretCommand {
    /// Create a new encrypted workspace secret from stdin or a safe file.
    Set(SecretSetArgs),
    /// Display secret metadata, optionally revealing the current value to a new mode-0600 file.
    Get(SecretGetArgs),
    /// Tombstone a secret while retaining its encrypted version history.
    Delete(SecretDeleteArgs),
    /// Add a new immutable encrypted version from stdin or a safe file.
    Rotate(SecretRotateArgs),
}

#[derive(Debug, Args)]
struct SecretSetArgs {
    /// Strict logical secret name; values are never accepted as arguments.
    name: String,
    /// Read exact secret bytes from this regular, non-symlink file instead of stdin.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Rejected compatibility catch: secret values must never be supplied in argv.
    #[arg(value_name = "VALUE", hide = true, num_args = 0..)]
    forbidden_values: Vec<RejectedSecretArgument>,
    /// Emit machine-readable metadata-only JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SecretGetArgs {
    /// Strict logical secret name.
    name: String,
    /// Explicitly reveal the current value to a new regular mode-0600 file.
    #[arg(long, value_name = "PATH")]
    reveal_to: Option<PathBuf>,
    /// Emit machine-readable metadata-only JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SecretDeleteArgs {
    /// Strict logical secret name.
    name: String,
    /// Emit machine-readable metadata-only JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SecretRotateArgs {
    /// Strict logical secret name.
    name: String,
    /// Read exact replacement bytes from this regular, non-symlink file instead of stdin.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Rejected compatibility catch: secret values must never be supplied in argv.
    #[arg(value_name = "VALUE", hide = true, num_args = 0..)]
    forbidden_values: Vec<RejectedSecretArgument>,
    /// Emit machine-readable metadata-only JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Clone)]
struct RejectedSecretArgument(Zeroizing<String>);

impl std::str::FromStr for RejectedSecretArgument {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(Zeroizing::new(value.to_owned())))
    }
}

impl fmt::Debug for RejectedSecretArgument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.0.len();
        formatter.write_str("RejectedSecretArgument([REDACTED])")
    }
}

#[derive(Debug, Args)]
pub(crate) struct VarsArgs {
    #[command(subcommand)]
    command: VarCommand,
}

impl VarsArgs {
    pub(crate) const fn wants_json(&self) -> bool {
        match &self.command {
            VarCommand::Set(args) => args.json,
            VarCommand::Get(args) => args.json,
            VarCommand::Delete(args) => args.json,
        }
    }
}

#[derive(Debug, Subcommand)]
enum VarCommand {
    /// Create or replace a non-secret workspace variable.
    Set(VarSetArgs),
    /// Print one non-secret workspace variable.
    Get(VarGetArgs),
    /// Delete one non-secret workspace variable.
    Delete(VarDeleteArgs),
}

#[derive(Debug, Args)]
struct VarSetArgs {
    name: String,
    value: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct VarGetArgs {
    name: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct VarDeleteArgs {
    name: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

pub(crate) fn execute_secrets(workspace: &Path, args: SecretsArgs) -> Result<(), AdminError> {
    match args.command {
        SecretCommand::Set(args) => secret_set(workspace, args),
        SecretCommand::Get(args) => secret_get(workspace, args),
        SecretCommand::Delete(args) => secret_delete(workspace, args),
        SecretCommand::Rotate(args) => secret_rotate(workspace, args),
    }
}

pub(crate) fn execute_vars(workspace: &Path, args: VarsArgs) -> Result<(), AdminError> {
    match args.command {
        VarCommand::Set(args) => var_set(workspace, args),
        VarCommand::Get(args) => var_get(workspace, args),
        VarCommand::Delete(args) => var_delete(workspace, args),
    }
}

#[derive(Debug, Error)]
pub(crate) enum AdminError {
    #[error(
        "secret values are forbidden in command arguments and environment; use stdin or --file"
    )]
    SecretValueArgument,
    #[error("name must be 1-{MAX_ADMIN_NAME_BYTES} ASCII letters, digits, '.', '-', or '_'")]
    InvalidName,
    #[error("variable value contains control characters")]
    InvalidVariableValue,
    #[error("variable value exceeds {limit} bytes: got {actual}")]
    VariableValueTooLarge { limit: usize, actual: usize },
    #[error("variable `{0}` was not found")]
    VariableNotFound(String),
    #[error("variable version counter overflowed")]
    VariableVersionOverflow,
    #[error("variable `{0}` has invalid version zero in local state")]
    InvalidVariableVersion(String),
    #[error("unsafe administration path {}: {reason}", path.display())]
    UnsafePath { path: PathBuf, reason: &'static str },
    #[error("{} has mode {actual:#06o}; expected exactly {expected:#06o}", path.display())]
    InsecurePermissions {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    #[error("local {0} does not exist")]
    StateMissing(&'static str),
    #[error("local secret state is incomplete; master.key and vault.json must either both exist or both be absent")]
    IncompleteSecretState,
    #[error("unsupported {kind} state version {version}")]
    UnsupportedStateVersion { kind: &'static str, version: u32 },
    #[error("invalid {kind} state: {source}")]
    InvalidState {
        kind: &'static str,
        source: serde_json::Error,
    },
    #[error("{kind} state exceeds {limit} bytes: got {actual}")]
    StateTooLarge {
        kind: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error("cannot read {}: {source}", path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("cannot write {}: {source}", path.display())]
    Write { path: PathBuf, source: io::Error },
    #[error("cannot read secret bytes from stdin: {0}")]
    ReadStdin(io::Error),
    #[error(
        "refusing to read a secret from an interactive terminal; pipe exact bytes or pass --file"
    )]
    TerminalSecretInput,
    #[error("{kind} exceeds {limit} bytes: got {actual}")]
    InputTooLarge {
        kind: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error("reveal target {} already exists; secret files are never overwritten", .0.display())]
    RevealTargetExists(PathBuf),
    #[error("could not reserve a private temporary file in {}", .0.display())]
    TemporaryExhausted(PathBuf),
    #[error("local master-key validation failed: {0}")]
    MasterKey(MasterKeyFileError),
    #[error("invalid encrypted secret state: {0}")]
    SecretState(SecretsError),
    #[error("secret operation failed: {0}")]
    SecretOperation(SecretsError),
    #[error("cannot serialize administration state: {0}")]
    SerializeState(serde_json::Error),
    #[error("cannot serialize JSON output: {0}")]
    SerializeOutput(serde_json::Error),
    #[error("cannot write command output: {0}")]
    Output(io::Error),
}

impl AdminError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::SecretValueArgument => "secret_value_in_argv",
            Self::InvalidName => "invalid_admin_name",
            Self::InvalidVariableValue
            | Self::VariableValueTooLarge { .. }
            | Self::VariableVersionOverflow
            | Self::InvalidVariableVersion(_) => "invalid_variable_value",
            Self::VariableNotFound(_) => "variable_not_found",
            Self::UnsafePath { .. }
            | Self::InsecurePermissions { .. }
            | Self::RevealTargetExists(_) => "unsafe_admin_path",
            Self::StateMissing(_) => "admin_state_missing",
            Self::IncompleteSecretState
            | Self::UnsupportedStateVersion { .. }
            | Self::InvalidState { .. }
            | Self::StateTooLarge { .. }
            | Self::MasterKey(_)
            | Self::SecretState(_) => "invalid_admin_state",
            Self::Read { .. }
            | Self::ReadStdin(_)
            | Self::TerminalSecretInput
            | Self::InputTooLarge { .. } => "secret_input_failed",
            Self::SecretOperation(_) => "secret_operation_failed",
            Self::Write { .. } | Self::TemporaryExhausted(_) | Self::SerializeState(_) => {
                "admin_write_failed"
            }
            Self::SerializeOutput(_) | Self::Output(_) => "output_failed",
        }
    }

    pub(crate) const fn exit_code(&self) -> u8 {
        match self {
            Self::Write { .. }
            | Self::TemporaryExhausted(_)
            | Self::SerializeState(_)
            | Self::SerializeOutput(_)
            | Self::Output(_) => 1,
            _ => 10,
        }
    }
}
