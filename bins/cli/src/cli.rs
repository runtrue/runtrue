#[path = "admin/mod.rs"]
mod admin;
#[path = "approve.rs"]
mod approve;
#[path = "commands/mod.rs"]
mod commands;
#[path = "error.rs"]
mod error;
#[path = "output.rs"]
mod output;
#[path = "paths.rs"]
mod paths;
#[path = "remote/mod.rs"]
mod remote;
#[path = "reusable.rs"]
mod reusable;
#[path = "strict_json.rs"]
mod strict_json;

use commands::{
    bisim, capsule, compare_capsule, doctor, init, replay, validate, write_atomic_output,
};
use error::CliError;
use output::{
    print_execution_result, print_human_artifacts, print_human_capsule, print_human_run, print_json,
};
use paths::{
    absolute, discover_workflows, display_path, read_bounded_file, read_event, resolve_one_workflow,
};
use strict_json::parse_strict_json;

use clap::{Args, Parser, Subcommand};
use std::{
    env,
    io::{self, Write as _},
    path::PathBuf,
    process::ExitCode,
};

#[cfg(test)]
use std::{fs, path::Path};

const EXIT_OK: u8 = 0;
const EXIT_INTERNAL: u8 = 1;
const EXIT_VALIDATION: u8 = 10;
const EXIT_EXECUTION: u8 = 20;
const MAX_EVENT_BYTES: u64 = 1024 * 1024;
const MAX_WORKFLOW_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "runtrue", version, about = "Run local. Run remote. Run true.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    const fn wants_json(&self) -> bool {
        match &self.command {
            Command::Init(args) => args.json,
            Command::Validate(args) => args.json,
            Command::Capsule(args) => args.json,
            Command::Run(args) => args.json,
            Command::Replay(args) => args.json,
            Command::CompareCapsule(args) => args.json,
            Command::Bisim(args) => args.json,
            Command::Doctor(args) => args.json,
            Command::Submit(args) => args.json,
            Command::Seal(args) => args.wants_json(),
            Command::Secrets(args) => args.wants_json(),
            Command::Vars(args) => args.wants_json(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a starter workflow under .runtrue/workflows.
    Init(InitArgs),
    /// Parse, validate, and compile one or more workflows without executing.
    Validate(ValidateArgs),
    /// Compile and display the exact deterministic execution capsule.
    Capsule(CapsuleArgs),
    /// Compile and execute a reviewed workflow on the local host.
    Run(RunArgs),
    /// Execute an immutable replay bundle on the local host.
    Replay(ReplayArgs),
    /// Compile the current workflow context and compare it with a replay capsule.
    CompareCapsule(CompareCapsuleArgs),
    /// Compare normalized observations from two execution engines.
    Bisim(BisimArgs),
    /// Inspect local configuration, security boundaries, and backend availability.
    Doctor(DoctorArgs),
    /// Compile locally, prove exact remote capsule parity, and create a remote run.
    Submit(remote::SubmitArgs),
    /// Approve or deny an exact Capsule and manage its Seal evidence.
    Seal(approve::SealArgs),
    /// Administer encrypted workspace-local secrets.
    Secrets(admin::SecretsArgs),
    /// Administer non-secret workspace-local variables.
    Vars(admin::VarsArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Replace the generated starter workflow if it already exists.
    #[arg(long)]
    force: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ValidateArgs {
    /// Workflow YAML file. When omitted, validates every discovered workflow.
    #[arg(long, value_name = "PATH")]
    workflow: Option<PathBuf>,
    /// Optional event fixture used during compilation.
    #[arg(long, value_name = "PATH")]
    event: Option<PathBuf>,
    /// Source commit identity included in the capsule.
    #[arg(long, default_value = "local-worktree")]
    source_commit: String,
    /// Base commit identity included in the capsule.
    #[arg(long)]
    base_commit: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CapsuleArgs {
    /// Job id (or matrix base id) to include in the Capsule with its dependencies.
    job: Option<String>,
    #[command(flatten)]
    context: ContextArgs,
    /// Emit the complete compilation envelope as machine-readable JSON.
    #[arg(long)]
    json: bool,
    /// Write the execution capsule JSON to this path.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Job id (or matrix base id) to run, including its dependencies.
    job: Option<String>,
    #[command(flatten)]
    context: ContextArgs,
    /// Required acknowledgement for unsandboxed native host execution.
    #[arg(long)]
    allow_native: bool,
    /// Emit the compilation identity and execution result as JSON.
    #[arg(long)]
    json: bool,
    /// Write a canonical secret-free replay bundle after execution.
    #[arg(long, value_name = "PATH")]
    replay_bundle: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ReplayArgs {
    /// Canonical replay bundle created by `runtrue run --replay-bundle`.
    #[arg(value_name = "BUNDLE")]
    bundle: PathBuf,
    /// Required acknowledgement for unsandboxed native host execution.
    #[arg(long)]
    allow_native: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CompareCapsuleArgs {
    /// Canonical replay bundle whose capsule identity is the expected value.
    #[arg(value_name = "BUNDLE")]
    bundle: PathBuf,
    /// Job id (or matrix base id) to compile, including dependencies.
    job: Option<String>,
    #[command(flatten)]
    context: ContextArgs,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct BisimArgs {
    /// Normalized observation emitted by the first execution engine.
    #[arg(value_name = "LEFT")]
    left: PathBuf,
    /// Normalized observation emitted by the second execution engine.
    #[arg(value_name = "RIGHT")]
    right: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ContextArgs {
    /// Workflow YAML file. When omitted, exactly one workflow must be discoverable.
    #[arg(long, value_name = "PATH")]
    workflow: Option<PathBuf>,
    /// JSON event fixture. Values are available through the `event` context.
    #[arg(long, value_name = "PATH")]
    event: Option<PathBuf>,
    /// Source commit identity included in the capsule.
    #[arg(long, default_value = "local-worktree")]
    source_commit: String,
    /// Base commit identity included in the capsule.
    #[arg(long)]
    base_commit: Option<String>,
}

pub(crate) fn main() -> ExitCode {
    let cli = Cli::parse();
    let wants_json = cli.wants_json();
    match execute(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if wants_json {
                let mut stderr = io::stderr().lock();
                let _ = serde_json::to_writer(
                    &mut stderr,
                    &serde_json::json!({
                        "error": {
                            "code": error.code(),
                            "message": error.to_string(),
                            "exit_code": error.exit_code()
                        }
                    }),
                );
                let _ = writeln!(stderr);
            } else {
                let _ = writeln!(io::stderr(), "runtrue: {error}");
            }
            ExitCode::from(error.exit_code())
        }
    }
}

fn execute(cli: Cli) -> Result<u8, CliError> {
    let workspace = env::current_dir().map_err(CliError::CurrentDirectory)?;
    match cli.command {
        Command::Init(args) => init(&workspace, args),
        Command::Validate(args) => validate(&workspace, args),
        Command::Capsule(args) => capsule(&workspace, args),
        Command::Run(args) => commands::run(&workspace, args),
        Command::Replay(args) => replay(&workspace, args),
        Command::CompareCapsule(args) => compare_capsule(&workspace, args),
        Command::Bisim(args) => bisim(&workspace, args),
        Command::Doctor(args) => doctor(&workspace, args),
        Command::Submit(args) => remote::execute(&workspace, args),
        Command::Seal(args) => approve::execute(&workspace, args),
        Command::Secrets(args) => {
            admin::execute_secrets(&workspace, args)?;
            Ok(EXIT_OK)
        }
        Command::Vars(args) => {
            admin::execute_vars(&workspace, args)?;
            Ok(EXIT_OK)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn display_path_is_host_independent_inside_workspace() {
        assert_eq!(
            display_path(
                Path::new("/repo"),
                Path::new("/repo/.runtrue/workflows/ci.yaml")
            ),
            ".runtrue/workflows/ci.yaml"
        );
    }

    #[test]
    fn event_json_rejects_duplicate_keys_at_every_depth() {
        for source in [r#"{"x":1,"x":2}"#, r#"{"x":{"y":1,"y":2}}"#] {
            let error = parse_strict_json(source.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(error.contains("duplicate JSON object key"), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn capsule_and_replay_bundles_are_private_atomic_and_never_follow_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temp = tempdir().unwrap();
        let output = temp.path().join("capsule.json");
        write_atomic_output(&output, b"first").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"first");
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_atomic_output(&output, b"second").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"second");

        let victim = temp.path().join("victim");
        fs::write(&victim, b"preserve").unwrap();
        let link = temp.path().join("linked-output");
        symlink(&victim, &link).unwrap();
        assert!(matches!(
            write_atomic_output(&link, b"overwrite"),
            Err(CliError::UnsafeOutputPath { .. })
        ));
        assert_eq!(fs::read(&victim).unwrap(), b"preserve");

        let real = temp.path().join("real");
        fs::create_dir(&real).unwrap();
        let linked_parent = temp.path().join("linked-parent");
        symlink(&real, &linked_parent).unwrap();
        assert!(matches!(
            write_atomic_output(&linked_parent.join("escape"), b"bad"),
            Err(CliError::UnsafeOutputPath { .. })
        ));
    }
}
