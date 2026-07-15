use clap::{Args, Parser, Subcommand};
use runtrue_backup::{
    activate_restore, create_backup, current_unix_ms, restore_backup, verify_backup,
    ActivateRestoreRequest, BackupLimits, BackupSourcePaths, CreateBackupRequest,
    LocalSecuritySeed, RestoreBackupRequest, VerifyBackupRequest,
};
use std::{error::Error, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "runtrue-backup",
    about = "Fail-closed single-node Runtrue backup and restore"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture SQLite online and copy bounded durable filesystem state.
    Create {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        blobs_dir: Option<PathBuf>,
        #[arg(long)]
        config_dir: Option<PathBuf>,
        #[arg(long)]
        key_ciphertext_dir: Option<PathBuf>,
        #[arg(long)]
        security_key_file: Option<PathBuf>,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Verify the manifest, every file digest, SQLite, audit, and key state.
    Verify {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        security_key_file: Option<PathBuf>,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Restore only into an absent or empty private target and enter safe mode.
    Restore {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        security_key_file: Option<PathBuf>,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Leave safe mode after the documented independent checks are complete.
    Activate {
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        security_key_file: Option<PathBuf>,
        #[arg(long)]
        expected_fencing_epoch: u64,
        #[arg(long, default_value_t = false)]
        acknowledge_restore_verification: bool,
        #[command(flatten)]
        limits: LimitArgs,
    },
}

#[derive(Args, Clone, Copy)]
struct LimitArgs {
    #[arg(long, default_value_t = 32 * 1024 * 1024)]
    max_manifest_bytes: u64,
    #[arg(long, default_value_t = 250_000)]
    max_entries: usize,
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024)]
    max_file_bytes: u64,
    #[arg(long, default_value_t = 64 * 1024 * 1024 * 1024)]
    max_database_bytes: u64,
    #[arg(long, default_value_t = 2 * 1024 * 1024 * 1024 * 1024)]
    max_total_bytes: u64,
}

impl LimitArgs {
    fn resolve(self) -> BackupLimits {
        BackupLimits {
            max_manifest_bytes: self.max_manifest_bytes,
            max_entries: self.max_entries,
            max_file_bytes: self.max_file_bytes,
            max_database_bytes: self.max_database_bytes,
            max_total_bytes: self.max_total_bytes,
            ..BackupLimits::default()
        }
    }
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("runtrue-backup: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    let report = match cli.command {
        Command::Create {
            database,
            output,
            blobs_dir,
            config_dir,
            key_ciphertext_dir,
            security_key_file,
            limits,
        } => {
            let seed = load_seed(security_key_file.as_ref())?;
            serde_json::to_value(create_backup(CreateBackupRequest {
                source: BackupSourcePaths {
                    database,
                    blobs: blobs_dir,
                    config: config_dir,
                    key_ciphertext: key_ciphertext_dir,
                },
                destination: output,
                local_security_seed: seed.as_ref(),
                created_unix_ms: current_unix_ms()?,
                limits: limits.resolve(),
            })?)?
        }
        Command::Verify {
            backup,
            security_key_file,
            limits,
        } => {
            let seed = load_seed(security_key_file.as_ref())?;
            serde_json::to_value(verify_backup(VerifyBackupRequest {
                backup,
                local_security_seed: seed.as_ref(),
                limits: limits.resolve(),
            })?)?
        }
        Command::Restore {
            backup,
            target,
            security_key_file,
            limits,
        } => {
            let seed = load_seed(security_key_file.as_ref())?;
            serde_json::to_value(restore_backup(RestoreBackupRequest {
                backup,
                target,
                local_security_seed: seed.as_ref(),
                restored_unix_ms: current_unix_ms()?,
                limits: limits.resolve(),
            })?)?
        }
        Command::Activate {
            target,
            security_key_file,
            expected_fencing_epoch,
            acknowledge_restore_verification,
            limits,
        } => {
            let seed = load_seed(security_key_file.as_ref())?;
            serde_json::to_value(activate_restore(ActivateRestoreRequest {
                target,
                local_security_seed: seed.as_ref(),
                expected_fencing_epoch,
                verification_acknowledged: acknowledge_restore_verification,
                limits: limits.resolve(),
            })?)?
        }
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn load_seed(path: Option<&PathBuf>) -> Result<Option<LocalSecuritySeed>, Box<dyn Error>> {
    path.map(LocalSecuritySeed::load)
        .transpose()
        .map_err(Into::into)
}
