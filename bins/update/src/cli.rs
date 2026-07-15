use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    name = "runtrue-update",
    about = "Verify rollback-resistant Runtrue updates"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Display the canonical signed-root envelope digest for out-of-band comparison.
    RootDigest {
        #[arg(long)]
        root: PathBuf,
    },
    /// Bootstrap durable trust only when the root matches an out-of-band digest.
    Bootstrap {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        expected_root_digest: String,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        now_unix_seconds: Option<u64>,
    },
    /// Verify a complete metadata chain and target without changing trust state.
    Verify {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        target_path: String,
        #[arg(long)]
        target_file: PathBuf,
        #[arg(long)]
        now_unix_seconds: Option<u64>,
    },
    /// Verify the full chain and target, then atomically commit the next trust state.
    Apply {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        target_path: String,
        #[arg(long)]
        target_file: PathBuf,
        #[arg(long)]
        now_unix_seconds: Option<u64>,
    },
    /// Generate one Ed25519 role key through the operating-system RNG.
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    /// Emit canonical in-toto/SLSA-style provenance for exact release files.
    Provenance {
        #[arg(long = "subject", required = true)]
        subjects: Vec<String>,
        #[arg(long)]
        source_repository: String,
        #[arg(long)]
        source_commit: String,
        #[arg(long)]
        source_ref: String,
        #[arg(long)]
        builder_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        built_unix_seconds: Option<u64>,
    },
    /// Emit a canonical CycloneDX inventory for exact release files.
    Sbom {
        #[arg(long = "component", required = true)]
        components: Vec<String>,
        #[arg(long)]
        package: String,
        #[arg(long)]
        cargo_metadata: PathBuf,
        #[arg(long)]
        cargo_lock: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        output: PathBuf,
    },
}
