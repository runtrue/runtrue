use clap::{Parser, Subcommand, ValueEnum};
use runtrue_attest::{ImageKind, SnapshotPhase};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "runtrue-image",
    version,
    about = "Build and verify Runtrue image trust metadata"
)]
pub(crate) struct Cli {
    /// Emit the command result as stable JSON.
    #[arg(long, global = true)]
    pub(crate) json: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Generate a purpose-separated Ed25519 image signing keypair.
    Keygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Calculate a qualified SHA-256 digest and exact byte length.
    Digest {
        #[arg(long)]
        file: PathBuf,
    },
    /// Fetch and verify an exact WASM component from a private OCI registry.
    StageComponent {
        /// Path to an ORAS binary whose bytes match --oras-digest.
        #[arg(long)]
        oras: PathBuf,
        /// Exact SHA-256 digest of the trusted ORAS binary.
        #[arg(long)]
        oras_digest: String,
        /// Exact OCI manifest reference, for example registry.example/org/action@sha256:HEX.
        #[arg(long)]
        reference: String,
        /// Expected SHA-256 digest of the application/wasm layer.
        #[arg(long)]
        payload_digest: String,
        /// Optional private, mode-0600 Docker/ORAS registry credential file.
        #[arg(long)]
        registry_config: Option<PathBuf>,
        /// New digest-named WASM file to create for runner preloading.
        #[arg(long)]
        output: PathBuf,
    },
    /// Create canonical unsigned image metadata.
    Manifest {
        #[arg(long, value_enum)]
        kind: KindArgument,
        #[arg(long)]
        name: String,
        #[arg(long)]
        payload: PathBuf,
        #[arg(long)]
        payload_media_type: String,
        #[arg(long)]
        operating_system: String,
        #[arg(long)]
        architecture: String,
        #[arg(long)]
        builder_id: String,
        #[arg(long)]
        provenance: PathBuf,
        #[arg(long)]
        sbom: PathBuf,
        #[arg(long)]
        created_unix_ms: u64,
        #[arg(long)]
        expires_unix_ms: Option<u64>,
        #[arg(long, value_enum)]
        snapshot_phase: Option<SnapshotPhaseArgument>,
        /// Add an exact subordinate object as NAME=sha256:HEX.
        #[arg(long = "component")]
        components: Vec<String>,
        /// Add a compatibility constraint as NAME=VALUE.
        #[arg(long = "compatibility")]
        compatibility: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign exact canonical manifest bytes with an installation image key.
    Sign {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify signature, payload, SBOM, provenance, expiry, and optionally warm-snapshot sterility.
    Verify {
        #[arg(long)]
        signed_manifest: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        payload: PathBuf,
        #[arg(long)]
        provenance: PathBuf,
        #[arg(long)]
        sbom: PathBuf,
        #[arg(long)]
        now_unix_ms: u64,
        #[arg(long)]
        require_warm_snapshot: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum KindArgument {
    FirecrackerKernel,
    FirecrackerRootFilesystem,
    FirecrackerSnapshot,
    GuestAgent,
    OciImage,
    ToolchainLayer,
    WasmComponent,
    WasmAot,
}

impl From<KindArgument> for ImageKind {
    fn from(value: KindArgument) -> Self {
        match value {
            KindArgument::FirecrackerKernel => Self::FirecrackerKernel,
            KindArgument::FirecrackerRootFilesystem => Self::FirecrackerRootFilesystem,
            KindArgument::FirecrackerSnapshot => Self::FirecrackerSnapshot,
            KindArgument::GuestAgent => Self::GuestAgent,
            KindArgument::OciImage => Self::OciImage,
            KindArgument::ToolchainLayer => Self::ToolchainLayer,
            KindArgument::WasmComponent => Self::WasmComponent,
            KindArgument::WasmAot => Self::WasmAot,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum SnapshotPhaseArgument {
    Sterile,
    JobIdentityInjected,
    SourceMounted,
    SecretReleased,
}

impl From<SnapshotPhaseArgument> for SnapshotPhase {
    fn from(value: SnapshotPhaseArgument) -> Self {
        match value {
            SnapshotPhaseArgument::Sterile => Self::Sterile,
            SnapshotPhaseArgument::JobIdentityInjected => Self::JobIdentityInjected,
            SnapshotPhaseArgument::SourceMounted => Self::SourceMounted,
            SnapshotPhaseArgument::SecretReleased => Self::SecretReleased,
        }
    }
}
