use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "runtrue-runner",
    about = "Runtrue fail-closed execution runner"
)]
pub(super) struct Args {
    /// mTLS runner-control URL used by daemon, once, and doctor.
    #[arg(long)]
    pub(super) endpoint: Option<String>,

    /// TLS-server-auth-only URL used exclusively by `enroll`.
    #[arg(long)]
    pub(super) enrollment_endpoint: Option<String>,

    /// Provisioned runner identity from the control plane.
    #[arg(long)]
    pub(super) runner_id: Option<String>,

    /// Mode-0700 root for atomically versioned enrolled credentials.
    #[arg(long)]
    pub(super) credential_directory: Option<PathBuf>,

    /// Mode-0600 file containing the one-time enrollment token.
    #[arg(long)]
    pub(super) enrollment_token_file: Option<PathBuf>,

    /// Mode-0600 autoscaler launch claim used only by `enroll-if-needed`.
    #[arg(long)]
    pub(super) launch_claim_file: Option<PathBuf>,

    /// Mode-0600 fixed-host software-update claim used only by `enroll-if-needed`.
    #[arg(long)]
    pub(super) update_claim_file: Option<PathBuf>,

    /// Durable local fencing/completion state directory.
    #[arg(long)]
    pub(super) state_directory: Option<PathBuf>,

    /// Absolute host-local lock coordinating OCI image admission with leases.
    #[arg(long)]
    pub(super) admission_lock: Option<PathBuf>,

    /// Root for ephemeral per-lease workspaces.
    #[arg(long)]
    pub(super) workspace_directory: Option<PathBuf>,

    /// Mode-0700 directory of mode-0600 raw or hex Ed25519 public keys.
    #[arg(long)]
    pub(super) capsule_keyring: Option<PathBuf>,

    /// Mode-0600 PEM CA certificate for the control plane.
    #[arg(long)]
    pub(super) ca_certificate: Option<PathBuf>,

    /// Mode-0600 PEM client certificate chain.
    #[arg(long)]
    pub(super) client_certificate: Option<PathBuf>,

    /// Mode-0600 PEM client private key.
    #[arg(long)]
    pub(super) client_private_key: Option<PathBuf>,

    /// Required generation for direct credentials; also upgrades legacy
    /// enrolled credentials that predate persisted selection metadata.
    #[arg(long)]
    pub(super) protocol_version: Option<u32>,

    /// Allow plaintext only for a numeric loopback IP endpoint.
    #[arg(long)]
    pub(super) insecure_loopback: bool,

    /// Explicitly permit trusted native process execution.
    #[arg(long)]
    pub(super) trusted_native: bool,

    /// Mode-0700 root for private per-lease Podman state.
    #[arg(long)]
    pub(super) oci_state_directory: Option<PathBuf>,

    /// Absolute, real, rootless Podman executable.
    #[arg(long)]
    pub(super) oci_podman: Option<PathBuf>,

    /// Mode-0600 default-deny seccomp JSON profile.
    #[arg(long)]
    pub(super) oci_seccomp_profile: Option<PathBuf>,

    /// Mode-0700 prehydrated Podman image store used with --pull=never.
    #[arg(long)]
    pub(super) oci_image_store: Option<PathBuf>,

    /// Mode-0600 JSON object containing the allowlisted Podman environment.
    #[arg(long)]
    pub(super) oci_runtime_environment: Option<PathBuf>,

    /// Mode-0700 directory of signed capsule/job/service OCI manifests.
    #[arg(long)]
    pub(super) oci_manifest_directory: Option<PathBuf>,

    /// Mode-0700 directory of mode-0600 OCI image verification keys.
    #[arg(long)]
    pub(super) oci_image_keyring: Option<PathBuf>,

    /// Mode-0700 directory of digest-named, preloaded WebAssembly Components.
    #[arg(long)]
    pub(super) wasm_component_directory: Option<PathBuf>,

    /// Mode-0700 directory of signed WebAssembly Component manifests.
    #[arg(long)]
    pub(super) wasm_manifest_directory: Option<PathBuf>,

    /// Mode-0700 directory of mode-0600 Component verification keys.
    #[arg(long)]
    pub(super) wasm_component_keyring: Option<PathBuf>,

    /// Absolute private directory for authenticated Wasmtime AOT state.
    #[arg(long)]
    pub(super) wasm_aot_cache: Option<PathBuf>,

    /// Mode-0600 file containing the 64-byte Wasm runtime key material.
    #[arg(long)]
    pub(super) wasm_runtime_key: Option<PathBuf>,

    /// Maximum concurrent in-process Wasm jobs. Other backends stay exclusive.
    #[arg(long)]
    pub(super) wasm_max_concurrent_jobs: Option<u32>,

    /// Mode-0700 root for Firecracker recovery and quarantine state.
    #[arg(long)]
    pub(super) firecracker_state_directory: Option<PathBuf>,

    /// Absolute, pinned Firecracker jailer executable.
    #[arg(long)]
    pub(super) firecracker_jailer: Option<PathBuf>,

    /// Absolute, pinned Firecracker VMM executable.
    #[arg(long)]
    pub(super) firecracker_binary: Option<PathBuf>,

    /// Absolute executable providing cp --reflink=always.
    #[arg(long)]
    pub(super) firecracker_reflink_copy: Option<PathBuf>,

    /// Absolute mode-0700 Firecracker jailer chroot base.
    #[arg(long)]
    pub(super) firecracker_jail_root: Option<PathBuf>,

    /// Relative cgroup-v2 parent dedicated to Firecracker jails.
    #[arg(long)]
    pub(super) firecracker_cgroup_parent: Option<PathBuf>,

    /// Absolute mode-0700 host-wide guest-CID lock directory.
    #[arg(long)]
    pub(super) firecracker_cid_lock_directory: Option<PathBuf>,

    /// Mode-0700 digest-named kernel/rootfs/guest/snapshot payload directory.
    #[arg(long)]
    pub(super) firecracker_image_payload_directory: Option<PathBuf>,

    /// Mode-0700 directory containing the exact signed image manifests.
    #[arg(long)]
    pub(super) firecracker_image_manifest_directory: Option<PathBuf>,

    /// Mode-0700 directory of mode-0600 image verification keys.
    #[arg(long)]
    pub(super) firecracker_image_keyring: Option<PathBuf>,

    /// Mode-0600 exact binary/host/topology compatibility profile.
    #[arg(long)]
    pub(super) firecracker_runtime_profile: Option<PathBuf>,

    /// Operator-configured placement region included in the posture digest.
    #[arg(long)]
    pub(super) region: Option<String>,

    /// Enroll a disposable runner identity that is removed after going offline.
    #[arg(long)]
    pub(super) ephemeral: bool,

    #[command(subcommand)]
    pub(super) command: Option<Command>,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub(super) enum Command {
    /// Generate a local Ed25519 key, enroll its CSR, and atomically install credentials.
    Enroll,
    /// Enroll from a bound launch claim when credentials are absent, then run as a daemon.
    EnrollIfNeeded,
    /// Run until drained or the authenticated stream closes.
    Daemon,
    /// Accept and finish one lease, including exact completion retries.
    Once,
    /// Validate local trust, inventory, paths, and transport configuration.
    Doctor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clap_exposes_enroll_doctor_once_and_backend_configuration() {
        use clap::CommandFactory as _;

        let help = Args::command().render_long_help().to_string();
        assert!(help.contains("doctor"));
        assert!(help.contains("once"));
        assert!(help.contains("enroll"));
        assert!(help.contains("--enrollment-endpoint"));
        assert!(help.contains("--enrollment-token-file"));
        assert!(help.contains("--launch-claim-file"));
        assert!(help.contains("--update-claim-file"));
        assert!(help.contains("enroll-if-needed"));
        assert!(help.contains("--credential-directory"));
        assert!(help.contains("--protocol-version"));
        assert!(help.contains("--oci-state-directory"));
        assert!(help.contains("--oci-image-keyring"));
        assert!(help.contains("--wasm-component-directory"));
        assert!(help.contains("--wasm-manifest-directory"));
        assert!(help.contains("--wasm-component-keyring"));
        assert!(help.contains("--wasm-aot-cache"));
        assert!(help.contains("--wasm-runtime-key"));
        assert!(help.contains("--wasm-max-concurrent-jobs"));
        assert!(help.contains("--firecracker-state-directory"));
        assert!(help.contains("--firecracker-jailer"));
        assert!(help.contains("--firecracker-binary"));
        assert!(help.contains("--firecracker-runtime-profile"));
        assert!(help.contains("--ephemeral"));
        assert!(!help.contains("rotate"));
    }
}
