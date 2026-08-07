use super::{
    args::{Args, Command},
    backends::{
        complete_firecracker_configuration, complete_oci_configuration, complete_wasm_configuration,
    },
    error::StartupError,
};
use runtrue_runner::{FirecrackerRuntimePaths, OciRuntimePaths, WasmRuntimePaths};
use std::{env, path::PathBuf};

const DEFAULT_STATE_DIRECTORY: &str = ".runtrue/runner/state";
const DEFAULT_WORKSPACE_DIRECTORY: &str = ".runtrue/runner/workspaces";
const DEFAULT_KEYRING_DIRECTORY: &str = ".runtrue/runner/trusted-capsule-keys";
const DEFAULT_CREDENTIAL_DIRECTORY: &str = ".runtrue/runner/credentials";
pub(super) const MAX_CAPSULE_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct Config {
    pub(super) endpoint: Option<String>,
    pub(super) enrollment_endpoint: Option<String>,
    pub(super) runner_id: Option<String>,
    pub(super) credential_directory: PathBuf,
    pub(super) enrollment_token_file: Option<PathBuf>,
    pub(super) launch_claim_file: Option<PathBuf>,
    pub(super) update_claim_file: Option<PathBuf>,
    pub(super) ca_certificate: Option<PathBuf>,
    pub(super) client_certificate: Option<PathBuf>,
    pub(super) client_private_key: Option<PathBuf>,
    pub(super) protocol_version: Option<u32>,
    pub(super) insecure_loopback: bool,
    pub(super) state_directory: PathBuf,
    pub(super) admission_lock: Option<PathBuf>,
    pub(super) workspace_directory: PathBuf,
    pub(super) capsule_keyring: PathBuf,
    pub(super) trusted_native: bool,
    pub(super) allow_credential_tainted_logs: bool,
    pub(super) oci: Option<OciRuntimePaths>,
    pub(super) wasm: Option<WasmRuntimePaths>,
    pub(super) wasm_max_concurrent_jobs: u32,
    pub(super) firecracker: Option<FirecrackerRuntimePaths>,
    pub(super) region: Option<String>,
    pub(super) ephemeral: bool,
    pub(super) command: Command,
}

impl Config {
    pub(super) fn load(args: Args) -> Result<Self, StartupError> {
        let endpoint = args
            .endpoint
            .or_else(|| env::var("RUNTRUE_RUNNER_ENDPOINT").ok());
        let enrollment_endpoint = args
            .enrollment_endpoint
            .or_else(|| env::var("RUNTRUE_RUNNER_ENROLLMENT_ENDPOINT").ok());
        let runner_id = args
            .runner_id
            .or_else(|| env::var("RUNTRUE_RUNNER_ID").ok());
        let credential_directory = args
            .credential_directory
            .or_else(|| env::var_os("RUNTRUE_RUNNER_CREDENTIAL_DIRECTORY").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CREDENTIAL_DIRECTORY));
        let enrollment_token_file = args
            .enrollment_token_file
            .or_else(|| env::var_os("RUNTRUE_RUNNER_ENROLLMENT_TOKEN_FILE").map(PathBuf::from));
        let launch_claim_file = args
            .launch_claim_file
            .or_else(|| env::var_os("RUNTRUE_RUNNER_LAUNCH_CLAIM_FILE").map(PathBuf::from));
        let update_claim_file = args
            .update_claim_file
            .or_else(|| env::var_os("RUNTRUE_RUNNER_UPDATE_CLAIM_FILE").map(PathBuf::from));
        let state_directory = args
            .state_directory
            .or_else(|| env::var_os("RUNTRUE_RUNNER_STATE_DIRECTORY").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIRECTORY));
        let admission_lock = args
            .admission_lock
            .or_else(|| env::var_os("RUNTRUE_RUNNER_ADMISSION_LOCK").map(PathBuf::from));
        let workspace_directory = args
            .workspace_directory
            .or_else(|| env::var_os("RUNTRUE_RUNNER_WORKSPACE_DIRECTORY").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_WORKSPACE_DIRECTORY));
        let capsule_keyring = args
            .capsule_keyring
            .or_else(|| env::var_os("RUNTRUE_RUNNER_CAPSULE_KEYRING").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_KEYRING_DIRECTORY));
        let ca_certificate = args
            .ca_certificate
            .or_else(|| env::var_os("RUNTRUE_RUNNER_CA_CERTIFICATE").map(PathBuf::from));
        let client_certificate = args
            .client_certificate
            .or_else(|| env::var_os("RUNTRUE_RUNNER_CLIENT_CERTIFICATE").map(PathBuf::from));
        let client_private_key = args
            .client_private_key
            .or_else(|| env::var_os("RUNTRUE_RUNNER_CLIENT_PRIVATE_KEY").map(PathBuf::from));
        let protocol_version = match args.protocol_version {
            Some(value) => Some(value),
            None => match env::var("RUNTRUE_RUNNER_PROTOCOL_VERSION") {
                Ok(value) => Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| StartupError::InvalidProtocolVersion)?,
                ),
                Err(env::VarError::NotPresent) => None,
                Err(env::VarError::NotUnicode(_)) => {
                    return Err(StartupError::InvalidProtocolVersion)
                }
            },
        };
        if protocol_version.is_some_and(|value| !runtrue_protocol::supports_protocol_version(value))
        {
            return Err(StartupError::InvalidProtocolVersion);
        }
        let insecure_loopback = args.insecure_loopback
            || environment_flag("RUNTRUE_RUNNER_INSECURE_LOOPBACK")?.unwrap_or(false);
        let trusted_native = args.trusted_native
            || environment_flag("RUNTRUE_RUNNER_TRUSTED_NATIVE")?.unwrap_or(false);
        let allow_credential_tainted_logs = args.allow_credential_tainted_logs
            || environment_flag("RUNTRUE_RUNNER_ALLOW_CREDENTIAL_TAINTED_LOGS")?.unwrap_or(false);
        let oci = complete_oci_configuration([
            configured_path(
                args.oci_state_directory,
                "RUNTRUE_RUNNER_OCI_STATE_DIRECTORY",
            ),
            configured_path(args.oci_podman, "RUNTRUE_RUNNER_OCI_PODMAN"),
            configured_path(
                args.oci_seccomp_profile,
                "RUNTRUE_RUNNER_OCI_SECCOMP_PROFILE",
            ),
            configured_path(args.oci_image_store, "RUNTRUE_RUNNER_OCI_IMAGE_STORE"),
            configured_path(
                args.oci_runtime_environment,
                "RUNTRUE_RUNNER_OCI_RUNTIME_ENVIRONMENT",
            ),
            configured_path(
                args.oci_manifest_directory,
                "RUNTRUE_RUNNER_OCI_MANIFEST_DIRECTORY",
            ),
            configured_path(args.oci_image_keyring, "RUNTRUE_RUNNER_OCI_IMAGE_KEYRING"),
        ])?;
        let wasm = complete_wasm_configuration([
            configured_path(
                args.wasm_component_directory,
                "RUNTRUE_RUNNER_WASM_COMPONENT_DIRECTORY",
            ),
            configured_path(
                args.wasm_manifest_directory,
                "RUNTRUE_RUNNER_WASM_MANIFEST_DIRECTORY",
            ),
            configured_path(
                args.wasm_component_keyring,
                "RUNTRUE_RUNNER_WASM_COMPONENT_KEYRING",
            ),
            configured_path(args.wasm_aot_cache, "RUNTRUE_RUNNER_WASM_AOT_CACHE"),
            configured_path(args.wasm_runtime_key, "RUNTRUE_RUNNER_WASM_RUNTIME_KEY"),
        ])?;
        let wasm_max_concurrent_jobs = configured_u32(
            args.wasm_max_concurrent_jobs,
            "RUNTRUE_RUNNER_WASM_MAX_CONCURRENT_JOBS",
        )?
        .unwrap_or(1);
        if wasm_max_concurrent_jobs == 0
            || wasm_max_concurrent_jobs > runtrue_runner_core::MAX_CONCURRENT_WASM_JOBS
            || (wasm.is_none() && wasm_max_concurrent_jobs != 1)
        {
            return Err(StartupError::InvalidWasmConcurrency);
        }
        let firecracker = complete_firecracker_configuration([
            configured_path(
                args.firecracker_state_directory,
                "RUNTRUE_RUNNER_FIRECRACKER_STATE_DIRECTORY",
            ),
            configured_path(args.firecracker_jailer, "RUNTRUE_RUNNER_FIRECRACKER_JAILER"),
            configured_path(args.firecracker_binary, "RUNTRUE_RUNNER_FIRECRACKER_BINARY"),
            configured_path(
                args.firecracker_reflink_copy,
                "RUNTRUE_RUNNER_FIRECRACKER_REFLINK_COPY",
            ),
            configured_path(
                args.firecracker_jail_root,
                "RUNTRUE_RUNNER_FIRECRACKER_JAIL_ROOT",
            ),
            configured_path(
                args.firecracker_cgroup_parent,
                "RUNTRUE_RUNNER_FIRECRACKER_CGROUP_PARENT",
            ),
            configured_path(
                args.firecracker_cid_lock_directory,
                "RUNTRUE_RUNNER_FIRECRACKER_CID_LOCK_DIRECTORY",
            ),
            configured_path(
                args.firecracker_image_payload_directory,
                "RUNTRUE_RUNNER_FIRECRACKER_IMAGE_PAYLOAD_DIRECTORY",
            ),
            configured_path(
                args.firecracker_image_manifest_directory,
                "RUNTRUE_RUNNER_FIRECRACKER_IMAGE_MANIFEST_DIRECTORY",
            ),
            configured_path(
                args.firecracker_image_keyring,
                "RUNTRUE_RUNNER_FIRECRACKER_IMAGE_KEYRING",
            ),
            configured_path(
                args.firecracker_runtime_profile,
                "RUNTRUE_RUNNER_FIRECRACKER_RUNTIME_PROFILE",
            ),
        ])?;
        let region = args
            .region
            .or_else(|| env::var("RUNTRUE_RUNNER_REGION").ok());
        let ephemeral =
            args.ephemeral || environment_flag("RUNTRUE_RUNNER_EPHEMERAL")?.unwrap_or(false);
        let command = args.command.unwrap_or(Command::Daemon);
        if ephemeral && !matches!(command, Command::Enroll | Command::EnrollIfNeeded) {
            return Err(StartupError::EphemeralRequiresEnrollment);
        }
        Ok(Self {
            endpoint,
            enrollment_endpoint,
            runner_id,
            credential_directory,
            enrollment_token_file,
            launch_claim_file,
            update_claim_file,
            ca_certificate,
            client_certificate,
            client_private_key,
            protocol_version,
            insecure_loopback,
            state_directory,
            admission_lock,
            workspace_directory,
            capsule_keyring,
            trusted_native,
            allow_credential_tainted_logs,
            oci,
            wasm,
            wasm_max_concurrent_jobs,
            firecracker,
            region,
            ephemeral,
            command,
        })
    }
}

fn configured_path(value: Option<PathBuf>, environment: &'static str) -> Option<PathBuf> {
    value.or_else(|| env::var_os(environment).map(PathBuf::from))
}

fn configured_u32(
    value: Option<u32>,
    environment: &'static str,
) -> Result<Option<u32>, StartupError> {
    match value {
        Some(value) => Ok(Some(value)),
        None => match env::var(environment) {
            Ok(value) => value
                .parse()
                .map(Some)
                .map_err(|_| StartupError::InvalidUnsignedInteger { name: environment }),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => {
                Err(StartupError::InvalidUnsignedInteger { name: environment })
            }
        },
    }
}

fn environment_flag(name: &'static str) -> Result<Option<bool>, StartupError> {
    let Ok(value) = env::var(name) else {
        return Ok(None);
    };
    match value.as_str() {
        "true" | "1" => Ok(Some(true)),
        "false" | "0" => Ok(Some(false)),
        _ => Err(StartupError::InvalidEnvironmentFlag { name }),
    }
}
