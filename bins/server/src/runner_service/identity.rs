use super::{
    optional_string, parse_isolation, validate_inventory, wasm_concurrency, RunnerSession,
};
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_scheduler::{Lease, RunnerRecord, RunnerStatus};
use runtrue_workflow_ir::{Architecture, ExecutionCapsule, OperatingSystem};
use std::{collections::BTreeSet, sync::Arc};
use tonic::Status;
#[derive(Debug, Clone)]
pub(super) struct AuthenticatedIdentity {
    pub(super) runner_id: String,
    pub(super) certificate_fingerprint: Option<ContentDigest>,
    pub(super) certificate_expires_unix_ms: Option<u64>,
}

pub(super) struct RunnerDataSubject {
    pub(super) session: Arc<RunnerSession>,
    pub(super) lease: Lease,
    pub(super) capsule: ExecutionCapsule,
    pub(super) job_key: String,
    pub(super) run_id: String,
    pub(super) repository: runtrue_control_plane::RepositoryRecord,
}

pub(super) fn enrolled_runner_record(
    runner_id: &str,
    tenant_id: &str,
    pool_id: &str,
    inventory: &v1::RunnerInventory,
    ephemeral: bool,
    now_unix_ms: u64,
) -> Result<RunnerRecord, Status> {
    let os = match inventory.os.as_str() {
        "linux" => OperatingSystem::Linux,
        "windows" => OperatingSystem::Windows,
        "macos" => OperatingSystem::Macos,
        _ => {
            return Err(Status::invalid_argument(
                "runner inventory contains an unknown operating system",
            ));
        }
    };
    let arch = match inventory.architecture.as_str() {
        "amd64" => Architecture::Amd64,
        "arm64" => Architecture::Arm64,
        _ => {
            return Err(Status::invalid_argument(
                "runner inventory contains an unknown architecture",
            ));
        }
    };
    let mut isolation_backends = BTreeSet::new();
    for backend in &inventory.isolation_backends {
        if !isolation_backends.insert(parse_isolation(backend)?) {
            return Err(Status::invalid_argument(
                "runner inventory repeats an isolation backend",
            ));
        }
    }
    let self_reported_capabilities = inventory
        .capabilities
        .iter()
        .filter(|capability| capability.key != "runtrue.posture.digest")
        .map(|capability| capability.key.clone())
        .collect();
    let runner = RunnerRecord {
        id: runner_id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        pool_id: pool_id.to_owned(),
        ephemeral,
        retired: false,
        os,
        arch,
        isolation_backends,
        logical_cpus: inventory.logical_cpus,
        memory_bytes: inventory.memory_bytes,
        storage_bytes: inventory.local_storage_bytes,
        max_concurrent_wasm_jobs: wasm_concurrency(inventory)?,
        region: optional_string(&inventory.region).map(str::to_owned),
        verified_capabilities: BTreeSet::new(),
        self_reported_capabilities,
        status: RunnerStatus::Offline,
        active_jobs: 0,
        active_wasm_jobs: 0,
        used_cpus: 0,
        used_memory_bytes: 0,
        used_storage_bytes: 0,
        locality: BTreeSet::new(),
        package_tiers: std::collections::BTreeMap::new(),
        last_heartbeat_unix_ms: now_unix_ms,
    };
    validate_inventory(&runner, inventory, inventory.protocol_version)?;
    Ok(runner)
}
