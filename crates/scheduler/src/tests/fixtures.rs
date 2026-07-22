use crate::{QueuedJob, RunnerRecord, RunnerStatus, SchedulingRequirements};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{Architecture, Isolation, OperatingSystem};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn runner(id: &str) -> RunnerRecord {
    RunnerRecord {
        id: id.to_owned(),
        tenant_id: "tenant".to_owned(),
        pool_id: "trusted".to_owned(),
        ephemeral: false,
        retired: false,
        os: OperatingSystem::Linux,
        arch: Architecture::Amd64,
        isolation_backends: [Isolation::Microvm].into_iter().collect(),
        logical_cpus: 8,
        memory_bytes: 16 * 1024 * 1024,
        storage_bytes: 100 * 1024 * 1024,
        max_concurrent_wasm_jobs: 1,
        region: Some("us-east".to_owned()),
        verified_capabilities: ["kvm".to_owned()].into_iter().collect(),
        self_reported_capabilities: ["gpu".to_owned()].into_iter().collect(),
        status: RunnerStatus::Online,
        active_jobs: 0,
        active_wasm_jobs: 0,
        used_cpus: 0,
        used_memory_bytes: 0,
        used_storage_bytes: 0,
        locality: BTreeSet::new(),
        package_tiers: BTreeMap::new(),
        last_heartbeat_unix_ms: 0,
    }
}

pub(super) fn job(id: &str, tenant: &str) -> QueuedJob {
    QueuedJob {
        id: id.to_owned(),
        tenant_id: tenant.to_owned(),
        repository_id: "repo".to_owned(),
        capsule_digest: ContentDigest::sha256(id),
        requirements: SchedulingRequirements {
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation: Isolation::Microvm,
            cpu: 1,
            memory_bytes: 1024,
            storage_bytes: 1024,
            region: Some("us-east".to_owned()),
            required_capabilities: ["kvm".to_owned()].into_iter().collect(),
            allowed_pools: ["trusted".to_owned()].into_iter().collect(),
        },
        priority: 0,
        queued_unix_ms: 1,
        preferred_content: BTreeSet::new(),
        retryable_after_runner_loss: true,
    }
}
