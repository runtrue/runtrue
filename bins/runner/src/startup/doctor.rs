use runtrue_runner::{
    FirecrackerJobExecutor, OciJobExecutor, TrustedCapsuleKeys, VerifiedInventory, WasmJobExecutor,
};
use serde::Serialize;

#[derive(Serialize)]
struct Doctor<'a> {
    status: &'static str,
    runner_id: &'a str,
    endpoint: &'a str,
    protocol_version: u32,
    operating_system: &'a str,
    architecture: &'a str,
    logical_cpus: u32,
    memory_bytes: u64,
    storage_bytes: u64,
    posture_digest: String,
    binary_digest: String,
    trusted_capsule_key_ids: Vec<String>,
    trusted_native_enabled: bool,
    oci_enabled: bool,
    verified_oci_manifests: usize,
    oci_state_root: Option<String>,
    wasm_enabled: bool,
    verified_wasm_components: usize,
    wasm_target_triple: Option<String>,
    wasm_aot_cache: Option<String>,
    firecracker_enabled: bool,
    firecracker_version: Option<String>,
    firecracker_image_set_digest: Option<String>,
    firecracker_guest_image_digest: Option<String>,
    firecracker_snapshot_enabled: bool,
    firecracker_state_root: Option<String>,
    firecracker_vm_vcpus: Option<u16>,
    firecracker_vm_memory_bytes: Option<u64>,
    firecracker_guest_cid: Option<u32>,
}

pub(super) struct DoctorContext<'a> {
    pub(super) runner_id: &'a str,
    pub(super) endpoint: &'a str,
    pub(super) inventory: &'a VerifiedInventory,
    pub(super) trusted_keys: &'a TrustedCapsuleKeys,
    pub(super) trusted_native: bool,
}

pub(super) struct DoctorBackends<'a> {
    pub(super) oci: Option<&'a OciJobExecutor>,
    pub(super) wasm: Option<&'a WasmJobExecutor>,
    pub(super) firecracker: Option<&'a FirecrackerJobExecutor>,
}

pub(super) fn report(
    context: DoctorContext<'_>,
    backends: DoctorBackends<'_>,
) -> Result<String, serde_json::Error> {
    let DoctorContext {
        runner_id,
        endpoint,
        inventory,
        trusted_keys,
        trusted_native,
    } = context;
    let DoctorBackends {
        oci,
        wasm,
        firecracker,
    } = backends;
    serde_json::to_string_pretty(&Doctor {
        status: "ok",
        runner_id,
        endpoint,
        protocol_version: inventory.wire.protocol_version,
        operating_system: &inventory.wire.os,
        architecture: &inventory.wire.architecture,
        logical_cpus: inventory.profile.logical_cpus,
        memory_bytes: inventory.profile.memory_bytes,
        storage_bytes: inventory.profile.storage_bytes,
        posture_digest: inventory.profile.posture_digest.to_string(),
        binary_digest: inventory.binary_digest.to_string(),
        trusted_capsule_key_ids: trusted_keys
            .key_ids
            .iter()
            .map(ToString::to_string)
            .collect(),
        trusted_native_enabled: trusted_native,
        oci_enabled: oci.is_some(),
        verified_oci_manifests: oci.map_or(0, OciJobExecutor::manifest_count),
        oci_state_root: oci.map(|executor| executor.state_root().display().to_string()),
        wasm_enabled: wasm.is_some(),
        verified_wasm_components: wasm.map_or(0, WasmJobExecutor::component_count),
        wasm_target_triple: wasm.map(|executor| executor.target_triple().to_owned()),
        wasm_aot_cache: wasm.map(|executor| executor.aot_cache().display().to_string()),
        firecracker_enabled: firecracker.is_some(),
        firecracker_version: firecracker.map(|executor| executor.firecracker_version().to_owned()),
        firecracker_image_set_digest: firecracker
            .map(|executor| executor.image_set_digest().to_string()),
        firecracker_guest_image_digest: firecracker
            .map(|executor| executor.guest_image_digest().to_string()),
        firecracker_snapshot_enabled: firecracker
            .is_some_and(FirecrackerJobExecutor::snapshot_enabled),
        firecracker_state_root: firecracker
            .map(|executor| executor.state_root().display().to_string()),
        firecracker_vm_vcpus: firecracker.map(FirecrackerJobExecutor::vm_vcpu_count),
        firecracker_vm_memory_bytes: firecracker.map(FirecrackerJobExecutor::vm_memory_bytes),
        firecracker_guest_cid: firecracker.map(FirecrackerJobExecutor::guest_cid),
    })
}
