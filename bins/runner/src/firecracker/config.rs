/// All filesystem authority for the backend is explicit. Supplying any one of
/// these paths through the CLI requires supplying the complete set.
#[derive(Debug, Clone)]
pub struct FirecrackerRuntimePaths {
    pub state_root: PathBuf,
    pub jailer: PathBuf,
    pub firecracker: PathBuf,
    pub reflink_copy: PathBuf,
    pub jail_root: PathBuf,
    pub cgroup_parent: PathBuf,
    pub cid_lock_directory: PathBuf,
    pub image_payload_directory: PathBuf,
    pub image_manifest_directory: PathBuf,
    pub image_keyring_directory: PathBuf,
    pub runtime_profile: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeProfile {
    pub(super) profile_version: u32,
    pub(super) architecture: Architecture,
    pub(super) firecracker_version: String,
    pub(super) firecracker_binary_digest: ContentDigest,
    pub(super) firecracker_binary_size_bytes: u64,
    pub(super) jailer_version: String,
    pub(super) jailer_binary_digest: ContentDigest,
    pub(super) jailer_binary_size_bytes: u64,
    pub(super) snapshot_format_version: String,
    pub(super) cpu_template: String,
    pub(super) cpu_feature_digest: ContentDigest,
    pub(super) mitigation_profile_digest: ContentDigest,
    pub(super) vcpu_count: u16,
    pub(super) memory_bytes: u64,
    pub(super) guest_cid: u32,
    pub(super) jailed_uid: u32,
    pub(super) jailed_gid: u32,
    pub(super) guest_vsock_port: u32,
    pub(super) guest_capsule_trust_directory: PathBuf,
}

impl RuntimeProfile {
    pub(super) fn validate(&self) -> Result<(), RunnerError> {
        const MIB: u64 = 1024 * 1024;
        if self.profile_version != 1
            || self.firecracker_version.is_empty()
            || self.firecracker_version.len() > 256
            || self.jailer_version.is_empty()
            || self.jailer_version.len() > 256
            || self.jailer_version != self.firecracker_version
            || self.snapshot_format_version.is_empty()
            || self.snapshot_format_version.len() > 256
            || self.cpu_template.is_empty()
            || self.cpu_template.len() > 256
            || self.vcpu_count == 0
            || self.vcpu_count > 64
            || self.memory_bytes < 128 * MIB
            || self.memory_bytes % MIB != 0
            || self.guest_cid < 3
            || self.jailed_uid == 0
            || self.jailed_gid == 0
            || self.guest_vsock_port < 1024
            || !self.guest_capsule_trust_directory.is_absolute()
            || [
                self.firecracker_version.as_str(),
                self.jailer_version.as_str(),
                self.snapshot_format_version.as_str(),
                self.cpu_template.as_str(),
            ]
            .iter()
            .any(|value| value.bytes().any(|byte| byte.is_ascii_control()))
        {
            return Err(RunnerError::FirecrackerConfiguration(
                "invalid Firecracker runtime profile".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn snapshot_runtime(&self) -> Result<SnapshotRuntimeCompatibility, RunnerError> {
        SnapshotRuntimeCompatibility::new(SnapshotRuntimeRequirements {
            firecracker_version: self.firecracker_version.clone(),
            firecracker_binary_digest: self.firecracker_binary_digest.clone(),
            firecracker_binary_size_bytes: self.firecracker_binary_size_bytes,
            snapshot_format_version: self.snapshot_format_version.clone(),
            cpu_template: self.cpu_template.clone(),
            cpu_feature_digest: self.cpu_feature_digest.clone(),
            mitigation_profile_digest: self.mitigation_profile_digest.clone(),
            vcpu_count: self.vcpu_count,
            memory_bytes: self.memory_bytes,
            guest_cid: self.guest_cid,
        })
        .map_err(Into::into)
    }
}
use super::{
    Architecture, ContentDigest, Deserialize, PathBuf, RunnerError, SnapshotRuntimeCompatibility,
    SnapshotRuntimeRequirements,
};
