use super::{
    COMPAT_BOOT_CONFIG_PATH, COMPAT_CPU_FEATURES, COMPAT_CPU_TEMPLATE, COMPAT_FIRECRACKER_BINARY,
    COMPAT_FIRECRACKER_BINARY_SIZE, COMPAT_FIRECRACKER_VERSION, COMPAT_GUEST_CID,
    COMPAT_MEMORY_BYTES, COMPAT_MITIGATIONS, COMPAT_NETWORK_PROFILE, COMPAT_ROOTFS_PATH,
    COMPAT_SNAPSHOT_FORMAT, COMPAT_SNAPSHOT_ROLE, COMPAT_VCPU_COUNT, COMPAT_VSOCK_PATH,
    SNAPSHOT_NETWORK_PROFILE,
};
use crate::FirecrackerError;
use runtrue_model::ContentDigest;
use std::collections::BTreeMap;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRuntimeCompatibility {
    pub(crate) firecracker_version: String,
    pub(crate) firecracker_binary_digest: ContentDigest,
    pub(crate) firecracker_binary_size_bytes: u64,
    pub(crate) snapshot_format_version: String,
    pub(crate) cpu_template: String,
    pub(crate) cpu_feature_digest: ContentDigest,
    pub(crate) mitigation_profile_digest: ContentDigest,
    pub(crate) vcpu_count: u16,
    pub(crate) memory_bytes: u64,
    pub(crate) guest_cid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRuntimeRequirements {
    pub firecracker_version: String,
    pub firecracker_binary_digest: ContentDigest,
    pub firecracker_binary_size_bytes: u64,
    pub snapshot_format_version: String,
    pub cpu_template: String,
    pub cpu_feature_digest: ContentDigest,
    pub mitigation_profile_digest: ContentDigest,
    pub vcpu_count: u16,
    pub memory_bytes: u64,
    pub guest_cid: u32,
}

impl SnapshotRuntimeCompatibility {
    pub fn new(requirements: SnapshotRuntimeRequirements) -> Result<Self, FirecrackerError> {
        let compatibility = Self {
            firecracker_version: requirements.firecracker_version,
            firecracker_binary_digest: requirements.firecracker_binary_digest,
            firecracker_binary_size_bytes: requirements.firecracker_binary_size_bytes,
            snapshot_format_version: requirements.snapshot_format_version,
            cpu_template: requirements.cpu_template,
            cpu_feature_digest: requirements.cpu_feature_digest,
            mitigation_profile_digest: requirements.mitigation_profile_digest,
            vcpu_count: requirements.vcpu_count,
            memory_bytes: requirements.memory_bytes,
            guest_cid: requirements.guest_cid,
        };
        if compatibility.firecracker_binary_size_bytes == 0
            || compatibility.vcpu_count == 0
            || compatibility.vcpu_count > 64
            || compatibility.memory_bytes < 128 * 1024 * 1024
            || !compatibility.memory_bytes.is_multiple_of(1024 * 1024)
            || compatibility.guest_cid < 3
        {
            return Err(FirecrackerError::InvalidConfiguration(
                "snapshot VM topology is invalid".to_owned(),
            ));
        }
        for (name, value) in [
            (
                "Firecracker version",
                compatibility.firecracker_version.as_str(),
            ),
            (
                "snapshot format version",
                compatibility.snapshot_format_version.as_str(),
            ),
            ("CPU template", compatibility.cpu_template.as_str()),
        ] {
            if value.is_empty()
                || value.len() > 256
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(FirecrackerError::InvalidConfiguration(format!(
                    "snapshot {name} is invalid"
                )));
            }
        }
        Ok(compatibility)
    }

    pub(super) fn signed_map(&self, role: &'static str) -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                COMPAT_FIRECRACKER_VERSION.to_owned(),
                self.firecracker_version.clone(),
            ),
            (
                COMPAT_FIRECRACKER_BINARY.to_owned(),
                self.firecracker_binary_digest.to_string(),
            ),
            (
                COMPAT_FIRECRACKER_BINARY_SIZE.to_owned(),
                self.firecracker_binary_size_bytes.to_string(),
            ),
            (
                COMPAT_SNAPSHOT_FORMAT.to_owned(),
                self.snapshot_format_version.clone(),
            ),
            (COMPAT_CPU_TEMPLATE.to_owned(), self.cpu_template.clone()),
            (
                COMPAT_CPU_FEATURES.to_owned(),
                self.cpu_feature_digest.to_string(),
            ),
            (
                COMPAT_MITIGATIONS.to_owned(),
                self.mitigation_profile_digest.to_string(),
            ),
            (COMPAT_VCPU_COUNT.to_owned(), self.vcpu_count.to_string()),
            (
                COMPAT_MEMORY_BYTES.to_owned(),
                self.memory_bytes.to_string(),
            ),
            (COMPAT_GUEST_CID.to_owned(), self.guest_cid.to_string()),
            (
                COMPAT_NETWORK_PROFILE.to_owned(),
                SNAPSHOT_NETWORK_PROFILE.to_owned(),
            ),
            (COMPAT_ROOTFS_PATH.to_owned(), "/rootfs.ext4".to_owned()),
            (
                COMPAT_BOOT_CONFIG_PATH.to_owned(),
                "/boot-config.img".to_owned(),
            ),
            (COMPAT_VSOCK_PATH.to_owned(), "/run/vsock.sock".to_owned()),
            (COMPAT_SNAPSHOT_ROLE.to_owned(), role.to_owned()),
        ])
    }

    #[must_use]
    pub fn firecracker_version(&self) -> &str {
        &self.firecracker_version
    }

    #[must_use]
    pub const fn firecracker_binary_digest(&self) -> &ContentDigest {
        &self.firecracker_binary_digest
    }

    #[must_use]
    pub const fn firecracker_binary_size_bytes(&self) -> u64 {
        self.firecracker_binary_size_bytes
    }

    #[must_use]
    pub fn snapshot_format_version(&self) -> &str {
        &self.snapshot_format_version
    }

    #[must_use]
    pub fn cpu_template(&self) -> &str {
        &self.cpu_template
    }

    #[must_use]
    pub const fn cpu_feature_digest(&self) -> &ContentDigest {
        &self.cpu_feature_digest
    }

    #[must_use]
    pub const fn mitigation_profile_digest(&self) -> &ContentDigest {
        &self.mitigation_profile_digest
    }

    #[must_use]
    pub const fn vcpu_count(&self) -> u16 {
        self.vcpu_count
    }

    #[must_use]
    pub const fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    #[must_use]
    pub const fn guest_cid(&self) -> u32 {
        self.guest_cid
    }
}
