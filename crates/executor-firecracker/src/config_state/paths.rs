use std::path::PathBuf;
pub struct JobStatePaths {
    pub directory: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub guest: PathBuf,
    pub snapshot: Option<SnapshotStatePaths>,
    pub boot_config: PathBuf,
    pub firecracker_config: PathBuf,
    pub api_socket: PathBuf,
    pub vsock_socket: PathBuf,
    pub log_fifo: PathBuf,
    pub metrics_fifo: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotStatePaths {
    pub state: PathBuf,
    pub memory: PathBuf,
    pub(crate) state_digest: runtrue_model::ContentDigest,
    pub(crate) state_size_bytes: u64,
    pub(crate) memory_digest: runtrue_model::ContentDigest,
    pub(crate) memory_size_bytes: u64,
    pub(crate) compatibility: crate::SnapshotRuntimeCompatibility,
}

impl SnapshotStatePaths {
    #[must_use]
    pub const fn compatibility(&self) -> &crate::SnapshotRuntimeCompatibility {
        &self.compatibility
    }
}
