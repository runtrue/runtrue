use super::validation::verify_immutable_mode;
use crate::{image::verify_payload, FirecrackerError, JobStatePaths};
use runtrue_model::ContentDigest;
use serde::Serialize;
use std::path::{Path, PathBuf};
const MAX_API_REQUEST_BYTES: usize = 64 * 1024;
pub const IN_JAIL_VSOCK_SOCKET: &str = "/run/vsock.sock";
pub const IN_JAIL_SNAPSHOT_STATE: &str = "/snapshot.vmstate";
pub const IN_JAIL_SNAPSHOT_MEMORY: &str = "/snapshot.memory";
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotLoadRequest {
    snapshot_path: String,
    mem_backend: MemoryBackend,
    track_dirty_pages: bool,
    resume_vm: bool,
    vsock_override: VsockOverride,
    #[serde(skip)]
    host_state_path: PathBuf,
    #[serde(skip)]
    host_memory_path: PathBuf,
    #[serde(skip)]
    state_digest: ContentDigest,
    #[serde(skip)]
    memory_digest: ContentDigest,
    #[serde(skip)]
    state_size_bytes: u64,
    #[serde(skip)]
    memory_size_bytes: u64,
    #[serde(skip)]
    compatibility: crate::SnapshotRuntimeCompatibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct MemoryBackend {
    backend_path: String,
    backend_type: MemoryBackendType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum MemoryBackendType {
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct VsockOverride {
    uds_path: String,
}

impl SnapshotLoadRequest {
    pub(super) fn build(paths: &JobStatePaths) -> Result<Self, FirecrackerError> {
        let snapshot = paths.snapshot.as_ref().ok_or_else(|| {
            FirecrackerError::InvalidConfiguration(
                "snapshot load request requires staged state and memory".to_owned(),
            )
        })?;
        for (actual, expected) in [
            (&snapshot.state, "snapshot.vmstate"),
            (&snapshot.memory, "snapshot.memory"),
        ] {
            if actual.file_name().and_then(|name| name.to_str()) != Some(expected) {
                return Err(FirecrackerError::InvalidConfiguration(
                    "staged snapshot path does not match the signed jail layout".to_owned(),
                ));
            }
        }
        Ok(Self {
            snapshot_path: IN_JAIL_SNAPSHOT_STATE.to_owned(),
            mem_backend: MemoryBackend {
                backend_path: IN_JAIL_SNAPSHOT_MEMORY.to_owned(),
                backend_type: MemoryBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: true,
            vsock_override: VsockOverride {
                uds_path: IN_JAIL_VSOCK_SOCKET.to_owned(),
            },
            host_state_path: snapshot.state.clone(),
            host_memory_path: snapshot.memory.clone(),
            state_digest: snapshot.state_digest.clone(),
            memory_digest: snapshot.memory_digest.clone(),
            state_size_bytes: snapshot.state_size_bytes,
            memory_size_bytes: snapshot.memory_size_bytes,
            compatibility: snapshot.compatibility.clone(),
        })
    }

    pub(crate) fn verify_firecracker_binary(&self, path: &Path) -> Result<(), FirecrackerError> {
        verify_payload(
            path,
            self.compatibility.firecracker_binary_size_bytes,
            &self.compatibility.firecracker_binary_digest,
        )
    }

    pub(super) fn verify_staged_artifacts(&self) -> Result<(), FirecrackerError> {
        verify_immutable_mode(&self.host_state_path)?;
        verify_immutable_mode(&self.host_memory_path)?;
        verify_payload(
            &self.host_state_path,
            self.state_size_bytes,
            &self.state_digest,
        )?;
        verify_payload(
            &self.host_memory_path,
            self.memory_size_bytes,
            &self.memory_digest,
        )
    }

    pub fn json_bytes(&self) -> Result<Vec<u8>, FirecrackerError> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_API_REQUEST_BYTES {
            return Err(FirecrackerError::InvalidConfiguration(
                "snapshot API request exceeds its bound".to_owned(),
            ));
        }
        Ok(bytes)
    }
}
