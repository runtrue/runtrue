use super::{SnapshotApi, SnapshotLoadRequest};
use crate::{FirecrackerError, FirecrackerVmConfig, JobStatePaths};
pub enum FirecrackerLaunchPlan {
    Cold(FirecrackerVmConfig),
    Snapshot(SnapshotLoadRequest),
}

impl FirecrackerLaunchPlan {
    pub fn build(
        paths: &JobStatePaths,
        vcpus: u16,
        memory_bytes: u64,
        guest_cid: u32,
        tap_device: Option<&str>,
    ) -> Result<Self, FirecrackerError> {
        if let Some(snapshot) = &paths.snapshot {
            if tap_device.is_some() {
                return Err(FirecrackerError::InvalidConfiguration(
                    "sterile snapshots are admitted only with a disconnected network profile"
                        .to_owned(),
                ));
            }
            // CPU and memory topology are persisted in the signed snapshot;
            // callers cannot override them at load time. Non-zero values are
            // still required so one API cannot accidentally accept empty host
            // scheduling requirements for only one boot mode.
            if vcpus != snapshot.compatibility.vcpu_count
                || memory_bytes != snapshot.compatibility.memory_bytes
                || guest_cid != snapshot.compatibility.guest_cid
            {
                return Err(FirecrackerError::InvalidConfiguration(
                    "snapshot vCPU, memory, or guest CID does not match the signed topology"
                        .to_owned(),
                ));
            }
            return Ok(Self::Snapshot(SnapshotLoadRequest::build(paths)?));
        }
        Ok(Self::Cold(FirecrackerVmConfig::build_cold(
            paths,
            vcpus,
            memory_bytes,
            guest_cid,
            tap_device,
        )?))
    }

    #[must_use]
    pub const fn snapshot_request(&self) -> Option<&SnapshotLoadRequest> {
        match self {
            Self::Snapshot(request) => Some(request),
            Self::Cold(_) => None,
        }
    }

    #[must_use]
    pub const fn cold_config(&self) -> Option<&FirecrackerVmConfig> {
        match self {
            Self::Cold(config) => Some(config),
            Self::Snapshot(_) => None,
        }
    }

    pub fn load_snapshot(&self, api: &dyn SnapshotApi) -> Result<(), FirecrackerError> {
        match self {
            Self::Snapshot(request) => {
                request.verify_staged_artifacts()?;
                api.load(request)
            }
            Self::Cold(_) => Err(FirecrackerError::InvalidConfiguration(
                "cold launch capsule cannot call the snapshot API".to_owned(),
            )),
        }
    }
}
