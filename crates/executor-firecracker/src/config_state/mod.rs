mod manager;
mod reflink;
mod secure_fs;
pub use manager::JobStateManager;
use secure_fs::{
    create_private_fifo_placeholder, prepare_private_directory, remove_boot_secret, set_mode,
    write_new_private,
};
mod state;
pub use reflink::{ProcessReflinkProvisioner, ReflinkProvisioner};
pub use state::JobState;
mod config;
mod paths;
use crate::{
    image::{copy_verified_payload, verify_payload},
    FirecrackerError,
};
pub use config::FirecrackerVmConfig;
pub use paths::{JobStatePaths, SnapshotStatePaths};
use runtrue_guest_core::{GuestBootConfig, MAX_GUEST_BOOT_CONFIG_BYTES};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

const BOOT_CONFIG_DRIVE_BYTES: usize = MAX_GUEST_BOOT_CONFIG_BYTES;

fn state_id(job_id: &str, session_id: &str) -> Result<String, FirecrackerError> {
    if job_id.is_empty() || session_id.is_empty() || job_id.len() > 1024 || session_id.len() > 1024
    {
        return Err(FirecrackerError::InvalidConfiguration(
            "job and session ids must be bounded and non-empty".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"runtrue.firecracker.job-state.v1\0");
    hasher.update(job_id.as_bytes());
    hasher.update([0]);
    hasher.update(session_id.as_bytes());
    Ok(format!("job-{}", &hex::encode(hasher.finalize())[..32]))
}

fn write_boot_drive(path: &Path, boot: &GuestBootConfig) -> Result<(), FirecrackerError> {
    boot.validate().map_err(|error| {
        FirecrackerError::InvalidConfiguration(format!("invalid guest boot config: {error}"))
    })?;
    let encoded = Zeroizing::new(serde_json::to_vec(boot)?);
    if encoded.len() >= BOOT_CONFIG_DRIVE_BYTES {
        return Err(FirecrackerError::InvalidConfiguration(
            "guest boot config exceeds its drive bound".to_owned(),
        ));
    }
    let mut drive = Zeroizing::new(vec![0_u8; BOOT_CONFIG_DRIVE_BYTES]);
    drive[..encoded.len()].copy_from_slice(&encoded);
    write_new_private(path, &drive)
}

fn copy_and_verify(
    source: &Path,
    destination: &Path,
    size: u64,
    digest: &runtrue_model::ContentDigest,
) -> Result<(), FirecrackerError> {
    copy_and_verify_mode(source, destination, size, digest, 0o600)
}

fn copy_and_verify_mode(
    source: &Path,
    destination: &Path,
    size: u64,
    digest: &runtrue_model::ContentDigest,
    mode: u32,
) -> Result<(), FirecrackerError> {
    copy_verified_payload(source, destination, size, digest, mode)?;
    set_mode(destination, mode)?;
    verify_payload(destination, size, digest)
}

#[cfg(test)]
mod tests;
