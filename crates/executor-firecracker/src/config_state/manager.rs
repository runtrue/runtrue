use super::{
    copy_and_verify, copy_and_verify_mode, create_private_fifo_placeholder,
    prepare_private_directory, remove_boot_secret, set_mode, state_id, write_boot_drive, JobState,
    JobStatePaths, ReflinkProvisioner, SnapshotStatePaths,
};
use crate::{
    image::verify_payload, state_io, FirecrackerError, FirecrackerPaths, VerifiedImageSet,
};
use runtrue_guest_core::GuestBootConfig;
use std::{fs, path::PathBuf};
#[derive(Debug, Clone)]
pub struct JobStateManager {
    active_root: PathBuf,
    quarantine_root: PathBuf,
}

impl JobStateManager {
    /// Build the exact `<chroot-base>/<exec-file-name>/<vm-id>/root` layout
    /// expected by the upstream jailer.
    pub fn for_jailer(
        paths: &FirecrackerPaths,
        quarantine_root: impl Into<PathBuf>,
    ) -> Result<Self, FirecrackerError> {
        let executable_name = paths.firecracker.file_name().ok_or_else(|| {
            FirecrackerError::InvalidConfiguration(
                "Firecracker executable has no file name".to_owned(),
            )
        })?;
        Self::new(paths.jail_root.join(executable_name), quarantine_root)
    }

    pub fn new(
        active_root: impl Into<PathBuf>,
        quarantine_root: impl Into<PathBuf>,
    ) -> Result<Self, FirecrackerError> {
        let manager = Self {
            active_root: active_root.into(),
            quarantine_root: quarantine_root.into(),
        };
        prepare_private_directory(&manager.active_root)?;
        prepare_private_directory(&manager.quarantine_root)?;
        Ok(manager)
    }

    pub fn stage<P: ReflinkProvisioner>(
        &self,
        job_id: &str,
        session_id: &str,
        images: &VerifiedImageSet,
        boot: &GuestBootConfig,
        provisioner: &P,
    ) -> Result<JobState, FirecrackerError> {
        let state_id = state_id(job_id, session_id)?;
        let state_directory = self.active_root.join(&state_id);
        fs::create_dir(&state_directory).map_err(|source| state_io(&state_directory, source))?;
        set_mode(&state_directory, 0o700)?;
        let directory = state_directory.join("root");
        fs::create_dir(&directory).map_err(|source| state_io(&directory, source))?;
        set_mode(&directory, 0o700)?;
        let run_directory = directory.join("run");
        fs::create_dir(&run_directory).map_err(|source| state_io(&run_directory, source))?;
        set_mode(&run_directory, 0o700)?;
        let paths = JobStatePaths {
            kernel: directory.join("kernel"),
            rootfs: directory.join("rootfs.ext4"),
            guest: directory.join("runtrue-guest"),
            snapshot: images.snapshot.as_ref().map(|snapshot| SnapshotStatePaths {
                state: directory.join("snapshot.vmstate"),
                memory: directory.join("snapshot.memory"),
                state_digest: snapshot.state.digest().clone(),
                state_size_bytes: snapshot.state.signed.manifest.payload_size_bytes,
                memory_digest: snapshot.memory.digest().clone(),
                memory_size_bytes: snapshot.memory.signed.manifest.payload_size_bytes,
                compatibility: snapshot.compatibility.clone(),
            }),
            boot_config: directory.join("boot-config.img"),
            firecracker_config: directory.join("firecracker.json"),
            api_socket: run_directory.join("firecracker-api.sock"),
            vsock_socket: run_directory.join("vsock.sock"),
            log_fifo: run_directory.join("firecracker.log"),
            metrics_fifo: run_directory.join("firecracker.metrics"),
            directory,
        };
        let staged = (|| {
            copy_and_verify(
                &images.kernel.payload_path,
                &paths.kernel,
                images.kernel.signed.manifest.payload_size_bytes,
                images.kernel.digest(),
            )?;
            verify_payload(
                &images.rootfs.payload_path,
                images.rootfs.signed.manifest.payload_size_bytes,
                images.rootfs.digest(),
            )?;
            provisioner.reflink(&images.rootfs.payload_path, &paths.rootfs)?;
            set_mode(&paths.rootfs, 0o600)?;
            verify_payload(
                &paths.rootfs,
                images.rootfs.signed.manifest.payload_size_bytes,
                images.rootfs.digest(),
            )?;
            copy_and_verify(
                &images.guest.payload_path,
                &paths.guest,
                images.guest.signed.manifest.payload_size_bytes,
                images.guest.digest(),
            )?;
            if let (Some(snapshot), Some(destinations)) = (&images.snapshot, &paths.snapshot) {
                copy_and_verify_mode(
                    &snapshot.state.payload_path,
                    &destinations.state,
                    snapshot.state.signed.manifest.payload_size_bytes,
                    snapshot.state.digest(),
                    0o400,
                )?;
                verify_payload(
                    &snapshot.memory.payload_path,
                    snapshot.memory.signed.manifest.payload_size_bytes,
                    snapshot.memory.digest(),
                )?;
                provisioner.reflink(&snapshot.memory.payload_path, &destinations.memory)?;
                set_mode(&destinations.memory, 0o400)?;
                verify_payload(
                    &destinations.memory,
                    snapshot.memory.signed.manifest.payload_size_bytes,
                    snapshot.memory.digest(),
                )?;
            }
            write_boot_drive(&paths.boot_config, boot)?;
            create_private_fifo_placeholder(&paths.log_fifo)?;
            create_private_fifo_placeholder(&paths.metrics_fifo)?;
            Ok(())
        })();
        if let Err(error) = staged {
            if remove_boot_secret(&paths.boot_config).is_ok() {
                let quarantine = self
                    .quarantine_root
                    .join(format!("{state_id}-stage-failed"));
                let _ = fs::rename(&state_directory, quarantine);
            }
            return Err(error);
        }
        Ok(JobState {
            paths,
            state_directory,
            state_id,
            quarantine_root: self.quarantine_root.clone(),
            finalized: false,
        })
    }
}
