use super::{remove_boot_secret, write_new_private, JobStatePaths};
use crate::{state_io, FirecrackerError};
use std::{fs, path::PathBuf};
pub struct JobState {
    pub(super) paths: JobStatePaths,
    pub(super) state_directory: PathBuf,
    pub(super) state_id: String,
    pub(super) quarantine_root: PathBuf,
    pub(super) finalized: bool,
}

impl JobState {
    #[must_use]
    pub const fn paths(&self) -> &JobStatePaths {
        &self.paths
    }

    #[must_use]
    pub fn vm_id(&self) -> &str {
        &self.state_id
    }

    pub fn cleanup_success(mut self) -> Result<(), FirecrackerError> {
        remove_boot_secret(&self.paths.boot_config)?;
        fs::remove_dir_all(&self.state_directory)
            .map_err(|source| state_io(&self.state_directory, source))?;
        self.finalized = true;
        Ok(())
    }

    pub fn quarantine(mut self, reason: &str) -> Result<PathBuf, FirecrackerError> {
        remove_boot_secret(&self.paths.boot_config)?;
        let reason_path = self.paths.directory.join("QUARANTINE_REASON");
        write_new_private(&reason_path, reason.as_bytes())?;
        let destination = self
            .quarantine_root
            .join(format!("{}-quarantined", self.state_id));
        fs::rename(&self.state_directory, &destination)
            .map_err(|source| state_io(&destination, source))?;
        self.finalized = true;
        Ok(destination)
    }
}

impl Drop for JobState {
    fn drop(&mut self) {
        if self.finalized {
            return;
        }
        if remove_boot_secret(&self.paths.boot_config).is_ok() {
            let destination = self
                .quarantine_root
                .join(format!("{}-abandoned", self.state_id));
            let _ = fs::rename(&self.state_directory, destination);
        }
    }
}
