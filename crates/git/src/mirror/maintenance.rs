impl MirrorManager {
    /// Run a full integrity pass outside the checkout critical path.
    pub fn maintenance_fsck(
        &self,
        identity: &RepositoryIdentity,
        origin: &str,
    ) -> Result<MaintenanceOutcome, GitError> {
        self.maintain(identity, origin, MaintenanceKind::Fsck)
    }

    /// Repack without pruning and then perform a full integrity pass.
    pub fn maintenance_gc(
        &self,
        identity: &RepositoryIdentity,
        origin: &str,
    ) -> Result<MaintenanceOutcome, GitError> {
        self.maintain(identity, origin, MaintenanceKind::Gc)
    }

    fn maintain(
        &self,
        identity: &RepositoryIdentity,
        origin: &str,
        kind: MaintenanceKind,
    ) -> Result<MaintenanceOutcome, GitError> {
        let origin = self.origin_policy.normalize(origin)?;
        let digest = identity.digest();
        let name = digest_name(&digest)?;
        let _writer = match self.acquire_writer(&name)? {
            Some(writer) => writer,
            None => return Ok(MaintenanceOutcome::SkippedBusy),
        };
        let directory = self.root.join("mirrors").join(&name);
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(MaintenanceOutcome::Missing)
            }
            Err(source) => return Err(GitError::Filesystem(directory, source)),
            Ok(_) => {}
        }
        let metadata = IdentityMetadata {
            metadata_version: 1,
            identity: identity.clone(),
            origin,
        };
        if let Err(error) = self.verify_mirror(&directory, &metadata, true) {
            if matches!(
                error,
                GitError::MirrorIdentityChanged | GitError::MirrorOriginChanged
            ) {
                return Err(error);
            }
            self.quarantine_path(&directory, &name, "fsck")?;
            return Ok(MaintenanceOutcome::Quarantined);
        }
        if kind == MaintenanceKind::Gc {
            let repository = directory.join(MIRROR_DIRECTORY);
            let arguments = vec![
                "--git-dir".to_owned(),
                repository.display().to_string(),
                "gc".to_owned(),
                "--quiet".to_owned(),
                "--prune=never".to_owned(),
            ];
            if self
                .run_git_process(
                    &repository,
                    &arguments,
                    self.limits.max_command_output_bytes,
                    None,
                    None,
                    false,
                )
                .is_err()
                || self.verify_mirror(&directory, &metadata, true).is_err()
            {
                self.quarantine_path(&directory, &name, "gc")?;
                return Ok(MaintenanceOutcome::Quarantined);
            }
            sync_tree(&directory)?;
        }
        Ok(MaintenanceOutcome::Completed)
    }
}
use super::{
    digest_name, fs, io, sync_tree, GitError, IdentityMetadata, MaintenanceKind,
    MaintenanceOutcome, MirrorManager, RepositoryIdentity, MIRROR_DIRECTORY,
};
