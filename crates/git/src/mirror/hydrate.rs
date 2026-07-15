impl MirrorManager {
    /// Materialize one exact commit from a verified mirror. The published
    /// workspace contains no alternates or hard-linked objects and every
    /// regular file and directory is non-writable.
    pub fn hydrate(
        &self,
        mirror: &MirrorHandle,
        commit: &str,
        destination: &Path,
    ) -> Result<HydrationOutcome, GitError> {
        validate_object_id(commit)?;
        let name = digest_name(&mirror.identity_digest)?;
        let expected_mirror = self.root.join("mirrors").join(&name).join(MIRROR_DIRECTORY);
        if mirror.repository.root() != expected_mirror
            || mirror.identity.digest() != mirror.identity_digest
        {
            return Err(GitError::HydrationMismatch);
        }
        let (parent, destination_name) = hydration_destination(destination)?;
        let (_, parent_fd) = open_real_directory(&parent)?;
        validate_hydration_parent(&parent, &parent_fd)?;
        if fs::symlink_metadata(destination).is_ok() {
            return self
                .validate_hydrated_workspace(mirror, commit, destination)
                .map(HydrationOutcome::Ready);
        }
        let _writer = match self.acquire_writer(&name)? {
            Some(writer) => writer,
            None => {
                return Ok(HydrationOutcome::DirectCloneRequired(
                    MirrorMiss::WriterTimeout,
                ))
            }
        };
        // Another process may have published while this process waited.
        if fs::symlink_metadata(destination).is_ok() {
            return self
                .validate_hydrated_workspace(mirror, commit, destination)
                .map(HydrationOutcome::Ready);
        }
        let metadata = IdentityMetadata {
            metadata_version: 1,
            identity: mirror.identity.clone(),
            origin: mirror.origin.clone(),
        };
        let mirror_directory = self.root.join("mirrors").join(&name);
        if let Err(error) = self.verify_mirror(&mirror_directory, &metadata, false) {
            if matches!(
                error,
                GitError::MirrorIdentityChanged | GitError::MirrorOriginChanged
            ) {
                return Err(error);
            }
            if fs::symlink_metadata(&mirror_directory).is_ok() {
                let _ = self.quarantine_path(&mirror_directory, &name, "hydrate");
                return Ok(HydrationOutcome::DirectCloneRequired(
                    MirrorMiss::CorruptQuarantined,
                ));
            }
            return Ok(HydrationOutcome::DirectCloneRequired(
                MirrorMiss::MirrorUnavailable,
            ));
        }
        if !mirror
            .repository
            .verify_commit(commit)
            .is_ok_and(|actual| actual == commit)
        {
            return Ok(HydrationOutcome::DirectCloneRequired(
                MirrorMiss::RequestedCommitUnavailable,
            ));
        }

        let staging_name = format!("runtrue-hydrate-{}", unique_suffix()?);
        validate_managed_name(&staging_name)?;
        mkdirat(
            parent_fd.as_raw_fd(),
            staging_name.as_str(),
            Mode::from_bits_truncate(0o700),
        )
        .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        fsync(parent_fd.as_raw_fd())
            .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        let staging = parent.join(&staging_name);
        let materialized = self.materialize_hydration(mirror, commit, &staging);
        if let Err(error) = materialized {
            let _ = make_tree_owner_writable(&staging);
            let _ = remove_tree_no_follow(&staging);
            if hydration_failure_is_miss(&error) {
                return Ok(HydrationOutcome::DirectCloneRequired(
                    MirrorMiss::MirrorUnavailable,
                ));
            }
            return Err(error);
        }
        rustix::fs::renameat_with(
            &parent_fd,
            staging_name.as_str(),
            &parent_fd,
            destination_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            let _ = make_tree_owner_writable(&staging);
            let _ = remove_tree_no_follow(&staging);
            GitError::SecureFilesystem(error.to_string())
        })?;
        fsync(parent_fd.as_raw_fd())
            .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        Ok(HydrationOutcome::Ready(HydratedWorkspace {
            path: destination.to_owned(),
            commit: commit.to_owned(),
            mirror_identity_digest: mirror.identity_digest.clone(),
        }))
    }

    fn materialize_hydration(
        &self,
        mirror: &MirrorHandle,
        commit: &str,
        staging: &Path,
    ) -> Result<(), GitError> {
        let clone = vec![
            "clone".to_owned(),
            "--quiet".to_owned(),
            "--no-local".to_owned(),
            "--no-hardlinks".to_owned(),
            "--no-checkout".to_owned(),
            "--no-tags".to_owned(),
            "--no-recurse-submodules".to_owned(),
            mirror.repository.root().display().to_string(),
            staging.display().to_string(),
        ];
        self.run_git_process(
            staging
                .parent()
                .ok_or_else(|| GitError::UnsafeHydrationDestination(staging.to_owned()))?,
            &clone,
            self.limits.max_command_output_bytes,
            None,
            None,
            true,
        )?;
        let checkout = vec![
            "-C".to_owned(),
            staging.display().to_string(),
            "checkout".to_owned(),
            "--quiet".to_owned(),
            "--detach".to_owned(),
            commit.to_owned(),
        ];
        self.run_git_process(
            staging,
            &checkout,
            self.limits.max_command_output_bytes,
            None,
            None,
            false,
        )?;
        let remove_origin = vec![
            "-C".to_owned(),
            staging.display().to_string(),
            "remote".to_owned(),
            "remove".to_owned(),
            "origin".to_owned(),
        ];
        self.run_git_process(staging, &remove_origin, 16 * 1024, None, None, false)?;
        let repository = GitRepository::open(staging, self.limits.git)?;
        let actual = repository.verify_commit(commit)?;
        if actual != commit {
            return Err(GitError::HydrationMismatch);
        }
        let head = repository.run_git(&["rev-parse", "HEAD"], 1024)?;
        if parse_one_line(&head.stdout, "hydrated HEAD")? != commit {
            return Err(GitError::HydrationMismatch);
        }
        if !repository.run_git(&["remote"], 4096)?.stdout.is_empty() {
            return Err(GitError::HydrationMismatch);
        }
        reject_alternates(repository.git_dir())?;
        verify_no_shared_objects(&repository.git_dir().join("objects"))?;
        self.run_fsck(repository.git_dir(), true)?;
        write_hydration_metadata(
            &repository.git_dir().join(HYDRATION_MARKER),
            &HydrationMetadata {
                metadata_version: 1,
                commit: commit.to_owned(),
                mirror_identity_digest: mirror.identity_digest.clone(),
            },
        )?;
        sync_tree(staging)?;
        make_tree_read_only(staging)?;
        self.validate_hydrated_workspace(mirror, commit, staging)?;
        Ok(())
    }

    pub(super) fn validate_hydrated_workspace(
        &self,
        mirror: &MirrorHandle,
        commit: &str,
        path: &Path,
    ) -> Result<HydratedWorkspace, GitError> {
        let repository = GitRepository::open(path, self.limits.git)?;
        let marker = read_hydration_metadata(&repository.git_dir().join(HYDRATION_MARKER))?;
        if marker.metadata_version != 1
            || marker.commit != commit
            || marker.mirror_identity_digest != mirror.identity_digest
            || repository.verify_commit(commit)? != commit
        {
            return Err(GitError::HydrationMismatch);
        }
        let head = repository.run_git(&["rev-parse", "HEAD"], 1024)?;
        if parse_one_line(&head.stdout, "hydrated HEAD")? != commit
            || !repository.run_git(&["remote"], 4096)?.stdout.is_empty()
        {
            return Err(GitError::HydrationMismatch);
        }
        reject_alternates(repository.git_dir())?;
        verify_no_shared_objects(&repository.git_dir().join("objects"))?;
        verify_tree_read_only(path)?;
        Ok(HydratedWorkspace {
            path: path.to_owned(),
            commit: commit.to_owned(),
            mirror_identity_digest: mirror.identity_digest.clone(),
        })
    }
}
use super::{
    digest_name, fs, fsync, hydration_destination, hydration_failure_is_miss,
    make_tree_owner_writable, make_tree_read_only, mkdirat, open_real_directory, parse_one_line,
    read_hydration_metadata, reject_alternates, remove_tree_no_follow, sync_tree, unique_suffix,
    validate_hydration_parent, validate_managed_name, validate_object_id, verify_no_shared_objects,
    verify_tree_read_only, write_hydration_metadata, GitError, GitRepository, HydratedWorkspace,
    HydrationMetadata, HydrationOutcome, IdentityMetadata, MirrorHandle, MirrorManager, MirrorMiss,
    Mode, Path, HYDRATION_MARKER, MIRROR_DIRECTORY,
};
use std::os::fd::AsRawFd as _;
