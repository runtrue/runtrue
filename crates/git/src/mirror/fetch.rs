impl MirrorManager {
    pub fn sync(
        &self,
        identity: &RepositoryIdentity,
        origin: &str,
        requested_commits: &[String],
        credentials: &dyn GitCredentialProvider,
    ) -> Result<MirrorSyncOutcome, GitError> {
        let origin = self.origin_policy.normalize(origin)?;
        validate_requested_commits(requested_commits)?;
        let request = CredentialRequest {
            identity: identity.clone(),
            origin: origin.clone(),
            repository_read_only: true,
        };
        let credential = credentials.credential(&request)?;
        credential.ensure_live()?;
        self.sync_endpoint(
            identity,
            &origin,
            requested_commits,
            FetchEndpoint::Https(credential),
        )
    }

    #[cfg(test)]
    pub fn sync_from_local_path(
        &self,
        identity: &RepositoryIdentity,
        logical_origin: &str,
        source: &Path,
        requested_commits: &[String],
    ) -> Result<MirrorSyncOutcome, GitError> {
        let origin = self.origin_policy.normalize(logical_origin)?;
        validate_requested_commits(requested_commits)?;
        let (source, _) = open_real_directory(source)?;
        self.sync_endpoint(
            identity,
            &origin,
            requested_commits,
            FetchEndpoint::TestLocal(source),
        )
    }

    fn sync_endpoint(
        &self,
        identity: &RepositoryIdentity,
        origin: &NormalizedOrigin,
        requested_commits: &[String],
        endpoint: FetchEndpoint,
    ) -> Result<MirrorSyncOutcome, GitError> {
        let identity_digest = identity.digest();
        let name = digest_name(&identity_digest)?;
        let _writer = match self.acquire_writer(&name)? {
            Some(writer) => writer,
            None => return Ok(MirrorSyncOutcome::Miss(MirrorMiss::WriterTimeout)),
        };
        self.recover_staging(&name)?;
        let published = self.root.join("mirrors").join(&name);
        if fs::symlink_metadata(&published).is_ok() {
            return self.sync_warm(
                identity,
                &identity_digest,
                origin,
                requested_commits,
                endpoint,
                &published,
            );
        }
        self.sync_cold(
            identity,
            &identity_digest,
            origin,
            requested_commits,
            endpoint,
            &published,
        )
    }

    fn sync_cold(
        &self,
        identity: &RepositoryIdentity,
        identity_digest: &ContentDigest,
        origin: &NormalizedOrigin,
        requested_commits: &[String],
        endpoint: FetchEndpoint,
        published: &Path,
    ) -> Result<MirrorSyncOutcome, GitError> {
        let name = digest_name(identity_digest)?;
        let staging_name = format!("{name}-{}", unique_suffix()?);
        let staging = self.create_managed_directory("staging", &staging_name)?;
        let metadata = IdentityMetadata {
            metadata_version: 1,
            identity: identity.clone(),
            origin: origin.clone(),
        };
        if let Err(error) = self.initialize_staging(&staging, &metadata) {
            let _ = self.quarantine_path(&staging, &name, "initialize");
            return Err(error);
        }
        let repository_path = staging.join(MIRROR_DIRECTORY);
        if let Err(error) = self.fetch(&repository_path, origin, requested_commits, &endpoint) {
            let _ = self.quarantine_path(&staging, &name, "fetch");
            return if fetch_failure_is_miss(&error) {
                Ok(MirrorSyncOutcome::Miss(MirrorMiss::FetchUnavailable))
            } else {
                Err(error)
            };
        }
        let repository = match GitRepository::open(&repository_path, self.limits.git) {
            Ok(repository) => repository,
            Err(error) => {
                let _ = self.quarantine_path(&staging, &name, "invalid");
                return if mirror_corruption(&error) {
                    Ok(MirrorSyncOutcome::Miss(MirrorMiss::CorruptQuarantined))
                } else {
                    Err(error)
                };
            }
        };
        if !all_commits_present(&repository, requested_commits) {
            let _ = self.quarantine_path(&staging, &name, "missing-commit");
            return Ok(MirrorSyncOutcome::Miss(
                MirrorMiss::RequestedCommitUnavailable,
            ));
        }
        if let Err(error) = self.verify_mirror(&staging, &metadata, true) {
            let _ = self.quarantine_path(&staging, &name, "invalid");
            return if mirror_corruption(&error) {
                Ok(MirrorSyncOutcome::Miss(MirrorMiss::CorruptQuarantined))
            } else {
                Err(error)
            };
        }
        sync_tree(&staging)?;
        self.rename_managed("staging", &staging_name, "mirrors", &name)?;
        sync_directory(&self.root.join("mirrors"))?;
        let handle = self.open_published(identity, identity_digest, origin, published)?;
        Ok(MirrorSyncOutcome::Ready(Box::new(handle)))
    }

    fn sync_warm(
        &self,
        identity: &RepositoryIdentity,
        identity_digest: &ContentDigest,
        origin: &NormalizedOrigin,
        requested_commits: &[String],
        endpoint: FetchEndpoint,
        published: &Path,
    ) -> Result<MirrorSyncOutcome, GitError> {
        let metadata = IdentityMetadata {
            metadata_version: 1,
            identity: identity.clone(),
            origin: origin.clone(),
        };
        let current = match self.open_published(identity, identity_digest, origin, published) {
            Ok(handle) => handle,
            Err(error @ (GitError::MirrorIdentityChanged | GitError::MirrorOriginChanged)) => {
                return Err(error);
            }
            Err(_) => {
                self.quarantine_path(published, &digest_name(identity_digest)?, "pre-fetch")?;
                return Ok(MirrorSyncOutcome::Miss(MirrorMiss::CorruptQuarantined));
            }
        };
        let fetch = self.fetch(
            current.repository.root(),
            origin,
            requested_commits,
            &endpoint,
        );
        if let Err(error) = fetch {
            if fetch_failure_is_miss(&error) {
                match self.verify_mirror(published, &metadata, false) {
                    Ok(()) if all_commits_present(&current.repository, requested_commits) => {
                        return Ok(MirrorSyncOutcome::Ready(Box::new(current)));
                    }
                    Ok(()) => {}
                    Err(
                        error @ (GitError::MirrorIdentityChanged | GitError::MirrorOriginChanged),
                    ) => {
                        return Err(error);
                    }
                    Err(_) => {
                        self.quarantine_path(
                            published,
                            &digest_name(identity_digest)?,
                            "post-fetch",
                        )?;
                        return Ok(MirrorSyncOutcome::Miss(MirrorMiss::CorruptQuarantined));
                    }
                }
            }
            return if fetch_failure_is_miss(&error) {
                Ok(MirrorSyncOutcome::Miss(MirrorMiss::FetchUnavailable))
            } else {
                Err(error)
            };
        }
        if let Err(error) = self.verify_mirror(published, &metadata, false) {
            self.quarantine_path(published, &digest_name(identity_digest)?, "post-fetch")?;
            return if mirror_corruption(&error) {
                Ok(MirrorSyncOutcome::Miss(MirrorMiss::CorruptQuarantined))
            } else {
                Err(error)
            };
        }
        let repository = GitRepository::open(current.repository.root(), self.limits.git)?;
        if !all_commits_present(&repository, requested_commits) {
            return Ok(MirrorSyncOutcome::Miss(
                MirrorMiss::RequestedCommitUnavailable,
            ));
        }
        Ok(MirrorSyncOutcome::Ready(Box::new(MirrorHandle {
            identity: identity.clone(),
            identity_digest: identity_digest.clone(),
            origin: origin.clone(),
            repository,
        })))
    }

    fn initialize_staging(
        &self,
        staging: &Path,
        metadata: &IdentityMetadata,
    ) -> Result<(), GitError> {
        write_identity_metadata(&staging.join(IDENTITY_METADATA_FILE), metadata)?;
        let repository = staging.join(MIRROR_DIRECTORY);
        let arguments = vec![
            "init".to_owned(),
            "--bare".to_owned(),
            "--quiet".to_owned(),
            repository.display().to_string(),
        ];
        self.run_git_process(staging, &arguments, 16 * 1024, None, None, false)?;
        write_exact_config(&repository.join("config"), &metadata.origin)?;
        Ok(())
    }

    fn fetch(
        &self,
        repository: &Path,
        origin: &NormalizedOrigin,
        requested_commits: &[String],
        endpoint: &FetchEndpoint,
    ) -> Result<(), GitError> {
        let mut arguments = vec![
            "--git-dir".to_owned(),
            repository.display().to_string(),
            "fetch".to_owned(),
            "--force".to_owned(),
            "--prune".to_owned(),
            "--no-tags".to_owned(),
            "--no-recurse-submodules".to_owned(),
            "--no-write-fetch-head".to_owned(),
        ];
        let pinned_addresses;
        let (credential, scoped_origin, test_file) = match endpoint {
            FetchEndpoint::Https(credential) => {
                pinned_addresses = resolve_public_addresses(origin)?;
                credential.ensure_live()?;
                arguments.push(origin.as_str().to_owned());
                (Some(credential), Some(origin), false)
            }
            #[cfg(test)]
            FetchEndpoint::TestLocal(source) => {
                pinned_addresses = Vec::new();
                arguments.push(source.display().to_string());
                (None, None, true)
            }
        };
        arguments.extend(FETCH_REFSPECS.iter().map(|value| (*value).to_owned()));
        arguments.extend(
            requested_commits
                .iter()
                .map(|commit| format!("+{commit}:refs/runtrue/requested/{commit}")),
        );
        self.run_git_process(
            repository,
            &arguments,
            self.limits.max_command_output_bytes,
            credential,
            scoped_origin.map(|origin| (origin, pinned_addresses.as_slice())),
            test_file,
        )?;
        Ok(())
    }

    fn open_published(
        &self,
        identity: &RepositoryIdentity,
        identity_digest: &ContentDigest,
        origin: &NormalizedOrigin,
        published: &Path,
    ) -> Result<MirrorHandle, GitError> {
        let metadata = IdentityMetadata {
            metadata_version: 1,
            identity: identity.clone(),
            origin: origin.clone(),
        };
        self.verify_mirror(published, &metadata, false)?;
        let repository = GitRepository::open(published.join(MIRROR_DIRECTORY), self.limits.git)?;
        if repository.remote_origin_url()? != origin.as_str() {
            return Err(GitError::MirrorOriginChanged);
        }
        Ok(MirrorHandle {
            identity: identity.clone(),
            identity_digest: identity_digest.clone(),
            origin: origin.clone(),
            repository,
        })
    }

    pub(super) fn verify_mirror(
        &self,
        directory: &Path,
        metadata: &IdentityMetadata,
        full_fsck: bool,
    ) -> Result<(), GitError> {
        verify_identity_metadata(&directory.join(IDENTITY_METADATA_FILE), metadata)?;
        let repository_path = directory.join(MIRROR_DIRECTORY);
        verify_exact_config(&repository_path.join("config"), &metadata.origin)?;
        reject_alternates(&repository_path)?;
        let repository = GitRepository::open(&repository_path, self.limits.git)?;
        if repository.remote_origin_url()? != metadata.origin.as_str() {
            return Err(GitError::MirrorOriginChanged);
        }
        self.run_fsck(&repository_path, full_fsck)?;
        verify_ref_and_object_counts(&repository, self.limits)?;
        inspect_tree_confined(&repository_path, self.limits)?;
        Ok(())
    }

    pub(super) fn run_fsck(&self, repository: &Path, full: bool) -> Result<(), GitError> {
        let mut arguments = vec![
            "--git-dir".to_owned(),
            repository.display().to_string(),
            "fsck".to_owned(),
            "--strict".to_owned(),
            "--no-dangling".to_owned(),
        ];
        arguments.push(if full {
            "--full".to_owned()
        } else {
            "--connectivity-only".to_owned()
        });
        self.run_git_process(
            repository,
            &arguments,
            self.limits.max_command_output_bytes,
            None,
            None,
            false,
        )?;
        Ok(())
    }
}
use super::{
    all_commits_present, digest_name, fetch_failure_is_miss, fs, inspect_tree_confined,
    mirror_corruption, reject_alternates, resolve_public_addresses, sync_directory, sync_tree,
    unique_suffix, validate_requested_commits, verify_exact_config, verify_identity_metadata,
    verify_ref_and_object_counts, write_exact_config, write_identity_metadata, ContentDigest,
    CredentialRequest, FetchEndpoint, GitCredentialProvider, GitError, GitRepository,
    IdentityMetadata, MirrorHandle, MirrorManager, MirrorMiss, MirrorSyncOutcome, NormalizedOrigin,
    Path, RepositoryIdentity, FETCH_REFSPECS, IDENTITY_METADATA_FILE, MIRROR_DIRECTORY,
};
#[cfg(test)]
use crate::open_real_directory;
