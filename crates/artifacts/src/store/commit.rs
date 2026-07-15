use runtrue_model::ContentDigest;
use runtrue_storage::{PathSnapshot, TreeEntryKind};
use std::path::{Path, PathBuf};

impl ArtifactStore {
    pub fn commit(
        &self,
        request: &ArtifactCommitRequest<'_>,
    ) -> Result<ArtifactHandle, ArtifactError> {
        let directory = self.validate_commit_request(request)?;
        let content = self.cas.capture_path(request.source)?;
        self.commit_verified_snapshot(request, content, &directory)
    }

    /// Commit a preverified file/tree snapshot without resolving a source path.
    /// The complete CAS graph is reverified before the existing one-use claim
    /// protocol is allowed to publish the record.
    pub fn commit_snapshot(
        &self,
        request: &ArtifactSnapshotCommitRequest<'_>,
    ) -> Result<ArtifactHandle, ArtifactError> {
        let directory = self.validate_commit_request(request)?;
        self.commit_verified_snapshot(request, request.snapshot.clone(), &directory)
    }

    fn validate_commit_request<R: ArtifactCommitParameters>(
        &self,
        request: &R,
    ) -> Result<PathBuf, ArtifactError> {
        self.validate_presented_ticket(request.ticket())?;
        let directory = self.ticket_directory(&request.ticket().ticket_id)?;
        if directory.join("claim.json").exists() {
            return Err(ArtifactError::TicketConsumed);
        }
        if request.now_unix_seconds() >= request.ticket().expires_at_unix_seconds {
            return Err(ArtifactError::TicketExpired);
        }
        if request.active_lease_id() != request.ticket().lease_id {
            return Err(ArtifactError::LeaseMismatch);
        }
        if request.active_fencing_generation() != request.ticket().fencing_generation {
            return Err(ArtifactError::StaleFence {
                ticket: request.ticket().fencing_generation,
                active: request.active_fencing_generation(),
            });
        }
        if request.declared_size_bytes() > request.ticket().max_bytes
            || request.declared_size_bytes() > self.limits.max_artifact_bytes
        {
            return Err(ArtifactError::ArtifactTooLarge {
                limit: request
                    .ticket()
                    .max_bytes
                    .min(self.limits.max_artifact_bytes),
                actual: request.declared_size_bytes(),
            });
        }
        validate_media_type(request.media_type(), self.limits)?;
        validate_retention(
            request.now_unix_seconds(),
            request.retention_until_unix_seconds(),
            self.limits,
        )?;
        validate_scan_state(request.scan_state(), self.limits)?;
        validate_producer(request.producer(), self.limits)?;
        Ok(directory)
    }

    fn commit_verified_snapshot<R: ArtifactCommitParameters>(
        &self,
        request: &R,
        content: PathSnapshot,
        directory: &Path,
    ) -> Result<ArtifactHandle, ArtifactError> {
        let (content_digest, size_bytes) = snapshot_identity(&content);
        if size_bytes != request.declared_size_bytes() {
            return Err(ArtifactError::ContentSizeMismatch {
                declared: request.declared_size_bytes(),
                actual: size_bytes,
            });
        }
        if size_bytes > request.ticket().max_bytes || size_bytes > self.limits.max_artifact_bytes {
            return Err(ArtifactError::ArtifactTooLarge {
                limit: request
                    .ticket()
                    .max_bytes
                    .min(self.limits.max_artifact_bytes),
                actual: size_bytes,
            });
        }
        if &content_digest != request.declared_content_digest() {
            return Err(ArtifactError::ContentDigestMismatch {
                declared: request.declared_content_digest().clone(),
                actual: content_digest,
            });
        }
        if request
            .ticket()
            .expected_content_digest
            .as_ref()
            .is_some_and(|expected| expected != request.declared_content_digest())
        {
            return Err(ArtifactError::TicketContentMismatch);
        }
        self.verify_snapshot(
            &content,
            request.declared_content_digest(),
            request.declared_size_bytes(),
        )?;
        let provenance = verify_provenance_link(
            request.provenance(),
            request.producer(),
            &request.ticket().name,
            request.declared_content_digest(),
        )?;
        let record = ArtifactRecord {
            record_version: ARTIFACT_RECORD_VERSION,
            tenant_id: request.ticket().tenant_id.clone(),
            repository_id: request.ticket().repository_id.clone(),
            run_id: request.ticket().run_id.clone(),
            job_id: request.ticket().job_id.clone(),
            step_id: request.ticket().step_id.clone(),
            name: request.ticket().name.clone(),
            classification: request.ticket().classification,
            content,
            content_digest: request.declared_content_digest().clone(),
            size_bytes,
            media_type: request.media_type().to_owned(),
            producer: request.producer().clone(),
            provenance,
            scan_state: request.scan_state().clone(),
            committed_at_unix_seconds: request.now_unix_seconds(),
            retention_until_unix_seconds: request.retention_until_unix_seconds(),
            legal_hold: request.legal_hold(),
            promotion: None,
        };
        let artifact_id = self.store_record(&record)?;
        let claim = TicketClaim {
            claim_version: CLAIM_VERSION,
            ticket_id: request.ticket().ticket_id.clone(),
            artifact_id: artifact_id.clone(),
        };
        let claim_bytes = serde_json::to_vec(&claim).map_err(ArtifactError::SerializeMetadata)?;
        match append_metadata(directory, "claim.json", &claim_bytes) {
            Ok(()) => Ok(ArtifactHandle {
                artifact_id,
                record,
            }),
            Err(ArtifactError::MetadataExists(_)) => Err(ArtifactError::TicketConsumed),
            Err(error) => Err(error),
        }
    }

    /// Recover the committed artifact ID for a consumed ticket, for example
    /// after a caller lost the response following the atomic claim.
    pub(crate) fn verify_snapshot(
        &self,
        snapshot: &PathSnapshot,
        expected_digest: &ContentDigest,
        expected_size: u64,
    ) -> Result<(), ArtifactError> {
        match snapshot {
            PathSnapshot::File {
                digest, size_bytes, ..
            } => {
                let verified = self.cas.verify_blob(digest)?;
                if digest != expected_digest
                    || *size_bytes != expected_size
                    || verified != *size_bytes
                {
                    return Err(ArtifactError::InvalidMetadata(
                        "artifact file content failed verification".to_owned(),
                    ));
                }
            }
            PathSnapshot::Directory {
                manifest_digest, ..
            } => {
                let inspected = self.cas.inspect_tree(manifest_digest)?;
                if PathSnapshot::from(inspected.clone()) != *snapshot
                    || manifest_digest != expected_digest
                    || inspected.total_file_bytes != expected_size
                {
                    return Err(ArtifactError::InvalidMetadata(
                        "artifact tree summary failed verification".to_owned(),
                    ));
                }
                let manifest = self.cas.load_tree_manifest(manifest_digest)?;
                for entry in manifest.entries {
                    if let TreeEntryKind::File {
                        digest, size_bytes, ..
                    } = entry.kind
                    {
                        if self.cas.verify_blob(&digest)? != size_bytes {
                            return Err(ArtifactError::InvalidMetadata(format!(
                                "artifact tree file `{}` has the wrong size",
                                entry.path
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
use crate::{
    append_metadata, snapshot_identity, validate_media_type, validate_producer, validate_retention,
    validate_scan_state, verify_provenance_link, ArtifactCommitParameters, ArtifactCommitRequest,
    ArtifactError, ArtifactHandle, ArtifactRecord, ArtifactSnapshotCommitRequest, ArtifactStore,
    TicketClaim, ARTIFACT_RECORD_VERSION, CLAIM_VERSION,
};
