use runtrue_model::ContentDigest;
use runtrue_storage::FsCas;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Verify one immutable artifact record and its complete content/provenance
/// graph directly from a CAS. This read-only entry point is used by backup and
/// lifecycle verification where creating ticket metadata or store layout
/// would violate the no-mutation boundary.
pub fn verify_immutable_artifact_record(
    cas: &FsCas,
    artifact_id: &ContentDigest,
    limits: ArtifactLimits,
) -> Result<ArtifactHandle, ArtifactError> {
    let verifier = ArtifactStore {
        root: PathBuf::new(),
        cas: cas.clone(),
        limits: limits.validate()?,
    };
    verifier.load(artifact_id)
}

impl ArtifactStore {
    pub fn claimed_artifact(
        &self,
        ticket: &ArtifactTicket,
    ) -> Result<Option<ContentDigest>, ArtifactError> {
        self.validate_presented_ticket(ticket)?;
        let directory = self.ticket_directory(&ticket.ticket_id)?;
        let claim_path = directory.join("claim.json");
        match fs::symlink_metadata(&claim_path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(io_failure(
                    "inspect artifact ticket claim",
                    &claim_path,
                    source,
                ));
            }
        }
        let bytes = read_small_regular(&claim_path, self.limits.max_ticket_bytes)?;
        let claim: TicketClaim = serde_json::from_slice(&bytes)
            .map_err(|error| ArtifactError::InvalidMetadata(error.to_string()))?;
        if claim.claim_version != CLAIM_VERSION || claim.ticket_id != ticket.ticket_id {
            return Err(ArtifactError::InvalidMetadata(
                "ticket claim does not match the ticket".to_owned(),
            ));
        }
        // A claim is an index, not an authority. Re-load the referenced record
        // so its CAS digest, content, and provenance signature are verified,
        // then prove that it belongs to the presented immutable ticket.
        let artifact = self.load(&claim.artifact_id)?;
        let record = &artifact.record;
        if record.tenant_id != ticket.tenant_id
            || record.repository_id != ticket.repository_id
            || record.run_id != ticket.run_id
            || record.job_id != ticket.job_id
            || record.step_id != ticket.step_id
            || record.name != ticket.name
            || record.classification != ticket.classification
            || record.size_bytes > ticket.max_bytes
            || record.committed_at_unix_seconds < ticket.issued_at_unix_seconds
            || record.committed_at_unix_seconds >= ticket.expires_at_unix_seconds
            || ticket
                .expected_content_digest
                .as_ref()
                .is_some_and(|expected| expected != &record.content_digest)
        {
            return Err(ArtifactError::InvalidMetadata(
                "ticket claim references an artifact outside the ticket subject".to_owned(),
            ));
        }
        Ok(Some(claim.artifact_id))
    }

    pub fn load(&self, artifact_id: &ContentDigest) -> Result<ArtifactHandle, ArtifactError> {
        let bytes = self
            .cas
            .read_blob_limited(artifact_id, self.limits.max_record_bytes)?;
        let record: ArtifactRecord = serde_json::from_slice(&bytes)
            .map_err(|error| ArtifactError::InvalidMetadata(error.to_string()))?;
        self.validate_record(&record)?;
        self.verify_snapshot(&record.content, &record.content_digest, record.size_bytes)?;
        Ok(ArtifactHandle {
            artifact_id: artifact_id.clone(),
            record,
        })
    }

    pub fn materialize(
        &self,
        artifact_id: &ContentDigest,
        destination: impl AsRef<Path>,
    ) -> Result<ArtifactHandle, ArtifactError> {
        let artifact = self.load(artifact_id)?;
        self.cas
            .materialize_path(&artifact.record.content, destination)?;
        Ok(artifact)
    }
}
use crate::{
    io_failure, read_small_regular, ArtifactError, ArtifactHandle, ArtifactLimits, ArtifactRecord,
    ArtifactStore, ArtifactTicket, TicketClaim, CLAIM_VERSION,
};
