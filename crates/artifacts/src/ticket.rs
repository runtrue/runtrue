use rand_core::{OsRng, RngCore};
use runtrue_attest::{CapsuleVerifyingKey, SignedProvenance};
use runtrue_model::ContentDigest;
use runtrue_storage::PathSnapshot;
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub(crate) const TICKET_VERSION: u32 = 1;
pub(crate) const CLAIM_VERSION: u32 = 1;

const fn default_job_attempt() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactTicket {
    pub ticket_version: u32,
    pub ticket_id: ContentDigest,
    pub nonce: ContentDigest,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    #[serde(default = "default_job_attempt")]
    pub job_attempt: u32,
    pub step_id: String,
    pub lease_id: String,
    pub fencing_generation: u64,
    pub name: String,
    pub classification: ArtifactClassification,
    pub max_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_content_digest: Option<ContentDigest>,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactTicketRequest {
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub lease_id: String,
    pub fencing_generation: u64,
    pub name: String,
    pub classification: ArtifactClassification,
    pub max_bytes: u64,
    pub expected_content_digest: Option<ContentDigest>,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

pub struct VerifiedArtifactProvenance<'a> {
    pub signed: &'a SignedProvenance,
    pub verifying_key: &'a CapsuleVerifyingKey,
}

pub struct ArtifactCommitRequest<'a> {
    pub ticket: &'a ArtifactTicket,
    pub active_lease_id: &'a str,
    pub active_fencing_generation: u64,
    pub now_unix_seconds: u64,
    pub source: &'a Path,
    pub declared_content_digest: ContentDigest,
    pub declared_size_bytes: u64,
    pub media_type: String,
    pub retention_until_unix_seconds: u64,
    pub legal_hold: bool,
    pub scan_state: ArtifactScanState,
    pub producer: ArtifactProducer,
    pub provenance: VerifiedArtifactProvenance<'a>,
}

/// Commit content that a preceding upload phase already placed in this store's
/// CAS. Every referenced blob and tree summary is reverified before the ticket
/// claim is published.
pub struct ArtifactSnapshotCommitRequest<'a> {
    pub ticket: &'a ArtifactTicket,
    pub active_lease_id: &'a str,
    pub active_fencing_generation: u64,
    pub now_unix_seconds: u64,
    pub snapshot: &'a PathSnapshot,
    pub declared_content_digest: ContentDigest,
    pub declared_size_bytes: u64,
    pub media_type: String,
    pub retention_until_unix_seconds: u64,
    pub legal_hold: bool,
    pub scan_state: ArtifactScanState,
    pub producer: ArtifactProducer,
    pub provenance: VerifiedArtifactProvenance<'a>,
}

pub(crate) trait ArtifactCommitParameters {
    fn ticket(&self) -> &ArtifactTicket;
    fn active_lease_id(&self) -> &str;
    fn active_fencing_generation(&self) -> u64;
    fn now_unix_seconds(&self) -> u64;
    fn declared_content_digest(&self) -> &ContentDigest;
    fn declared_size_bytes(&self) -> u64;
    fn media_type(&self) -> &str;
    fn retention_until_unix_seconds(&self) -> u64;
    fn legal_hold(&self) -> bool;
    fn scan_state(&self) -> &ArtifactScanState;
    fn producer(&self) -> &ArtifactProducer;
    fn provenance(&self) -> &VerifiedArtifactProvenance<'_>;
}

macro_rules! impl_artifact_commit_parameters {
    ($request:ty) => {
        impl ArtifactCommitParameters for $request {
            fn ticket(&self) -> &ArtifactTicket {
                self.ticket
            }

            fn active_lease_id(&self) -> &str {
                self.active_lease_id
            }

            fn active_fencing_generation(&self) -> u64 {
                self.active_fencing_generation
            }

            fn now_unix_seconds(&self) -> u64 {
                self.now_unix_seconds
            }

            fn declared_content_digest(&self) -> &ContentDigest {
                &self.declared_content_digest
            }

            fn declared_size_bytes(&self) -> u64 {
                self.declared_size_bytes
            }

            fn media_type(&self) -> &str {
                &self.media_type
            }

            fn retention_until_unix_seconds(&self) -> u64 {
                self.retention_until_unix_seconds
            }

            fn legal_hold(&self) -> bool {
                self.legal_hold
            }

            fn scan_state(&self) -> &ArtifactScanState {
                &self.scan_state
            }

            fn producer(&self) -> &ArtifactProducer {
                &self.producer
            }

            fn provenance(&self) -> &VerifiedArtifactProvenance<'_> {
                &self.provenance
            }
        }
    };
}

impl_artifact_commit_parameters!(ArtifactCommitRequest<'_>);
impl_artifact_commit_parameters!(ArtifactSnapshotCommitRequest<'_>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TicketClaim {
    pub(crate) claim_version: u32,
    pub(crate) ticket_id: ContentDigest,
    pub(crate) artifact_id: ContentDigest,
}

impl ArtifactStore {
    pub fn issue_ticket(
        &self,
        request: ArtifactTicketRequest,
    ) -> Result<ArtifactTicket, ArtifactError> {
        self.validate_ticket_request(&request)?;
        for _ in 0..32 {
            let mut random = [0_u8; 32];
            OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| ArtifactError::RandomnessUnavailable)?;
            let nonce = ContentDigest::sha256(random);
            let mut ticket = ArtifactTicket {
                ticket_version: TICKET_VERSION,
                ticket_id: ContentDigest::sha256(b"pending-ticket-id"),
                nonce,
                tenant_id: request.tenant_id.clone(),
                repository_id: request.repository_id.clone(),
                run_id: request.run_id.clone(),
                job_id: request.job_id.clone(),
                job_attempt: request.job_attempt,
                step_id: request.step_id.clone(),
                lease_id: request.lease_id.clone(),
                fencing_generation: request.fencing_generation,
                name: request.name.clone(),
                classification: request.classification,
                max_bytes: request.max_bytes,
                expected_content_digest: request.expected_content_digest.clone(),
                issued_at_unix_seconds: request.issued_at_unix_seconds,
                expires_at_unix_seconds: request.expires_at_unix_seconds,
            };
            ticket.ticket_id = ticket_subject_digest(&ticket)?;
            let directory = self.ticket_directory_path(&ticket.ticket_id)?;
            match fs::create_dir(&directory) {
                Ok(()) => {
                    let bytes =
                        serde_json::to_vec(&ticket).map_err(ArtifactError::SerializeMetadata)?;
                    if bytes.len() as u64 > self.limits.max_ticket_bytes {
                        let _ = fs::remove_dir(&directory);
                        return Err(ArtifactError::MetadataLimit {
                            kind: "artifact ticket",
                            limit: self.limits.max_ticket_bytes,
                            actual: bytes.len() as u64,
                        });
                    }
                    if let Err(error) = append_metadata(&directory, "ticket.json", &bytes) {
                        let _ = fs::remove_dir_all(&directory);
                        return Err(error);
                    }
                    sync_directory(directory.parent().ok_or_else(|| {
                        ArtifactError::InvalidConfiguration(
                            "ticket directory has no parent".to_owned(),
                        )
                    })?)?;
                    return Ok(ticket);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(io_failure(
                        "create artifact ticket directory",
                        &directory,
                        source,
                    ));
                }
            }
        }
        Err(ArtifactError::InvalidConfiguration(
            "could not allocate a unique artifact ticket".to_owned(),
        ))
    }

    /// Reload and revalidate a durable upload ticket by its subject digest.
    pub fn ticket(&self, ticket_id: &ContentDigest) -> Result<ArtifactTicket, ArtifactError> {
        let directory = self.ticket_directory(ticket_id)?;
        let bytes =
            read_small_regular(&directory.join("ticket.json"), self.limits.max_ticket_bytes)?;
        let ticket: ArtifactTicket =
            serde_json::from_slice(&bytes).map_err(ArtifactError::SerializeMetadata)?;
        self.validate_presented_ticket(&ticket)?;
        if &ticket.ticket_id != ticket_id {
            return Err(ArtifactError::TicketContentMismatch);
        }
        Ok(ticket)
    }

    /// Commit one file or directory and atomically consume its ticket.
    fn validate_ticket_request(
        &self,
        request: &ArtifactTicketRequest,
    ) -> Result<(), ArtifactError> {
        for (field, value) in [
            ("tenant_id", request.tenant_id.as_str()),
            ("repository_id", request.repository_id.as_str()),
            ("run_id", request.run_id.as_str()),
            ("job_id", request.job_id.as_str()),
            ("step_id", request.step_id.as_str()),
            ("lease_id", request.lease_id.as_str()),
        ] {
            validate_identifier(field, value, self.limits)?;
        }
        validate_artifact_name(&request.name, self.limits)?;
        if !request.classification.can_upload_directly() {
            return Err(ArtifactError::InvalidTicket(
                "release/public classifications require promotion".to_owned(),
            ));
        }
        if request.fencing_generation == 0 || request.job_attempt == 0 {
            return Err(ArtifactError::InvalidTicket(
                "fencing generation must be positive".to_owned(),
            ));
        }
        if request.max_bytes == 0 || request.max_bytes > self.limits.max_artifact_bytes {
            return Err(ArtifactError::InvalidTicket(
                "ticket byte bound is zero or exceeds the installation maximum".to_owned(),
            ));
        }
        if request.expires_at_unix_seconds <= request.issued_at_unix_seconds
            || request
                .expires_at_unix_seconds
                .saturating_sub(request.issued_at_unix_seconds)
                > self.limits.max_ticket_lifetime_seconds
        {
            return Err(ArtifactError::InvalidTicket(
                "ticket expiry is invalid or exceeds the maximum lifetime".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_presented_ticket(
        &self,
        ticket: &ArtifactTicket,
    ) -> Result<(), ArtifactError> {
        if ticket.ticket_version != TICKET_VERSION
            || ticket_subject_digest(ticket)? != ticket.ticket_id
        {
            return Err(ArtifactError::InvalidTicket(
                "ticket identity or version is invalid".to_owned(),
            ));
        }
        self.validate_ticket_request(&ArtifactTicketRequest {
            tenant_id: ticket.tenant_id.clone(),
            repository_id: ticket.repository_id.clone(),
            run_id: ticket.run_id.clone(),
            job_id: ticket.job_id.clone(),
            job_attempt: ticket.job_attempt,
            step_id: ticket.step_id.clone(),
            lease_id: ticket.lease_id.clone(),
            fencing_generation: ticket.fencing_generation,
            name: ticket.name.clone(),
            classification: ticket.classification,
            max_bytes: ticket.max_bytes,
            expected_content_digest: ticket.expected_content_digest.clone(),
            issued_at_unix_seconds: ticket.issued_at_unix_seconds,
            expires_at_unix_seconds: ticket.expires_at_unix_seconds,
        })?;
        let directory = self.ticket_directory(&ticket.ticket_id)?;
        let stored_path = directory.join("ticket.json");
        let bytes = read_small_regular(&stored_path, self.limits.max_ticket_bytes)?;
        let stored: ArtifactTicket = serde_json::from_slice(&bytes)
            .map_err(|error| ArtifactError::InvalidMetadata(error.to_string()))?;
        if &stored != ticket {
            return Err(ArtifactError::InvalidTicket(
                "presented ticket does not match immutable server state".to_owned(),
            ));
        }
        Ok(())
    }

    fn ticket_directory_path(&self, ticket_id: &ContentDigest) -> Result<PathBuf, ArtifactError> {
        let encoded = digest_hex(ticket_id)?;
        let algorithm = self.root.join("tickets/sha256");
        ensure_directory(&algorithm)?;
        let prefix = algorithm.join(&encoded[..2]);
        ensure_directory(&prefix)?;
        Ok(prefix.join(&encoded[2..]))
    }

    pub(crate) fn ticket_directory(
        &self,
        ticket_id: &ContentDigest,
    ) -> Result<PathBuf, ArtifactError> {
        let directory = self.ticket_directory_path(ticket_id)?;
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|source| io_failure("inspect ticket directory", &directory, source))?;
        require_directory(&directory, &metadata)?;
        Ok(directory)
    }
}

pub(crate) fn ticket_subject_digest(
    ticket: &ArtifactTicket,
) -> Result<ContentDigest, ArtifactError> {
    #[derive(Serialize)]
    struct Subject<'a> {
        ticket_version: u32,
        nonce: &'a ContentDigest,
        tenant_id: &'a str,
        repository_id: &'a str,
        run_id: &'a str,
        job_id: &'a str,
        step_id: &'a str,
        lease_id: &'a str,
        fencing_generation: u64,
        name: &'a str,
        classification: ArtifactClassification,
        max_bytes: u64,
        expected_content_digest: &'a Option<ContentDigest>,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    }
    let subject = Subject {
        ticket_version: ticket.ticket_version,
        nonce: &ticket.nonce,
        tenant_id: &ticket.tenant_id,
        repository_id: &ticket.repository_id,
        run_id: &ticket.run_id,
        job_id: &ticket.job_id,
        step_id: &ticket.step_id,
        lease_id: &ticket.lease_id,
        fencing_generation: ticket.fencing_generation,
        name: &ticket.name,
        classification: ticket.classification,
        max_bytes: ticket.max_bytes,
        expected_content_digest: &ticket.expected_content_digest,
        issued_at_unix_seconds: ticket.issued_at_unix_seconds,
        expires_at_unix_seconds: ticket.expires_at_unix_seconds,
    };
    let bytes = serde_json::to_vec(&subject).map_err(ArtifactError::SerializeMetadata)?;
    Ok(ContentDigest::sha256(bytes))
}
use crate::{
    append_metadata, digest_hex, ensure_directory, io_failure, read_small_regular,
    require_directory, sync_directory, validate_artifact_name, validate_identifier,
    ArtifactClassification, ArtifactError, ArtifactProducer, ArtifactScanState, ArtifactStore,
};
