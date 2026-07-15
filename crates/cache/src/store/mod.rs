use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use runtrue_storage::{FsCas, TreeEntryKind, TreeSnapshot};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

mod commit;
mod metadata;
mod promotion;
mod restore;

/// Filesystem metadata store paired with an immutable content store.
#[derive(Debug, Clone)]
pub struct CacheStore {
    root: PathBuf,
    cas: FsCas,
    limits: CacheLimits,
}

struct PreparedCacheCommit {
    identity: CacheIdentity,
    identity_digest: ContentDigest,
    generation: u64,
    fencing_generation: u64,
    producer: CacheProducer,
    claim_ticket_id: Option<ContentDigest>,
}

impl CacheStore {
    pub fn open(
        root: impl AsRef<Path>,
        cas: FsCas,
        limits: CacheLimits,
    ) -> Result<Self, CacheError> {
        let limits = limits.validate()?;
        let requested = root.as_ref();
        match fs::symlink_metadata(requested) {
            Ok(metadata) => require_directory(requested, &metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(requested)
                    .map_err(|source| io_failure("create cache root", requested, source))?;
                let metadata = fs::symlink_metadata(requested)
                    .map_err(|source| io_failure("inspect cache root", requested, source))?;
                require_directory(requested, &metadata)?;
            }
            Err(source) => return Err(io_failure("inspect cache root", requested, source)),
        }
        let root = requested
            .canonicalize()
            .map_err(|source| io_failure("canonicalize cache root", requested, source))?;
        let store = Self { root, cas, limits };
        store.ensure_layout()?;
        Ok(store)
    }

    #[must_use]
    pub fn cas(&self) -> &FsCas {
        &self.cas
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn limits(&self) -> CacheLimits {
        self.limits
    }

    /// Persist a random, bounded, short-lived one-use cache write authority.
    pub fn issue_write_ticket(
        &self,
        request: CacheWriteTicketRequest,
    ) -> Result<CacheWriteTicket, CacheError> {
        self.validate_ticket_request(&request)?;
        let identity_digest = request.identity.digest(self.limits)?;
        let current = self.read_head(&identity_digest)?;
        if request.operation == CacheTicketOperation::Commit {
            require_expected_head(request.expected_head.as_ref(), current.as_ref())?;
            require_fresh_fence(request.fencing_generation, current.as_ref())?;
        } else if request.expected_head.is_some() || request.expected_tree_manifest_digest.is_some()
        {
            return Err(CacheError::InvalidTicket(
                "restore ticket callers cannot select cache content".to_owned(),
            ));
        }
        let restore_entry = if request.operation == CacheTicketOperation::Restore {
            current
                .clone()
                .map(|head| self.load_entry(&request.identity, head))
                .transpose()?
        } else {
            None
        };

        for _ in 0..32 {
            let mut random = [0_u8; 32];
            OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| CacheError::RandomnessUnavailable)?;
            let mut ticket = CacheWriteTicket {
                ticket_version: CACHE_TICKET_VERSION,
                ticket_id: ContentDigest::sha256(b"pending-cache-ticket-id"),
                nonce: ContentDigest::sha256(random),
                operation: request.operation,
                tenant_id: request.tenant_id.clone(),
                repository_id: request.repository_id.clone(),
                job_id: request.job_id.clone(),
                job_attempt: request.job_attempt,
                step_id: request.step_id.clone(),
                lease_id: request.lease_id.clone(),
                producer_capsule_digest: request.producer_capsule_digest.clone(),
                fencing_generation: request.fencing_generation,
                writer_trust_domain: request.writer_trust_domain.clone(),
                identity: request.identity.clone(),
                identity_digest: identity_digest.clone(),
                expected_head: restore_entry
                    .as_ref()
                    .map(|entry| entry.head.clone())
                    .or_else(|| request.expected_head.clone()),
                expected_tree_manifest_digest: restore_entry
                    .as_ref()
                    .map(|entry| entry.manifest.tree.manifest_digest.clone())
                    .or_else(|| request.expected_tree_manifest_digest.clone()),
                max_total_bytes: request.max_total_bytes,
                issued_at_unix_seconds: request.issued_at_unix_seconds,
                expires_at_unix_seconds: request.expires_at_unix_seconds,
            };
            ticket.ticket_id = cache_ticket_subject_digest(&ticket)?;
            let directory = self.ticket_directory_path(&ticket.ticket_id)?;
            match fs::create_dir(&directory) {
                Ok(()) => {
                    let bytes =
                        serde_json::to_vec(&ticket).map_err(CacheError::SerializeMetadata)?;
                    if bytes.len() as u64 > self.limits.max_ticket_bytes {
                        let _ = fs::remove_dir(&directory);
                        return Err(CacheError::MetadataLimit {
                            kind: "cache ticket",
                            limit: self.limits.max_ticket_bytes,
                            actual: bytes.len() as u64,
                        });
                    }
                    if let Err(error) = append_metadata(&directory, "ticket.json", &bytes) {
                        let _ = fs::remove_dir_all(&directory);
                        return Err(error);
                    }
                    sync_directory(directory.parent().ok_or_else(|| {
                        CacheError::InvalidConfiguration(
                            "cache ticket directory has no parent".to_owned(),
                        )
                    })?)?;
                    return Ok(ticket);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(io_failure(
                        "create cache ticket directory",
                        &directory,
                        source,
                    ))
                }
            }
        }
        Err(CacheError::InvalidConfiguration(
            "could not allocate a unique cache ticket".to_owned(),
        ))
    }

    /// Reload and revalidate a durable ticket by its subject digest.
    pub fn write_ticket(&self, ticket_id: &ContentDigest) -> Result<CacheWriteTicket, CacheError> {
        let directory = self.ticket_directory_path(ticket_id)?;
        let bytes =
            read_small_regular_file(&directory.join("ticket.json"), self.limits.max_ticket_bytes)?;
        let ticket: CacheWriteTicket =
            serde_json::from_slice(&bytes).map_err(CacheError::SerializeMetadata)?;
        self.validate_presented_ticket(&ticket)?;
        if &ticket.ticket_id != ticket_id {
            return Err(CacheError::TicketScopeMismatch);
        }
        Ok(ticket)
    }

    /// Publish a fully preverified CAS snapshot and atomically consume the
    fn validate_ticket_request(&self, request: &CacheWriteTicketRequest) -> Result<(), CacheError> {
        for (field, value) in [
            ("ticket.tenant_id", request.tenant_id.as_str()),
            ("ticket.repository_id", request.repository_id.as_str()),
            ("ticket.job_id", request.job_id.as_str()),
            ("ticket.step_id", request.step_id.as_str()),
            ("ticket.lease_id", request.lease_id.as_str()),
        ] {
            validate_identifier(field, value, self.limits)?;
        }
        request.identity.validate(self.limits)?;
        request.writer_trust_domain.validate(self.limits)?;
        if request.tenant_id != request.identity.tenant_id
            || request.repository_id != request.identity.repository_id
            || match request.operation {
                CacheTicketOperation::Commit => !request
                    .writer_trust_domain
                    .can_write_to(&request.identity.trust_domain),
                CacheTicketOperation::Restore => !request
                    .writer_trust_domain
                    .can_read_from(&request.identity.trust_domain),
            }
        {
            return Err(CacheError::InvalidTicket(
                "ticket scope, writer trust, and cache identity do not match".to_owned(),
            ));
        }
        validate_fence(request.fencing_generation)?;
        if request.job_attempt == 0 {
            return Err(CacheError::InvalidTicket(
                "ticket job attempt must be one-based".to_owned(),
            ));
        }
        if request.max_total_bytes == 0
            || request.max_total_bytes > self.cas.limits().max_tree_total_bytes
        {
            return Err(CacheError::InvalidTicket(
                "ticket byte bound is zero or exceeds the CAS tree limit".to_owned(),
            ));
        }
        if request.expires_at_unix_seconds <= request.issued_at_unix_seconds
            || request
                .expires_at_unix_seconds
                .saturating_sub(request.issued_at_unix_seconds)
                > self.limits.max_ticket_lifetime_seconds
        {
            return Err(CacheError::InvalidTicket(
                "ticket expiry is invalid or exceeds its maximum lifetime".to_owned(),
            ));
        }
        let identity_digest = request.identity.digest(self.limits)?;
        if let Some(expected) = &request.expected_head {
            validate_head(expected, &identity_digest, expected.generation)?;
        }
        Ok(())
    }

    fn validate_presented_ticket(&self, ticket: &CacheWriteTicket) -> Result<(), CacheError> {
        if ticket.ticket_version != CACHE_TICKET_VERSION
            || ticket.identity.digest(self.limits)? != ticket.identity_digest
            || cache_ticket_subject_digest(ticket)? != ticket.ticket_id
        {
            return Err(CacheError::InvalidTicket(
                "ticket identity or version is invalid".to_owned(),
            ));
        }
        self.validate_ticket_request(&CacheWriteTicketRequest {
            operation: ticket.operation,
            tenant_id: ticket.tenant_id.clone(),
            repository_id: ticket.repository_id.clone(),
            job_id: ticket.job_id.clone(),
            job_attempt: ticket.job_attempt,
            step_id: ticket.step_id.clone(),
            lease_id: ticket.lease_id.clone(),
            producer_capsule_digest: ticket.producer_capsule_digest.clone(),
            fencing_generation: ticket.fencing_generation,
            writer_trust_domain: ticket.writer_trust_domain.clone(),
            identity: ticket.identity.clone(),
            expected_head: ticket.expected_head.clone(),
            expected_tree_manifest_digest: ticket.expected_tree_manifest_digest.clone(),
            max_total_bytes: ticket.max_total_bytes,
            issued_at_unix_seconds: ticket.issued_at_unix_seconds,
            expires_at_unix_seconds: ticket.expires_at_unix_seconds,
        })?;
        let directory = self.ticket_directory(&ticket.ticket_id)?;
        let stored_path = directory.join("ticket.json");
        let bytes = read_small_regular_file(&stored_path, self.limits.max_ticket_bytes)?;
        let stored: CacheWriteTicket = serde_json::from_slice(&bytes)
            .map_err(|error| CacheError::InvalidTicket(error.to_string()))?;
        if &stored != ticket {
            return Err(CacheError::InvalidTicket(
                "presented ticket does not match immutable server state".to_owned(),
            ));
        }
        Ok(())
    }

    fn read_head(&self, identity_digest: &ContentDigest) -> Result<Option<CacheHead>, CacheError> {
        let directory = self.head_directory(identity_digest)?;
        let mut latest: Option<(u64, PathBuf)> = None;
        let mut records = 0_usize;
        for entry in fs::read_dir(&directory)
            .map_err(|source| io_failure("read cache head directory", &directory, source))?
        {
            let entry =
                entry.map_err(|source| io_failure("read cache head entry", &directory, source))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CacheError::CorruptHead("non-UTF-8 cache head filename".to_owned()))?;
            if name.starts_with('.') {
                continue;
            }
            let Some(number) = name.strip_suffix(".head") else {
                continue;
            };
            if number.len() != HEAD_GENERATION_WIDTH
                || !number.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(CacheError::CorruptHead(format!(
                    "invalid head filename `{name}`"
                )));
            }
            records += 1;
            if records > self.limits.max_head_records {
                return Err(CacheError::CorruptHead(
                    "cache head record limit exceeded".to_owned(),
                ));
            }
            let generation = number.parse::<u64>().map_err(|_| {
                CacheError::CorruptHead(format!("invalid head generation `{number}`"))
            })?;
            if latest
                .as_ref()
                .is_none_or(|(current, _)| generation > *current)
            {
                latest = Some((generation, entry.path()));
            }
        }
        let Some((generation, path)) = latest else {
            return Ok(None);
        };
        let bytes = read_small_regular_file(&path, self.limits.max_head_bytes)?;
        let head: CacheHead = serde_json::from_slice(&bytes)
            .map_err(|error| CacheError::CorruptHead(error.to_string()))?;
        validate_head(&head, identity_digest, generation)?;
        Ok(Some(head))
    }

    fn read_head_generation(
        &self,
        identity_digest: &ContentDigest,
        generation: u64,
    ) -> Result<Option<CacheHead>, CacheError> {
        let directory = self.head_directory(identity_digest)?;
        let path = directory.join(format!("{generation:020}.head"));
        let bytes = match read_small_regular_file(&path, self.limits.max_head_bytes) {
            Ok(bytes) => bytes,
            Err(CacheError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let head: CacheHead = serde_json::from_slice(&bytes)
            .map_err(|error| CacheError::CorruptHead(error.to_string()))?;
        validate_head(&head, identity_digest, generation)?;
        Ok(Some(head))
    }

    fn append_head(&self, head: &CacheHead) -> Result<(), CacheError> {
        validate_head(head, &head.identity_digest, head.generation)?;
        let directory = self.head_directory(&head.identity_digest)?;
        let final_path = directory.join(format!(
            "{:0width$}.head",
            head.generation,
            width = HEAD_GENERATION_WIDTH
        ));
        let bytes = serde_json::to_vec(head).map_err(CacheError::SerializeMetadata)?;
        if bytes.len() as u64 > self.limits.max_head_bytes {
            return Err(CacheError::MetadataLimit {
                kind: "cache head",
                limit: self.limits.max_head_bytes,
                actual: bytes.len() as u64,
            });
        }
        let temporary = reserve_temporary_file(&directory, "head")?;
        let write_result = write_temporary_metadata(&temporary, &bytes);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        match fs::hard_link(&temporary, &final_path) {
            Ok(()) => {
                fs::remove_file(&temporary)
                    .map_err(|source| io_failure("remove head temporary", &temporary, source))?;
                sync_directory(&directory)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temporary);
                Err(CacheError::HeadConflict {
                    current: self.read_head(&head.identity_digest)?,
                })
            }
            Err(source) => {
                let _ = fs::remove_file(&temporary);
                Err(io_failure("append cache head", &final_path, source))
            }
        }
    }

    fn store_manifest(&self, manifest: &CacheManifest) -> Result<ContentDigest, CacheError> {
        self.validate_manifest(manifest)?;
        let bytes = serde_json::to_vec(manifest).map_err(CacheError::SerializeMetadata)?;
        if bytes.len() as u64 > self.limits.max_manifest_bytes {
            return Err(CacheError::MetadataLimit {
                kind: "cache manifest",
                limit: self.limits.max_manifest_bytes,
                actual: bytes.len() as u64,
            });
        }
        Ok(self.cas.put_bytes(&bytes)?.digest)
    }

    fn load_entry(
        &self,
        expected_identity: &CacheIdentity,
        head: CacheHead,
    ) -> Result<CacheEntry, CacheError> {
        let bytes = self
            .cas
            .read_blob_limited(&head.manifest_digest, self.limits.max_manifest_bytes)?;
        let manifest: CacheManifest = serde_json::from_slice(&bytes)
            .map_err(|error| CacheError::InvalidManifest(error.to_string()))?;
        self.validate_manifest(&manifest)?;
        if &manifest.identity != expected_identity
            || manifest.identity_digest != head.identity_digest
            || manifest.generation != head.generation
            || manifest.fencing_generation != head.fencing_generation
            || manifest.claim_ticket_id != head.claim_ticket_id
        {
            return Err(CacheError::InvalidManifest(
                "cache head and immutable manifest do not identify the same generation".to_owned(),
            ));
        }
        let inspected = self.cas.inspect_tree(&manifest.tree.manifest_digest)?;
        if inspected != manifest.tree {
            return Err(CacheError::InvalidManifest(
                "cache tree summary does not match its manifest".to_owned(),
            ));
        }
        Ok(CacheEntry { head, manifest })
    }

    fn validate_manifest(&self, manifest: &CacheManifest) -> Result<(), CacheError> {
        if manifest.version != CACHE_MANIFEST_VERSION {
            return Err(CacheError::InvalidManifest(format!(
                "unsupported cache manifest version {}",
                manifest.version
            )));
        }
        manifest.identity.validate(self.limits)?;
        if manifest.identity.digest(self.limits)? != manifest.identity_digest {
            return Err(CacheError::InvalidManifest(
                "cache identity digest mismatch".to_owned(),
            ));
        }
        if manifest.generation == 0 || manifest.fencing_generation == 0 {
            return Err(CacheError::InvalidManifest(
                "generation and fencing generation must be positive".to_owned(),
            ));
        }
        validate_producer(&manifest.producer, self.limits)?;
        if let Some(promotion) = &manifest.promotion {
            validate_promotion_evidence(&promotion.evidence, self.limits)?;
        }
        Ok(())
    }

    fn verify_tree_content(&self, snapshot: &TreeSnapshot) -> Result<(), CacheError> {
        let inspected = self.cas.inspect_tree(&snapshot.manifest_digest)?;
        if &inspected != snapshot {
            return Err(CacheError::InvalidManifest(
                "cache tree summary does not match its CAS manifest".to_owned(),
            ));
        }
        let manifest = self.cas.load_tree_manifest(&snapshot.manifest_digest)?;
        for entry in manifest.entries {
            if let TreeEntryKind::File {
                digest, size_bytes, ..
            } = entry.kind
            {
                let verified_size = self.cas.verify_blob(&digest)?;
                if verified_size != size_bytes {
                    return Err(CacheError::InvalidManifest(format!(
                        "tree file `{}` size mismatch",
                        entry.path
                    )));
                }
            }
        }
        Ok(())
    }
}

fn validate_fence(fencing_generation: u64) -> Result<(), CacheError> {
    if fencing_generation == 0 {
        Err(CacheError::StaleFence {
            current: 1,
            attempted: 0,
        })
    } else {
        Ok(())
    }
}

fn require_fresh_fence(attempted: u64, current: Option<&CacheHead>) -> Result<(), CacheError> {
    if let Some(current) = current {
        if attempted < current.fencing_generation {
            return Err(CacheError::StaleFence {
                current: current.fencing_generation,
                attempted,
            });
        }
    }
    Ok(())
}

fn require_expected_head(
    expected: Option<&CacheHead>,
    current: Option<&CacheHead>,
) -> Result<(), CacheError> {
    let matches = match (expected, current) {
        (None, None) => true,
        (Some(expected), Some(current)) => expected == current,
        (None, Some(_)) | (Some(_), None) => false,
    };
    if matches {
        Ok(())
    } else {
        Err(CacheError::HeadConflict {
            current: current.cloned(),
        })
    }
}

fn next_generation(current: Option<&CacheHead>) -> Result<u64, CacheError> {
    current.map_or(Ok(1), |head| {
        head.generation
            .checked_add(1)
            .ok_or(CacheError::GenerationOverflow)
    })
}

fn validate_head(
    head: &CacheHead,
    expected_identity: &ContentDigest,
    expected_generation: u64,
) -> Result<(), CacheError> {
    if head.version != CACHE_HEAD_VERSION
        || &head.identity_digest != expected_identity
        || head.generation != expected_generation
        || head.generation == 0
        || head.fencing_generation == 0
    {
        return Err(CacheError::CorruptHead(
            "cache head fields do not match its immutable path".to_owned(),
        ));
    }
    Ok(())
}
use crate::{
    append_metadata, cache_ticket_subject_digest, io_failure, read_small_regular_file,
    require_directory, reserve_temporary_file, sync_directory, validate_identifier,
    validate_producer, validate_promotion_evidence, write_temporary_metadata, CacheEntry,
    CacheError, CacheHead, CacheIdentity, CacheLimits, CacheManifest, CacheProducer,
    CacheTicketOperation, CacheWriteTicket, CacheWriteTicketRequest, CACHE_HEAD_VERSION,
    CACHE_MANIFEST_VERSION, CACHE_TICKET_VERSION, HEAD_GENERATION_WIDTH,
};
