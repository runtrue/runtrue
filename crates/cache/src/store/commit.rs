use runtrue_storage::TreeSnapshot;

impl CacheStore {
    pub fn commit_ticketed_snapshot(
        &self,
        request: &CacheSnapshotCommitRequest<'_>,
    ) -> Result<CacheEntry, CacheError> {
        self.validate_presented_ticket(request.ticket)?;
        if request.ticket.operation != CacheTicketOperation::Commit {
            return Err(CacheError::TicketScopeMismatch);
        }
        if self.claimed_cache_entry(request.ticket)?.is_some() {
            return Err(CacheError::TicketConsumed);
        }
        if request.now_unix_seconds < request.ticket.issued_at_unix_seconds {
            return Err(CacheError::TicketNotYetValid);
        }
        if request.now_unix_seconds >= request.ticket.expires_at_unix_seconds {
            return Err(CacheError::TicketExpired);
        }
        if request.active_tenant_id != request.ticket.tenant_id
            || request.active_repository_id != request.ticket.repository_id
            || request.active_job_id != request.ticket.job_id
            || request.active_step_id != request.ticket.step_id
            || request.active_writer_trust_domain != &request.ticket.writer_trust_domain
        {
            return Err(CacheError::TicketScopeMismatch);
        }
        if request.active_lease_id != request.ticket.lease_id {
            return Err(CacheError::LeaseMismatch);
        }
        if request.active_fencing_generation != request.ticket.fencing_generation {
            return Err(CacheError::StaleFence {
                current: request.active_fencing_generation,
                attempted: request.ticket.fencing_generation,
            });
        }
        if request.producer.job_id != request.ticket.job_id
            || request.producer.step_id != request.ticket.step_id
            || request.producer.lease_id != request.ticket.lease_id
            || request.producer.capsule_digest != request.ticket.producer_capsule_digest
        {
            return Err(CacheError::TicketScopeMismatch);
        }
        if request.snapshot.total_file_bytes > request.ticket.max_total_bytes {
            return Err(CacheError::CacheContentTooLarge {
                limit: request.ticket.max_total_bytes,
                actual: request.snapshot.total_file_bytes,
            });
        }
        if request
            .ticket
            .expected_tree_manifest_digest
            .as_ref()
            .is_some_and(|expected| expected != &request.snapshot.manifest_digest)
        {
            return Err(CacheError::TicketContentMismatch);
        }

        let prepared = self.prepare_commit(
            &request.ticket.writer_trust_domain,
            request.ticket.identity.clone(),
            request.ticket.expected_head.as_ref(),
            request.ticket.fencing_generation,
            request.producer.clone(),
            Some(request.ticket.ticket_id.clone()),
        )?;
        match self.publish_verified_tree(prepared, request.snapshot.clone()) {
            Ok(entry) => Ok(entry),
            Err(error @ CacheError::HeadConflict { .. }) => {
                if self.claimed_cache_entry(request.ticket)?.is_some() {
                    Err(CacheError::TicketConsumed)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Resolve the immutable generation bound into a restore ticket.
    pub fn ticketed_restore_entry(
        &self,
        request: &CacheRestoreRequest<'_>,
    ) -> Result<Option<CacheEntry>, CacheError> {
        let ticket = request.ticket;
        self.validate_presented_ticket(ticket)?;
        if ticket.operation != CacheTicketOperation::Restore
            || ticket.tenant_id != request.active_tenant_id
            || ticket.repository_id != request.active_repository_id
            || ticket.job_id != request.active_job_id
            || ticket.job_attempt != request.active_job_attempt
            || ticket.step_id != request.active_step_id
            || ticket.lease_id != request.active_lease_id
            || ticket.fencing_generation != request.active_fencing_generation
        {
            return Err(CacheError::TicketScopeMismatch);
        }
        if request.now_unix_seconds < ticket.issued_at_unix_seconds {
            return Err(CacheError::TicketNotYetValid);
        }
        if request.now_unix_seconds >= ticket.expires_at_unix_seconds {
            return Err(CacheError::TicketExpired);
        }
        let Some(head) = ticket.expected_head.clone() else {
            return Ok(None);
        };
        let entry = self.load_entry(&ticket.identity, head)?;
        if ticket.expected_tree_manifest_digest.as_ref()
            != Some(&entry.manifest.tree.manifest_digest)
        {
            return Err(CacheError::TicketContentMismatch);
        }
        self.verify_tree_content(&entry.manifest.tree)?;
        Ok(Some(entry))
    }

    /// Recover the exact immutable generation claimed by a ticket even if a
    /// later generation has become current.
    pub fn claimed_cache_entry(
        &self,
        ticket: &CacheWriteTicket,
    ) -> Result<Option<CacheEntry>, CacheError> {
        self.validate_presented_ticket(ticket)?;
        let generation = next_generation(ticket.expected_head.as_ref())?;
        let Some(head) = self.read_head_generation(&ticket.identity_digest, generation)? else {
            return Ok(None);
        };
        if head.claim_ticket_id.as_ref() != Some(&ticket.ticket_id) {
            return Ok(None);
        }
        let entry = self.load_entry(&ticket.identity, head)?;
        if entry.manifest.claim_ticket_id.as_ref() != Some(&ticket.ticket_id)
            || entry.manifest.generation != generation
            || entry.manifest.fencing_generation != ticket.fencing_generation
            || entry.manifest.producer.job_id != ticket.job_id
            || entry.manifest.producer.step_id != ticket.step_id
            || entry.manifest.producer.lease_id != ticket.lease_id
            || entry.manifest.producer.capsule_digest != ticket.producer_capsule_digest
            || entry.manifest.tree.total_file_bytes > ticket.max_total_bytes
            || ticket
                .expected_tree_manifest_digest
                .as_ref()
                .is_some_and(|expected| expected != &entry.manifest.tree.manifest_digest)
        {
            return Err(CacheError::InvalidTicketClaim(
                "claimed generation does not match the immutable ticket subject".to_owned(),
            ));
        }
        self.verify_tree_content(&entry.manifest.tree)?;
        Ok(Some(entry))
    }

    /// Capture and commit a new generation. `expected_head` is `None` only for
    /// creation; subsequent writes require the exact current token.
    pub fn commit_tree(
        &self,
        writer: &TrustDomain,
        identity: CacheIdentity,
        source: impl AsRef<Path>,
        expected_head: Option<&CacheHead>,
        fencing_generation: u64,
        producer: CacheProducer,
    ) -> Result<CacheEntry, CacheError> {
        let prepared = self.prepare_commit(
            writer,
            identity,
            expected_head,
            fencing_generation,
            producer,
            None,
        )?;
        let tree = self.cas.capture_tree(source)?;
        self.publish_verified_tree(prepared, tree)
    }

    fn prepare_commit(
        &self,
        writer: &TrustDomain,
        identity: CacheIdentity,
        expected_head: Option<&CacheHead>,
        fencing_generation: u64,
        producer: CacheProducer,
        claim_ticket_id: Option<ContentDigest>,
    ) -> Result<PreparedCacheCommit, CacheError> {
        identity.validate(self.limits)?;
        if !writer.can_write_to(&identity.trust_domain) {
            return Err(CacheError::UnauthorizedWrite);
        }
        validate_fence(fencing_generation)?;
        validate_producer(&producer, self.limits)?;
        let identity_digest = identity.digest(self.limits)?;
        let current = self.read_head(&identity_digest)?;
        require_expected_head(expected_head, current.as_ref())?;
        require_fresh_fence(fencing_generation, current.as_ref())?;
        let generation = next_generation(current.as_ref())?;
        Ok(PreparedCacheCommit {
            identity,
            identity_digest,
            generation,
            fencing_generation,
            producer,
            claim_ticket_id,
        })
    }

    fn publish_verified_tree(
        &self,
        prepared: PreparedCacheCommit,
        tree: TreeSnapshot,
    ) -> Result<CacheEntry, CacheError> {
        self.verify_tree_content(&tree)?;
        let manifest = CacheManifest {
            version: CACHE_MANIFEST_VERSION,
            identity: prepared.identity,
            identity_digest: prepared.identity_digest.clone(),
            generation: prepared.generation,
            fencing_generation: prepared.fencing_generation,
            tree,
            producer: prepared.producer,
            claim_ticket_id: prepared.claim_ticket_id.clone(),
            promotion: None,
        };
        let manifest_digest = self.store_manifest(&manifest)?;
        let head = CacheHead {
            version: CACHE_HEAD_VERSION,
            identity_digest: prepared.identity_digest,
            generation: prepared.generation,
            fencing_generation: prepared.fencing_generation,
            manifest_digest,
            claim_ticket_id: prepared.claim_ticket_id,
        };
        self.append_head(&head)?;
        Ok(CacheEntry { head, manifest })
    }
}
use super::{
    next_generation, require_expected_head, require_fresh_fence, validate_fence,
    PreparedCacheCommit,
};
use crate::{
    validate_producer, CacheEntry, CacheError, CacheHead, CacheIdentity, CacheManifest,
    CacheProducer, CacheRestoreRequest, CacheSnapshotCommitRequest, CacheStore,
    CacheTicketOperation, CacheWriteTicket, TrustDomain, CACHE_HEAD_VERSION,
    CACHE_MANIFEST_VERSION,
};
use runtrue_model::ContentDigest;
use std::path::Path;
