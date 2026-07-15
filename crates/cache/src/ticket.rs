use crate::{default_job_attempt, CacheError, CacheHead, CacheIdentity, TrustDomain};
use runtrue_model::ContentDigest;
use runtrue_storage::TreeSnapshot;
use serde::{Deserialize, Serialize};

/// Immutable producer identity retained on every generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheProducer {
    pub capsule_digest: ContentDigest,
    pub job_id: String,
    pub step_id: String,
    pub lease_id: String,
}

/// Operation authorized by a durable cache write ticket. New operations must
/// define separate validation and claim semantics; only `Commit` is accepted
/// by this version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CacheTicketOperation {
    Commit,
    Restore,
}

/// Immutable, server-persisted, one-use authority to publish one cache
/// generation under an exact lease, fence, trust domain, identity, and head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheWriteTicket {
    pub ticket_version: u32,
    pub ticket_id: ContentDigest,
    pub nonce: ContentDigest,
    pub operation: CacheTicketOperation,
    pub tenant_id: String,
    pub repository_id: String,
    pub job_id: String,
    #[serde(default = "default_job_attempt")]
    pub job_attempt: u32,
    pub step_id: String,
    pub lease_id: String,
    pub producer_capsule_digest: ContentDigest,
    pub fencing_generation: u64,
    pub writer_trust_domain: TrustDomain,
    pub identity: CacheIdentity,
    pub identity_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_head: Option<CacheHead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_tree_manifest_digest: Option<ContentDigest>,
    pub max_total_bytes: u64,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheWriteTicketRequest {
    pub operation: CacheTicketOperation,
    pub tenant_id: String,
    pub repository_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub lease_id: String,
    pub producer_capsule_digest: ContentDigest,
    pub fencing_generation: u64,
    pub writer_trust_domain: TrustDomain,
    pub identity: CacheIdentity,
    pub expected_head: Option<CacheHead>,
    pub expected_tree_manifest_digest: Option<ContentDigest>,
    pub max_total_bytes: u64,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

/// Commit a tree that a preceding upload phase already placed in this store's
/// CAS. The CAS is fully reverified before the append-only head is published.
pub struct CacheSnapshotCommitRequest<'a> {
    pub ticket: &'a CacheWriteTicket,
    pub active_tenant_id: &'a str,
    pub active_repository_id: &'a str,
    pub active_job_id: &'a str,
    pub active_step_id: &'a str,
    pub active_lease_id: &'a str,
    pub active_fencing_generation: u64,
    pub active_writer_trust_domain: &'a TrustDomain,
    pub now_unix_seconds: u64,
    pub snapshot: &'a TreeSnapshot,
    pub producer: CacheProducer,
}

pub struct CacheRestoreRequest<'a> {
    pub ticket: &'a CacheWriteTicket,
    pub active_tenant_id: &'a str,
    pub active_repository_id: &'a str,
    pub active_job_id: &'a str,
    pub active_job_attempt: u32,
    pub active_step_id: &'a str,
    pub active_lease_id: &'a str,
    pub active_fencing_generation: u64,
    pub now_unix_seconds: u64,
}
pub(crate) fn cache_ticket_subject_digest(
    ticket: &CacheWriteTicket,
) -> Result<ContentDigest, CacheError> {
    #[derive(Serialize)]
    struct Subject<'a> {
        ticket_version: u32,
        nonce: &'a ContentDigest,
        operation: CacheTicketOperation,
        tenant_id: &'a str,
        repository_id: &'a str,
        job_id: &'a str,
        step_id: &'a str,
        lease_id: &'a str,
        producer_capsule_digest: &'a ContentDigest,
        fencing_generation: u64,
        writer_trust_domain: &'a TrustDomain,
        identity: &'a CacheIdentity,
        identity_digest: &'a ContentDigest,
        expected_head: &'a Option<CacheHead>,
        expected_tree_manifest_digest: &'a Option<ContentDigest>,
        max_total_bytes: u64,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    }
    let subject = Subject {
        ticket_version: ticket.ticket_version,
        nonce: &ticket.nonce,
        operation: ticket.operation,
        tenant_id: &ticket.tenant_id,
        repository_id: &ticket.repository_id,
        job_id: &ticket.job_id,
        step_id: &ticket.step_id,
        lease_id: &ticket.lease_id,
        producer_capsule_digest: &ticket.producer_capsule_digest,
        fencing_generation: ticket.fencing_generation,
        writer_trust_domain: &ticket.writer_trust_domain,
        identity: &ticket.identity,
        identity_digest: &ticket.identity_digest,
        expected_head: &ticket.expected_head,
        expected_tree_manifest_digest: &ticket.expected_tree_manifest_digest,
        max_total_bytes: ticket.max_total_bytes,
        issued_at_unix_seconds: ticket.issued_at_unix_seconds,
        expires_at_unix_seconds: ticket.expires_at_unix_seconds,
    };
    let bytes = serde_json::to_vec(&subject).map_err(CacheError::SerializeMetadata)?;
    Ok(ContentDigest::sha256(bytes))
}

pub(crate) fn validate_producer(
    producer: &CacheProducer,
    limits: crate::CacheLimits,
) -> Result<(), CacheError> {
    crate::validate_identifier("producer.job_id", &producer.job_id, limits)?;
    crate::validate_identifier("producer.step_id", &producer.step_id, limits)?;
    crate::validate_identifier("producer.lease_id", &producer.lease_id, limits)
}
