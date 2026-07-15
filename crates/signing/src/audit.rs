use crate::{canonical_bytes, SigningError, SigningRequest};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAuditKind {
    Requested,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningAuditEvent {
    pub event_id: ContentDigest,
    pub kind: SigningAuditKind,
    pub request_id: String,
    pub request_digest: ContentDigest,
    pub tenant_id: String,
    pub purpose: String,
    pub approval_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_envelope_digest: Option<ContentDigest>,
    pub occurred_at_unix_seconds: u64,
}

pub trait SigningAuditSink: Send + Sync {
    fn record(&self, event: &SigningAuditEvent) -> Result<(), SigningError>;
}

pub(crate) fn audit_event(
    kind: SigningAuditKind,
    request: &SigningRequest,
    request_digest: &ContentDigest,
    signature_envelope_digest: Option<ContentDigest>,
    occurred_at_unix_seconds: u64,
) -> Result<SigningAuditEvent, SigningError> {
    #[derive(Serialize)]
    struct AuditIdentity<'a> {
        kind: SigningAuditKind,
        request_id: &'a str,
        request_digest: &'a ContentDigest,
        signature_envelope_digest: &'a Option<ContentDigest>,
    }
    let identity = AuditIdentity {
        kind,
        request_id: &request.request_id,
        request_digest,
        signature_envelope_digest: &signature_envelope_digest,
    };
    Ok(SigningAuditEvent {
        event_id: ContentDigest::sha256(canonical_bytes(&identity)?),
        kind,
        request_id: request.request_id.clone(),
        request_digest: request_digest.clone(),
        tenant_id: request.tenant_id.clone(),
        purpose: request.purpose.clone(),
        approval_id: request.approval_id.clone(),
        signature_envelope_digest,
        occurred_at_unix_seconds,
    })
}
