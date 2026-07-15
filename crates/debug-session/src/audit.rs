use crate::{canonical_digest, DebugSessionError, DebugSessionRecord};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugAuditKind {
    Opened,
    Connected,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugAuditEvent {
    pub event_id: ContentDigest,
    pub kind: DebugAuditKind,
    pub session_id: String,
    pub tenant_id: String,
    pub run_id: String,
    pub job_id: String,
    pub actor_id: String,
    pub approval_id: String,
    pub approval_subject_digest: ContentDigest,
    pub occurred_unix_ms: u64,
}

pub trait DebugAuditSink {
    fn record(&mut self, event: &DebugAuditEvent) -> Result<(), DebugSessionError>;
}

pub(crate) fn debug_audit_event(
    kind: DebugAuditKind,
    record: &DebugSessionRecord,
    occurred_unix_ms: u64,
) -> Result<DebugAuditEvent, DebugSessionError> {
    #[derive(Serialize)]
    struct AuditIdentity<'a> {
        kind: DebugAuditKind,
        session_id: &'a str,
        approval_subject_digest: &'a ContentDigest,
    }
    let identity = AuditIdentity {
        kind,
        session_id: &record.session_id,
        approval_subject_digest: &record.approval_subject_digest,
    };
    Ok(DebugAuditEvent {
        event_id: canonical_digest(&identity)?,
        kind,
        session_id: record.session_id.clone(),
        tenant_id: record.tenant_id.clone(),
        run_id: record.run_id.clone(),
        job_id: record.job_id.clone(),
        actor_id: record.actor_id.clone(),
        approval_id: record.approval_id.clone(),
        approval_subject_digest: record.approval_subject_digest.clone(),
        occurred_unix_ms,
    })
}
