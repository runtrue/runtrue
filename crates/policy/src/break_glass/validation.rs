use super::{
    BreakGlassStatus, NewBreakGlassRequest, BREAK_GLASS_DOMAIN, MAX_BREAK_GLASS_DURATION_MS,
    MAX_BREAK_GLASS_MFA_AGE_MS, MAX_BREAK_GLASS_TEXT_BYTES,
};
use runtrue_model::ContentDigest;
use thiserror::Error;
pub(super) fn subject_digest(request: &NewBreakGlassRequest) -> ContentDigest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(BREAK_GLASS_DOMAIN);
    for value in [
        request.id.as_str(),
        request.tenant_id.as_str(),
        request.requester_id.as_str(),
        request.action.as_str(),
        request.resource_kind.as_str(),
        request.resource_id.as_str(),
        request.reason.as_str(),
        request.incident_reference.as_str(),
    ] {
        let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&request.requested_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&request.requester_mfa_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&request.expires_unix_ms.to_be_bytes());
    bytes.push(u8::from(request.require_second_approver));
    for approver in &request.eligible_approvers {
        let length = u64::try_from(approver.len()).unwrap_or(u64::MAX);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(approver.as_bytes());
    }
    ContentDigest::sha256(bytes)
}

pub(super) fn validate_recent_mfa(
    mfa_unix_ms: u64,
    action_unix_ms: u64,
) -> Result<(), BreakGlassError> {
    if mfa_unix_ms > action_unix_ms
        || action_unix_ms.saturating_sub(mfa_unix_ms) > MAX_BREAK_GLASS_MFA_AGE_MS
    {
        return Err(BreakGlassError::RecentMfaRequired);
    }
    Ok(())
}

pub(super) fn validate_text(kind: &'static str, value: &str) -> Result<(), BreakGlassError> {
    if value.trim().is_empty()
        || value.len() > MAX_BREAK_GLASS_TEXT_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(BreakGlassError::InvalidText(kind));
    }
    Ok(())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BreakGlassError {
    #[error("invalid break-glass {0}")]
    InvalidText(&'static str),
    #[error("action `{0}` can never be authorized through break-glass")]
    PermanentlyForbiddenAction(String),
    #[error(
        "break-glass duration must be positive and no more than {MAX_BREAK_GLASS_DURATION_MS}ms"
    )]
    InvalidDuration,
    #[error("recent MFA is required for break-glass")]
    RecentMfaRequired,
    #[error("break-glass independent approver set is invalid")]
    InvalidApproverSet,
    #[error("break-glass state does not permit the operation: {0:?}")]
    InvalidState(BreakGlassStatus),
    #[error("break-glass subject, actor, action, or resource does not match")]
    SubjectMismatch,
    #[error("actor is not an eligible independent break-glass approver")]
    IneligibleApprover,
    #[error("break-glass approval time is invalid")]
    InvalidDecisionTime,
    #[error("break-glass notification time is invalid")]
    InvalidNotificationTime,
    #[error("persisted break-glass request does not match its exact evidence history")]
    IntegrityMismatch,
}
