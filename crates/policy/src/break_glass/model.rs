use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) const BREAK_GLASS_DOMAIN: &[u8] = b"runtrue.break-glass.subject.v1\0";
pub const MAX_BREAK_GLASS_DURATION_MS: u64 = 15 * 60 * 1_000;
pub const MAX_BREAK_GLASS_MFA_AGE_MS: u64 = 5 * 60 * 1_000;
pub const MAX_BREAK_GLASS_TEXT_BYTES: usize = 2_000;
pub const MAX_BREAK_GLASS_APPROVERS: usize = 1_000;

pub(super) const NEVER_BREAK_GLASS_ACTIONS: [&str; 3] = [
    "RevealNonExportableSigningKey",
    "DeleteAuditEvent",
    "SuppressAuditEvent",
];
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakGlassStatus {
    PendingApproval,
    PendingNotification,
    Active,
    Denied,
    Expired,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBreakGlassRequest {
    pub id: String,
    pub tenant_id: String,
    pub requester_id: String,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub reason: String,
    pub incident_reference: String,
    pub requested_unix_ms: u64,
    pub requester_mfa_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub require_second_approver: bool,
    pub eligible_approvers: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassApproval {
    pub actor_id: String,
    pub approve: bool,
    pub reason: String,
    pub subject_digest: ContentDigest,
    pub decided_unix_ms: u64,
    pub actor_mfa_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassNotificationReceipt {
    pub subject_digest: ContentDigest,
    pub channel: String,
    pub delivery_id: String,
    pub notified_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassUse {
    pub subject_digest: ContentDigest,
    pub actor_id: String,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub incident_reference: String,
    pub used_unix_ms: u64,
    pub reauthenticated_unix_ms: u64,
}

/// Exact-action emergency authorization. It becomes usable only after any
/// required independent approval and an acknowledged external notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassRequest {
    pub id: String,
    pub tenant_id: String,
    pub requester_id: String,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub reason: String,
    pub incident_reference: String,
    pub requested_unix_ms: u64,
    pub requester_mfa_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub require_second_approver: bool,
    pub eligible_approvers: BTreeSet<String>,
    pub subject_digest: ContentDigest,
    pub status: BreakGlassStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<BreakGlassApproval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification: Option<BreakGlassNotificationReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_record: Option<BreakGlassUse>,
}
