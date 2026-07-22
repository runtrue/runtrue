use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Identifies the boundary at which an event entered the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableEventSource {
    Frontend,
    Backend,
    System,
}

impl DurableEventSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Frontend => "frontend",
            Self::Backend => "backend",
            Self::System => "system",
        }
    }
}

/// An immutable event and the first durable task that dispatches it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableEventRecord {
    pub id: String,
    pub tenant_id: String,
    pub source: DurableEventSource,
    pub kind: String,
    pub handler_kind: String,
    pub payload: Value,
    pub payload_digest: ContentDigest,
    pub idempotency_identity: String,
    pub actor_identity: String,
    pub task_id: String,
    pub created_unix_ms: u64,
}

/// A caller-selected, idempotent request to redeliver a failed event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayEventRequest {
    pub id: String,
    pub event_id: String,
    pub requested_by: String,
    pub requested_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventReplayRecord {
    pub id: String,
    pub event_id: String,
    pub task_id: String,
    pub requested_by: String,
    pub requested_unix_ms: u64,
}
