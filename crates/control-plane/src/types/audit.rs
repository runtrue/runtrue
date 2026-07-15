use serde::Deserialize;
use serde::Serialize;

/// Low-cardinality metadata copied into immutable policy/session journals so
/// an audit event can be emitted without persisting request secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct R9AuditMetadata {
    pub actor_id: String,
    pub correlation_id: String,
    pub occurred_unix_ms: u64,
}
