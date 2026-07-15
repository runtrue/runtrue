use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPrincipal {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditResource {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuditValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Digest(ContentDigest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventData {
    pub observed_unix_ms: u64,
    pub tenant_id: String,
    pub actor: AuditPrincipal,
    pub action: String,
    pub resource: AuditResource,
    pub result: String,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, AuditValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub sequence: u64,
    pub installation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<ContentDigest>,
    pub data: AuditEventData,
    pub event_hash: ContentDigest,
}
