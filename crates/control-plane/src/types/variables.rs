use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VariableSnapshot {
    pub id: String,
    pub tenant_id: String,
    pub scope: String,
    pub version: u64,
    pub values: BTreeMap<String, Value>,
    pub digest: ContentDigest,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VariableRecord {
    pub tenant_id: String,
    pub scope: String,
    pub name: String,
    pub value: Value,
    pub version: u64,
    pub updated_unix_ms: u64,
}
