use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRecord {
    pub id: String,
    pub tenant_id: String,
    pub owner: String,
    pub name: String,
    pub default_branch: String,
    pub visibility: String,
    pub created_unix_ms: u64,
}
