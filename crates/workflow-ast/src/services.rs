use crate::{StrictMap, ValueBinding};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub image: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub env: StrictMap<ValueBinding>,
    #[serde(default)]
    pub healthcheck: Option<Healthcheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Healthcheck {
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default = "default_health_interval")]
    pub interval: String,
    #[serde(default = "default_health_timeout")]
    pub timeout: String,
    #[serde(default = "default_health_retries")]
    pub retries: u32,
}

fn default_health_interval() -> String {
    "1s".to_owned()
}

fn default_health_timeout() -> String {
    "2s".to_owned()
}

const fn default_health_retries() -> u32 {
    30
}
