use crate::{InputDefinition, StrictMap};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Triggers {
    #[serde(default)]
    pub push: Option<GitTrigger>,
    #[serde(default)]
    pub pull_request: Option<GitTrigger>,
    #[serde(default)]
    pub pull_request_target: Option<WebhookTrigger>,
    #[serde(default)]
    pub issue_comment: Option<WebhookTrigger>,
    #[serde(default)]
    pub check_run: Option<WebhookTrigger>,
    #[serde(default)]
    pub merge_queue: Option<EmptyObject>,
    #[serde(default)]
    pub schedule: Vec<ScheduleTrigger>,
    #[serde(default)]
    pub manual: Option<ManualTrigger>,
    #[serde(default)]
    pub api: Option<EmptyObject>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookTrigger {
    #[serde(default)]
    pub types: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyObject {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitTrigger {
    #[serde(default)]
    pub branches: Vec<String>,
    #[serde(default, rename = "branches-ignore")]
    pub branches_ignore: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default, rename = "paths-ignore")]
    pub paths_ignore: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleTrigger {
    pub cron: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
}

fn default_timezone() -> String {
    "UTC".to_owned()
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualTrigger {
    #[serde(default)]
    pub inputs: StrictMap<InputDefinition>,
}
