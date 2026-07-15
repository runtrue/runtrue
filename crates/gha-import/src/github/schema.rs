use super::{GithubJob, GithubPermissions, GithubTriggers};
use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct GithubWorkflow {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default, rename = "on")]
    pub(crate) triggers: Option<GithubTriggers>,
    #[serde(default)]
    pub(crate) permissions: Option<GithubPermissions>,
    #[serde(default)]
    pub(crate) env: BTreeMap<String, YamlValue>,
    #[serde(default)]
    pub(crate) concurrency: Option<YamlValue>,
    pub(crate) jobs: BTreeMap<String, GithubJob>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, YamlValue>,
}
