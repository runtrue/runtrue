use super::{GithubPermissions, GithubStep};
use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct GithubJob {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) needs: Option<YamlValue>,
    #[serde(default, rename = "runs-on")]
    pub(crate) runs_on: Option<YamlValue>,
    #[serde(default, rename = "if")]
    pub(crate) condition: Option<YamlValue>,
    #[serde(default)]
    pub(crate) permissions: Option<GithubPermissions>,
    #[serde(default)]
    pub(crate) env: BTreeMap<String, YamlValue>,
    #[serde(default)]
    pub(crate) strategy: Option<GithubStrategy>,
    #[serde(default)]
    pub(crate) services: BTreeMap<String, GithubService>,
    #[serde(default)]
    pub(crate) steps: Vec<GithubStep>,
    #[serde(default, rename = "timeout-minutes")]
    pub(crate) timeout_minutes: Option<YamlValue>,
    #[serde(default)]
    pub(crate) outputs: BTreeMap<String, YamlValue>,
    #[serde(default)]
    pub(crate) uses: Option<YamlValue>,
    #[serde(default)]
    pub(crate) secrets: Option<YamlValue>,
    #[serde(default)]
    pub(crate) container: Option<YamlValue>,
    #[serde(default)]
    pub(crate) defaults: Option<YamlValue>,
    #[serde(default)]
    pub(crate) concurrency: Option<YamlValue>,
    #[serde(default)]
    pub(crate) environment: Option<YamlValue>,
    #[serde(default, rename = "continue-on-error")]
    pub(crate) continue_on_error: Option<YamlValue>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, YamlValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct GithubStrategy {
    #[serde(default)]
    pub(crate) matrix: Option<YamlValue>,
    #[serde(default, rename = "fail-fast")]
    pub(crate) fail_fast: Option<YamlValue>,
    #[serde(default, rename = "max-parallel")]
    pub(crate) max_parallel: Option<YamlValue>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, YamlValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct GithubService {
    #[serde(default)]
    pub(crate) image: Option<YamlValue>,
    #[serde(default)]
    pub(crate) env: BTreeMap<String, YamlValue>,
    #[serde(default)]
    pub(crate) ports: Vec<YamlValue>,
    #[serde(default)]
    pub(crate) options: Option<YamlValue>,
    #[serde(default)]
    pub(crate) credentials: Option<YamlValue>,
    #[serde(default)]
    pub(crate) volumes: Option<YamlValue>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, YamlValue>,
}
