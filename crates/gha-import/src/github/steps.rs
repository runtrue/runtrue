use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct GithubStep {
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) run: Option<YamlValue>,
    #[serde(default)]
    pub(crate) uses: Option<YamlValue>,
    #[serde(default, rename = "with")]
    pub(crate) inputs: BTreeMap<String, YamlValue>,
    #[serde(default)]
    pub(crate) env: BTreeMap<String, YamlValue>,
    #[serde(default)]
    pub(crate) shell: Option<YamlValue>,
    #[serde(default, rename = "working-directory")]
    pub(crate) working_directory: Option<YamlValue>,
    #[serde(default, rename = "if")]
    pub(crate) condition: Option<YamlValue>,
    #[serde(default, rename = "continue-on-error")]
    pub(crate) continue_on_error: Option<YamlValue>,
    #[serde(default, rename = "timeout-minutes")]
    pub(crate) timeout_minutes: Option<YamlValue>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, YamlValue>,
}
