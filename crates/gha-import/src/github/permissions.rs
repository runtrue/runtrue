use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum GithubPermissions {
    Keyword(String),
    Map(BTreeMap<String, YamlValue>),
}
