use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum GithubTriggers {
    One(String),
    Many(Vec<String>),
    Map(BTreeMap<String, YamlValue>),
}
