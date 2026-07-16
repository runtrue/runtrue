use crate::{StepCapabilitySet, StepOutputSchema, ValueBinding};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedStep {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    pub action: StepAction,
    pub inputs: BTreeMap<String, ValueBinding>,
    pub environment: BTreeMap<String, ValueBinding>,
    pub capabilities: StepCapabilitySet,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheDeclaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    pub continue_on_error: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub outputs: BTreeMap<String, StepOutputSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum StepAction {
    Component {
        reference: String,
    },
    Command {
        program: String,
        args: Vec<ValueBinding>,
    },
    Container {
        entrypoint: Option<String>,
        args: Option<Vec<ValueBinding>>,
    },
    Script {
        shell: Shell,
        script: String,
        script_digest: ContentDigest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Shell {
    Bash,
    Sh,
    Pwsh,
    Cmd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDeclaration {
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub mode: CacheMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheMode {
    ReadOnly,
    ReadWrite,
    WriteOnly,
}
