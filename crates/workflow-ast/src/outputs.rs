use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowOutputDefinition {
    /// A context path of the form `needs.<job>.outputs.<output>`.
    pub from: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobValueOutputDefinition {
    /// Context path `steps.<step>.outputs.<name>`.
    pub from: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepOutputDefinition {
    #[serde(rename = "type")]
    pub kind: StepOutputType,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepOutputType {
    String,
    Integer,
    Number,
    Boolean,
    Json,
    ArtifactReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputDefinition {
    pub path: String,
    #[serde(default = "default_retention")]
    pub retention: String,
    #[serde(default)]
    pub classification: ArtifactClassification,
}

fn default_retention() -> String {
    "7d".to_owned()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactClassification {
    #[default]
    UntrustedBuild,
    Quarantined,
    VerifiedTestOutput,
    ReleaseCandidate,
    PromotedRelease,
    Sensitive,
    Public,
}
