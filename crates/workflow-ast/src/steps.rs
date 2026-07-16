use crate::{
    Access, CachePermissions, NetworkPolicy, OidcAllow, SecretRequest, SigningRequest,
    StepOutputDefinition, StrictMap, ValueBinding,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "if")]
    pub condition: Option<String>,
    #[serde(default)]
    pub uses: Option<String>,
    #[serde(default, rename = "with")]
    pub inputs: StrictMap<ValueBinding>,
    #[serde(default)]
    pub run: Option<Run>,
    #[serde(default)]
    pub env: StrictMap<ValueBinding>,
    #[serde(default)]
    pub capabilities: StepCapabilities,
    #[serde(default)]
    pub cache: Option<CacheDeclaration>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default, rename = "continue-on-error")]
    pub continue_on_error: bool,
    /// Schema for values returned over the executor's bounded structured
    /// channel. Stdout and stderr are never interpreted as outputs.
    #[serde(default)]
    pub outputs: StrictMap<StepOutputDefinition>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finalizer {
    #[serde(flatten)]
    pub step: Step,
    /// A required finalizer may turn primary success into failure, but cannot
    /// replace a primary failure/cancellation with success.
    #[serde(default)]
    pub required: bool,
    /// Whether this finalizer is safe to execute after cancellation begins.
    #[serde(default, rename = "run-on-cancel")]
    pub run_on_cancel: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Run {
    Command(CommandRun),
    Script(ScriptRun),
    Container(ContainerRun),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerRun {
    pub container: ContainerInvocation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerInvocation {
    #[serde(default)]
    pub entrypoint: Option<String>,
    #[serde(default)]
    pub args: Option<Vec<ValueBinding>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRun {
    pub command: Vec<String>,
    #[serde(default)]
    pub args: Vec<ValueBinding>,
    #[serde(default, rename = "working-directory")]
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptRun {
    pub shell: Shell,
    pub script: String,
    #[serde(default, rename = "working-directory")]
    pub working_directory: Option<String>,
    #[serde(default, rename = "unsafe-interpolation")]
    pub unsafe_interpolation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Shell {
    Bash,
    Sh,
    Pwsh,
    Cmd,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepCapabilities {
    #[serde(default)]
    pub fs: Option<FilesystemCapabilities>,
    #[serde(default)]
    pub network: Option<NetworkPolicy>,
    #[serde(default)]
    pub secrets: Vec<SecretRequest>,
    #[serde(default)]
    pub checks: Access,
    #[serde(default)]
    pub artifacts: Access,
    #[serde(default)]
    pub cache: Option<CachePermissions>,
    #[serde(default)]
    pub oidc: Option<OidcAllow>,
    /// Exact signing operations this step may request. An empty list is deny.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signing: Vec<SigningRequest>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemCapabilities {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDeclaration {
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub mode: CacheMode,
    #[serde(default, rename = "max-size")]
    pub max_size: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheMode {
    ReadOnly,
    #[default]
    ReadWrite,
    WriteOnly,
}
