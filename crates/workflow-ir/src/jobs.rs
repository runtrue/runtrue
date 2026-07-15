use crate::{
    ArtifactOutput, JobValueOutput, PermissionSet, PlannedStep, ScalarValue, ValueBinding,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedJob {
    pub id: String,
    pub base_id: String,
    pub name: String,
    pub needs: Vec<String>,
    pub matrix: BTreeMap<String, ScalarValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    pub trust: Trust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub runner: RunnerRequirements,
    pub permissions: PermissionSet,
    pub timeout_ms: u64,
    pub retries: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<String>,
    pub variables: BTreeMap<String, ScalarValue>,
    pub services: Vec<PlannedService>,
    pub steps: Vec<PlannedStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finalizers: Vec<PlannedFinalizer>,
    #[serde(
        default = "default_finalizer_timeout_ms",
        skip_serializing_if = "is_default_finalizer_timeout_ms"
    )]
    pub finalizer_timeout_ms: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub value_outputs: BTreeMap<String, JobValueOutput>,
    pub outputs: BTreeMap<String, ArtifactOutput>,
}

const fn default_finalizer_timeout_ms() -> u64 {
    120_000
}
const fn is_default_finalizer_timeout_ms(value: &u64) -> bool {
    *value == default_finalizer_timeout_ms()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedFinalizer {
    pub step: PlannedStep,
    pub required: bool,
    pub run_on_cancel: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trust {
    UntrustedOk,
    TrustedOnly,
    ProtectedBranchOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRequirements {
    pub os: OperatingSystem,
    pub arch: Architecture,
    pub isolation: Isolation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    pub cpu: u16,
    pub memory_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    Linux,
    Windows,
    Macos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    Amd64,
    Arm64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Isolation {
    Wasm,
    Oci,
    Microvm,
    Native,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedService {
    pub id: String,
    pub image: String,
    pub ports: Vec<u16>,
    pub environment: BTreeMap<String, ValueBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<Healthcheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Healthcheck {
    pub command: Vec<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub retries: u32,
}
