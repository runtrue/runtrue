use crate::{
    Finalizer, JobValueOutputDefinition, OutputDefinition, Permissions, Runner, Scalar, Service,
    Step, StrictMap,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub needs: Vec<String>,
    #[serde(default, rename = "if")]
    pub condition: Option<String>,
    /// Immutable human-readable reusable-workflow reference. The compiler
    /// resolves this through `.runtrue.lock` and an authenticated source bundle.
    #[serde(default)]
    pub uses: Option<String>,
    /// Static, typed arguments for a reusable-workflow call.
    #[serde(default, rename = "with")]
    pub inputs: StrictMap<Scalar>,
    #[serde(default)]
    pub trust: Trust,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub runner: Runner,
    #[serde(default)]
    pub permissions: Option<Permissions>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub retries: u32,
    #[serde(default)]
    pub matrix: StrictMap<Vec<Scalar>>,
    /// Runtime matrix input produced through a declared structured output.
    /// This is mutually exclusive with `matrix` and is expanded only by the
    /// shared bounded expansion function after the producer succeeds.
    #[serde(default, rename = "dynamic-matrix")]
    pub dynamic_matrix: Option<DynamicMatrixDefinition>,
    #[serde(default)]
    pub concurrency: Option<String>,
    #[serde(default)]
    pub vars: StrictMap<Scalar>,
    #[serde(default)]
    pub services: StrictMap<Service>,
    #[serde(default)]
    pub steps: Vec<Step>,
    /// Attempt-scoped cleanup steps. These are deliberately distinct from
    /// normal steps so cancellation and required-cleanup behavior are signed.
    #[serde(default)]
    pub finalizers: Vec<Finalizer>,
    #[serde(default, rename = "finalizer-timeout")]
    pub finalizer_timeout: Option<String>,
    /// Typed job values projected from declared step outputs. Artifact file
    /// outputs remain in `outputs`; these values never name workspace paths.
    #[serde(default, rename = "value-outputs")]
    pub value_outputs: StrictMap<JobValueOutputDefinition>,
    #[serde(default)]
    pub outputs: StrictMap<OutputDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicMatrixDefinition {
    /// Context path `needs.<job>.outputs.<name>`.
    pub from: String,
    #[serde(rename = "max-jobs")]
    pub max_jobs: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trust {
    #[default]
    UntrustedOk,
    TrustedOnly,
    ProtectedBranchOnly,
}
