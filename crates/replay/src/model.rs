use runtrue_engine::{JobState, RunState, StepState};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{ExecutionCapsule, WorkflowFrontendReportArtifact};
use serde::{Deserialize, Serialize};

pub const REPLAY_SCHEMA_VERSION: u32 = 1;
pub const MAX_REPLAY_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBundle {
    pub schema_version: u32,
    /// The immutable Capsule reproduced by this bundle.
    ///
    /// This field is part of the canonical Replay Bundle digest.
    pub capsule: ExecutionCapsule,
    pub capsule_digest: ContentDigest,
    pub approval_subject_digest: ContentDigest,
    pub required_secret_metadata_ids: Vec<String>,
    pub input_artifact_digests: Vec<ContentDigest>,
    pub artifact_references: Vec<ContentDigest>,
    pub cache_references: Vec<ContentDigest>,
    /// Client-produced translation diagnostics bound by the signed capsule.
    /// This is a compilation artifact, not Provider Evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_frontend_report: Option<WorkflowFrontendReportArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ReplayOutcome>,
}

impl ReplayBundle {
    /// Return the immutable Capsule carried by this Replay Bundle.
    #[must_use]
    pub const fn capsule(&self) -> &ExecutionCapsule {
        &self.capsule
    }

    /// Return the digest that identifies the carried Capsule.
    #[must_use]
    pub const fn capsule_digest(&self) -> &ContentDigest {
        &self.capsule_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayOutcome {
    pub state: RunState,
    pub jobs: Vec<ReplayJobOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayJobOutcome {
    pub id: String,
    pub state: JobState,
    pub attempts: Vec<ReplayAttemptOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAttemptOutcome {
    pub number: u32,
    pub steps: Vec<ReplayStepOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayStepOutcome {
    pub id: String,
    pub state: StepState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub continued_on_error: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayEnvelope {
    pub bundle: ReplayBundle,
    pub bundle_digest: ContentDigest,
}
