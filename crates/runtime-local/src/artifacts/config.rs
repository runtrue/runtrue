use runtrue_artifacts::{ArtifactClassification as StoredArtifactClassification, ArtifactLimits};
use runtrue_model::ContentDigest;
use runtrue_storage::CasLimits;
use serde::Serialize;
use std::path::PathBuf;

/// Local immutable artifact-store identity and resource policy.
#[derive(Debug, Clone)]
pub struct LocalArtifactConfig {
    pub workspace: PathBuf,
    pub artifact_root: PathBuf,
    pub tenant_id: String,
    pub repository_id: String,
    pub runner_id: String,
    pub runner_image_digest: ContentDigest,
    pub ticket_lifetime_seconds: u64,
    pub artifact_limits: ArtifactLimits,
    pub cas_limits: CasLimits,
}

impl LocalArtifactConfig {
    #[must_use]
    pub fn for_workspace(workspace: impl Into<PathBuf>) -> Self {
        let workspace = workspace.into();
        let runner_id = format!(
            "local-native/{}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        Self {
            artifact_root: workspace.join(".runtrue/artifacts"),
            workspace,
            tenant_id: "local-tenant".to_owned(),
            repository_id: "local-workspace".to_owned(),
            runner_image_digest: ContentDigest::sha256(runner_id.as_bytes()),
            runner_id,
            ticket_lifetime_seconds: 300,
            artifact_limits: ArtifactLimits::default(),
            cas_limits: CasLimits::default(),
        }
    }
}

/// Captured durable output surfaced by the CLI and replay bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalArtifactCapture {
    pub job_id: String,
    pub output_name: String,
    pub source_path: String,
    pub artifact_id: ContentDigest,
    pub content_digest: ContentDigest,
    pub classification: StoredArtifactClassification,
    pub retention_until_unix_seconds: u64,
}
