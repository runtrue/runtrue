use crate::daemon::RunnerError;
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_storage::PathSnapshot;
use runtrue_workflow_ir::ArtifactClassification;
use serde::Serialize;

pub(super) fn snapshot_identity(
    snapshot: &PathSnapshot,
) -> (ContentDigest, u64, ContentDigest, &'static str) {
    match snapshot {
        PathSnapshot::File {
            digest, size_bytes, ..
        } => (
            digest.clone(),
            *size_bytes,
            digest.clone(),
            "application/octet-stream",
        ),
        PathSnapshot::Directory {
            manifest_digest,
            total_file_bytes,
            ..
        } => (
            manifest_digest.clone(),
            *total_file_bytes,
            manifest_digest.clone(),
            "application/vnd.runtrue.tree+json",
        ),
    }
}

pub(super) const fn classification_name(value: ArtifactClassification) -> &'static str {
    match value {
        ArtifactClassification::UntrustedBuild => "untrusted-build",
        ArtifactClassification::Quarantined => "quarantined",
        ArtifactClassification::VerifiedTestOutput => "verified-test-output",
        ArtifactClassification::ReleaseCandidate => "release-candidate",
        ArtifactClassification::PromotedRelease => "promoted-release",
        ArtifactClassification::Sensitive => "sensitive",
        ArtifactClassification::Public => "public",
    }
}

pub(super) fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, RunnerError> {
    serde_json::to_vec(value).map_err(|error| RunnerError::DataPlane(error.to_string()))
}

pub(super) fn canonical_json<T>(bytes: &[u8], kind: &str) -> Result<T, RunnerError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| RunnerError::DataPlane(format!("invalid {kind}: {error}")))?;
    if canonical_bytes(&value)? != bytes {
        return Err(RunnerError::DataPlane(format!("noncanonical {kind}")));
    }
    Ok(value)
}

pub(super) fn wire_digest(digest: &ContentDigest) -> Result<v1::Digest, RunnerError> {
    v1::Digest::try_from(digest)
        .map_err(|_| RunnerError::DataPlane("digest cannot be encoded".to_owned()))
}
