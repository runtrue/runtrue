pub const RUNNER_COMPONENT_PROFILE_DIGEST_FIELD: &str = "runtrue.component-profile-sha256";

pub fn fixed_updater_claim_proof_message(
    pool_id: &str,
    slot_id: &str,
    nonce_digest: &ContentDigest,
    issued_unix_ms: u64,
) -> Result<Vec<u8>, UpdateError> {
    fn field(message: &mut Vec<u8>, value: &[u8]) {
        message.extend_from_slice(&(value.len() as u64).to_be_bytes());
        message.extend_from_slice(value);
    }
    if !valid_text(pool_id) || !valid_text(slot_id) {
        return Err(UpdateError::InvalidRunnerComponentProfile);
    }
    let mut message = b"runtrue.fixed-updater.claim-proof.v1\0".to_vec();
    field(&mut message, pool_id.as_bytes());
    field(&mut message, slot_id.as_bytes());
    field(&mut message, nonce_digest.as_str().as_bytes());
    message.extend_from_slice(&issued_unix_ms.to_be_bytes());
    Ok(message)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerComponentProfile {
    pub component_name: String,
    pub release_version: String,
    pub artifact_name: String,
    pub artifact_length: u64,
    pub artifact_digest: ContentDigest,
    pub artifact_media_type: String,
    pub platform: String,
    pub architecture: String,
    pub installed_digest: ContentDigest,
    pub runner_version: String,
    pub engine_version: String,
    pub protocol_min: u32,
    pub protocol_max: u32,
    pub package_format: String,
    pub allowed_installation_paths: Vec<String>,
    pub allowed_modes: Vec<u32>,
}

impl RunnerComponentProfile {
    pub fn validate(&self) -> Result<(), UpdateError> {
        let strings = [
            self.component_name.as_str(),
            self.release_version.as_str(),
            self.artifact_name.as_str(),
            self.artifact_media_type.as_str(),
            self.platform.as_str(),
            self.architecture.as_str(),
            self.runner_version.as_str(),
            self.engine_version.as_str(),
        ];
        let package_valid = match self.package_format.as_str() {
            "raw" => {
                self.allowed_installation_paths.as_slice() == ["bin/runtrue-runner"]
                    && self.allowed_modes.as_slice() == [0o555]
                    && self.installed_digest == self.artifact_digest
            }
            "oci-image" => {
                self.allowed_installation_paths.is_empty() && self.allowed_modes.is_empty()
            }
            _ => false,
        };
        if self.component_name != "runtrue-runner"
            || self.artifact_length == 0
            || self.protocol_min == 0
            || self.protocol_max < self.protocol_min
            || strings.iter().any(|value| !valid_text(value))
            || !package_valid
        {
            return Err(UpdateError::InvalidRunnerComponentProfile);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, UpdateError> {
        self.validate()?;
        Ok(ContentDigest::sha256(canonical_bytes(self)?))
    }

    pub fn verify_signed_target(&self, target: &TargetDescription) -> Result<(), UpdateError> {
        let digest = self.digest()?;
        if self.release_version != target.version
            || self.artifact_length != target.length
            || self.artifact_digest != target.sha256
            || self.artifact_media_type != target.media_type
            || self.platform != target.platform
            || self.architecture != target.architecture
            || target
                .custom
                .get(RUNNER_COMPONENT_PROFILE_DIGEST_FIELD)
                .map(String::as_str)
                != Some(digest.as_str())
        {
            return Err(UpdateError::InvalidRunnerComponentProfile);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBundle {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_rotations: Vec<SignedEnvelope<RootMetadata>>,
    pub targets: SignedEnvelope<TargetsMetadata>,
    pub snapshot: SignedEnvelope<SnapshotMetadata>,
    pub timestamp: SignedEnvelope<TimestampMetadata>,
}

impl ReleaseBundle {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        canonical_bytes(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, UpdateError> {
        decode_canonical(bytes, MAX_METADATA_BYTES * 4)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub next_state: TrustedState,
    pub target_path: String,
    pub target: TargetDescription,
}

/// Canonical in-toto/SLSA-style statement emitted by the release builder.
/// GitHub's keyless artifact attestation signs the same target digests in the
/// protected publish job; this local statement remains useful offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProvenance {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<ReleaseSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: ReleasePredicate,
}

impl ReleaseProvenance {
    pub fn new(
        mut subject: Vec<ReleaseSubject>,
        source_repository: impl Into<String>,
        source_commit: impl Into<String>,
        source_ref: impl Into<String>,
        builder_id: impl Into<String>,
        built_unix_seconds: u64,
    ) -> Result<Self, UpdateError> {
        subject.sort_by(|left, right| left.name.cmp(&right.name));
        let statement = Self {
            statement_type: "https://in-toto.io/Statement/v1".to_owned(),
            subject,
            predicate_type: "https://slsa.dev/provenance/v1".to_owned(),
            predicate: ReleasePredicate {
                build_definition: ReleaseBuildDefinition {
                    build_type: "https://runtrue.dev/build/release/v1".to_owned(),
                    source_repository: source_repository.into(),
                    source_commit: source_commit.into(),
                    source_ref: source_ref.into(),
                },
                run_details: ReleaseRunDetails {
                    builder_id: builder_id.into(),
                    built_unix_seconds,
                },
            },
        };
        statement.validate()?;
        Ok(statement)
    }

    pub fn validate(&self) -> Result<(), UpdateError> {
        if self.statement_type != "https://in-toto.io/Statement/v1"
            || self.predicate_type != "https://slsa.dev/provenance/v1"
            || self.predicate.build_definition.build_type != "https://runtrue.dev/build/release/v1"
            || self.subject.is_empty()
            || self.subject.len() > MAX_TARGETS
            || self
                .subject
                .windows(2)
                .any(|pair| pair[0].name >= pair[1].name)
            || !valid_text(&self.predicate.build_definition.source_repository)
            || !valid_text(&self.predicate.build_definition.source_commit)
            || !valid_text(&self.predicate.build_definition.source_ref)
            || !valid_text(&self.predicate.run_details.builder_id)
        {
            return Err(UpdateError::InvalidReleaseProvenance);
        }
        for subject in &self.subject {
            subject.validate()?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        self.validate()?;
        canonical_bytes(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSubject {
    pub name: String,
    pub digest: ReleaseDigest,
    pub length: u64,
}

impl ReleaseSubject {
    pub fn from_bytes(name: impl Into<String>, bytes: &[u8]) -> Result<Self, UpdateError> {
        let subject = Self {
            name: name.into(),
            digest: ReleaseDigest {
                sha256: digest_hex(&ContentDigest::sha256(bytes)).to_owned(),
            },
            length: u64::try_from(bytes.len()).map_err(|_| UpdateError::TargetTooLarge)?,
        };
        subject.validate()?;
        Ok(subject)
    }

    pub(crate) fn validate(&self) -> Result<(), UpdateError> {
        if self.name.len() > MAX_STRING_BYTES
            || normalize_relative_path(&self.name).ok().as_deref() != Some(self.name.as_str())
            || self.length > MAX_TARGET_BYTES
            || self.digest.sha256.len() != 64
            || !is_lower_hex(&self.digest.sha256)
        {
            return Err(UpdateError::InvalidReleaseProvenance);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseDigest {
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePredicate {
    #[serde(rename = "buildDefinition")]
    pub build_definition: ReleaseBuildDefinition,
    #[serde(rename = "runDetails")]
    pub run_details: ReleaseRunDetails,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBuildDefinition {
    #[serde(rename = "buildType")]
    pub build_type: String,
    pub source_repository: String,
    pub source_commit: String,
    pub source_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRunDetails {
    pub builder_id: String,
    pub built_unix_seconds: u64,
}

use crate::{
    canonical_bytes, decode_canonical, digest_hex, is_lower_hex, valid_text, RootMetadata,
    SignedEnvelope, SnapshotMetadata, TargetDescription, TargetsMetadata, TimestampMetadata,
    TrustedState, UpdateError, MAX_METADATA_BYTES, MAX_STRING_BYTES, MAX_TARGETS, MAX_TARGET_BYTES,
};
use runtrue_model::{normalize_relative_path, ContentDigest};
use serde::{Deserialize, Serialize};
