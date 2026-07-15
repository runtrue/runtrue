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
