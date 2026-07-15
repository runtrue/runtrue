use runtrue_attest::{CapsuleVerifyingKey, SignedProvenance};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProducer {
    pub capsule_digest: ContentDigest,
    pub workflow_digest: ContentDigest,
    pub source_repository: String,
    pub source_commit: String,
    pub runner_id: String,
    pub runner_image_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_attestation_digest: Option<ContentDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProvenance {
    pub statement_digest: ContentDigest,
    pub signer_key_id: ContentDigest,
    pub output_name: String,
    pub verifying_key: Vec<u8>,
    pub signed: SignedProvenance,
}

pub(crate) fn verify_provenance_link(
    provenance: &VerifiedArtifactProvenance<'_>,
    producer: &ArtifactProducer,
    output_name: &str,
    content_digest: &ContentDigest,
) -> Result<ArtifactProvenance, ArtifactError> {
    provenance
        .verifying_key
        .verify_provenance(provenance.signed)?;
    let statement = &provenance.signed.statement;
    if statement.capsule_digest != producer.capsule_digest
        || statement.workflow_digest != producer.workflow_digest
        || statement.source_repository != producer.source_repository
        || statement.source_commit != producer.source_commit
        || statement.builder_id != producer.runner_id
        || statement.runner_image_digest != producer.runner_image_digest
        || statement.outputs.get(output_name) != Some(content_digest)
    {
        return Err(ArtifactError::ProvenanceMismatch);
    }
    Ok(ArtifactProvenance {
        statement_digest: provenance.signed.statement_digest.clone(),
        signer_key_id: provenance.signed.key_id.clone(),
        output_name: output_name.to_owned(),
        verifying_key: provenance.verifying_key.to_bytes().to_vec(),
        signed: provenance.signed.clone(),
    })
}

pub(crate) fn verify_stored_provenance(
    provenance: &ArtifactProvenance,
    producer: &ArtifactProducer,
    output_name: &str,
    content_digest: &ContentDigest,
) -> Result<(), ArtifactError> {
    let verifying_key = CapsuleVerifyingKey::from_bytes(&provenance.verifying_key)?;
    verifying_key.verify_provenance(&provenance.signed)?;
    let statement = &provenance.signed.statement;
    if provenance.statement_digest != provenance.signed.statement_digest
        || provenance.signer_key_id != provenance.signed.key_id
        || provenance.signer_key_id != verifying_key.key_id()
        || provenance.output_name != output_name
        || statement.capsule_digest != producer.capsule_digest
        || statement.workflow_digest != producer.workflow_digest
        || statement.source_repository != producer.source_repository
        || statement.source_commit != producer.source_commit
        || statement.builder_id != producer.runner_id
        || statement.runner_image_digest != producer.runner_image_digest
        || statement.outputs.get(output_name) != Some(content_digest)
    {
        return Err(ArtifactError::ProvenanceMismatch);
    }
    Ok(())
}

pub(crate) fn validate_producer(
    producer: &ArtifactProducer,
    limits: ArtifactLimits,
) -> Result<(), ArtifactError> {
    for (field, value) in [
        (
            "producer.source_repository",
            producer.source_repository.as_str(),
        ),
        ("producer.source_commit", producer.source_commit.as_str()),
        ("producer.runner_id", producer.runner_id.as_str()),
    ] {
        validate_identifier(field, value, limits)?;
    }
    Ok(())
}

pub(crate) fn validate_scan_state(
    scan_state: &ArtifactScanState,
    limits: ArtifactLimits,
) -> Result<(), ArtifactError> {
    match scan_state {
        ArtifactScanState::Pending => Ok(()),
        ArtifactScanState::Passed { scanner, .. } | ArtifactScanState::Failed { scanner, .. } => {
            validate_identifier("scan.scanner", scanner, limits)
        }
        ArtifactScanState::Waived { approval_id, .. } => {
            validate_identifier("scan.approval_id", approval_id, limits)
        }
    }
}
use crate::{
    validate_identifier, ArtifactError, ArtifactLimits, ArtifactScanState,
    VerifiedArtifactProvenance,
};
