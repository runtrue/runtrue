use runtrue_model::ContentDigest;
use runtrue_storage::PathSnapshot;

pub(crate) const ARTIFACT_RECORD_VERSION: u32 = 1;

impl ArtifactStore {
    pub(crate) fn store_record(
        &self,
        record: &ArtifactRecord,
    ) -> Result<ContentDigest, ArtifactError> {
        self.validate_record(record)?;
        let bytes = serde_json::to_vec(record).map_err(ArtifactError::SerializeMetadata)?;
        if bytes.len() as u64 > self.limits.max_record_bytes {
            return Err(ArtifactError::MetadataLimit {
                kind: "artifact record",
                limit: self.limits.max_record_bytes,
                actual: bytes.len() as u64,
            });
        }
        Ok(self.cas.put_bytes(&bytes)?.digest)
    }

    pub(crate) fn validate_record(&self, record: &ArtifactRecord) -> Result<(), ArtifactError> {
        if record.record_version != ARTIFACT_RECORD_VERSION {
            return Err(ArtifactError::InvalidMetadata(
                "unsupported artifact record version".to_owned(),
            ));
        }
        for (field, value) in [
            ("tenant_id", record.tenant_id.as_str()),
            ("repository_id", record.repository_id.as_str()),
            ("run_id", record.run_id.as_str()),
            ("job_id", record.job_id.as_str()),
            ("step_id", record.step_id.as_str()),
        ] {
            validate_identifier(field, value, self.limits)?;
        }
        validate_artifact_name(&record.name, self.limits)?;
        validate_media_type(&record.media_type, self.limits)?;
        validate_producer(&record.producer, self.limits)?;
        validate_scan_state(&record.scan_state, self.limits)?;
        validate_retention(
            record.committed_at_unix_seconds,
            record.retention_until_unix_seconds,
            self.limits,
        )?;
        if record.size_bytes > self.limits.max_artifact_bytes {
            return Err(ArtifactError::ArtifactTooLarge {
                limit: self.limits.max_artifact_bytes,
                actual: record.size_bytes,
            });
        }
        if record.provenance.output_name != record.name {
            return Err(ArtifactError::InvalidMetadata(
                "provenance output name does not match artifact name".to_owned(),
            ));
        }
        if let Some(promotion) = &record.promotion {
            if promotion.to != record.classification || !promotion.from.can_promote_to(promotion.to)
            {
                return Err(ArtifactError::InvalidMetadata(
                    "artifact promotion metadata is inconsistent".to_owned(),
                ));
            }
            validate_promotion_evidence(
                promotion.from,
                promotion.to,
                &promotion.evidence,
                self.limits,
            )?;
        }
        let (digest, size) = snapshot_identity(&record.content);
        if digest != record.content_digest || size != record.size_bytes {
            return Err(ArtifactError::InvalidMetadata(
                "artifact content summary is inconsistent".to_owned(),
            ));
        }
        verify_stored_provenance(
            &record.provenance,
            &record.producer,
            &record.name,
            &record.content_digest,
        )?;
        Ok(())
    }
}

pub(crate) fn snapshot_identity(snapshot: &PathSnapshot) -> (ContentDigest, u64) {
    match snapshot {
        PathSnapshot::File {
            digest, size_bytes, ..
        } => (digest.clone(), *size_bytes),
        PathSnapshot::Directory {
            manifest_digest,
            total_file_bytes,
            ..
        } => (manifest_digest.clone(), *total_file_bytes),
    }
}
use crate::{
    validate_artifact_name, validate_identifier, validate_media_type, validate_producer,
    validate_promotion_evidence, validate_retention, validate_scan_state, verify_stored_provenance,
    ArtifactError, ArtifactRecord, ArtifactStore,
};
