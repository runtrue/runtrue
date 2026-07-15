use crate::validation::{collect_secret_ids, decode_canonical_envelope, ensure_sorted_unique};
use crate::{
    ReplayBundle, ReplayEnvelope, ReplayError, ReplayOutcome, MAX_REPLAY_BUNDLE_BYTES,
    REPLAY_SCHEMA_VERSION,
};
use runtrue_engine::ExecutionResult;
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{canonicalize_value, ExecutionCapsule};

impl ReplayBundle {
    pub fn new(
        capsule: ExecutionCapsule,
        approval_subject_digest: ContentDigest,
        result: Option<&ExecutionResult>,
    ) -> Result<Self, ReplayError> {
        let capsule_digest = capsule.digest()?;
        let required_secret_metadata_ids = collect_secret_ids(&capsule);
        Ok(Self {
            schema_version: REPLAY_SCHEMA_VERSION,
            capsule,
            capsule_digest,
            approval_subject_digest,
            required_secret_metadata_ids,
            input_artifact_digests: Vec::new(),
            artifact_references: Vec::new(),
            cache_references: Vec::new(),
            outcome: result.map(ReplayOutcome::from),
        })
    }

    pub fn verify(&self) -> Result<(), ReplayError> {
        if self.schema_version != REPLAY_SCHEMA_VERSION {
            return Err(ReplayError::UnsupportedSchema(self.schema_version));
        }
        let actual = self.capsule.digest()?;
        if actual != self.capsule_digest {
            return Err(ReplayError::CapsuleDigestMismatch {
                expected: self.capsule_digest.clone(),
                actual,
            });
        }
        ensure_sorted_unique(&self.required_secret_metadata_ids, "secret metadata ids")?;
        ensure_sorted_unique(&self.input_artifact_digests, "input artifact digests")?;
        ensure_sorted_unique(&self.artifact_references, "artifact references")?;
        ensure_sorted_unique(&self.cache_references, "cache references")?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReplayError> {
        let value = serde_json::to_value(self)?;
        Ok(serde_json::to_vec(&canonicalize_value(value))?)
    }

    pub fn digest(&self) -> Result<ContentDigest, ReplayError> {
        Ok(ContentDigest::sha256(self.canonical_bytes()?))
    }

    pub fn seal(self) -> Result<ReplayEnvelope, ReplayError> {
        self.verify()?;
        let bundle_digest = self.digest()?;
        Ok(ReplayEnvelope {
            bundle: self,
            bundle_digest,
        })
    }
}

impl ReplayEnvelope {
    pub fn verify(&self) -> Result<(), ReplayError> {
        self.bundle.verify()?;
        let actual = self.bundle.digest()?;
        if actual != self.bundle_digest {
            return Err(ReplayError::BundleDigestMismatch {
                expected: self.bundle_digest.clone(),
                actual,
            });
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReplayError> {
        let value = serde_json::to_value(self)?;
        Ok(serde_json::to_vec(&canonicalize_value(value))?)
    }

    /// Decode the exact canonical on-disk representation.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReplayError> {
        if bytes.len() > MAX_REPLAY_BUNDLE_BYTES {
            return Err(ReplayError::TooLarge(bytes.len()));
        }
        decode_canonical_envelope(bytes)
    }
}
