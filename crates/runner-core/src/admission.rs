use crate::{
    validation::{
        required_digest, timestamp_millis, validate_identifier, validate_wire_requirements,
    },
    AdmittedLease, CapsuleTrustStore, RunnerAdmissionError, VerifiedRunnerProfile,
};
use runtrue_attest::{CapsuleSignature, CAPSULE_MEDIA_TYPE, CAPSULE_SIGNATURE_ALGORITHM};
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_workflow_ir::{ExecutionCapsule, CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION};

pub const DEFAULT_MAX_CANONICAL_CAPSULE_BYTES: usize = 16 * 1024 * 1024;

/// Admission policy for one runner connection.
#[derive(Debug, Clone)]
pub struct RunnerAdmission {
    trust_store: CapsuleTrustStore,
    profile: VerifiedRunnerProfile,
    installation_fencing_epoch: u64,
    max_capsule_bytes: usize,
}

impl RunnerAdmission {
    pub fn new(
        trust_store: CapsuleTrustStore,
        profile: VerifiedRunnerProfile,
        installation_fencing_epoch: u64,
    ) -> Result<Self, RunnerAdmissionError> {
        profile.validate()?;
        if installation_fencing_epoch == 0 {
            return Err(RunnerAdmissionError::InvalidInstallationEpoch);
        }
        if trust_store.is_empty() {
            return Err(RunnerAdmissionError::EmptyTrustStore);
        }
        Ok(Self {
            trust_store,
            profile,
            installation_fencing_epoch,
            max_capsule_bytes: DEFAULT_MAX_CANONICAL_CAPSULE_BYTES,
        })
    }

    pub fn set_max_capsule_bytes(
        &mut self,
        max_capsule_bytes: usize,
    ) -> Result<(), RunnerAdmissionError> {
        if max_capsule_bytes == 0 {
            return Err(RunnerAdmissionError::InvalidCapsuleLimit);
        }
        self.max_capsule_bytes = max_capsule_bytes;
        Ok(())
    }

    #[must_use]
    pub const fn installation_fencing_epoch(&self) -> u64 {
        self.installation_fencing_epoch
    }

    /// Validate a lease offer and its separately fetched capsule as one unit.
    pub fn admit(
        &self,
        offer: &v1::LeaseOffer,
        fetched: &v1::FetchExecutionCapsuleResponse,
        now_unix_ms: u64,
    ) -> Result<AdmittedLease, RunnerAdmissionError> {
        validate_identifier("lease id", &offer.lease_id)?;
        validate_identifier("job id", &offer.job_id)?;
        validate_identifier("offer runner id", &offer.runner_id)?;
        if offer.runner_id != self.profile.runner_id {
            return Err(RunnerAdmissionError::WrongRunner {
                expected: self.profile.runner_id.clone(),
                actual: offer.runner_id.clone(),
            });
        }
        if offer.fencing_generation == 0 {
            return Err(RunnerAdmissionError::InvalidFencingGeneration);
        }
        if offer.installation_fencing_epoch != self.installation_fencing_epoch {
            return Err(RunnerAdmissionError::StaleInstallationEpoch {
                expected: self.installation_fencing_epoch,
                actual: offer.installation_fencing_epoch,
            });
        }

        let issued_unix_ms = timestamp_millis(offer.issued_at.as_ref(), "issued_at")?;
        let accept_by_unix_ms = timestamp_millis(offer.accept_by.as_ref(), "accept_by")?;
        let expires_unix_ms = timestamp_millis(offer.expires_at.as_ref(), "expires_at")?;
        // Field 14 was added without changing protocol generation. Old servers
        // omit it; their initial soft expiry is the only conservative local
        // execution bound available. New servers must provide an immutable
        // hard deadline while `expires_at` remains a renewable server-side
        // lease-fencing window.
        let hard_deadline_unix_ms = offer
            .hard_deadline
            .as_ref()
            .map(|value| timestamp_millis(Some(value), "hard_deadline"))
            .transpose()?
            .unwrap_or(expires_unix_ms);
        if issued_unix_ms > accept_by_unix_ms
            || accept_by_unix_ms >= expires_unix_ms
            || expires_unix_ms > hard_deadline_unix_ms
        {
            return Err(RunnerAdmissionError::InvalidLeaseWindow);
        }
        if now_unix_ms < issued_unix_ms || now_unix_ms >= accept_by_unix_ms {
            return Err(RunnerAdmissionError::OfferOutsideAcceptanceWindow);
        }

        let offered_digest =
            required_digest(offer.capsule_digest.as_ref(), "offer capsule digest")?;
        let fetched_digest = required_digest(fetched.digest.as_ref(), "fetched capsule digest")?;
        if offered_digest != fetched_digest {
            return Err(RunnerAdmissionError::CapsuleDigestDisagreement);
        }
        if fetched.canonical_capsule.is_empty()
            || fetched.canonical_capsule.len() > self.max_capsule_bytes
        {
            return Err(RunnerAdmissionError::CapsuleSize {
                limit: self.max_capsule_bytes,
                actual: fetched.canonical_capsule.len(),
            });
        }
        if ContentDigest::sha256(&fetched.canonical_capsule) != offered_digest {
            return Err(RunnerAdmissionError::CapsuleDigestMismatch);
        }
        if fetched.media_type != CAPSULE_MEDIA_TYPE {
            return Err(RunnerAdmissionError::UnsupportedCapsuleMediaType(
                fetched.media_type.clone(),
            ));
        }
        if offer.capsule_signature != fetched.signature
            || offer.capsule_signing_key_id != fetched.signing_key_id
        {
            return Err(RunnerAdmissionError::SignatureEnvelopeDisagreement);
        }

        let capsule: ExecutionCapsule = serde_json::from_slice(&fetched.canonical_capsule)
            .map_err(RunnerAdmissionError::InvalidCapsuleJson)?;
        let canonical = capsule
            .canonical_bytes()
            .map_err(RunnerAdmissionError::CanonicalCapsule)?;
        if canonical != fetched.canonical_capsule {
            return Err(RunnerAdmissionError::NonCanonicalCapsule);
        }
        if capsule
            .digest()
            .map_err(RunnerAdmissionError::CanonicalCapsule)?
            != offered_digest
        {
            return Err(RunnerAdmissionError::CapsuleDigestMismatch);
        }

        let key_id = ContentDigest::parse(fetched.signing_key_id.clone())
            .map_err(|_| RunnerAdmissionError::InvalidSigningKeyId)?;
        let signature = CapsuleSignature {
            signature_version: 1,
            algorithm: CAPSULE_SIGNATURE_ALGORITHM.to_owned(),
            key_id: key_id.clone(),
            capsule_digest: offered_digest.clone(),
            capsule_schema_version: capsule.schema_version,
            engine_compatibility_version: capsule.engine_compatibility_version.clone(),
            media_type: fetched.media_type.clone(),
            signature: fetched.signature.clone(),
        };
        self.trust_store
            .get(&key_id)?
            .verify_capsule(&capsule, &signature)
            .map_err(RunnerAdmissionError::InvalidCapsuleSignature)?;
        if capsule.schema_version != CAPSULE_SCHEMA_VERSION {
            return Err(RunnerAdmissionError::UnsupportedCapsuleSchemaVersion {
                expected: CAPSULE_SCHEMA_VERSION,
                actual: capsule.schema_version,
            });
        }
        if capsule.engine_compatibility_version != ENGINE_COMPATIBILITY_VERSION {
            return Err(
                RunnerAdmissionError::UnsupportedEngineCompatibilityVersion {
                    expected: ENGINE_COMPATIBILITY_VERSION,
                    actual: capsule.engine_compatibility_version,
                },
            );
        }

        let job = capsule
            .jobs
            .iter()
            .find(|job| job.id == offer.job_id)
            .ok_or_else(|| RunnerAdmissionError::JobNotInCapsule(offer.job_id.clone()))?;
        let wire_requirements = offer
            .requirements
            .as_ref()
            .ok_or(RunnerAdmissionError::MissingRequirements)?;
        validate_wire_requirements(wire_requirements, &job.runner, &self.profile)?;

        Ok(AdmittedLease {
            lease_id: offer.lease_id.clone(),
            job_id: offer.job_id.clone(),
            fencing_generation: offer.fencing_generation,
            installation_fencing_epoch: offer.installation_fencing_epoch,
            issued_unix_ms,
            accept_by_unix_ms,
            expires_unix_ms,
            hard_deadline_unix_ms,
            capsule_digest: offered_digest,
            signing_key_id: key_id,
            capsule_signature: signature,
            capsule,
        })
    }
}
