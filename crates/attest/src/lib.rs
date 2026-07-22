//! Domain-separated execution-capsule signatures and provenance statements.
//!
//! Signatures cover the exact canonical capsule bytes, qualified digest, schema,
//! and engine compatibility generation. This prevents a signature from being
//! replayed as another Runtrue object type or under another compatibility rule.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{
    canonicalize_value, ExecutionCapsule, ExpandedJobSet, ParityGrade, WorkflowFrontendProvenance,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;
use zeroize::Zeroize;

mod image;

pub use image::*;

const CAPSULE_SIGNATURE_DOMAIN: &[u8] = b"runtrue.execution-capsule.signature.v1\0";
const PROVENANCE_SIGNATURE_DOMAIN: &[u8] = b"runtrue.provenance.signature.v1\0";
const EXPANDED_JOB_SET_SIGNATURE_DOMAIN: &[u8] = b"runtrue.expanded-job-set.signature.v1\0";
pub const CAPSULE_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const CAPSULE_MEDIA_TYPE: &str =
    "application/vnd.runtrue.execution-capsule+canonical-json;version=1";

/// Secret signing key material. Debug output is always redacted and the owned
/// seed copy is zeroized on drop.
pub struct CapsuleSigningKey {
    seed: [u8; 32],
}

impl CapsuleSigningKey {
    pub fn generate() -> Result<Self, AttestError> {
        let mut seed = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| AttestError::RandomnessUnavailable)?;
        Ok(Self { seed })
    }

    #[must_use]
    pub const fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    #[must_use]
    pub fn verifying_key(&self) -> CapsuleVerifyingKey {
        CapsuleVerifyingKey(SigningKey::from_bytes(&self.seed).verifying_key())
    }

    pub fn sign_capsule(
        &self,
        capsule: &ExecutionCapsule,
    ) -> Result<CapsuleSignature, AttestError> {
        let canonical_capsule = capsule.canonical_bytes()?;
        let capsule_digest = ContentDigest::sha256(&canonical_capsule);
        let message = capsule_signature_message(capsule, &capsule_digest, &canonical_capsule);
        let signing = SigningKey::from_bytes(&self.seed);
        let signature = signing.sign(&message);
        Ok(CapsuleSignature {
            signature_version: 1,
            algorithm: CAPSULE_SIGNATURE_ALGORITHM.to_owned(),
            key_id: self.verifying_key().key_id(),
            capsule_digest,
            capsule_schema_version: capsule.schema_version,
            engine_compatibility_version: capsule.engine_compatibility_version.clone(),
            media_type: CAPSULE_MEDIA_TYPE.to_owned(),
            signature: signature.to_bytes().to_vec(),
        })
    }

    pub fn sign_provenance(
        &self,
        provenance: &ProvenanceStatement,
    ) -> Result<SignedProvenance, AttestError> {
        provenance.validate()?;
        let bytes = provenance.canonical_bytes()?;
        let statement_digest = ContentDigest::sha256(&bytes);
        let mut message = Vec::with_capacity(PROVENANCE_SIGNATURE_DOMAIN.len() + bytes.len());
        message.extend_from_slice(PROVENANCE_SIGNATURE_DOMAIN);
        message.extend_from_slice(statement_digest.as_str().as_bytes());
        message.push(0);
        message.extend_from_slice(&bytes);
        let signature = SigningKey::from_bytes(&self.seed).sign(&message);
        Ok(SignedProvenance {
            statement: provenance.clone(),
            statement_digest,
            algorithm: CAPSULE_SIGNATURE_ALGORITHM.to_owned(),
            key_id: self.verifying_key().key_id(),
            signature: signature.to_bytes().to_vec(),
        })
    }

    pub fn sign_expanded_job_set(
        &self,
        job_set: &ExpandedJobSet,
    ) -> Result<ExpandedJobSetSignature, AttestError> {
        let canonical = job_set.canonical_bytes()?;
        let job_set_digest = ContentDigest::sha256(&canonical);
        let mut message = Vec::with_capacity(
            EXPANDED_JOB_SET_SIGNATURE_DOMAIN.len()
                + job_set_digest.as_str().len()
                + canonical.len()
                + 1,
        );
        message.extend_from_slice(EXPANDED_JOB_SET_SIGNATURE_DOMAIN);
        message.extend_from_slice(job_set_digest.as_str().as_bytes());
        message.push(0);
        message.extend_from_slice(&canonical);
        let signature = SigningKey::from_bytes(&self.seed).sign(&message);
        Ok(ExpandedJobSetSignature {
            signature_version: 1,
            algorithm: CAPSULE_SIGNATURE_ALGORITHM.to_owned(),
            key_id: self.verifying_key().key_id(),
            job_set_digest,
            signature: signature.to_bytes().to_vec(),
        })
    }
}

impl Drop for CapsuleSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl fmt::Debug for CapsuleSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapsuleSigningKey(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CapsuleVerifyingKey(VerifyingKey);

impl CapsuleVerifyingKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AttestError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AttestError::InvalidPublicKeyLength(bytes.len()))?;
        Ok(Self(VerifyingKey::from_bytes(&bytes)?))
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    #[must_use]
    pub fn key_id(&self) -> ContentDigest {
        ContentDigest::sha256(self.to_bytes())
    }

    pub fn verify_capsule(
        &self,
        capsule: &ExecutionCapsule,
        signature: &CapsuleSignature,
    ) -> Result<(), AttestError> {
        signature.validate_metadata(capsule, self)?;
        let canonical_capsule = capsule.canonical_bytes()?;
        let actual_digest = ContentDigest::sha256(&canonical_capsule);
        if actual_digest != signature.capsule_digest {
            return Err(AttestError::CapsuleDigestMismatch {
                expected: signature.capsule_digest.clone(),
                actual: actual_digest,
            });
        }
        let message =
            capsule_signature_message(capsule, &signature.capsule_digest, &canonical_capsule);
        let signature_bytes: [u8; 64] = signature
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AttestError::InvalidSignatureLength(signature.signature.len()))?;
        self.0
            .verify(&message, &Signature::from_bytes(&signature_bytes))?;
        Ok(())
    }

    pub fn verify_provenance(&self, signed: &SignedProvenance) -> Result<(), AttestError> {
        if signed.algorithm != CAPSULE_SIGNATURE_ALGORITHM || signed.key_id != self.key_id() {
            return Err(AttestError::SignatureMetadataMismatch);
        }
        signed.statement.validate()?;
        let bytes = signed.statement.canonical_bytes()?;
        let actual_digest = ContentDigest::sha256(&bytes);
        if actual_digest != signed.statement_digest {
            return Err(AttestError::StatementDigestMismatch);
        }
        let mut message = Vec::with_capacity(PROVENANCE_SIGNATURE_DOMAIN.len() + bytes.len());
        message.extend_from_slice(PROVENANCE_SIGNATURE_DOMAIN);
        message.extend_from_slice(signed.statement_digest.as_str().as_bytes());
        message.push(0);
        message.extend_from_slice(&bytes);
        let signature_bytes: [u8; 64] = signed
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AttestError::InvalidSignatureLength(signed.signature.len()))?;
        self.0
            .verify(&message, &Signature::from_bytes(&signature_bytes))?;
        Ok(())
    }

    pub fn verify_expanded_job_set(
        &self,
        job_set: &ExpandedJobSet,
        signed: &ExpandedJobSetSignature,
    ) -> Result<(), AttestError> {
        if signed.signature_version != 1
            || signed.algorithm != CAPSULE_SIGNATURE_ALGORITHM
            || signed.key_id != self.key_id()
        {
            return Err(AttestError::SignatureMetadataMismatch);
        }
        let canonical = job_set.canonical_bytes()?;
        let actual = ContentDigest::sha256(&canonical);
        if actual != signed.job_set_digest {
            return Err(AttestError::StatementDigestMismatch);
        }
        let mut message = Vec::with_capacity(
            EXPANDED_JOB_SET_SIGNATURE_DOMAIN.len() + actual.as_str().len() + canonical.len() + 1,
        );
        message.extend_from_slice(EXPANDED_JOB_SET_SIGNATURE_DOMAIN);
        message.extend_from_slice(actual.as_str().as_bytes());
        message.push(0);
        message.extend_from_slice(&canonical);
        let signature: [u8; 64] = signed
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AttestError::InvalidSignatureLength(signed.signature.len()))?;
        self.0
            .verify(&message, &Signature::from_bytes(&signature))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpandedJobSetSignature {
    pub signature_version: u32,
    pub algorithm: String,
    pub key_id: ContentDigest,
    pub job_set_digest: ContentDigest,
    pub signature: Vec<u8>,
}

impl fmt::Debug for CapsuleVerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapsuleVerifyingKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleSignature {
    pub signature_version: u32,
    pub algorithm: String,
    pub key_id: ContentDigest,
    pub capsule_digest: ContentDigest,
    pub capsule_schema_version: u32,
    pub engine_compatibility_version: String,
    pub media_type: String,
    pub signature: Vec<u8>,
}

impl CapsuleSignature {
    fn validate_metadata(
        &self,
        capsule: &ExecutionCapsule,
        key: &CapsuleVerifyingKey,
    ) -> Result<(), AttestError> {
        if self.signature_version != 1
            || self.algorithm != CAPSULE_SIGNATURE_ALGORITHM
            || self.media_type != CAPSULE_MEDIA_TYPE
            || self.key_id != key.key_id()
            || self.capsule_schema_version != capsule.schema_version
            || self.engine_compatibility_version != capsule.engine_compatibility_version
        {
            return Err(AttestError::SignatureMetadataMismatch);
        }
        Ok(())
    }
}

fn capsule_signature_message(
    capsule: &ExecutionCapsule,
    digest: &ContentDigest,
    canonical_capsule: &[u8],
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(CAPSULE_SIGNATURE_DOMAIN.len() + canonical_capsule.len() + 128);
    message.extend_from_slice(CAPSULE_SIGNATURE_DOMAIN);
    message.extend_from_slice(&capsule.schema_version.to_be_bytes());
    message.extend_from_slice(capsule.engine_compatibility_version.as_bytes());
    message.push(0);
    message.extend_from_slice(digest.as_str().as_bytes());
    message.push(0);
    message.extend_from_slice(canonical_capsule);
    message
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceStatement {
    pub statement_version: u32,
    pub source_repository: String,
    pub source_commit: String,
    pub workflow_digest: ContentDigest,
    pub capsule_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_frontend: Option<WorkflowFrontendProvenance>,
    pub builder_id: String,
    pub runner_image_digest: ContentDigest,
    pub parity_grade: ParityGrade,
    pub resolved_dependencies: Vec<ContentDigest>,
    pub inputs: BTreeMap<String, ContentDigest>,
    pub outputs: BTreeMap<String, ContentDigest>,
    pub policy_version_ids: Vec<String>,
}

impl ProvenanceStatement {
    pub fn validate(&self) -> Result<(), AttestError> {
        if self.statement_version != 1
            || self.source_repository.is_empty()
            || self.source_commit.is_empty()
            || self.builder_id.is_empty()
            || self.workflow_frontend.as_ref().is_some_and(|frontend| {
                frontend.frontend_id.is_empty()
                    || frontend.contract_generation == 0
                    || frontend.frontend_generation == 0
            })
            || self
                .resolved_dependencies
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .policy_version_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(AttestError::InvalidProvenance);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AttestError> {
        let value = serde_json::to_value(self)?;
        Ok(serde_json::to_vec(&canonicalize_value(value))?)
    }

    pub fn digest(&self) -> Result<ContentDigest, AttestError> {
        Ok(ContentDigest::sha256(self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProvenance {
    pub statement: ProvenanceStatement,
    pub statement_digest: ContentDigest,
    pub algorithm: String,
    pub key_id: ContentDigest,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid capsule signing public key length {0}; expected 32 bytes")]
    InvalidPublicKeyLength(usize),
    #[error("invalid signature length {0}; expected 64 bytes")]
    InvalidSignatureLength(usize),
    #[error("capsule signature metadata does not match the capsule or verification key")]
    SignatureMetadataMismatch,
    #[error("capsule digest mismatch: expected {expected}, found {actual}")]
    CapsuleDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("provenance statement digest mismatch")]
    StatementDigestMismatch,
    #[error("invalid or noncanonical provenance statement")]
    InvalidProvenance,
    #[error(transparent)]
    Capsule(#[from] runtrue_workflow_ir::CapsuleError),
    #[error("signature verification failed: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("attestation JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_workflow_ir::{
        ApprovalRequirements, CapsuleContext, PermissionSet, WorkflowIdentity,
        CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
    };

    fn capsule() -> ExecutionCapsule {
        ExecutionCapsule {
            schema_version: CAPSULE_SCHEMA_VERSION,
            engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
            compiler_version: "test".to_owned(),
            workflow: WorkflowIdentity {
                name: "test".to_owned(),
                digest: ContentDigest::sha256(b"workflow"),
                source_path: ".runtrue/workflows/test.yaml".to_owned(),
            },
            context: CapsuleContext {
                source_commit: "commit".to_owned(),
                source_tree_digest: None,
                base_commit: None,
                source_trust: Default::default(),
                normalized_event_digest: ContentDigest::sha256(b"event"),
                normalized_event_json: None,
                scm: None,
                event_context: BTreeMap::new(),
                lockfile_digest: None,
                workflow_frontend: None,
                policy_version_ids: vec!["policy-v1".to_owned()],
            },
            variables: BTreeMap::new(),
            permissions: PermissionSet::default(),
            jobs: Vec::new(),
            dynamic_jobs: Vec::new(),
            approval: ApprovalRequirements {
                workflow_definition: false,
                privileged_execution: false,
                reasons: Vec::new(),
            },
            expected_parity: ParityGrade::AExact,
        }
    }

    #[test]
    fn exact_capsule_signature_round_trips_and_mutations_fail() {
        let key = CapsuleSigningKey::from_seed([7; 32]);
        let verifying = key.verifying_key();
        let capsule = capsule();
        let signature = key.sign_capsule(&capsule).unwrap();
        verifying.verify_capsule(&capsule, &signature).unwrap();

        let mut changed = capsule.clone();
        changed.context.source_commit = "changed".to_owned();
        assert!(matches!(
            verifying.verify_capsule(&changed, &signature),
            Err(AttestError::CapsuleDigestMismatch { .. })
        ));
        let other = CapsuleSigningKey::from_seed([8; 32]).verifying_key();
        assert!(matches!(
            other.verify_capsule(&capsule, &signature),
            Err(AttestError::SignatureMetadataMismatch)
        ));
    }

    #[test]
    fn signing_key_debug_is_redacted() {
        let key = CapsuleSigningKey::from_seed([42; 32]);
        assert_eq!(format!("{key:?}"), "CapsuleSigningKey(<redacted>)");
    }

    #[test]
    fn provenance_is_canonical_signed_and_verified() {
        let key = CapsuleSigningKey::from_seed([9; 32]);
        let statement = ProvenanceStatement {
            statement_version: 1,
            source_repository: "repo".to_owned(),
            source_commit: "commit".to_owned(),
            workflow_digest: ContentDigest::sha256(b"workflow"),
            capsule_digest: ContentDigest::sha256(b"capsule"),
            workflow_frontend: Some(WorkflowFrontendProvenance {
                frontend_id: "runtrue.test".to_owned(),
                contract_generation: 1,
                frontend_generation: 2,
                configuration_digest: ContentDigest::sha256(b"frontend-config"),
                input_digest: ContentDigest::sha256(b"frontend-input"),
                native_digest: ContentDigest::sha256(b"native-workflow"),
                report_digest: Some(ContentDigest::sha256(b"compatibility-report")),
            }),
            builder_id: "runner:image".to_owned(),
            runner_image_digest: ContentDigest::sha256(b"runner"),
            parity_grade: ParityGrade::AExact,
            resolved_dependencies: vec![ContentDigest::sha256(b"dependency")],
            inputs: BTreeMap::from([("source".to_owned(), ContentDigest::sha256(b"input"))]),
            outputs: BTreeMap::from([("artifact".to_owned(), ContentDigest::sha256(b"output"))]),
            policy_version_ids: vec!["policy-v1".to_owned()],
        };
        let signed = key.sign_provenance(&statement).unwrap();
        key.verifying_key().verify_provenance(&signed).unwrap();
        assert_eq!(
            signed.statement.workflow_frontend,
            statement.workflow_frontend
        );

        let mut tampered = signed;
        tampered.statement.source_commit = "other".to_owned();
        assert!(matches!(
            key.verifying_key().verify_provenance(&tampered),
            Err(AttestError::StatementDigestMismatch)
        ));
    }

    #[test]
    fn expanded_job_set_signature_is_domain_separated_and_exact() {
        let key = CapsuleSigningKey::from_seed([17; 32]);
        let set = ExpandedJobSet {
            version: 1,
            parent_capsule_digest: ContentDigest::sha256(b"capsule"),
            producer_job_id: "producer".to_owned(),
            producer_output_name: "matrix".to_owned(),
            matrix_input_digest: ContentDigest::sha256(b"input"),
            generated_job_ids: Vec::new(),
            jobs: Vec::new(),
            policy_epoch: 3,
        };
        let signed = key.sign_expanded_job_set(&set).unwrap();
        key.verifying_key()
            .verify_expanded_job_set(&set, &signed)
            .unwrap();
        let mut changed = set;
        changed.policy_epoch += 1;
        assert!(matches!(
            key.verifying_key()
                .verify_expanded_job_set(&changed, &signed),
            Err(AttestError::StatementDigestMismatch)
        ));
    }
}
