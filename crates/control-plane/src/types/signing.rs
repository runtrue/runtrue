use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerPolicyRecord {
    pub id: String,
    pub tenant_id: String,
    pub provider_configuration_id: String,
    pub provider_configuration_digest: ContentDigest,
    pub provider_configuration_version: u64,
    pub backend_key_reference: String,
    pub purpose: String,
    pub operation: String,
    pub public_key_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub status: String,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    pub version: u64,
}

impl SignerPolicyRecord {
    pub fn expected_policy_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        #[derive(Serialize)]
        struct Material<'a> {
            id: &'a str,
            tenant_id: &'a str,
            provider_configuration_id: &'a str,
            provider_configuration_digest: &'a ContentDigest,
            provider_configuration_version: u64,
            backend_key_reference: &'a str,
            purpose: &'a str,
            operation: &'a str,
            public_key_digest: &'a ContentDigest,
            status: &'a str,
        }
        let material = Material {
            id: &self.id,
            tenant_id: &self.tenant_id,
            provider_configuration_id: &self.provider_configuration_id,
            provider_configuration_digest: &self.provider_configuration_digest,
            provider_configuration_version: self.provider_configuration_version,
            backend_key_reference: &self.backend_key_reference,
            purpose: &self.purpose,
            operation: &self.operation,
            public_key_digest: &self.public_key_digest,
            status: &self.status,
        };
        let mut bytes = b"runtrue.signer-policy.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&material)?);
        Ok(ContentDigest::sha256(bytes))
    }
}

impl fmt::Debug for SignerPolicyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignerPolicyRecord")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("provider_configuration_id", &self.provider_configuration_id)
            .field(
                "provider_configuration_digest",
                &self.provider_configuration_digest,
            )
            .field(
                "provider_configuration_version",
                &self.provider_configuration_version,
            )
            .field("backend_key_reference", &"<backend key reference>")
            .field("purpose", &self.purpose)
            .field("operation", &self.operation)
            .field("public_key_digest", &self.public_key_digest)
            .field("policy_digest", &self.policy_digest)
            .field("status", &self.status)
            .field("created_unix_ms", &self.created_unix_ms)
            .field("updated_unix_ms", &self.updated_unix_ms)
            .field("version", &self.version)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningResultReservation {
    pub request_id: String,
    pub tenant_id: String,
    pub provider_configuration_id: String,
    pub provider_configuration_digest: ContentDigest,
    pub provider_configuration_version: u64,
    pub environment_id: String,
    pub deployment_request_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub policy_epoch: u64,
    pub environment_version: u64,
    pub approval_request_id: String,
    pub approval_subject_digest: ContentDigest,
    pub artifact_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
    pub purpose: String,
    pub operation: String,
    pub signer_policy_id: String,
    pub signer_policy_digest: ContentDigest,
    pub signer_policy_version: u64,
    pub request_digest: ContentDigest,
    pub requested_unix_ms: u64,
    pub expires_unix_ms: u64,
}

impl SigningResultReservation {
    pub fn expected_request_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        let mut clone = self.clone();
        clone.request_digest = ContentDigest::sha256([]);
        let mut bytes = b"runtrue.signing-result-reservation.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&clone)?);
        Ok(ContentDigest::sha256(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSigningResult {
    pub signer_key_id: String,
    pub algorithm: String,
    pub signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Vec<u8>>,
    pub signed_unix_ms: u64,
    pub result_digest: ContentDigest,
}

impl PublicSigningResult {
    pub fn expected_result_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        #[derive(Serialize)]
        struct Material<'a> {
            signer_key_id: &'a str,
            algorithm: &'a str,
            signature: &'a [u8],
            certificate: &'a Option<Vec<u8>>,
            attestation: &'a Option<Vec<u8>>,
            signed_unix_ms: u64,
        }
        let material = Material {
            signer_key_id: &self.signer_key_id,
            algorithm: &self.algorithm,
            signature: &self.signature,
            certificate: &self.certificate,
            attestation: &self.attestation,
            signed_unix_ms: self.signed_unix_ms,
        };
        let mut bytes = b"runtrue.public-signing-result.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&material)?);
        Ok(ContentDigest::sha256(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningResultState {
    Reserved,
    Signed(PublicSigningResult),
    Complete(PublicSigningResult),
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningResultJournalRecord {
    pub reservation: SigningResultReservation,
    pub state: SigningResultState,
    pub retry_attempts: u32,
    pub updated_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
}
