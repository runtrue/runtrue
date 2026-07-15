use crate::state::read_bounded_private_file;
use crate::{
    credentials::{
        CredentialError, LoadedRunnerCredentials, NewRunnerCredentials, PendingRotationResponse,
        RunnerCredentialStore,
    },
    transport::{EnrollmentEndpointSecurity, TransportError},
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ED25519};
use runtrue_protocol::{resolve_selected_protocol_version, v1, PROTOCOL_MAX, PROTOCOL_MIN};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_CSR_BYTES: usize = 16 * 1024;

pub(crate) struct GeneratedCertificateRequest {
    pub private_key_pem: Zeroizing<String>,
    pub csr_der: Vec<u8>,
}

pub(crate) fn generate_certificate_request() -> Result<GeneratedCertificateRequest, EnrollmentError>
{
    let key = Zeroizing::new(
        KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|_| EnrollmentError::CertificateRequestGeneration)?,
    );
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names.clear();
    params.key_usages.clear();
    params.extended_key_usages.clear();
    params.custom_extensions.clear();
    let csr_der = params
        .serialize_request(&*key)
        .map_err(|_| EnrollmentError::CertificateRequestGeneration)?
        .der()
        .to_vec();
    if csr_der.is_empty() || csr_der.len() > MAX_CSR_BYTES {
        return Err(EnrollmentError::CertificateRequestGeneration);
    }
    Ok(GeneratedCertificateRequest {
        private_key_pem: Zeroizing::new(key.serialize_pem()),
        csr_der,
    })
}

pub async fn enroll_runner(
    endpoint: &EnrollmentEndpointSecurity,
    enrollment_token: &str,
    inventory: v1::RunnerInventory,
    credentials: &RunnerCredentialStore,
    ephemeral: bool,
) -> Result<LoadedRunnerCredentials, EnrollmentError> {
    endpoint.validate_configuration()?;
    if enrollment_token.is_empty() || enrollment_token.len() > 4096 {
        return Err(EnrollmentError::InvalidEnrollmentToken);
    }
    // The existing singleton field remains generation one so a current runner
    // can enroll against an old server that ignores the additive range.
    if inventory.protocol_version != PROTOCOL_MIN {
        return Err(EnrollmentError::InvalidInventoryProtocol);
    }
    let generated = generate_certificate_request()?;
    let response = endpoint
        .enroll(v1::EnrollRequest {
            enrollment_token: enrollment_token.to_owned(),
            certificate_signing_request: generated.csr_der,
            inventory: Some(inventory),
            attestation: None,
            protocol_min: PROTOCOL_MIN,
            protocol_max: PROTOCOL_MAX,
            ephemeral,
        })
        .await?;
    let selected_protocol_version = resolve_selected_protocol_version(
        response.protocol_min,
        response.protocol_max,
        PROTOCOL_MIN,
        response.selected_protocol_version,
    )
    .map_err(|_| EnrollmentError::ProtocolMismatch)?;
    let certificate_expires_unix_ms = timestamp_millis(response.certificate_expires_at.as_ref())?;
    let authoritative_posture_digest =
        parse_authoritative_posture(response.authoritative_posture_digest.as_ref())?;
    credentials
        .install(&NewRunnerCredentials {
            runner_id: response.runner_id,
            pool_id: response.runner_pool_id,
            certificate_expires_unix_ms,
            private_key_pem: generated.private_key_pem,
            certificate_chain_pem: response.certificate_chain_pem,
            authoritative_posture_digest,
            selected_protocol_version,
        })
        .map_err(EnrollmentError::from)
}

pub async fn enroll_runner_from_token_file(
    endpoint: &EnrollmentEndpointSecurity,
    enrollment_token_file: &Path,
    inventory: v1::RunnerInventory,
    credentials: &RunnerCredentialStore,
    ephemeral: bool,
) -> Result<LoadedRunnerCredentials, EnrollmentError> {
    let bytes = Zeroizing::new(read_bounded_private_file(enrollment_token_file, 4096)?);
    let mut token = Zeroizing::new(
        std::str::from_utf8(&bytes)
            .map_err(|_| EnrollmentError::InvalidEnrollmentToken)?
            .to_owned(),
    );
    while token.ends_with(['\r', '\n']) {
        token.pop();
    }
    enroll_runner(endpoint, &token, inventory, credentials, ephemeral).await
}

pub(crate) fn pending_rotation_response(
    response: v1::RotateCertificateResponse,
    expected_csr_digest: &runtrue_model::ContentDigest,
) -> Result<PendingRotationResponse, EnrollmentError> {
    if let Some(echoed) = response.csr_digest.as_ref() {
        let echoed = runtrue_model::ContentDigest::try_from(echoed)
            .map_err(|_| EnrollmentError::RotationBindingMismatch)?;
        if &echoed != expected_csr_digest {
            return Err(EnrollmentError::RotationBindingMismatch);
        }
    }
    let expected_certificate_fingerprint = response
        .certificate_fingerprint
        .as_ref()
        .map(runtrue_model::ContentDigest::try_from)
        .transpose()
        .map_err(|_| EnrollmentError::RotationBindingMismatch)?;
    let pending = PendingRotationResponse {
        certificate_expires_unix_ms: timestamp_millis(response.certificate_expires_at.as_ref())?,
        certificate_chain_pem: response.certificate_chain_pem,
    };
    if let Some(expected) = expected_certificate_fingerprint {
        if pending.certificate_fingerprint()? != expected {
            return Err(EnrollmentError::RotationBindingMismatch);
        }
    }
    Ok(pending)
}

fn parse_authoritative_posture(
    digest: Option<&v1::Digest>,
) -> Result<Option<runtrue_model::ContentDigest>, EnrollmentError> {
    digest
        .map(runtrue_model::ContentDigest::try_from)
        .transpose()
        .map_err(|_| EnrollmentError::InvalidAuthoritativePostureDigest)
}

fn timestamp_millis(timestamp: Option<&prost_types::Timestamp>) -> Result<u64, EnrollmentError> {
    let timestamp = timestamp.ok_or(EnrollmentError::InvalidCertificateExpiry)?;
    if timestamp.seconds < 0 || !(0..1_000_000_000).contains(&timestamp.nanos) {
        return Err(EnrollmentError::InvalidCertificateExpiry);
    }
    u64::try_from(timestamp.seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .and_then(|millis| millis.checked_add(u64::from(timestamp.nanos as u32) / 1_000_000))
        .filter(|value| *value > 0)
        .ok_or(EnrollmentError::InvalidCertificateExpiry)
}

#[derive(Debug, Error)]
pub enum EnrollmentError {
    #[error("runner enrollment token is empty or exceeds its bound")]
    InvalidEnrollmentToken,
    #[error("could not generate an Ed25519 runner certificate request")]
    CertificateRequestGeneration,
    #[error("runner enrollment inventory must use the generation-one compatibility envelope")]
    InvalidInventoryProtocol,
    #[error("control plane and runner protocol ranges do not overlap")]
    ProtocolMismatch,
    #[error("control plane returned an invalid certificate expiry")]
    InvalidCertificateExpiry,
    #[error("control plane returned an invalid authoritative posture digest")]
    InvalidAuthoritativePostureDigest,
    #[error("control plane certificate rotation response does not match the pending request")]
    RotationBindingMismatch,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Credentials(#[from] CredentialError),
    #[error(transparent)]
    State(#[from] crate::StateError),
}

#[cfg(test)]
mod posture_tests {
    use super::*;

    #[test]
    fn authoritative_posture_is_canonical_and_legacy_absence_is_explicit() {
        assert_eq!(parse_authoritative_posture(None).unwrap(), None);
        let expected = runtrue_model::ContentDigest::sha256(b"authoritative");
        let wire = v1::Digest::try_from(&expected).unwrap();
        assert_eq!(
            parse_authoritative_posture(Some(&wire)).unwrap(),
            Some(expected)
        );
        assert!(parse_authoritative_posture(Some(&v1::Digest {
            algorithm: "sha512".to_owned(),
            value: vec![0; 32],
        }))
        .is_err());
    }

    #[test]
    fn old_and_new_server_selections_are_validated_without_downgrade() {
        assert_eq!(
            resolve_selected_protocol_version(0, 0, PROTOCOL_MIN, 0).unwrap(),
            PROTOCOL_MIN
        );
        assert_eq!(
            resolve_selected_protocol_version(PROTOCOL_MIN, PROTOCOL_MIN, PROTOCOL_MIN, 0).unwrap(),
            PROTOCOL_MIN
        );
        assert_eq!(
            resolve_selected_protocol_version(
                PROTOCOL_MIN,
                PROTOCOL_MAX,
                PROTOCOL_MIN,
                PROTOCOL_MAX
            )
            .unwrap(),
            PROTOCOL_MAX
        );
        if PROTOCOL_MIN != PROTOCOL_MAX {
            assert!(resolve_selected_protocol_version(
                PROTOCOL_MIN,
                PROTOCOL_MAX,
                PROTOCOL_MIN,
                PROTOCOL_MIN,
            )
            .is_err());
        }
        for (minimum, maximum) in [(0, PROTOCOL_MAX), (PROTOCOL_MIN, 0), (2, 1)] {
            assert!(resolve_selected_protocol_version(minimum, maximum, PROTOCOL_MIN, 0).is_err());
        }
    }
}
