use base64ct::{Base64, Encoding as _};
use rand_core::{OsRng, RngCore as _};
use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
    SerialNumber, PKCS_ED25519,
};
use runtrue_control_plane::{RunnerCertificateRecord, RunnerCertificateStatus};
use runtrue_model::ContentDigest;
use rustls_pki_types::{pem::PemObject as _, CertificateDer, CertificateSigningRequestDer};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use time::OffsetDateTime;
use x509_parser::{
    certification_request::X509CertificationRequest, parse_x509_certificate, prelude::FromDer as _,
};
use zeroize::Zeroizing;

pub const MAX_RUNNER_CSR_BYTES: usize = 16 * 1024;
pub const DEFAULT_RUNNER_CERTIFICATE_LIFETIME: Duration = Duration::from_secs(4 * 60 * 60);
pub const DEFAULT_RUNNER_CERTIFICATE_OVERLAP: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_RUNNER_ROTATION_NOTICE: Duration = Duration::from_secs(30 * 60);
const CERTIFICATE_NOT_BEFORE_SKEW: Duration = Duration::from_secs(60);
const MAX_CERTIFICATE_IDENTITY_BYTES: usize = 128;
const SERIAL_BYTES: usize = 20;

pub struct RunnerCertificateAuthority {
    ca_der: Vec<u8>,
    ca_pem: String,
    signing_key: Zeroizing<KeyPair>,
    ca_not_before_unix_ms: u64,
    ca_not_after_unix_ms: u64,
    certificate_lifetime: Duration,
}

pub struct IssuedRunnerCertificate {
    pub certificate_chain_pem: Vec<u8>,
    pub record: RunnerCertificateRecord,
}

/// Validate durable rotation response bytes before returning them to a runner.
/// The journal is the replay source of truth, so accepting a different leaf,
/// expiry, or non-canonical chain here could permanently poison recovery after
/// the original rotation response was lost.
pub(crate) fn validate_issued_certificate_chain(
    certificate_chain_pem: &[u8],
    record: &RunnerCertificateRecord,
) -> Result<(), RunnerCertificateError> {
    let certificates = CertificateDer::pem_slice_iter(certificate_chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RunnerCertificateError::InvalidIssuedChain)?;
    let [leaf_der, ca_der] = certificates.as_slice() else {
        return Err(RunnerCertificateError::InvalidIssuedChain);
    };
    let canonical = format!(
        "{}\n{}\n",
        certificate_pem(leaf_der.as_ref()),
        certificate_pem(ca_der.as_ref())
    );
    if canonical.as_bytes() != certificate_chain_pem {
        return Err(RunnerCertificateError::InvalidIssuedChain);
    }

    let (leaf_remainder, leaf) = parse_x509_certificate(leaf_der.as_ref())
        .map_err(|_| RunnerCertificateError::InvalidIssuedChain)?;
    let (ca_remainder, ca) = parse_x509_certificate(ca_der.as_ref())
        .map_err(|_| RunnerCertificateError::InvalidIssuedChain)?;
    let not_before_unix_ms = unix_seconds_to_millis(leaf.validity().not_before.timestamp())
        .map_err(|_| RunnerCertificateError::InvalidIssuedChain)?;
    let not_after_unix_ms = unix_seconds_to_millis(leaf.validity().not_after.timestamp())
        .map_err(|_| RunnerCertificateError::InvalidIssuedChain)?;
    if !leaf_remainder.is_empty()
        || !ca_remainder.is_empty()
        || ContentDigest::sha256(leaf_der.as_ref()) != record.fingerprint
        || hex::encode(leaf.raw_serial()) != record.serial_hex
        || not_before_unix_ms != record.not_before_unix_ms
        || not_after_unix_ms != record.not_after_unix_ms
        || leaf.issuer() != ca.subject()
        || !ca
            .basic_constraints()
            .map_err(|_| RunnerCertificateError::InvalidIssuedChain)?
            .is_some_and(|extension| extension.value.ca)
        || !ca
            .key_usage()
            .map_err(|_| RunnerCertificateError::InvalidIssuedChain)?
            .is_some_and(|extension| extension.value.key_cert_sign())
        || leaf.verify_signature(Some(ca.public_key())).is_err()
    {
        return Err(RunnerCertificateError::InvalidIssuedChain);
    }
    Ok(())
}

impl RunnerCertificateAuthority {
    pub fn load(
        ca_certificate_pem: &[u8],
        ca_private_key_pem: &[u8],
        certificate_lifetime: Duration,
    ) -> Result<Self, RunnerCertificateError> {
        if certificate_lifetime.is_zero()
            || certificate_lifetime > Duration::from_secs(24 * 60 * 60)
        {
            return Err(RunnerCertificateError::InvalidLifetime);
        }
        let certificates = CertificateDer::pem_slice_iter(ca_certificate_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RunnerCertificateError::InvalidCa)?;
        let [ca_der] = certificates.as_slice() else {
            return Err(RunnerCertificateError::InvalidCa);
        };
        let (remainder, parsed) = parse_x509_certificate(ca_der.as_ref())
            .map_err(|_| RunnerCertificateError::InvalidCa)?;
        if !remainder.is_empty()
            || !parsed
                .basic_constraints()
                .map_err(|_| RunnerCertificateError::InvalidCa)?
                .is_some_and(|extension| extension.value.ca)
            || !parsed
                .key_usage()
                .map_err(|_| RunnerCertificateError::InvalidCa)?
                .is_some_and(|extension| extension.value.key_cert_sign())
        {
            return Err(RunnerCertificateError::InvalidCa);
        }

        let key_pem = std::str::from_utf8(ca_private_key_pem)
            .map_err(|_| RunnerCertificateError::InvalidCaKey)?;
        let signing_key = Zeroizing::new(
            KeyPair::from_pem(key_pem).map_err(|_| RunnerCertificateError::InvalidCaKey)?,
        );
        if signing_key.subject_public_key_info() != parsed.public_key().raw {
            return Err(RunnerCertificateError::CaKeyMismatch);
        }
        let ca_pem = certificate_pem(ca_der.as_ref());
        let ca_not_before_unix_ms =
            unix_seconds_to_millis(parsed.validity().not_before.timestamp())?;
        let ca_not_after_unix_ms = unix_seconds_to_millis(parsed.validity().not_after.timestamp())?;
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or(RunnerCertificateError::ClockRange)?;
        if now_unix_ms < ca_not_before_unix_ms || now_unix_ms >= ca_not_after_unix_ms {
            return Err(RunnerCertificateError::CaNotValid);
        }
        Ok(Self {
            ca_der: ca_der.as_ref().to_vec(),
            ca_pem,
            signing_key,
            ca_not_before_unix_ms,
            ca_not_after_unix_ms,
            certificate_lifetime,
        })
    }

    pub fn issue(
        &self,
        certificate_signing_request: &[u8],
        runner_id: &str,
        pool_id: &str,
        now_unix_ms: u64,
    ) -> Result<IssuedRunnerCertificate, RunnerCertificateError> {
        validate_certificate_identity(runner_id)?;
        validate_certificate_identity(pool_id)?;
        if certificate_signing_request.is_empty()
            || certificate_signing_request.len() > MAX_RUNNER_CSR_BYTES
        {
            return Err(RunnerCertificateError::CsrSize);
        }

        // rcgen's CSR parser historically accepted a valid DER prefix. Perform
        // an explicit full-DER parse first so smuggled trailing bytes fail.
        let (remainder, _) = X509CertificationRequest::from_der(certificate_signing_request)
            .map_err(|_| RunnerCertificateError::InvalidCsr)?;
        if !remainder.is_empty() {
            return Err(RunnerCertificateError::InvalidCsr);
        }
        let csr_der = CertificateSigningRequestDer::from(certificate_signing_request);
        let csr = CertificateSigningRequestParams::from_der(&csr_der)
            .map_err(|_| RunnerCertificateError::InvalidCsr)?;
        if csr.public_key.algorithm() != &PKCS_ED25519 {
            return Err(RunnerCertificateError::UnsupportedCsrKey);
        }

        if now_unix_ms < self.ca_not_before_unix_ms || now_unix_ms >= self.ca_not_after_unix_ms {
            return Err(RunnerCertificateError::CaNotValid);
        }
        let requested_expiry = now_unix_ms
            .checked_add(duration_millis(self.certificate_lifetime)?)
            .ok_or(RunnerCertificateError::ClockRange)?;
        let not_after_unix_ms = requested_expiry.min(self.ca_not_after_unix_ms) / 1_000 * 1_000;
        if not_after_unix_ms <= now_unix_ms {
            return Err(RunnerCertificateError::CaNotValid);
        }
        let not_before_unix_ms =
            (now_unix_ms.saturating_sub(duration_millis(CERTIFICATE_NOT_BEFORE_SKEW)?) / 1_000
                * 1_000)
                .max(self.ca_not_before_unix_ms);

        let mut serial = [0_u8; SERIAL_BYTES];
        OsRng
            .try_fill_bytes(&mut serial)
            .map_err(|_| RunnerCertificateError::RandomnessUnavailable)?;
        normalize_serial(&mut serial);

        // Every CSR-controlled field is deliberately discarded. Only the
        // signature-verified Ed25519 public key survives into server-owned
        // leaf parameters.
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, runner_id);
        distinguished_name.push(DnType::OrganizationalUnitName, pool_id);
        let identity_uri = format!("urn:runtrue:runner:{pool_id}:{runner_id}");
        let mut params = CertificateParams::default();
        params.not_before = offset_date_time(not_before_unix_ms)?;
        params.not_after = offset_date_time(not_after_unix_ms)?;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(identity_uri)
                .map_err(|_| RunnerCertificateError::InvalidIdentity)?,
        )];
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.name_constraints = None;
        params.crl_distribution_points.clear();
        params.custom_extensions.clear();
        params.use_authority_key_identifier_extension = true;
        let ca_der = CertificateDer::from(self.ca_der.as_slice());
        let issuer = Issuer::from_ca_cert_der(&ca_der, &*self.signing_key)
            .map_err(|_| RunnerCertificateError::InvalidCa)?;
        let certificate = params
            .signed_by(&csr.public_key, &issuer)
            .map_err(|_| RunnerCertificateError::IssuanceFailed)?;
        let leaf_der = certificate.der().as_ref();
        let (_, leaf) =
            parse_x509_certificate(leaf_der).map_err(|_| RunnerCertificateError::IssuanceFailed)?;
        let chain = format!("{}\n{}\n", certificate.pem().trim(), self.ca_pem);
        Ok(IssuedRunnerCertificate {
            certificate_chain_pem: chain.into_bytes(),
            record: RunnerCertificateRecord {
                fingerprint: ContentDigest::sha256(leaf_der),
                runner_id: runner_id.to_owned(),
                pool_id: pool_id.to_owned(),
                // Persist the canonical ASN.1 INTEGER representation from the
                // certificate that runners receive. This keeps durable replay
                // validation independent of rcgen's input-byte handling.
                serial_hex: hex::encode(leaf.raw_serial()),
                not_before_unix_ms,
                not_after_unix_ms,
                status: RunnerCertificateStatus::Active,
                issued_unix_ms: now_unix_ms,
                overlap_until_unix_ms: None,
                revoked_unix_ms: None,
            },
        })
    }
}

fn normalize_serial(serial: &mut [u8; SERIAL_BYTES]) {
    // X.509 serial numbers are positive ASN.1 INTEGERs. Keep the sign bit clear
    // and the first octet nonzero so DER canonicalization cannot remove an
    // octet and make the durable serial differ from the issued certificate.
    serial[0] = (serial[0] & 0x7f).max(1);
}

fn validate_certificate_identity(value: &str) -> Result<(), RunnerCertificateError> {
    if value.is_empty()
        || value.len() > MAX_CERTIFICATE_IDENTITY_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RunnerCertificateError::InvalidIdentity);
    }
    Ok(())
}

fn unix_seconds_to_millis(value: i64) -> Result<u64, RunnerCertificateError> {
    u64::try_from(value)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or(RunnerCertificateError::ClockRange)
}

fn duration_millis(duration: Duration) -> Result<u64, RunnerCertificateError> {
    u64::try_from(duration.as_millis()).map_err(|_| RunnerCertificateError::ClockRange)
}

fn offset_date_time(unix_ms: u64) -> Result<OffsetDateTime, RunnerCertificateError> {
    let nanos = i128::from(unix_ms)
        .checked_mul(1_000_000)
        .ok_or(RunnerCertificateError::ClockRange)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| RunnerCertificateError::ClockRange)
}

fn certificate_pem(der: &[u8]) -> String {
    let encoded = Base64::encode_string(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----");
    pem
}

#[derive(Debug, Error)]
pub enum RunnerCertificateError {
    #[error("runner certificate lifetime is invalid")]
    InvalidLifetime,
    #[error("runner certificate authority certificate is invalid or is not allowed to sign certificates")]
    InvalidCa,
    #[error("runner certificate authority private key is invalid")]
    InvalidCaKey,
    #[error("runner certificate authority certificate and private key do not match")]
    CaKeyMismatch,
    #[error("runner certificate authority is not currently valid")]
    CaNotValid,
    #[error("runner certificate signing request must contain 1 to 16384 DER bytes")]
    CsrSize,
    #[error("runner certificate signing request is invalid")]
    InvalidCsr,
    #[error("runner certificate signing request must use Ed25519")]
    UnsupportedCsrKey,
    #[error("runner or pool identity cannot be represented in a certificate")]
    InvalidIdentity,
    #[error("runner certificate issuance failed")]
    IssuanceFailed,
    #[error("issued runner certificate chain does not match its durable record")]
    InvalidIssuedChain,
    #[error("certificate time is outside the supported range")]
    ClockRange,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, PKCS_ECDSA_P256_SHA256};
    use x509_parser::extensions::{GeneralName, ParsedExtension};

    fn authority() -> RunnerCertificateAuthority {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "test-ca");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = OffsetDateTime::from_unix_timestamp(1).unwrap();
        params.not_after = OffsetDateTime::from_unix_timestamp(4_102_444_800).unwrap();
        let certificate = params.self_signed(&key).unwrap();
        RunnerCertificateAuthority::load(
            certificate.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            DEFAULT_RUNNER_CERTIFICATE_LIFETIME,
        )
        .unwrap()
    }

    fn csr(key: &KeyPair, hostile_extensions: bool) -> Vec<u8> {
        let mut params = CertificateParams::default();
        if hostile_extensions {
            params.distinguished_name = DistinguishedName::new();
            params
                .distinguished_name
                .push(DnType::CommonName, "attacker");
            params.subject_alt_names =
                vec![SanType::DnsName("attacker.invalid".try_into().unwrap())];
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }
        params.serialize_request(key).unwrap().der().to_vec()
    }

    #[test]
    fn issuance_consumes_full_der_and_overwrites_all_csr_controlled_fields() {
        let authority = authority();
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let issued = authority
            .issue(&csr(&key, true), "runner-1", "pool-1", 1_700_000_000_000)
            .unwrap();
        let leaf = CertificateDer::from_pem_slice(&issued.certificate_chain_pem).unwrap();
        let (remainder, parsed) = parse_x509_certificate(leaf.as_ref()).unwrap();
        assert!(remainder.is_empty());
        assert!(parsed
            .basic_constraints()
            .unwrap()
            .is_some_and(|extension| !extension.value.ca));
        assert!(parsed
            .key_usage()
            .unwrap()
            .is_some_and(|extension| extension.value.digital_signature()));
        assert!(parsed
            .extended_key_usage()
            .unwrap()
            .is_some_and(|extension| extension.value.client_auth && !extension.value.server_auth));
        let sans = parsed.subject_alternative_name().unwrap().unwrap();
        assert_eq!(sans.value.general_names.len(), 1);
        assert!(matches!(
            &sans.value.general_names[0],
            GeneralName::URI("urn:runtrue:runner:pool-1:runner-1")
        ));
        assert!(parsed.extensions().iter().all(|extension| !matches!(
            extension.parsed_extension(),
            ParsedExtension::SubjectAlternativeName(value)
                if value.general_names.iter().any(|name| matches!(name, GeneralName::DNSName("attacker.invalid")))
        )));
    }

    #[test]
    fn malformed_oversized_trailing_and_non_ed25519_csrs_fail_closed() {
        let authority = authority();
        assert!(matches!(
            authority.issue(&[], "runner-1", "pool-1", 1_700_000_000_000),
            Err(RunnerCertificateError::CsrSize)
        ));
        assert!(matches!(
            authority.issue(
                &vec![0; MAX_RUNNER_CSR_BYTES + 1],
                "runner-1",
                "pool-1",
                1_700_000_000_000
            ),
            Err(RunnerCertificateError::CsrSize)
        ));
        let ed = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut trailing = csr(&ed, false);
        trailing.push(0);
        assert!(matches!(
            authority.issue(&trailing, "runner-1", "pool-1", 1_700_000_000_000),
            Err(RunnerCertificateError::InvalidCsr)
        ));
        let p256 = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        assert!(matches!(
            authority.issue(&csr(&p256, false), "runner-1", "pool-1", 1_700_000_000_000),
            Err(RunnerCertificateError::UnsupportedCsrKey)
        ));
    }

    #[test]
    fn serials_are_canonical_before_certificate_encoding() {
        let mut leading_zero = [0_u8; SERIAL_BYTES];
        leading_zero[SERIAL_BYTES - 1] = 42;
        normalize_serial(&mut leading_zero);
        assert_eq!(leading_zero[0], 1);

        let mut sign_bit_set = [0xff_u8; SERIAL_BYTES];
        normalize_serial(&mut sign_bit_set);
        assert_eq!(sign_bit_set[0], 0x7f);
    }

    #[test]
    fn durable_serial_matches_the_emitted_certificate() {
        let authority = authority();
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let issued = authority
            .issue(&csr(&key, false), "runner-1", "pool-1", 1_700_000_000_000)
            .unwrap();
        let leaf = CertificateDer::from_pem_slice(&issued.certificate_chain_pem).unwrap();
        let (_, parsed) = parse_x509_certificate(leaf.as_ref()).unwrap();

        assert_eq!(issued.record.serial_hex, hex::encode(parsed.raw_serial()));
        validate_issued_certificate_chain(&issued.certificate_chain_pem, &issued.record).unwrap();
    }
}
