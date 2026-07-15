pub(super) fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(super) fn validate_credential_pair(
    metadata: &CredentialMetadata,
    private_key_pem: &[u8],
    certificate_chain_pem: &[u8],
) -> Result<Vec<u8>, CredentialError> {
    let key_text = std::str::from_utf8(private_key_pem).map_err(|_| CredentialError::InvalidKey)?;
    let key = Zeroizing::new(KeyPair::from_pem(key_text).map_err(|_| CredentialError::InvalidKey)?);
    if key.algorithm() != &PKCS_ED25519 {
        return Err(CredentialError::InvalidKey);
    }
    let certificates = CertificateDer::pem_slice_iter(certificate_chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CredentialError::InvalidCertificate)?;
    if certificates.len() != 2 {
        return Err(CredentialError::InvalidCertificate);
    }
    let (remainder, leaf) = parse_x509_certificate(certificates[0].as_ref())
        .map_err(|_| CredentialError::InvalidCertificate)?;
    let (ca_remainder, ca) = parse_x509_certificate(certificates[1].as_ref())
        .map_err(|_| CredentialError::InvalidCertificate)?;
    if !remainder.is_empty()
        || !ca_remainder.is_empty()
        || !leaf.validity().is_valid()
        || !ca.validity().is_valid()
        || key.subject_public_key_info() != leaf.public_key().raw
        || leaf
            .basic_constraints()
            .map_err(|_| CredentialError::InvalidCertificate)?
            .is_none_or(|extension| extension.value.ca)
        || !leaf
            .key_usage()
            .map_err(|_| CredentialError::InvalidCertificate)?
            .is_some_and(|extension| extension.value.digital_signature())
        || !leaf
            .extended_key_usage()
            .map_err(|_| CredentialError::InvalidCertificate)?
            .is_some_and(|extension| extension.value.client_auth && !extension.value.server_auth)
        || !ca
            .basic_constraints()
            .map_err(|_| CredentialError::InvalidCertificate)?
            .is_some_and(|extension| extension.value.ca)
        || !ca
            .key_usage()
            .map_err(|_| CredentialError::InvalidCertificate)?
            .is_some_and(|extension| extension.value.key_cert_sign())
        || leaf.verify_signature(Some(ca.public_key())).is_err()
    {
        return Err(CredentialError::InvalidCertificate);
    }
    let expected_uri = format!(
        "urn:runtrue:runner:{}:{}",
        metadata.pool_id, metadata.runner_id
    );
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| CredentialError::InvalidCertificate)?
        .ok_or(CredentialError::InvalidCertificate)?;
    if san.value.general_names.as_slice() != [GeneralName::URI(&expected_uri)] {
        return Err(CredentialError::IdentityMismatch);
    }
    let common_name = leaf
        .subject()
        .iter_common_name()
        .next()
        .and_then(|value| value.as_str().ok());
    let organizational_unit = leaf
        .subject()
        .iter_organizational_unit()
        .next()
        .and_then(|value| value.as_str().ok());
    if common_name != Some(metadata.runner_id.as_str())
        || organizational_unit != Some(metadata.pool_id.as_str())
    {
        return Err(CredentialError::IdentityMismatch);
    }
    let certificate_expiry = u64::try_from(leaf.validity().not_after.timestamp())
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or(CredentialError::InvalidCertificate)?;
    if certificate_expiry != metadata.certificate_expires_unix_ms {
        return Err(CredentialError::IdentityMismatch);
    }
    Ok(normalize_certificate_chain(&certificates))
}

fn normalize_certificate_chain(certificates: &[CertificateDer<'_>]) -> Vec<u8> {
    let mut chain = String::new();
    for certificate in certificates {
        chain.push_str("-----BEGIN CERTIFICATE-----\n");
        let encoded = Base64::encode_string(certificate.as_ref());
        for line in encoded.as_bytes().chunks(64) {
            chain.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            chain.push('\n');
        }
        chain.push_str("-----END CERTIFICATE-----\n");
    }
    chain.into_bytes()
}

pub(super) fn certificate_chain_fingerprints(
    certificate_chain_pem: &[u8],
) -> Result<(runtrue_model::ContentDigest, runtrue_model::ContentDigest), CredentialError> {
    let certificates = CertificateDer::pem_slice_iter(certificate_chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CredentialError::InvalidCertificate)?;
    let [leaf, issuer] = certificates.as_slice() else {
        return Err(CredentialError::InvalidCertificate);
    };
    Ok((
        runtrue_model::ContentDigest::sha256(leaf.as_ref()),
        runtrue_model::ContentDigest::sha256(issuer.as_ref()),
    ))
}

pub(super) fn certificate_fingerprint(
    certificate_chain_pem: &[u8],
) -> Result<runtrue_model::ContentDigest, CredentialError> {
    certificate_chain_fingerprints(certificate_chain_pem).map(|(leaf, _)| leaf)
}
use super::{CredentialError, CredentialMetadata};
use base64ct::{Base64, Encoding as _};
use rcgen::{KeyPair, PublicKeyData as _, PKCS_ED25519};
use rustls_pki_types::{pem::PemObject as _, CertificateDer};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};
use zeroize::Zeroizing;
