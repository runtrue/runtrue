//! Validation for externally configured provider bindings.
use super::model::{
    ExternalSecretLeaseMetadata, ProviderError, MAX_PROVIDER_IDENTIFIER_BYTES,
    MAX_PROVIDER_REFERENCE_BYTES,
};
pub(super) fn validate_lease_metadata(
    metadata: &ExternalSecretLeaseMetadata,
    expected_provider_id: &str,
) -> Result<(), ProviderError> {
    if metadata.provider != expected_provider_id
        || metadata.fencing_generation == 0
        || metadata.installation_fencing_epoch == 0
        || metadata.job_attempt == 0
    {
        return Err(ProviderError::InvalidLeaseMetadata);
    }
    validate_identifier("external secret release id", &metadata.release_id)?;
    validate_provider_id(&metadata.provider)?;
    validate_identifier("tenant id", &metadata.tenant_id)?;
    validate_identifier("repository id", &metadata.repository_id)?;
    validate_identifier("run id", &metadata.run_id)?;
    validate_identifier("runner id", &metadata.runner_id)?;
    validate_identifier("secret metadata id", &metadata.secret_metadata_id)?;
    validate_identifier("execution lease id", &metadata.execution_lease_id)?;
    validate_identifier("job id", &metadata.job_id)?;
    validate_identifier("step id", &metadata.step_id)?;
    validate_identifier("secret purpose", &metadata.purpose)?;
    if let Some(lease_id) = &metadata.provider_lease_id {
        validate_identifier("Vault lease id", lease_id)?;
    }
    Ok(())
}

pub(super) fn validate_namespace(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_REFERENCE_BYTES
        || value
            .split('/')
            .any(|segment| validate_path_segment(segment).is_err())
    {
        return Err(ProviderError::InvalidProviderConfiguration);
    }
    Ok(())
}

pub(super) fn validate_path_segment(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > MAX_PROVIDER_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'/' || byte == b'\\')
    {
        return Err(ProviderError::InvalidProviderReference);
    }
    Ok(())
}

pub(super) fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte >> 4)]));
            encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

pub(super) fn validate_identifier(kind: &'static str, value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderError::InvalidIdentifier(kind));
    }
    Ok(())
}

pub(super) fn validate_provider_id(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProviderError::InvalidProviderConfiguration);
    }
    Ok(())
}
pub(super) fn strict_json<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, ProviderError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value =
        T::deserialize(&mut deserializer).map_err(|_| ProviderError::InvalidProviderResponse)?;
    deserializer
        .end()
        .map_err(|_| ProviderError::InvalidProviderResponse)?;
    Ok(value)
}
