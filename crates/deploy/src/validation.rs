use crate::{DeploymentError, EnvironmentPolicy};
use std::collections::BTreeMap;

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 1024;
pub(crate) const MAX_METADATA_ENTRIES: usize = 128;
pub(crate) const MAX_METADATA_VALUE_BYTES: usize = 4096;

pub(crate) fn idempotency_scope(
    environment: &EnvironmentPolicy,
    key: &str,
) -> Result<String, DeploymentError> {
    validate_identifier("idempotency key", key)?;
    Ok(format!(
        "{}\0{}\0{}",
        environment.tenant_id, environment.id, key
    ))
}

pub(crate) fn validate_metadata(
    metadata: &BTreeMap<String, String>,
) -> Result<(), DeploymentError> {
    if metadata.len() > MAX_METADATA_ENTRIES {
        return Err(DeploymentError::InvalidMetadata);
    }
    for (key, value) in metadata {
        validate_identifier("deployment metadata key", key)?;
        if value.len() > MAX_METADATA_VALUE_BYTES || value.contains('\0') {
            return Err(DeploymentError::InvalidMetadata);
        }
    }
    Ok(())
}

pub(crate) fn validate_identifier(kind: &'static str, value: &str) -> Result<(), DeploymentError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(DeploymentError::InvalidIdentifier(kind));
    }
    Ok(())
}
