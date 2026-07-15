//! Vault validation and public error taxonomy.
use super::SecretsError;
use super::{
    model::{SecretIdentity, SecretMetadata, SecretStatus, MAX_IDENTITY_BYTES, MAX_SECRET_BYTES},
    store::SecretRecord,
};
use crate::SecretPlaintext;
pub(super) fn metadata(
    identity: &SecretIdentity,
    record: &SecretRecord,
) -> Result<SecretMetadata, SecretsError> {
    Ok(SecretMetadata {
        identity: identity.clone(),
        status: record.status,
        current_version: current_version(record)?,
    })
}

pub(super) fn current_version(record: &SecretRecord) -> Result<u64, SecretsError> {
    record
        .versions
        .last_key_value()
        .map(|(version, _)| *version)
        .ok_or(SecretsError::MissingVersions)
}

pub(super) fn require_active(
    identity: &SecretIdentity,
    status: SecretStatus,
) -> Result<(), SecretsError> {
    if status == SecretStatus::Tombstoned {
        return Err(SecretsError::SecretTombstoned(identity.clone()));
    }
    Ok(())
}

pub(super) fn require_binding(
    field: &'static str,
    expected: &str,
    actual: &str,
) -> Result<(), SecretsError> {
    if expected != actual {
        return Err(SecretsError::LeaseBindingMismatch { field });
    }
    Ok(())
}

pub(super) fn validate_component(field: &'static str, value: &str) -> Result<(), SecretsError> {
    if value.is_empty() {
        return Err(SecretsError::InvalidComponent {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > MAX_IDENTITY_BYTES {
        return Err(SecretsError::InvalidComponent {
            field,
            reason: "is too long",
        });
    }
    if value.contains('\0') {
        return Err(SecretsError::InvalidComponent {
            field,
            reason: "must not contain NUL",
        });
    }
    Ok(())
}

pub(super) fn validate_version(version: u64) -> Result<(), SecretsError> {
    if version == 0 {
        return Err(SecretsError::InvalidVersion);
    }
    Ok(())
}

pub(super) fn validate_plaintext(plaintext: &SecretPlaintext) -> Result<(), SecretsError> {
    if plaintext.len() > MAX_SECRET_BYTES {
        return Err(SecretsError::SecretTooLarge {
            limit: MAX_SECRET_BYTES,
            actual: plaintext.len(),
        });
    }
    Ok(())
}
