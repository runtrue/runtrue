use crate::{AuditError, AuditEventData, AuditValue};

pub const MAX_METADATA_FIELDS: usize = 64;
pub const MAX_TEXT_BYTES: usize = 8 * 1024;

pub(crate) fn validate_data(data: &AuditEventData) -> Result<(), AuditError> {
    for (name, value) in [
        ("tenant_id", data.tenant_id.as_str()),
        ("actor.kind", data.actor.kind.as_str()),
        ("actor.id", data.actor.id.as_str()),
        ("action", data.action.as_str()),
        ("resource.kind", data.resource.kind.as_str()),
        ("resource.id", data.resource.id.as_str()),
        ("result", data.result.as_str()),
        ("request_id", data.request_id.as_str()),
    ] {
        if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
            return Err(AuditError::InvalidText(name));
        }
    }
    if data.metadata.len() > MAX_METADATA_FIELDS {
        return Err(AuditError::TooManyMetadataFields(data.metadata.len()));
    }
    for (key, value) in &data.metadata {
        if key.is_empty() || key.len() > 128 || key.contains('\0') {
            return Err(AuditError::InvalidText("metadata key"));
        }
        if matches!(value, AuditValue::String(value) if value.len() > MAX_TEXT_BYTES || value.contains('\0'))
        {
            return Err(AuditError::InvalidText("metadata value"));
        }
    }
    Ok(())
}
