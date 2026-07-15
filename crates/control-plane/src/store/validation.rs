use crate::ControlPlaneError;

pub(super) fn validate_idempotency_key(value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty() || value.len() > super::MAX_IDEMPOTENCY_KEY_BYTES || value.contains('\0') {
        return Err(ControlPlaneError::InvalidInput("invalid idempotency key"));
    }
    Ok(())
}

pub(super) fn validate_text(_field: &'static str, value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty() || value.len() > super::MAX_TEXT_BYTES || value.contains('\0') {
        return Err(ControlPlaneError::InvalidInput(
            "empty, oversized, or NUL text",
        ));
    }
    Ok(())
}

pub(super) fn validate_page(limit: usize, cursor: Option<&str>) -> Result<(), ControlPlaneError> {
    if limit == 0 || limit > 100 {
        return Err(ControlPlaneError::InvalidInput(
            "page limit must be between one and one hundred",
        ));
    }
    if let Some(cursor) = cursor {
        validate_text("page cursor", cursor)?;
    }
    Ok(())
}
