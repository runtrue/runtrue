use crate::ArtifactError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactLimits {
    pub max_artifact_bytes: u64,
    pub max_record_bytes: u64,
    pub max_ticket_bytes: u64,
    pub max_identifier_bytes: usize,
    pub max_media_type_bytes: usize,
    pub max_ticket_lifetime_seconds: u64,
    pub max_retention_seconds: u64,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_artifact_bytes: 16 * 1024 * 1024 * 1024,
            max_record_bytes: 1024 * 1024,
            max_ticket_bytes: 64 * 1024,
            max_identifier_bytes: 512,
            max_media_type_bytes: 512,
            max_ticket_lifetime_seconds: 60 * 60,
            max_retention_seconds: 10 * 365 * 24 * 60 * 60,
        }
    }
}

impl ArtifactLimits {
    pub(crate) fn validate(self) -> Result<Self, ArtifactError> {
        if self.max_artifact_bytes == 0
            || self.max_record_bytes == 0
            || self.max_ticket_bytes == 0
            || self.max_identifier_bytes == 0
            || self.max_media_type_bytes == 0
            || self.max_ticket_lifetime_seconds == 0
            || self.max_retention_seconds == 0
        {
            return Err(ArtifactError::InvalidConfiguration(
                "all artifact limits must be greater than zero".to_owned(),
            ));
        }
        Ok(self)
    }
}

pub(crate) fn validate_retention(
    now: u64,
    retention_until: u64,
    limits: ArtifactLimits,
) -> Result<(), ArtifactError> {
    if retention_until <= now || retention_until.saturating_sub(now) > limits.max_retention_seconds
    {
        return Err(ArtifactError::InvalidRetention);
    }
    Ok(())
}

pub(crate) fn validate_media_type(
    media_type: &str,
    limits: ArtifactLimits,
) -> Result<(), ArtifactError> {
    if media_type.is_empty()
        || media_type.len() > limits.max_media_type_bytes
        || media_type.chars().any(char::is_control)
        || !media_type.contains('/')
    {
        return Err(ArtifactError::InvalidMediaType);
    }
    Ok(())
}

pub(crate) fn validate_artifact_name(
    name: &str,
    limits: ArtifactLimits,
) -> Result<(), ArtifactError> {
    validate_identifier("artifact.name", name, limits)?;
    if name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(ArtifactError::UnsafeArtifactName(name.to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_identifier(
    field: &'static str,
    value: &str,
    limits: ArtifactLimits,
) -> Result<(), ArtifactError> {
    if value.is_empty()
        || value.len() > limits.max_identifier_bytes
        || value.chars().any(char::is_control)
    {
        return Err(ArtifactError::InvalidMetadata(format!(
            "{field} must be non-empty, bounded UTF-8 without control characters"
        )));
    }
    Ok(())
}
