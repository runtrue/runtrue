use super::{ImageAttestError, ImageKind, ImageManifest, SnapshotPhase, UpdateMetadata};

pub const MAX_IMAGE_COMPONENTS: usize = 1_024;
pub const MAX_UPDATE_TARGETS: usize = 10_000;
pub const MAX_IMAGE_METADATA_VALUE_BYTES: usize = 4_096;

impl ImageManifest {
    pub fn validate(&self) -> Result<(), ImageAttestError> {
        if self.manifest_version != 1 || self.payload_size_bytes == 0 {
            return Err(ImageAttestError::InvalidManifest(
                "manifest version must be 1 and payload size must be positive",
            ));
        }
        validate_identifier("image name", &self.name)?;
        validate_identifier("payload media type", &self.payload_media_type)?;
        validate_identifier("operating system", &self.operating_system)?;
        validate_identifier("architecture", &self.architecture)?;
        validate_identifier("builder id", &self.builder_id)?;
        if self
            .expires_unix_ms
            .is_some_and(|expires| expires <= self.created_unix_ms)
        {
            return Err(ImageAttestError::InvalidManifest(
                "image expiry must be after creation",
            ));
        }
        if self.components.len() > MAX_IMAGE_COMPONENTS
            || self.compatibility.len() > MAX_IMAGE_COMPONENTS
        {
            return Err(ImageAttestError::ManifestLimitExceeded);
        }
        for name in self.components.keys() {
            validate_identifier("component name", name)?;
        }
        for (name, value) in &self.compatibility {
            validate_identifier("compatibility key", name)?;
            validate_identifier("compatibility value", value)?;
        }
        match (self.kind, self.snapshot_phase) {
            (ImageKind::FirecrackerSnapshot, Some(_)) => {}
            (ImageKind::FirecrackerSnapshot, None) => {
                return Err(ImageAttestError::InvalidManifest(
                    "Firecracker snapshots require an explicit snapshot phase",
                ));
            }
            (_, Some(_)) => {
                return Err(ImageAttestError::InvalidManifest(
                    "snapshot phase is valid only for Firecracker snapshots",
                ));
            }
            (_, None) => {}
        }
        Ok(())
    }

    /// Reject a warm-pool publication unless the snapshot is explicitly
    /// sterile. A non-snapshot can never be mistaken for a warm snapshot.
    pub fn authorize_warm_snapshot_publication(&self) -> Result<(), ImageAttestError> {
        self.validate()?;
        if self.kind != ImageKind::FirecrackerSnapshot
            || self.snapshot_phase != Some(SnapshotPhase::Sterile)
        {
            return Err(ImageAttestError::SnapshotNotSterile);
        }
        Ok(())
    }
}

impl UpdateMetadata {
    pub fn validate(&self) -> Result<(), ImageAttestError> {
        if self.metadata_version != 1
            || self.generation == 0
            || self.expires_unix_ms <= self.issued_unix_ms
            || self.targets.is_empty()
            || self.targets.len() > MAX_UPDATE_TARGETS
        {
            return Err(ImageAttestError::InvalidUpdateMetadata);
        }
        validate_identifier("update channel", &self.channel)?;
        for (name, target) in &self.targets {
            validate_identifier("update target", name)?;
            if target.payload_size_bytes == 0 {
                return Err(ImageAttestError::InvalidUpdateMetadata);
            }
        }
        Ok(())
    }
}

pub(super) fn validate_identifier(kind: &'static str, value: &str) -> Result<(), ImageAttestError> {
    if value.is_empty()
        || value.len() > MAX_IMAGE_METADATA_VALUE_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ImageAttestError::InvalidIdentifier(kind));
    }
    Ok(())
}
