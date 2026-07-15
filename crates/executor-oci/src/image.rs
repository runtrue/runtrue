/// Exact approved image and signer expectation supplied with the execution
/// assignment. References containing a tag, even alongside a digest, fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedImage {
    pub(crate) reference: String,
    pub(crate) digest: ContentDigest,
    pub(crate) signature_identity: String,
    pub(crate) platform: OciPlatform,
}

impl LockedImage {
    pub fn new(
        reference: impl Into<String>,
        signature_identity: impl Into<String>,
        platform: OciPlatform,
    ) -> Result<Self, OciError> {
        let reference = reference.into();
        let digest = validate_exact_image_reference(&reference)?;
        let signature_identity = signature_identity.into();
        validate_bounded_text("signature identity", &signature_identity, 1024, false)?;
        if platform.os != OperatingSystem::Linux {
            return Err(OciError::UnsupportedPlatform(platform.as_oci().to_owned()));
        }
        Ok(Self {
            reference,
            digest,
            signature_identity,
            platform,
        })
    }

    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    #[must_use]
    pub fn signature_identity(&self) -> &str {
        &self.signature_identity
    }

    #[must_use]
    pub const fn platform(&self) -> OciPlatform {
        self.platform
    }
}

/// Provider result after registry metadata, digest, platform, and signature
/// verification. The executor compares every field with the locked request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedImage {
    pub(crate) reference: String,
    pub(crate) digest: ContentDigest,
    pub(crate) signature_identity: String,
    pub(crate) platform: OciPlatform,
    pub(crate) signature_verified: bool,
}

impl AdmittedImage {
    pub fn verified(
        reference: impl Into<String>,
        signature_identity: impl Into<String>,
        platform: OciPlatform,
    ) -> Result<Self, OciError> {
        let reference = reference.into();
        let digest = validate_exact_image_reference(&reference)?;
        let signature_identity = signature_identity.into();
        validate_bounded_text(
            "verified signature identity",
            &signature_identity,
            1024,
            false,
        )?;
        Ok(Self {
            reference,
            digest,
            signature_identity,
            platform,
            signature_verified: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn unverified(request: &LockedImage) -> Self {
        Self {
            reference: request.reference.clone(),
            digest: request.digest.clone(),
            signature_identity: request.signature_identity.clone(),
            platform: request.platform,
            signature_verified: false,
        }
    }
}
use crate::{
    validate_bounded_text, validate_exact_image_reference, ContentDigest, OciError, OciPlatform,
    OperatingSystem,
};
