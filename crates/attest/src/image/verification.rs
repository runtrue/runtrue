use super::{
    ImageAttestError, ImageManifest, SignedImageManifest, UpdateMetadata, UpdateSignature,
    IMAGE_MANIFEST_MEDIA_TYPE, UPDATE_METADATA_MEDIA_TYPE,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use std::fmt;
use zeroize::Zeroize;

const IMAGE_SIGNATURE_DOMAIN: &[u8] = b"runtrue.isolation-image.signature.v1\0";
const UPDATE_SIGNATURE_DOMAIN: &[u8] = b"runtrue.update-metadata.signature.v1\0";
pub const IMAGE_SIGNATURE_ALGORITHM: &str = "ed25519";

/// Secret installation key used only for image and update metadata. It is
/// deliberately distinct from the execution-capsule signing type so key-purpose
/// separation remains visible in APIs and audits.
pub struct ImageSigningKey {
    seed: [u8; 32],
}

impl ImageSigningKey {
    pub fn generate() -> Result<Self, ImageAttestError> {
        let mut seed = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| ImageAttestError::RandomnessUnavailable)?;
        Ok(Self { seed })
    }

    #[must_use]
    pub const fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    #[must_use]
    pub fn verifying_key(&self) -> ImageVerifyingKey {
        ImageVerifyingKey(SigningKey::from_bytes(&self.seed).verifying_key())
    }

    pub fn sign_manifest(
        &self,
        manifest: &ImageManifest,
    ) -> Result<SignedImageManifest, ImageAttestError> {
        let canonical = manifest.canonical_bytes()?;
        let manifest_digest = ContentDigest::sha256(&canonical);
        let signature = SigningKey::from_bytes(&self.seed).sign(&signature_message(
            IMAGE_SIGNATURE_DOMAIN,
            IMAGE_MANIFEST_MEDIA_TYPE,
            &manifest_digest,
            &canonical,
        ));
        Ok(SignedImageManifest {
            manifest: manifest.clone(),
            manifest_digest,
            media_type: IMAGE_MANIFEST_MEDIA_TYPE.to_owned(),
            algorithm: IMAGE_SIGNATURE_ALGORITHM.to_owned(),
            key_id: self.verifying_key().key_id(),
            signature: signature.to_bytes().to_vec(),
        })
    }

    pub fn sign_update(
        &self,
        update: &UpdateMetadata,
    ) -> Result<UpdateSignature, ImageAttestError> {
        let canonical = update.canonical_bytes()?;
        let metadata_digest = ContentDigest::sha256(&canonical);
        let signature = SigningKey::from_bytes(&self.seed).sign(&signature_message(
            UPDATE_SIGNATURE_DOMAIN,
            UPDATE_METADATA_MEDIA_TYPE,
            &metadata_digest,
            &canonical,
        ));
        Ok(UpdateSignature {
            key_id: self.verifying_key().key_id(),
            metadata_digest,
            media_type: UPDATE_METADATA_MEDIA_TYPE.to_owned(),
            algorithm: IMAGE_SIGNATURE_ALGORITHM.to_owned(),
            signature: signature.to_bytes().to_vec(),
        })
    }
}

impl Drop for ImageSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl fmt::Debug for ImageSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ImageSigningKey(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ImageVerifyingKey(VerifyingKey);

impl ImageVerifyingKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ImageAttestError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ImageAttestError::InvalidPublicKeyLength(bytes.len()))?;
        Ok(Self(VerifyingKey::from_bytes(&bytes)?))
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    #[must_use]
    pub fn key_id(&self) -> ContentDigest {
        ContentDigest::sha256(self.to_bytes())
    }

    pub fn verify_manifest(&self, signed: &SignedImageManifest) -> Result<(), ImageAttestError> {
        if signed.algorithm != IMAGE_SIGNATURE_ALGORITHM
            || signed.media_type != IMAGE_MANIFEST_MEDIA_TYPE
            || signed.key_id != self.key_id()
        {
            return Err(ImageAttestError::SignatureMetadataMismatch);
        }
        let canonical = signed.manifest.canonical_bytes()?;
        let actual_digest = ContentDigest::sha256(&canonical);
        if actual_digest != signed.manifest_digest {
            return Err(ImageAttestError::ObjectDigestMismatch);
        }
        self.verify_signature(
            IMAGE_SIGNATURE_DOMAIN,
            IMAGE_MANIFEST_MEDIA_TYPE,
            &signed.manifest_digest,
            &canonical,
            &signed.signature,
        )
    }

    pub(super) fn verify_update(
        &self,
        update: &UpdateMetadata,
        signature: &UpdateSignature,
    ) -> Result<(), ImageAttestError> {
        if signature.algorithm != IMAGE_SIGNATURE_ALGORITHM
            || signature.media_type != UPDATE_METADATA_MEDIA_TYPE
            || signature.key_id != self.key_id()
        {
            return Err(ImageAttestError::SignatureMetadataMismatch);
        }
        let canonical = update.canonical_bytes()?;
        let actual_digest = ContentDigest::sha256(&canonical);
        if actual_digest != signature.metadata_digest {
            return Err(ImageAttestError::ObjectDigestMismatch);
        }
        self.verify_signature(
            UPDATE_SIGNATURE_DOMAIN,
            UPDATE_METADATA_MEDIA_TYPE,
            &signature.metadata_digest,
            &canonical,
            &signature.signature,
        )
    }

    fn verify_signature(
        &self,
        domain: &[u8],
        media_type: &str,
        digest: &ContentDigest,
        canonical: &[u8],
        signature: &[u8],
    ) -> Result<(), ImageAttestError> {
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| ImageAttestError::InvalidSignatureLength(signature.len()))?;
        self.0.verify(
            &signature_message(domain, media_type, digest, canonical),
            &Signature::from_bytes(&signature_bytes),
        )?;
        Ok(())
    }
}

impl fmt::Debug for ImageVerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageVerifyingKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

fn signature_message(
    domain: &[u8],
    media_type: &str,
    digest: &ContentDigest,
    canonical: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + media_type.len() + canonical.len() + 96);
    message.extend_from_slice(domain);
    message.extend_from_slice(media_type.as_bytes());
    message.push(0);
    message.extend_from_slice(digest.as_str().as_bytes());
    message.push(0);
    message.extend_from_slice(canonical);
    message
}
