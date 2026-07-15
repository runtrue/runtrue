//! Signed runtime-image manifests and rollback-resistant update metadata.
//!
//! Image, kernel, root-filesystem, snapshot, and Wasm AOT bytes are not trusted
//! merely because they are present in a local cache. This module binds their
//! exact content digests to architecture, build provenance, an SBOM, and
//! compatibility metadata. Warm microVM snapshots additionally carry an
//! explicit sterility phase so a snapshot made after source, identity, or
//! secrets were injected can never be published as a reusable base.

mod error;
mod model;
mod update;
mod validation;
mod verification;

pub use error::ImageAttestError;
pub use model::{
    ImageKind, ImageManifest, SignedImageManifest, SnapshotPhase, IMAGE_MANIFEST_MEDIA_TYPE,
};
pub use update::{
    SignedUpdateMetadata, TrustedUpdateState, UpdateMetadata, UpdateSignature, UpdateTarget,
    UPDATE_METADATA_MEDIA_TYPE,
};
pub use validation::{MAX_IMAGE_COMPONENTS, MAX_IMAGE_METADATA_VALUE_BYTES, MAX_UPDATE_TARGETS};
pub use verification::{ImageSigningKey, ImageVerifyingKey, IMAGE_SIGNATURE_ALGORITHM};

#[cfg(test)]
mod tests;
