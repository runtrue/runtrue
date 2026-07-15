#[cfg(unix)]
use super::secure_open::{nix_io, open_without_symlinks};
use super::{
    architecture_name, ImageArtifact, ImageTrustStore, VerifiedArtifact, COPY_BUFFER_BYTES,
};
use crate::{artifact_io, FirecrackerError};
#[cfg(unix)]
use nix::{
    sys::stat::{fstat, SFlag},
    unistd::read,
};
use runtrue_attest::ImageKind;
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::Architecture;
use sha2::{Digest as _, Sha256};
use std::path::Path;
pub(super) fn verify_artifact(
    trust: &ImageTrustStore,
    artifact: &ImageArtifact,
    expected_kind: ImageKind,
    architecture: Architecture,
    now_unix_ms: u64,
) -> Result<VerifiedArtifact, FirecrackerError> {
    trust.verify(&artifact.signed)?;
    let manifest = &artifact.signed.manifest;
    if manifest.kind != expected_kind {
        return Err(FirecrackerError::InvalidConfiguration(format!(
            "expected {expected_kind:?}, got {:?}",
            manifest.kind
        )));
    }
    if manifest.operating_system != "linux"
        || manifest.architecture != architecture_name(architecture)
    {
        return Err(FirecrackerError::InvalidConfiguration(format!(
            "image {} targets {}/{}, expected linux/{}",
            manifest.name,
            manifest.operating_system,
            manifest.architecture,
            architecture_name(architecture)
        )));
    }
    if manifest.created_unix_ms > now_unix_ms
        || manifest
            .expires_unix_ms
            .is_some_and(|expires| now_unix_ms >= expires)
    {
        return Err(FirecrackerError::InvalidConfiguration(format!(
            "image {} is not valid at the requested time",
            manifest.name
        )));
    }
    verify_payload(
        &artifact.payload_path,
        manifest.payload_size_bytes,
        &manifest.payload_digest,
    )?;
    Ok(VerifiedArtifact {
        signed: artifact.signed.clone(),
        payload_path: artifact.payload_path.clone(),
    })
}

pub(crate) fn verify_payload(
    path: &Path,
    expected_size: u64,
    expected_digest: &ContentDigest,
) -> Result<(), FirecrackerError> {
    if !path.is_absolute() {
        return Err(FirecrackerError::UnsafeArtifact {
            path: path.to_owned(),
            reason: "path must be absolute".to_owned(),
        });
    }
    #[cfg(not(unix))]
    return Err(FirecrackerError::UnsafeArtifact {
        path: path.to_owned(),
        reason: "race-safe image opening is unavailable on this platform".to_owned(),
    });

    #[cfg(unix)]
    let descriptor = open_without_symlinks(path)?;
    #[cfg(unix)]
    let metadata = fstat(descriptor.raw()).map_err(|error| artifact_io(path, nix_io(error)))?;
    #[cfg(unix)]
    if !SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFREG) {
        return Err(FirecrackerError::UnsafeArtifact {
            path: path.to_owned(),
            reason: "artifact must be a regular non-symlink file".to_owned(),
        });
    }
    #[cfg(unix)]
    let actual_size =
        u64::try_from(metadata.st_size).map_err(|_| FirecrackerError::UnsafeArtifact {
            path: path.to_owned(),
            reason: "artifact has a negative size".to_owned(),
        })?;
    #[cfg(unix)]
    if actual_size != expected_size {
        return Err(FirecrackerError::ArtifactSizeMismatch {
            path: path.to_owned(),
            expected: expected_size,
            actual: actual_size,
        });
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        #[cfg(unix)]
        let count = read(descriptor.raw(), &mut buffer)
            .map_err(|error| artifact_io(path, nix_io(error)))?;
        if count == 0 {
            break;
        }
        let count = u64::try_from(count).map_err(|_| {
            FirecrackerError::InvalidConfiguration("artifact length overflow".to_owned())
        })?;
        total = total.checked_add(count).ok_or_else(|| {
            FirecrackerError::InvalidConfiguration("artifact length overflow".to_owned())
        })?;
        if total > expected_size {
            return Err(FirecrackerError::ArtifactSizeMismatch {
                path: path.to_owned(),
                expected: expected_size,
                actual: total,
            });
        }
        hasher.update(
            &buffer[..usize::try_from(count).map_err(|_| {
                FirecrackerError::InvalidConfiguration("artifact length overflow".to_owned())
            })?],
        );
    }
    if total != expected_size {
        return Err(FirecrackerError::ArtifactSizeMismatch {
            path: path.to_owned(),
            expected: expected_size,
            actual: total,
        });
    }
    let actual = ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|error| FirecrackerError::InvalidConfiguration(error.to_string()))?;
    if &actual != expected_digest {
        return Err(FirecrackerError::ArtifactDigestMismatch {
            path: path.to_owned(),
        });
    }
    Ok(())
}
