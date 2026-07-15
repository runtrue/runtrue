use super::{
    secure_open::{nix_io, open_without_symlinks},
    COPY_BUFFER_BYTES,
};
use crate::{artifact_io, FirecrackerError};
#[cfg(unix)]
use nix::{
    sys::stat::{fstat, SFlag},
    unistd::read,
};
use runtrue_model::ContentDigest;
use sha2::{Digest as _, Sha256};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{fs, fs::OpenOptions, io::Write as _, path::Path};
pub(crate) fn copy_verified_payload(
    source: &Path,
    destination: &Path,
    expected_size: u64,
    expected_digest: &ContentDigest,
    mode: u32,
) -> Result<(), FirecrackerError> {
    #[cfg(not(unix))]
    {
        let _ = (source, destination, expected_size, expected_digest, mode);
        return Err(FirecrackerError::InvalidConfiguration(
            "race-safe image staging requires Unix".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        let descriptor = open_without_symlinks(source)?;
        let metadata =
            fstat(descriptor.raw()).map_err(|error| artifact_io(source, nix_io(error)))?;
        if !SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFREG)
            || u64::try_from(metadata.st_size).ok() != Some(expected_size)
        {
            return Err(FirecrackerError::UnsafeArtifact {
                path: source.to_owned(),
                reason: "staged source is not the expected regular file".to_owned(),
            });
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(mode);
        let mut output = options
            .open(destination)
            .map_err(|source| crate::state_io(destination, source))?;
        let result = (|| {
            let mut hasher = Sha256::new();
            let mut total = 0_u64;
            let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
            loop {
                let count = read(descriptor.raw(), &mut buffer)
                    .map_err(|error| artifact_io(source, nix_io(error)))?;
                if count == 0 {
                    break;
                }
                total = total
                    .checked_add(u64::try_from(count).map_err(|_| {
                        FirecrackerError::InvalidConfiguration(
                            "staged artifact length overflows".to_owned(),
                        )
                    })?)
                    .ok_or_else(|| {
                        FirecrackerError::InvalidConfiguration(
                            "staged artifact length overflows".to_owned(),
                        )
                    })?;
                if total > expected_size {
                    return Err(FirecrackerError::ArtifactSizeMismatch {
                        path: source.to_owned(),
                        expected: expected_size,
                        actual: total,
                    });
                }
                hasher.update(&buffer[..count]);
                output
                    .write_all(&buffer[..count])
                    .map_err(|source| crate::state_io(destination, source))?;
            }
            if total != expected_size {
                return Err(FirecrackerError::ArtifactSizeMismatch {
                    path: source.to_owned(),
                    expected: expected_size,
                    actual: total,
                });
            }
            let actual = ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
                .map_err(|error| FirecrackerError::InvalidConfiguration(error.to_string()))?;
            if &actual != expected_digest {
                return Err(FirecrackerError::ArtifactDigestMismatch {
                    path: source.to_owned(),
                });
            }
            output
                .sync_all()
                .map_err(|source| crate::state_io(destination, source))?;
            Ok(())
        })();
        if result.is_err() {
            drop(output);
            let _ = fs::remove_file(destination);
        }
        result
    }
}
