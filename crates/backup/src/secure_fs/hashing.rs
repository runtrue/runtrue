use super::identity::{identity, open_regular_nofollow};
use crate::BackupError;
use runtrue_model::ContentDigest;
use sha2::{Digest as _, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

const COPY_BUFFER_BYTES: usize = 64 * 1024;

pub(crate) fn hash_regular_file(
    path: &Path,
    limit: u64,
) -> Result<(u64, ContentDigest), BackupError> {
    let (mut file, initial) = open_regular_nofollow(path)?;
    if initial.length > limit {
        return Err(BackupError::LimitExceeded("file bytes"));
    }
    let result = stream_hash_copy(&mut file, None, limit, path)?;
    let after = file.metadata().map_err(|source| BackupError::Io {
        operation: "reinspect verified file",
        path: path.to_owned(),
        source,
    })?;
    if identity(&after) != initial {
        return Err(BackupError::SourceChanged(path.to_owned()));
    }
    Ok(result)
}

pub(super) fn stream_hash_copy(
    input: &mut File,
    mut output: Option<&mut File>,
    limit: u64,
    path: &Path,
) -> Result<(u64, ContentDigest), BackupError> {
    let mut buffer = Zeroizing::new(vec![0_u8; COPY_BUFFER_BYTES]);
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    loop {
        let read = input
            .read(buffer.as_mut_slice())
            .map_err(|source| BackupError::Io {
                operation: "read file",
                path: path.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(BackupError::LimitExceeded("file bytes"))?;
        if size > limit {
            return Err(BackupError::LimitExceeded("file bytes"));
        }
        hasher.update(&buffer[..read]);
        if let Some(writer) = output.as_deref_mut() {
            writer
                .write_all(&buffer[..read])
                .map_err(|source| BackupError::Io {
                    operation: "write copied file",
                    path: path.to_owned(),
                    source,
                })?;
        }
    }
    let digest = ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))?;
    Ok((size, digest))
}
