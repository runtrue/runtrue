use crate::{
    error::ImageCliError,
    output::{self, DigestResult},
    secure_fs::open_regular_no_follow,
};
use runtrue_model::ContentDigest;
use sha2::{Digest as _, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub(crate) const MAX_HASHED_FILE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

pub(crate) fn command(file: PathBuf, json: bool) -> Result<(), ImageCliError> {
    let (digest, size_bytes) = digest_file(&file, MAX_HASHED_FILE_BYTES)?;
    output::print(
        json,
        &DigestResult {
            path: file,
            digest,
            size_bytes,
        },
        "calculated image digest",
    )
}

pub(crate) fn digest_file(
    path: &Path,
    max_bytes: u64,
) -> Result<(ContentDigest, u64), ImageCliError> {
    let mut file = open_regular_no_follow(path, false)?;
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes {
        return Err(ImageCliError::FileTooLarge {
            path: path.to_path_buf(),
            limit: max_bytes,
            actual: metadata.len(),
        });
    }
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(u64::try_from(read).map_err(|_| ImageCliError::SizeOverflow)?)
            .ok_or(ImageCliError::SizeOverflow)?;
        if count > max_bytes {
            return Err(ImageCliError::FileTooLarge {
                path: path.to_path_buf(),
                limit: max_bytes,
                actual: count,
            });
        }
        hasher.update(&buffer[..read]);
    }
    if count != metadata.len() {
        return Err(ImageCliError::FileChanged(path.to_path_buf()));
    }
    Ok((
        ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))?,
        count,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_fs::write_new_file;
    use tempfile::TempDir;
    #[test]
    fn detects_exact_bytes() {
        let t = TempDir::new().unwrap();
        let p = t.path().join("payload");
        write_new_file(&p, b"payload", 0o600).unwrap();
        let (d, s) = digest_file(&p, 100).unwrap();
        assert_eq!(d, ContentDigest::sha256(b"payload"));
        assert_eq!(s, 7);
    }
}
