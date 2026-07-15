use crate::{secure_io::*, BlobRecord, StorageError, COPY_BUFFER_BYTES};
use runtrue_model::ContentDigest;
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
};

impl FsCas {
    pub(crate) fn put_reader_with_limit<R: Read>(
        &self,
        reader: R,
        limit: u64,
    ) -> Result<BlobRecord, StorageError> {
        self.put_reader_with_expectation(reader, limit, None)
    }

    pub(crate) fn put_reader_with_expectation<R: Read>(
        &self,
        mut reader: R,
        limit: u64,
        expected: Option<(&ContentDigest, u64)>,
    ) -> Result<BlobRecord, StorageError> {
        self.ensure_layout()?;
        let temporary_directory = self.root.join("tmp");
        let mut pending = PendingFile::create(&temporary_directory, "object")?;
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];

        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|source| io_failure("read object input", pending.path(), source))?;
            if read == 0 {
                break;
            }
            size = size
                .checked_add(read as u64)
                .ok_or(StorageError::LimitExceeded {
                    resource: "blob bytes",
                    limit,
                    actual: u64::MAX,
                })?;
            if size > limit {
                return Err(StorageError::LimitExceeded {
                    resource: "blob bytes",
                    limit,
                    actual: size,
                });
            }
            hasher.update(&buffer[..read]);
            pending
                .file_mut()
                .write_all(&buffer[..read])
                .map_err(|source| io_failure("write temporary object", pending.path(), source))?;
        }

        pending
            .file_mut()
            .sync_all()
            .map_err(|source| io_failure("sync temporary object", pending.path(), source))?;
        set_read_only_file(pending.path(), false)?;
        let digest = digest_from_hasher(hasher)?;
        if expected.is_some_and(|(expected_digest, expected_size)| {
            expected_digest != &digest || expected_size != size
        }) {
            return Err(StorageError::Manifest(
                "streamed object digest or declared size mismatch".to_owned(),
            ));
        }
        let final_path = self.object_path(&digest)?;
        let parent = final_path.parent().ok_or_else(|| {
            StorageError::InvalidConfiguration("CAS object has no parent directory".to_owned())
        })?;
        ensure_owned_directory(parent)?;

        let already_present = match fs::hard_link(pending.path(), &final_path) {
            Ok(()) => {
                sync_directory(parent)?;
                false
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing_size = self.verify_blob(&digest)?;
                if existing_size != size {
                    return Err(StorageError::Manifest(
                        "existing CAS object has an impossible verified size mismatch".to_owned(),
                    ));
                }
                true
            }
            Err(source) => {
                return Err(io_failure(
                    "commit immutable CAS object",
                    &final_path,
                    source,
                ));
            }
        };
        pending.discard()?;
        Ok(BlobRecord {
            digest,
            size_bytes: size,
            already_present,
        })
    }
}

pub(crate) fn hash_reader<R: Read>(
    reader: &mut R,
    limit: u64,
    retain: bool,
) -> Result<(ContentDigest, u64, Vec<u8>), StorageError> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| StorageError::ReadObject(source.to_string()))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(StorageError::LimitExceeded {
                resource: "blob bytes",
                limit,
                actual: u64::MAX,
            })?;
        if size > limit {
            return Err(StorageError::LimitExceeded {
                resource: "blob bytes",
                limit,
                actual: size,
            });
        }
        hasher.update(&buffer[..read]);
        if retain {
            bytes.extend_from_slice(&buffer[..read]);
        }
    }
    Ok((digest_from_hasher(hasher)?, size, bytes))
}

pub(crate) fn digest_from_hasher(hasher: Sha256) -> Result<ContentDigest, StorageError> {
    ContentDigest::parse(format!("sha256:{}", hex_lower(&hasher.finalize())))
        .map_err(|error| StorageError::UnsupportedDigest(error.to_string()))
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
use super::FsCas;
