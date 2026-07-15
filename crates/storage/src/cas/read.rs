use crate::{secure_io::*, BlobRecord, CasObjectRecord, StorageError, VerifiedBlobReader};
use runtrue_model::ContentDigest;
use std::{
    fs,
    io::{Cursor, Read, Seek, SeekFrom},
    time::UNIX_EPOCH,
};

impl FsCas {
    /// Store bytes atomically. Existing objects are verified and never replaced.
    pub fn put_bytes(&self, bytes: &[u8]) -> Result<BlobRecord, StorageError> {
        self.put_reader(Cursor::new(bytes))
    }

    /// Stream an object into the CAS while hashing and enforcing the blob limit.
    pub fn put_reader<R: Read>(&self, reader: R) -> Result<BlobRecord, StorageError> {
        self.put_reader_with_limit(reader, self.limits.max_blob_bytes)
    }

    /// Read and verify an object. A digest mismatch is an error, never a hit.
    pub fn read_blob(&self, digest: &ContentDigest) -> Result<Vec<u8>, StorageError> {
        self.read_blob_with_limit(digest, self.limits.max_blob_bytes)
    }

    /// Read and verify an object under a caller-specific bound that may be
    /// stricter than the store-wide blob limit.
    pub fn read_blob_limited(
        &self,
        digest: &ContentDigest,
        limit: u64,
    ) -> Result<Vec<u8>, StorageError> {
        self.read_blob_with_limit(digest, limit.min(self.limits.max_blob_bytes))
    }

    /// Verify an object without retaining its bytes in memory.
    pub fn verify_blob(&self, digest: &ContentDigest) -> Result<u64, StorageError> {
        let path = self.object_path(digest)?;
        let mut file = open_regular_nofollow(&path, "open CAS object")?;
        let metadata = file
            .metadata()
            .map_err(|source| io_failure("inspect CAS object", &path, source))?;
        if metadata.len() > self.limits.max_blob_bytes {
            return Err(StorageError::LimitExceeded {
                resource: "blob bytes",
                limit: self.limits.max_blob_bytes,
                actual: metadata.len(),
            });
        }
        let (actual, size, _) = hash_reader(&mut file, self.limits.max_blob_bytes, false)?;
        if &actual != digest {
            return Err(StorageError::CorruptBlob {
                expected: digest.clone(),
                actual,
            });
        }
        Ok(size)
    }

    /// Verify an immutable object and return a rewound, seekable stream.
    /// Corrupt content is rejected before any byte can reach a caller.
    pub fn verified_reader(
        &self,
        digest: &ContentDigest,
        limit: u64,
    ) -> Result<VerifiedBlobReader, StorageError> {
        let limit = limit.min(self.limits.max_blob_bytes);
        let path = self.object_path(digest)?;
        let mut file = open_regular_nofollow(&path, "open CAS object")?;
        let metadata = file
            .metadata()
            .map_err(|source| io_failure("inspect CAS object", &path, source))?;
        if metadata.len() > limit {
            return Err(StorageError::LimitExceeded {
                resource: "blob bytes",
                limit,
                actual: metadata.len(),
            });
        }
        let (actual, size_bytes, _) = hash_reader(&mut file, limit, false)?;
        if &actual != digest {
            return Err(StorageError::CorruptBlob {
                expected: digest.clone(),
                actual,
            });
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|source| io_failure("rewind verified CAS object", &path, source))?;
        Ok(VerifiedBlobReader {
            file,
            digest: digest.clone(),
            size_bytes,
        })
    }

    /// Enumerate the immutable namespace under an explicit object bound.
    /// Unexpected names, symlinks, and special nodes fail closed rather than
    /// remaining outside lifecycle accounting.
    pub fn inventory_objects(
        &self,
        maximum_objects: usize,
    ) -> Result<Vec<CasObjectRecord>, StorageError> {
        if maximum_objects == 0 {
            return Err(StorageError::InvalidConfiguration(
                "CAS inventory object bound must be positive".to_owned(),
            ));
        }
        let root = self.root.join("objects").join("sha256");
        let mut objects = Vec::new();
        for (prefix, prefix_path) in read_sorted_names(&root, "read CAS digest prefixes")? {
            if prefix.len() != 2
                || !prefix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(StorageError::UnsafePath(format!(
                    "invalid CAS digest prefix `{prefix}`"
                )));
            }
            let metadata = fs::symlink_metadata(&prefix_path)
                .map_err(|source| io_failure("inspect CAS digest prefix", &prefix_path, source))?;
            require_real_directory(&prefix_path, &metadata)?;
            for (suffix, path) in read_sorted_names(&prefix_path, "read CAS objects")? {
                if suffix.len() != 62
                    || !suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(StorageError::UnsafePath(format!(
                        "invalid CAS object name `{prefix}{suffix}`"
                    )));
                }
                if objects.len() >= maximum_objects {
                    return Err(StorageError::LimitExceeded {
                        resource: "CAS inventory objects",
                        limit: maximum_objects as u64,
                        actual: objects.len() as u64 + 1,
                    });
                }
                let file = open_regular_nofollow(&path, "open CAS inventory object")?;
                let metadata = file
                    .metadata()
                    .map_err(|source| io_failure("inspect CAS inventory object", &path, source))?;
                if metadata.len() > self.limits.max_blob_bytes {
                    return Err(StorageError::LimitExceeded {
                        resource: "blob bytes",
                        limit: self.limits.max_blob_bytes,
                        actual: metadata.len(),
                    });
                }
                let created_unix_ms = u64::try_from(
                    metadata
                        .modified()
                        .map_err(|source| io_failure("read CAS object timestamp", &path, source))?
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| {
                            StorageError::Manifest(
                                "CAS object timestamp predates Unix epoch".to_owned(),
                            )
                        })?
                        .as_millis(),
                )
                .map_err(|_| StorageError::Manifest("CAS object timestamp overflow".to_owned()))?;
                objects.push(CasObjectRecord {
                    digest: ContentDigest::parse(format!("sha256:{prefix}{suffix}"))
                        .map_err(|error| StorageError::Manifest(error.to_string()))?,
                    size_bytes: metadata.len(),
                    created_unix_ms,
                });
            }
        }
        Ok(objects)
    }

    /// Delete only an exact digest after verifying its complete contents.
    /// Missing objects replay successfully; corrupt candidates are retained.
    pub fn remove_verified_object(
        &self,
        digest: &ContentDigest,
    ) -> Result<Option<u64>, StorageError> {
        let path = self.object_path(digest)?;
        let size = match self.verify_blob(digest) {
            Ok(size) => size,
            Err(StorageError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        fs::remove_file(&path)
            .map_err(|source| io_failure("remove verified CAS object", &path, source))?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
        Ok(Some(size))
    }

    /// Stream a declared object into private staging and publish it only when
    /// its exact digest and size have been verified.
    pub fn put_verified_reader<R: Read>(
        &self,
        reader: R,
        expected_digest: &ContentDigest,
        expected_size: u64,
        limit: u64,
    ) -> Result<BlobRecord, StorageError> {
        if expected_size > limit.min(self.limits.max_blob_bytes) {
            return Err(StorageError::LimitExceeded {
                resource: "blob bytes",
                limit: limit.min(self.limits.max_blob_bytes),
                actual: expected_size,
            });
        }
        self.put_reader_with_expectation(
            reader,
            limit.min(self.limits.max_blob_bytes),
            Some((expected_digest, expected_size)),
        )
    }

    pub(crate) fn read_blob_with_limit(
        &self,
        digest: &ContentDigest,
        limit: u64,
    ) -> Result<Vec<u8>, StorageError> {
        let path = self.object_path(digest)?;
        let mut file = open_regular_nofollow(&path, "open CAS object")?;
        let metadata = file
            .metadata()
            .map_err(|source| io_failure("inspect CAS object", &path, source))?;
        if metadata.len() > limit {
            return Err(StorageError::LimitExceeded {
                resource: "blob bytes",
                limit,
                actual: metadata.len(),
            });
        }
        let (actual, _, bytes) = hash_reader(&mut file, limit, true)?;
        if &actual != digest {
            return Err(StorageError::CorruptBlob {
                expected: digest.clone(),
                actual,
            });
        }
        Ok(bytes)
    }
}
use super::{hash_reader, FsCas};
