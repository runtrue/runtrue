use runtrue_model::ContentDigest;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
};

/// Metadata returned after an object is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRecord {
    pub digest: ContentDigest,
    pub size_bytes: u64,
    /// True when another writer had already committed the same verified bytes.
    pub already_present: bool,
}

/// Bounded metadata used by the lifecycle worker. Object bytes are verified
/// separately immediately before deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasObjectRecord {
    pub digest: ContentDigest,
    pub size_bytes: u64,
    pub created_unix_ms: u64,
}

/// An immutable CAS object whose complete contents were verified before the
/// handle was returned. The handle is rewound and can be streamed without
/// retaining the object in memory.
#[derive(Debug)]
pub struct VerifiedBlobReader {
    pub(crate) file: File,
    pub(crate) digest: ContentDigest,
    pub(crate) size_bytes: u64,
}

impl VerifiedBlobReader {
    #[must_use]
    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

impl Read for VerifiedBlobReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for VerifiedBlobReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}
