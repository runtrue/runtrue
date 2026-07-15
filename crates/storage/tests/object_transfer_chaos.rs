use runtrue_model::ContentDigest;
use runtrue_storage::{CasLimits, FsCas, StorageError};
use std::{
    fs,
    io::{self, Cursor, Read},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread,
    time::Duration,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

enum ReadDirective {
    Emit(Vec<u8>),
    Fail(io::ErrorKind),
}

struct ProgressGatedReader {
    progress: Sender<usize>,
    directives: Receiver<ReadDirective>,
    reads: usize,
}

impl Read for ProgressGatedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.progress
            .send(self.reads)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "progress receiver closed"))?;
        self.reads += 1;
        match self.directives.recv_timeout(TEST_TIMEOUT) {
            Ok(ReadDirective::Emit(bytes)) => {
                let count = bytes.len().min(buffer.len());
                buffer[..count].copy_from_slice(&bytes[..count]);
                Ok(count)
            }
            Ok(ReadDirective::Fail(kind)) => Err(io::Error::new(kind, "injected reader failure")),
            Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "progress-gated reader stalled",
            )),
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "directive sender closed",
            )),
        }
    }
}

struct GeneratedReader {
    remaining: u64,
    byte: u8,
}

impl Read for GeneratedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = usize::try_from(self.remaining.min(buffer.len() as u64)).unwrap();
        buffer[..count].fill(self.byte);
        self.remaining -= count as u64;
        Ok(count)
    }
}

struct ReadBomb;

impl Read for ReadBomb {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        panic!("declared-size rejection must happen before reading input")
    }
}

fn cas(root: &Path, max_blob_bytes: u64) -> FsCas {
    FsCas::open(
        root,
        CasLimits {
            max_blob_bytes,
            ..CasLimits::default()
        },
    )
    .unwrap()
}

fn staging_entries(cas: &FsCas) -> Vec<PathBuf> {
    fs::read_dir(cas.root().join("tmp"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
}

fn assert_no_failed_publication(cas: &FsCas) {
    assert!(staging_entries(cas).is_empty(), "private staging leaked");
    assert!(
        cas.inventory_objects(1_000).unwrap().is_empty(),
        "failed transfer published immutable bytes"
    );
}

fn object_path(cas: &FsCas, digest: &ContentDigest) -> PathBuf {
    let encoded = digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("SHA-256 test digest");
    cas.root()
        .join("objects/sha256")
        .join(&encoded[..2])
        .join(&encoded[2..])
}

#[test]
fn progress_gated_stall_then_timeout_cleans_staging_without_publication() {
    let directory = tempfile::tempdir().unwrap();
    let cas = cas(&directory.path().join("cas"), 1024 * 1024);
    let worker_cas = cas.clone();
    let (progress_tx, progress_rx) = mpsc::channel();
    let (directive_tx, directive_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = worker_cas.put_reader(ProgressGatedReader {
            progress: progress_tx,
            directives: directive_rx,
            reads: 0,
        });
        result_tx.send(result).unwrap();
    });

    assert_eq!(progress_rx.recv_timeout(TEST_TIMEOUT).unwrap(), 0);
    assert_eq!(staging_entries(&cas).len(), 1);
    directive_tx
        .send(ReadDirective::Emit(vec![0x5a; 4096]))
        .unwrap();
    assert_eq!(progress_rx.recv_timeout(TEST_TIMEOUT).unwrap(), 1);
    assert!(matches!(
        result_rx.recv_timeout(Duration::from_millis(25)),
        Err(RecvTimeoutError::Timeout)
    ));
    directive_tx
        .send(ReadDirective::Fail(io::ErrorKind::TimedOut))
        .unwrap();

    let error = result_rx.recv_timeout(TEST_TIMEOUT).unwrap().unwrap_err();
    assert!(matches!(
        error,
        StorageError::Io { source, .. } if source.kind() == io::ErrorKind::TimedOut
    ));
    worker.join().unwrap();
    assert_no_failed_publication(&cas);
}

#[cfg(unix)]
#[test]
fn corrupt_immutable_object_is_rejected_retained_and_rejected_again_after_reopen() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("cas");
    let original = b"immutable verified bytes";
    let first = cas(&root, 1024 * 1024);
    let record = first.put_bytes(original).unwrap();
    let path = object_path(&first, &record.digest);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"substituted hostile data").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();

    let first_error = first
        .verified_reader(&record.digest, record.size_bytes)
        .unwrap_err();
    assert!(matches!(&first_error, StorageError::CorruptBlob { .. }));
    assert!(first_error.is_corruption());
    drop(first);

    let reopened = cas(&root, 1024 * 1024);
    let reopened_error = reopened
        .verified_reader(&record.digest, record.size_bytes)
        .unwrap_err();
    assert!(matches!(
        &reopened_error,
        StorageError::CorruptBlob { expected, .. } if expected == &record.digest
    ));
    assert!(reopened_error.is_corruption());
    let deletion_error = reopened.remove_verified_object(&record.digest).unwrap_err();
    assert!(matches!(deletion_error, StorageError::CorruptBlob { .. }));
    assert!(
        path.exists(),
        "corrupt evidence must not be silently deleted"
    );
    assert_eq!(reopened.inventory_objects(2).unwrap().len(), 1);
    assert!(staging_entries(&reopened).is_empty());
}

#[test]
fn exact_verified_commit_streams_and_replays_idempotently_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("cas");
    let bytes = vec![0xa7; 192 * 1024 + 17];
    let digest = ContentDigest::sha256(&bytes);
    let first = cas(&root, 1024 * 1024);
    let committed = first
        .put_verified_reader(
            Cursor::new(&bytes),
            &digest,
            bytes.len() as u64,
            bytes.len() as u64,
        )
        .unwrap();
    assert!(!committed.already_present);
    drop(first);

    let reopened = cas(&root, 1024 * 1024);
    let mut reader = reopened
        .verified_reader(&digest, bytes.len() as u64)
        .unwrap();
    let mut observed = Vec::new();
    reader.read_to_end(&mut observed).unwrap();
    assert_eq!(observed, bytes);
    let replay = reopened
        .put_verified_reader(
            Cursor::new(&observed),
            &digest,
            observed.len() as u64,
            observed.len() as u64,
        )
        .unwrap();
    assert!(replay.already_present);
    assert_eq!(replay.digest, digest);
    assert_eq!(reopened.inventory_objects(2).unwrap().len(), 1);
    assert!(staging_entries(&reopened).is_empty());
}

#[test]
fn bounds_and_integrity_failures_keep_distinct_classification_and_cleanup() {
    let directory = tempfile::tempdir().unwrap();

    let preflight = cas(&directory.path().join("preflight"), 64);
    let expected = ContentDigest::sha256(b"expected");
    let error = preflight
        .put_verified_reader(ReadBomb, &expected, 65, 64)
        .unwrap_err();
    assert!(matches!(
        &error,
        StorageError::LimitExceeded {
            resource: "blob bytes",
            limit: 64,
            actual: 65,
        }
    ));
    assert!(!error.is_corruption());
    assert_no_failed_publication(&preflight);

    let streamed = cas(&directory.path().join("streamed"), 64);
    let error = streamed
        .put_reader(GeneratedReader {
            remaining: 65,
            byte: 0x11,
        })
        .unwrap_err();
    assert!(matches!(
        &error,
        StorageError::LimitExceeded {
            resource: "blob bytes",
            limit: 64,
            actual: 65,
        }
    ));
    assert!(!error.is_corruption());
    assert_no_failed_publication(&streamed);

    for (name, expected_digest, expected_size) in [
        ("digest", ContentDigest::sha256(b"other"), 7),
        ("size", ContentDigest::sha256(b"payload"), 8),
    ] {
        let mismatch = cas(&directory.path().join(name), 64);
        let error = mismatch
            .put_verified_reader(Cursor::new(b"payload"), &expected_digest, expected_size, 64)
            .unwrap_err();
        assert!(matches!(&error, StorageError::Manifest(_)));
        assert!(error.is_corruption());
        assert_no_failed_publication(&mismatch);
    }

    let quota = cas(&directory.path().join("quota"), 64);
    quota.put_bytes(b"one").unwrap();
    quota.put_bytes(b"two").unwrap();
    let error = quota.inventory_objects(1).unwrap_err();
    assert!(matches!(
        &error,
        StorageError::LimitExceeded {
            resource: "CAS inventory objects",
            limit: 1,
            actual: 2,
        }
    ));
    assert!(!error.is_corruption());
    assert_eq!(quota.inventory_objects(2).unwrap().len(), 2);
    assert!(staging_entries(&quota).is_empty());
}
