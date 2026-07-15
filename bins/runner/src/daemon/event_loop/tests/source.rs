use super::*;

#[test]
fn source_wire_digest_is_strict_and_exact() {
    let digest = ContentDigest::sha256(b"source");
    let bytes = hex::decode(digest.as_str().trim_start_matches("sha256:")).unwrap();
    assert_eq!(digest_from_wire(DIGEST_ALGORITHM, &bytes).unwrap(), digest);
    assert!(digest_from_wire("sha512", &bytes).is_err());
    assert!(digest_from_wire(DIGEST_ALGORITHM, &bytes[..31]).is_err());
}

struct ChunkCancellationBroker {
    first_chunk: std::sync::mpsc::Sender<()>,
}

impl RunnerBrokerClient for ChunkCancellationBroker {
    fn request_secret_lease(
        &self,
        _: v1::SecretLeaseRequest,
        _: Duration,
    ) -> Result<v1::SecretLeaseResponse, TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }
    fn revoke_secret_lease(
        &self,
        _: v1::RevokeSecretLeaseRequest,
        _: Duration,
    ) -> Result<(), TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }
    fn mint_oidc_token(
        &self,
        _: v1::OidcTokenRequest,
        _: Duration,
    ) -> Result<v1::OidcTokenResponse, TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }

    fn download_source_object_to_cancellable(
        &self,
        _request: v2::ObjectDownloadRequest,
        writer: &mut dyn std::io::Write,
        _maximum_bytes: u64,
        _timeout: Duration,
        cancelled: Arc<AtomicBool>,
    ) -> Result<u64, TransportError> {
        writer.write_all(b"partial").unwrap();
        self.first_chunk.send(()).unwrap();
        while !cancelled.load(Ordering::Acquire) {
            thread::yield_now();
        }
        Err(TransportError::TransferCancelled)
    }
}

#[test]
fn cancellation_at_source_chunk_removes_staging_and_never_starts_executor() {
    let root = tempfile::tempdir().unwrap();
    let staging_path = root.path().join("source-staging");
    std::fs::create_dir(&staging_path).unwrap();
    let file_path = staging_path.join("object");
    let (sent, received) = std::sync::mpsc::channel();
    let broker = ChunkCancellationBroker { first_chunk: sent };
    let cancelled = Arc::new(AtomicBool::new(false));
    let task_cancelled = cancelled.clone();
    let executor_starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task = thread::spawn(move || {
        let mut file = File::create(file_path).unwrap();
        broker.download_source_object_to_cancellable(
            v2::ObjectDownloadRequest::default(),
            &mut file,
            1024,
            Duration::from_secs(1),
            task_cancelled,
        )
    });
    received.recv_timeout(Duration::from_secs(1)).unwrap();
    cancelled.store(true, Ordering::Release);
    assert!(matches!(
        task.join().unwrap(),
        Err(TransportError::TransferCancelled)
    ));
    std::fs::remove_dir_all(&staging_path).unwrap();
    assert!(!staging_path.exists());
    assert_eq!(executor_starts.load(Ordering::Acquire), 0);
}
