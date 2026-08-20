use super::*;

struct BrokerTransport {
    inner: FakeTransport,
    broker: Arc<dyn RunnerBrokerClient>,
}

#[async_trait]
impl RunnerTransport for BrokerTransport {
    async fn open(&mut self, hello: v1::RunnerHello) -> Result<v1::ControlHello, TransportError> {
        self.inner.open(hello).await
    }

    async fn send(&mut self, message: v1::RunnerMessage) -> Result<(), TransportError> {
        self.inner.send(message).await
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.inner.close().await
    }

    async fn next_control(&mut self) -> Result<Option<v1::ControlMessage>, TransportError> {
        self.inner.next_control().await
    }

    async fn fetch_capsule(
        &mut self,
        request: v1::FetchExecutionCapsuleRequest,
    ) -> Result<v1::FetchExecutionCapsuleResponse, TransportError> {
        self.inner.fetch_capsule(request).await
    }

    async fn complete_lease(
        &mut self,
        request: v1::CompleteLeaseRequest,
    ) -> Result<v1::CompleteLeaseResponse, TransportError> {
        self.inner.complete_lease(request).await
    }

    async fn rotate_certificate(
        &mut self,
        request: v1::RotateCertificateRequest,
    ) -> Result<v1::RotateCertificateResponse, TransportError> {
        self.inner.rotate_certificate(request).await
    }

    fn broker_client(&self) -> Option<Arc<dyn RunnerBrokerClient>> {
        Some(Arc::clone(&self.broker))
    }
}

struct SlowSourceBroker {
    delay: Duration,
}

impl RunnerBrokerClient for SlowSourceBroker {
    fn request_source_ticket(
        &self,
        _: v2::SourceTicketRequest,
        _: Duration,
    ) -> Result<v2::SourceTicketResponse, TransportError> {
        thread::sleep(self.delay);
        Err(TransportError::DataPlaneUnavailable)
    }

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
}

#[tokio::test]
async fn source_hydration_continues_accepted_lease_heartbeats() {
    let mut source_capsule = capsule();
    source_capsule.context.source_tree_digest = Some(ContentDigest::sha256(b"source manifest"));
    let (config, offer, fetched) = fixture_from_capsule(source_capsule, Isolation::Native, 1);
    let expected_lease_id = offer.lease_id.clone();
    let expected_generation = offer.fencing_generation;
    let shared = Arc::new(Mutex::new(FakeState {
        controls: VecDeque::from([v1::ControlMessage {
            body: Some(control_message::Body::LeaseOffer(Box::new(offer))),
        }]),
        fetched: Some(fetched),
        ..FakeState::default()
    }));
    let directory = tempfile::tempdir().unwrap();
    let transport = BrokerTransport {
        inner: FakeTransport(Arc::clone(&shared)),
        broker: Arc::new(SlowSourceBroker {
            delay: Duration::from_millis(450),
        }),
    };

    tokio::time::timeout(
        Duration::from_secs(3),
        RunnerDaemon::new(
            transport,
            FakeExecutor {
                wait_for_cancel: false,
            },
            config,
            RunnerStateStore::open(directory.path().join("state")).unwrap(),
            WorkspaceManager::open(directory.path().join("work")).unwrap(),
        )
        .run(),
    )
    .await
    .unwrap()
    .unwrap();

    let state = shared.lock().await;
    assert!(state.sent.iter().any(|message| matches!(
        &message.body,
        Some(runner_message::Body::LeaseDecision(decision)) if decision.accepted
    )));
    let hydration_heartbeats = state
        .sent
        .iter()
        .filter(|message| {
            matches!(
                &message.body,
                Some(runner_message::Body::Heartbeat(heartbeat))
                    if heartbeat.active_leases.as_slice() == [v1::ActiveLease {
                        lease_id: expected_lease_id.clone(),
                        fencing_generation: expected_generation,
                        state: "preparing".to_owned(),
                    }]
            )
        })
        .count();
    assert!(hydration_heartbeats >= 3, "observed {hydration_heartbeats}");
}

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
