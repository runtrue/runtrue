use super::*;

#[tokio::test]
async fn rotation_waits_for_active_lease_completion_then_atomically_installs() {
    let (mut config, offer, fetched) = fixture();
    config.mode = RunMode::Daemon;
    let directory = tempfile::tempdir().unwrap();
    let credential_store =
        RunnerCredentialStore::open(directory.path().join("credentials")).unwrap();
    let rotation_authority = test_ca();
    let first = credential_store
        .install(&initial_credentials(&rotation_authority))
        .unwrap();
    config.credential_store = Some(credential_store.clone());
    let shared = Arc::new(Mutex::new(FakeState {
        controls: VecDeque::from([
            v1::ControlMessage {
                body: Some(control_message::Body::LeaseOffer(Box::new(offer))),
            },
            v1::ControlMessage {
                body: Some(control_message::Body::RotateCertificate(
                    v1::RotateCertificateNow {
                        reason: "expiring".to_owned(),
                        deadline: Some(timestamp(now_unix_ms().unwrap() + 1_000)),
                    },
                )),
            },
        ]),
        fetched: Some(fetched),
        rotation_authority: Some(rotation_authority),
        ..FakeState::default()
    }));
    let error = RunnerDaemon::new(
        FakeTransport(Arc::clone(&shared)),
        FakeExecutor {
            wait_for_cancel: true,
        },
        config,
        RunnerStateStore::open(directory.path().join("state")).unwrap(),
        WorkspaceManager::open(directory.path().join("work")).unwrap(),
    )
    .run()
    .await
    .unwrap_err();
    assert!(matches!(error, RunnerError::CertificateRotated));
    let state = shared.lock().await;
    assert_eq!(state.rotation_requests.len(), 1);
    assert_eq!(state.completion_count_when_rotated, Some(1));
    assert_eq!(state.completions.last().unwrap().final_state, "canceled");
    drop(state);
    assert!(RunnerStateStore::open(directory.path().join("state"))
        .unwrap()
        .pending_completion()
        .unwrap()
        .is_some());
    let rotated = credential_store.load_current().unwrap();
    assert_ne!(rotated.client_certificate, first.client_certificate);
    assert_eq!(rotated.runner_id, "runner-1");
}

#[tokio::test]
async fn lost_rotation_response_retries_the_persisted_csr_after_restart() {
    let (mut config, _, _) = fixture();
    config.mode = RunMode::Daemon;
    let directory = tempfile::tempdir().unwrap();
    let credential_store =
        RunnerCredentialStore::open(directory.path().join("credentials")).unwrap();
    let rotation_authority = test_ca();
    let current = credential_store
        .install(&initial_credentials(&rotation_authority))
        .unwrap();
    let generated = generate_certificate_request().unwrap();
    let expected_csr = generated.csr_der.clone();
    credential_store
        .begin_rotation(&current, generated.private_key_pem, generated.csr_der)
        .unwrap();
    config.credential_store = Some(credential_store.clone());
    let shared = Arc::new(Mutex::new(FakeState {
        rotation_failures_remaining: 1,
        rotation_authority: Some(rotation_authority),
        ..FakeState::default()
    }));

    let first_error = RunnerDaemon::new(
        FakeTransport(Arc::clone(&shared)),
        FakeExecutor {
            wait_for_cancel: false,
        },
        config.clone(),
        RunnerStateStore::open(directory.path().join("state")).unwrap(),
        WorkspaceManager::open(directory.path().join("work")).unwrap(),
    )
    .run()
    .await
    .unwrap_err();
    assert!(matches!(
        first_error,
        RunnerError::Transport(TransportError::Status {
            code: tonic::Code::Unavailable,
            ..
        })
    ));
    assert_eq!(
        credential_store
            .load_pending_rotation()
            .unwrap()
            .unwrap()
            .csr_der,
        expected_csr
    );

    let second_error = RunnerDaemon::new(
        FakeTransport(Arc::clone(&shared)),
        FakeExecutor {
            wait_for_cancel: false,
        },
        config,
        RunnerStateStore::open(directory.path().join("state")).unwrap(),
        WorkspaceManager::open(directory.path().join("work")).unwrap(),
    )
    .run()
    .await
    .unwrap_err();
    assert!(matches!(second_error, RunnerError::CertificateRotated));
    let state = shared.lock().await;
    assert_eq!(state.rotation_requests.len(), 2);
    assert_eq!(
        state.rotation_requests[0].certificate_signing_request,
        expected_csr
    );
    assert_eq!(
        state.rotation_requests[1].certificate_signing_request,
        expected_csr
    );
    drop(state);
    assert!(credential_store.load_pending_rotation().unwrap().is_none());
    assert_ne!(
        credential_store
            .load_current()
            .unwrap()
            .certificate_fingerprint,
        current.certificate_fingerprint
    );
}

#[tokio::test]
async fn drain_rejects_new_work_and_exits_without_execution() {
    let (mut config, offer, fetched) = fixture();
    config.allow_trusted_native = false;
    config.mode = RunMode::Daemon;
    let shared = Arc::new(Mutex::new(FakeState {
        controls: VecDeque::from([
            v1::ControlMessage {
                body: Some(control_message::Body::LeaseOffer(Box::new(offer))),
            },
            v1::ControlMessage {
                body: Some(control_message::Body::DrainRunner(v1::DrainRunner {
                    reason: "maintenance".to_owned(),
                    deadline: Some(timestamp(now_unix_ms().unwrap() + 5_000)),
                })),
            },
        ]),
        fetched: Some(fetched),
        ..FakeState::default()
    }));
    let directory = tempfile::tempdir().unwrap();
    RunnerDaemon::new(
        FakeTransport(Arc::clone(&shared)),
        FakeExecutor {
            wait_for_cancel: false,
        },
        config,
        RunnerStateStore::open(directory.path().join("state")).unwrap(),
        WorkspaceManager::open(directory.path().join("work")).unwrap(),
    )
    .run()
    .await
    .unwrap();
    let state = shared.lock().await;
    assert!(state.completions.is_empty());
    assert!(state.sent.iter().any(|message| matches!(
        &message.body,
        Some(runner_message::Body::LeaseDecision(decision))
            if !decision.accepted && decision.rejection_code == "trusted_native_disabled"
    )));
}

#[tokio::test]
async fn once_runner_exits_after_rejecting_an_offer() {
    let (mut config, offer, fetched) = fixture();
    config.allow_trusted_native = false;
    let shared = Arc::new(Mutex::new(FakeState {
        controls: VecDeque::from([v1::ControlMessage {
            body: Some(control_message::Body::LeaseOffer(Box::new(offer))),
        }]),
        fetched: Some(fetched),
        ..FakeState::default()
    }));
    let directory = tempfile::tempdir().unwrap();

    RunnerDaemon::new(
        FakeTransport(Arc::clone(&shared)),
        FakeExecutor {
            wait_for_cancel: false,
        },
        config,
        RunnerStateStore::open(directory.path().join("state")).unwrap(),
        WorkspaceManager::open(directory.path().join("work")).unwrap(),
    )
    .run()
    .await
    .unwrap();

    let state = shared.lock().await;
    assert!(state.completions.is_empty());
    assert_eq!(state.closes, 1);
    assert!(state.sent.iter().any(|message| matches!(
        &message.body,
        Some(runner_message::Body::LeaseDecision(decision))
            if !decision.accepted && decision.rejection_code == "trusted_native_disabled"
    )));
}

#[tokio::test]
async fn wasm_runner_executes_two_accepted_leases_concurrently() {
    let (mut config, first_offer, fetched) = fixture_for(Isolation::Wasm, 2);
    config.mode = RunMode::Daemon;
    let mut second_offer = first_offer.clone();
    second_offer.lease_id = "lease-2".to_owned();
    let shared = Arc::new(Mutex::new(FakeState {
        controls: VecDeque::from([
            v1::ControlMessage {
                body: Some(control_message::Body::LeaseOffer(Box::new(first_offer))),
            },
            v1::ControlMessage {
                body: Some(control_message::Body::LeaseOffer(Box::new(second_offer))),
            },
            v1::ControlMessage {
                body: Some(control_message::Body::DrainRunner(v1::DrainRunner {
                    reason: "test complete".to_owned(),
                    deadline: Some(timestamp(now_unix_ms().unwrap() + 100)),
                })),
            },
        ]),
        fetched: Some(fetched),
        ..FakeState::default()
    }));
    let directory = tempfile::tempdir().unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        RunnerDaemon::new(
            FakeTransport(Arc::clone(&shared)),
            FakeExecutor {
                wait_for_cancel: true,
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
    let accepted = state
        .sent
        .iter()
        .filter(|message| {
            matches!(
                &message.body,
                Some(runner_message::Body::LeaseDecision(decision)) if decision.accepted
            )
        })
        .count();
    assert_eq!(accepted, 2);
    let completed = state
        .completions
        .iter()
        .map(|completion| completion.lease_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(completed, BTreeSet::from(["lease-1", "lease-2"]));
}
