use super::*;

#[test]
fn lifecycle_bridge_publishes_running_and_matching_terminal_states_only() {
    let running = StepStateObservation {
        job_id: "build".to_owned(),
        step_id: "publish".to_owned(),
        job_attempt: 1,
        from: Some(runtrue_engine::StepState::Created),
        to: runtrue_engine::StepState::Running,
        credential_taint: runtrue_engine::CredentialTaint::None,
    };
    assert!(publish_step_observation(&running));
    assert!(publish_step_observation(&StepStateObservation {
        from: Some(runtrue_engine::StepState::Running),
        to: runtrue_engine::StepState::Succeeded,
        ..running.clone()
    }));
    assert!(publish_step_observation(&StepStateObservation {
        from: Some(runtrue_engine::StepState::Created),
        to: runtrue_engine::StepState::Skipped,
        ..running.clone()
    }));
    assert!(!publish_step_observation(&StepStateObservation {
        from: Some(runtrue_engine::StepState::Created),
        to: runtrue_engine::StepState::Canceled,
        ..running
    }));
}

#[tokio::test]
async fn exact_completion_is_persisted_and_retried_idempotently() {
    let (config, offer, fetched) = fixture();
    let shared = Arc::new(Mutex::new(FakeState {
        controls: VecDeque::from([v1::ControlMessage {
            body: Some(control_message::Body::LeaseOffer(Box::new(offer))),
        }]),
        fetched: Some(fetched),
        ..FakeState::default()
    }));
    let transport = FakeTransport(Arc::clone(&shared));
    let directory = tempfile::tempdir().unwrap();
    let state = RunnerStateStore::open(directory.path().join("state")).unwrap();
    let workspaces = WorkspaceManager::open(directory.path().join("work")).unwrap();
    RunnerDaemon::new(
        transport,
        FakeExecutor {
            wait_for_cancel: false,
        },
        config,
        state,
        workspaces,
    )
    .run()
    .await
    .unwrap();
    let state = shared.lock().await;
    assert_eq!(state.hellos.len(), 1);
    assert_eq!(state.hellos[0].protocol_version, PROTOCOL_MAX);
    assert_eq!(
        state.hellos[0].inventory.as_ref().unwrap().protocol_version,
        PROTOCOL_MAX
    );
    assert_eq!(state.completions.len(), 2);
    assert_eq!(state.completions[0], state.completions[1]);
    assert!(state.sent.iter().any(|message| matches!(
        message.body,
        Some(runner_message::Body::LeaseDecision(v1::LeaseDecision {
            accepted: true,
            ..
        }))
    )));
}
