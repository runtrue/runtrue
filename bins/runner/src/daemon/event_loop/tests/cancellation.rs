use super::*;

#[tokio::test]
async fn matching_cancel_fence_stops_execution_and_is_acknowledged() {
    let (config, offer, fetched) = fixture();
    let cancel = v1::CancelLease {
        lease_id: offer.lease_id.clone(),
        fencing_generation: offer.fencing_generation,
        reason: "test".to_owned(),
        grace_period: Some(prost_types::Duration {
            seconds: 1,
            nanos: 0,
        }),
    };
    let shared = Arc::new(Mutex::new(FakeState {
        controls: VecDeque::from([
            v1::ControlMessage {
                body: Some(control_message::Body::LeaseOffer(Box::new(offer))),
            },
            v1::ControlMessage {
                body: Some(control_message::Body::CancelLease(cancel)),
            },
        ]),
        fetched: Some(fetched),
        ..FakeState::default()
    }));
    let directory = tempfile::tempdir().unwrap();
    RunnerDaemon::new(
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
    .unwrap();
    let state = shared.lock().await;
    assert_eq!(state.completions.last().unwrap().final_state, "canceled");
    assert!(state
        .sent
        .iter()
        .any(|message| matches!(message.body, Some(runner_message::Body::CancellationAck(_)))));
}
