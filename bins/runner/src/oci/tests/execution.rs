use super::*;
#[test]
fn service_lease_uses_oci_only_and_finalizes_network_and_containers() {
    let fixture = Fixture::new(true);
    fixture.write_job_manifest();
    fixture.write_service_manifest();
    let factory = RecordingFactory::default();
    let executor = fixture.load(factory.clone()).unwrap();
    let workspace = fixture._directory.path().join("workspace");
    fs::create_dir(&workspace).unwrap();

    executor.preflight_lease(&fixture.lease()).unwrap();
    let result = executor
        .execute(&fixture.lease(), &workspace, CancellationToken::default())
        .unwrap();

    assert!(result.succeeded());
    let invocations = factory
        .invocations
        .lock()
        .unwrap()
        .iter()
        .copied()
        .filter(|kind| *kind != RuntimeInvocationKind::ImageExists)
        .collect::<Vec<_>>();
    let network = invocations
        .iter()
        .position(|kind| *kind == RuntimeInvocationKind::NetworkCreate)
        .unwrap();
    let service = invocations
        .iter()
        .position(|kind| *kind == RuntimeInvocationKind::ServiceStart)
        .unwrap();
    let job = invocations
        .iter()
        .position(|kind| *kind == RuntimeInvocationKind::Run)
        .unwrap();
    assert!(network < service && service < job);
    assert!(invocations.ends_with(&[
        RuntimeInvocationKind::Remove,
        RuntimeInvocationKind::Exists,
        RuntimeInvocationKind::NetworkRemove,
        RuntimeInvocationKind::NetworkExists,
    ]));
    assert!(fs::read_dir(executor.state_root())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn pre_canceled_lease_never_starts_podman() {
    let fixture = Fixture::new(false);
    fixture.write_job_manifest();
    let factory = RecordingFactory::default();
    let executor = fixture.load(factory.clone()).unwrap();
    let startup_invocations = factory.invocations.lock().unwrap().len();
    let workspace = fixture._directory.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    let result = executor
        .execute(&fixture.lease(), &workspace, cancellation)
        .unwrap();

    assert_eq!(result.jobs["job"].state, runtrue_engine::JobState::Canceled);
    assert_eq!(
        factory.invocations.lock().unwrap().len(),
        startup_invocations
    );
}
#[test]
fn isolated_restart_sweeps_and_verifies_stale_runtime_state() {
    let fixture = Fixture::new(false);
    fixture.write_job_manifest();
    let factory = RecordingFactory::default();
    let executor = fixture.load(factory.clone()).unwrap();
    factory.invocations.lock().unwrap().clear();
    let (stale, job) = stale_job_state(&executor);
    let recovery = OciRecoveryConfig::new(&fixture.paths.podman);
    let mut runtime = RecordingRuntime {
        invocations: Arc::clone(&factory.invocations),
        recovery_leak: false,
        missing_image: false,
    };

    recover_abandoned_job_state(&job, &recovery, &mut runtime).unwrap();
    assert!(!job.exists());
    assert!(stale.exists());
    assert_eq!(
        *factory.invocations.lock().unwrap(),
        vec![
            RuntimeInvocationKind::RecoveryRemoveContainers,
            RuntimeInvocationKind::RecoveryListContainers,
            RuntimeInvocationKind::RecoveryPruneVolumes,
            RuntimeInvocationKind::RecoveryListVolumes,
            RuntimeInvocationKind::RecoveryPruneNetworks,
            RuntimeInvocationKind::RecoveryListNetworks,
        ]
    );
}

#[test]
fn isolated_restart_preserves_state_when_runtime_cannot_prove_cleanup() {
    let fixture = Fixture::new(false);
    fixture.write_job_manifest();
    let factory = RecordingFactory {
        recovery_leak: true,
        ..RecordingFactory::default()
    };
    let executor = fixture.load(factory.clone()).unwrap();
    factory.invocations.lock().unwrap().clear();
    let (_, job) = stale_job_state(&executor);
    let recovery = OciRecoveryConfig::new(&fixture.paths.podman);
    let mut runtime = RecordingRuntime {
        invocations: Arc::clone(&factory.invocations),
        recovery_leak: true,
        missing_image: false,
    };

    assert!(recover_abandoned_job_state(&job, &recovery, &mut runtime).is_err());
    assert!(job.exists());
}

#[test]
fn runner_restart_refuses_global_cleanup_against_the_shared_image_store() {
    let fixture = Fixture::new(false);
    fixture.write_job_manifest();
    let factory = RecordingFactory::default();
    let executor = fixture.load(factory.clone()).unwrap();
    factory.invocations.lock().unwrap().clear();
    let (stale, job) = stale_job_state(&executor);

    assert!(executor.cleanup_stale().is_err());
    assert!(stale.exists());
    assert!(job.exists());
    assert!(factory.invocations.lock().unwrap().is_empty());
}

fn stale_job_state(executor: &OciJobExecutor) -> (PathBuf, PathBuf) {
    let stale = executor.state_root().join("stale-lease");
    fs::create_dir(&stale).unwrap();
    private_directory(&stale);
    let job = stale.join("job-state");
    fs::create_dir(&job).unwrap();
    private_directory(&job);
    for child in ["storage", "run", "tmp"] {
        let path = job.join(child);
        fs::create_dir(&path).unwrap();
        private_directory(&path);
    }
    (stale, job)
}
