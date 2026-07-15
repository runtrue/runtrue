use super::*;
#[test]
fn topology_and_unwired_capabilities_fail_before_driver() {
    let driver = Arc::new(FakeDriver::default());
    let executor = executor(Arc::clone(&driver));
    let mut wrong_topology = capsule();
    wrong_topology.jobs[0].runner.cpu = 1;
    assert!(matches!(
        executor.preflight_lease(&lease(wrong_topology)),
        Err(RunnerError::FirecrackerAssignment(_))
    ));

    let mut secret = capsule();
    secret.jobs[0].steps[0]
        .capabilities
        .oidc_audiences
        .push("https://cloud.example".to_owned());
    assert!(matches!(
        executor.preflight_lease(&lease(secret)),
        Err(RunnerError::FirecrackerAssignment(_))
    ));
    let mut secret = capsule();
    secret.jobs[0].steps[0]
        .capabilities
        .secrets
        .push(runtrue_model::SecretReference {
            metadata_id: "secret-1".to_owned(),
            name: "TOKEN".to_owned(),
            purpose: None,
        });
    assert!(matches!(
        executor.preflight_lease(&lease(secret)),
        Err(RunnerError::FirecrackerAssignment(_))
    ));
    assert_eq!(driver.preflights.load(Ordering::Relaxed), 0);
}
