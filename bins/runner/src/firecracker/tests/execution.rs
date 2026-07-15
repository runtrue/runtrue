use super::*;
#[test]
fn fake_driver_executes_exact_selected_microvm_job_without_kvm() {
    let driver = Arc::new(FakeDriver::default());
    let executor = executor(Arc::clone(&driver));
    let lease = lease(capsule());
    executor.preflight_lease(&lease).unwrap();
    let outcome = executor
        .execute(&lease, CancellationToken::default(), None)
        .unwrap();
    assert_eq!(outcome.final_state, "succeeded");
    assert_eq!(driver.executions.load(Ordering::Relaxed), 1);
    assert_eq!(driver.preflights.load(Ordering::Relaxed), 2);
}

#[test]
fn cancellation_never_falls_back_or_reports_a_generic_failure() {
    let driver = Arc::new(FakeDriver {
        fail: true,
        ..FakeDriver::default()
    });
    let executor = executor(driver);
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let outcome = executor
        .execute(&lease(capsule()), cancellation, None)
        .unwrap();
    assert_eq!(outcome.final_state, "canceled");
    assert_eq!(outcome.error_code, "canceled");
}
