use super::*;
#[test]
fn stale_runtime_state_is_not_reused() {
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let request = command_request();
    let stale = fixture
        .executor
        .state_root
        .join(format!("job-{}-1", short_identity(&request.job_id)));
    fs::create_dir(stale).unwrap();
    assert!(matches!(
        fixture.executor.execute_request(&request),
        Err(OciError::InvalidState(_))
    ));
    assert!(fixture.executor.runtime().invocations.is_empty());
}
