use super::*;
#[test]
fn environment_limits_and_socket_locator_variables_fail_closed() {
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let mut socket = command_request();
    socket.environment.insert(
        "DOCKER_HOST".to_owned(),
        "unix:///var/run/docker.sock".to_owned(),
    );
    assert!(matches!(
        fixture.executor.execute_request(&socket),
        Err(OciError::ForbiddenSocketExposure(_))
    ));
    let mut oversized = command_request();
    oversized.environment.insert(
        "VALUE".to_owned(),
        "x".repeat(fixture.executor.config.limits.max_environment_value_bytes + 1),
    );
    assert!(matches!(
        fixture.executor.execute_request(&oversized),
        Err(OciError::InvalidEnvironmentValue(_))
    ));
    assert!(fixture.executor.runtime().invocations.is_empty());
}
