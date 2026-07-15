use super::*;
#[test]
fn traversal_workdirs_and_forbidden_mount_destinations_are_rejected() {
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let mut request = command_request();
    request.working_directory = Some("../escape".to_owned());
    assert!(matches!(
        fixture.executor.execute_request(&request),
        Err(OciError::UnsafeWorkingDirectory(_))
    ));

    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    let source = directory.path().join("source");
    let state = directory.path().join("state");
    let seccomp = directory.path().join("seccomp.json");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&source).unwrap();
    fs::write(&seccomp, br#"{"defaultAction":"SCMP_ACT_ERRNO"}"#).unwrap();
    let mut config = OciExecutorConfig::new("/usr/bin/podman", &seccomp);
    config.insert_job_image("job", locked_image()).unwrap();
    config
        .additional_mounts
        .push(OciMount::read_only(source, "/var/run"));
    assert!(matches!(
        OciExecutor::new(
            workspace,
            state,
            config,
            FakeAdmission::exact(),
            RecordingRuntime::default()
        ),
        Err(OciError::ForbiddenMount(_))
    ));
}

#[test]
fn seccomp_profile_must_be_valid_and_deny_by_default() {
    for profile in [
        b"{}".as_slice(),
        br#"{"defaultAction":"SCMP_ACT_ALLOW"}"#,
        br#"{"defaultAction":"SCMP_ACT_ERRNO","defaultAction":"SCMP_ACT_KILL"}"#,
        br#"{"defaultAction":"SCMP_ACT_ERRNO","listenerPath":"/tmp/notify.sock"}"#,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        let state = directory.path().join("state");
        let seccomp = directory.path().join("seccomp.json");
        fs::create_dir(&workspace).unwrap();
        fs::write(&seccomp, profile).unwrap();
        let mut config = OciExecutorConfig::new("/usr/bin/podman", &seccomp);
        config.insert_job_image("job", locked_image()).unwrap();
        assert!(matches!(
            OciExecutor::new(
                workspace,
                state,
                config,
                FakeAdmission::exact(),
                RecordingRuntime::default()
            ),
            Err(OciError::InvalidSeccompProfile(_))
        ));
    }
}

#[cfg(unix)]
#[test]
fn host_socket_mounts_are_rejected_even_when_explicitly_configured() {
    use std::os::unix::net::UnixListener;

    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    let state = directory.path().join("state");
    let seccomp = directory.path().join("seccomp.json");
    let socket = directory.path().join("docker.sock");
    fs::create_dir(&workspace).unwrap();
    fs::write(&seccomp, br#"{"defaultAction":"SCMP_ACT_ERRNO"}"#).unwrap();
    let _listener = UnixListener::bind(&socket).unwrap();
    let mut config = OciExecutorConfig::new("/usr/bin/podman", &seccomp);
    config.insert_job_image("job", locked_image()).unwrap();
    config
        .additional_mounts
        .push(OciMount::read_only(socket, "/socket"));
    assert!(matches!(
        OciExecutor::new(
            workspace,
            state,
            config,
            FakeAdmission::exact(),
            RecordingRuntime::default()
        ),
        Err(OciError::ForbiddenMount(_))
    ));
}

#[cfg(unix)]
#[test]
fn only_the_exact_private_runner_broker_socket_is_admitted() {
    use std::os::unix::{fs::PermissionsExt as _, net::UnixListener};

    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    let state = directory.path().join("state");
    let broker = directory.path().join("broker");
    let seccomp = directory.path().join("seccomp.json");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&broker).unwrap();
    fs::set_permissions(&broker, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&seccomp, br#"{"defaultAction":"SCMP_ACT_ERRNO"}"#).unwrap();
    let socket = broker.join("scm-proxy.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    let mut config = OciExecutorConfig::new("/usr/bin/podman", &seccomp);
    config.insert_job_image("job", locked_image()).unwrap();
    config.broker_socket = Some(OciMount::read_write(
        &socket,
        "/workspace/.runtrue-runtime/scm-proxy.sock",
    ));
    assert!(OciExecutor::new(
        &workspace,
        &state,
        config.clone(),
        FakeAdmission::exact(),
        RecordingRuntime::default(),
    )
    .is_ok());

    config.broker_socket = Some(OciMount::read_write(socket, "/workspace/other.sock"));
    assert!(matches!(
        OciExecutor::new(
            workspace,
            state,
            config,
            FakeAdmission::exact(),
            RecordingRuntime::default()
        ),
        Err(OciError::ForbiddenMount(_))
    ));
}

#[cfg(unix)]
#[test]
fn sockets_nested_inside_the_workspace_are_rejected() {
    use std::os::unix::net::UnixListener;

    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    let state = directory.path().join("state");
    let seccomp = directory.path().join("seccomp.json");
    fs::create_dir(&workspace).unwrap();
    fs::write(&seccomp, br#"{"defaultAction":"SCMP_ACT_ERRNO"}"#).unwrap();
    let _listener = UnixListener::bind(workspace.join("nested.sock")).unwrap();
    let mut config = OciExecutorConfig::new("/usr/bin/podman", &seccomp);
    config.insert_job_image("job", locked_image()).unwrap();
    assert!(matches!(
        OciExecutor::new(
            workspace,
            state,
            config,
            FakeAdmission::exact(),
            RecordingRuntime::default()
        ),
        Err(OciError::ForbiddenMount(_))
    ));
}

#[test]
fn preflight_rejects_ambient_capabilities_and_unused_image_assignments() {
    let fixture = fixture_with(AdmissionMode::Exact);
    let mut missing_lock = capsule();
    missing_lock.context.lockfile_digest = None;
    assert!(matches!(
        fixture.executor.preflight_capsule(&missing_lock),
        Err(OciError::UnsupportedFeature(_))
    ));
    let mut privileged = capsule();
    privileged.jobs[0]
        .runner
        .capabilities
        .push("privileged.container".to_owned());
    assert!(matches!(
        fixture.executor.preflight_capsule(&privileged),
        Err(OciError::UnsupportedFeature(_))
    ));

    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    let state = directory.path().join("state");
    let seccomp = directory.path().join("seccomp.json");
    fs::create_dir(&workspace).unwrap();
    fs::write(&seccomp, br#"{"defaultAction":"SCMP_ACT_ERRNO"}"#).unwrap();
    let mut config = OciExecutorConfig::new("/usr/bin/podman", &seccomp);
    config.insert_job_image("job", locked_image()).unwrap();
    config.insert_job_image("stale", locked_image()).unwrap();
    let executor = OciExecutor::new(
        workspace,
        state,
        config,
        FakeAdmission::exact(),
        RecordingRuntime::default(),
    )
    .unwrap();
    assert!(matches!(
        executor.preflight_capsule(&capsule()),
        Err(OciError::UnusedImageAssignment(job)) if job == "stale"
    ));
}
