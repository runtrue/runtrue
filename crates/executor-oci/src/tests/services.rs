use super::*;
#[test]
fn services_start_before_the_job_on_an_internal_job_only_network() {
    let mut fixture = fixture_with_config(AdmissionMode::Exact, true);
    fixture
        .executor
        .preflight_capsule(&capsule_with_service(Some(short_healthcheck(2))))
        .unwrap();
    let output = fixture
        .executor
        .execute_request(&command_request())
        .unwrap();
    assert!(output.succeeded());

    let runtime = fixture.executor.runtime();
    let kinds = runtime
        .invocations
        .iter()
        .map(RuntimeInvocation::kind)
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            RuntimeInvocationKind::NetworkCreate,
            RuntimeInvocationKind::ServiceStart,
            RuntimeInvocationKind::HealthCheck,
            RuntimeInvocationKind::Run,
            RuntimeInvocationKind::Remove,
            RuntimeInvocationKind::Exists,
        ]
    );
    let create = &runtime.invocations[0];
    assert!(create
        .arguments
        .iter()
        .any(|argument| argument == "--internal"));
    assert!(create
        .arguments
        .iter()
        .any(|argument| argument == "--driver=bridge"));
    let network = create.arguments.last().unwrap();
    let service = &runtime.invocations[1];
    let job = &runtime.invocations[3];
    for invocation in [service, job] {
        assert!(invocation
            .arguments
            .iter()
            .any(|argument| argument == &format!("--network={network}")));
    }
    for required in [
        "--pull=never",
        "--userns=host",
        "--read-only",
        "--security-opt=no-new-privileges",
        "--cap-drop=ALL",
    ] {
        assert!(service
            .arguments
            .iter()
            .any(|argument| argument == required));
    }
    assert!(!service
        .arguments
        .iter()
        .any(|argument| argument == "--userns=keep-id"));
    assert!(service
        .arguments
        .iter()
        .any(|argument| argument == SERVICE_IMAGE));
    assert!(service
        .arguments
        .iter()
        .any(|argument| argument == "--network-alias=postgres"));
    assert!(service
        .arguments
        .iter()
        .any(|argument| argument == "--expose=5432/tcp"));
    assert!(!service.arguments.iter().any(|argument| {
        argument == "-p"
            || argument.starts_with("--publish")
            || argument.starts_with("--mount")
            || argument.starts_with("--volume")
            || argument == "--privileged"
            || argument.starts_with("--cap-add")
    }));
    assert_eq!(
        runtime.service_environment_files,
        vec![b"POSTGRES_PASSWORD=test-only\n".to_vec()]
    );

    fixture.executor.finish_job("job", 1).unwrap();
    assert!(fixture.executor.job_state_path("job", 1).is_none());
    assert_eq!(
        fixture
            .executor
            .runtime()
            .invocations
            .iter()
            .rev()
            .take(4)
            .map(RuntimeInvocation::kind)
            .collect::<Vec<_>>(),
        vec![
            RuntimeInvocationKind::NetworkExists,
            RuntimeInvocationKind::NetworkRemove,
            RuntimeInvocationKind::Exists,
            RuntimeInvocationKind::Remove,
        ]
    );
}

#[test]
fn service_start_failure_removes_container_and_network_before_returning() {
    let mut fixture = fixture_with_config(AdmissionMode::Exact, true);
    fixture
        .executor
        .preflight_capsule(&capsule_with_service(None))
        .unwrap();
    fixture
        .executor
        .runtime_mut()
        .push(RuntimeResult::success());
    let mut failed = RuntimeResult::success();
    failed.exit_code = Some(125);
    fixture.executor.runtime_mut().push(failed);

    assert!(matches!(
        fixture.executor.execute_request(&command_request()),
        Err(OciError::ServiceStartupFailed {
            exit_code: Some(125),
            ..
        })
    ));
    assert!(fixture.executor.job_state_path("job", 1).is_none());
    assert_eq!(
        fixture
            .executor
            .runtime()
            .invocations
            .iter()
            .map(RuntimeInvocation::kind)
            .collect::<Vec<_>>(),
        vec![
            RuntimeInvocationKind::NetworkCreate,
            RuntimeInvocationKind::ServiceStart,
            RuntimeInvocationKind::Remove,
            RuntimeInvocationKind::Exists,
            RuntimeInvocationKind::NetworkRemove,
            RuntimeInvocationKind::NetworkExists,
        ]
    );
}

#[test]
fn unhealthy_service_has_bounded_retries_and_is_fully_cleaned() {
    let mut fixture = fixture_with_config(AdmissionMode::Exact, true);
    fixture
        .executor
        .preflight_capsule(&capsule_with_service(Some(short_healthcheck(2))))
        .unwrap();
    fixture
        .executor
        .runtime_mut()
        .push(RuntimeResult::success());
    fixture
        .executor
        .runtime_mut()
        .push(RuntimeResult::success());
    for _ in 0..2 {
        let mut unhealthy = RuntimeResult::success();
        unhealthy.exit_code = Some(1);
        fixture.executor.runtime_mut().push(unhealthy);
    }

    assert!(matches!(
        fixture.executor.execute_request(&command_request()),
        Err(OciError::ServiceUnhealthy {
            service_id,
            attempts: 2
        }) if service_id == "postgres"
    ));
    assert!(fixture.executor.job_state_path("job", 1).is_none());
    assert_eq!(
        fixture
            .executor
            .runtime()
            .invocations
            .iter()
            .filter(|invocation| invocation.kind == RuntimeInvocationKind::HealthCheck)
            .count(),
        2
    );
    assert!(fixture
        .executor
        .runtime()
        .controls
        .iter()
        .all(|(timeout, max_output, _)| !timeout.is_zero() && *max_output <= 4 * 1024 * 1024));
}

#[test]
fn cancellation_during_service_healthcheck_cleans_the_job_boundary() {
    let mut fixture = fixture_with_config(AdmissionMode::Exact, true);
    fixture
        .executor
        .preflight_capsule(&capsule_with_service(Some(short_healthcheck(3))))
        .unwrap();
    fixture
        .executor
        .runtime_mut()
        .push(RuntimeResult::success());
    fixture
        .executor
        .runtime_mut()
        .push(RuntimeResult::success());
    let mut canceled = RuntimeResult::success();
    canceled.exit_code = None;
    canceled.canceled = true;
    fixture.executor.runtime_mut().push(canceled);

    let output = fixture
        .executor
        .execute_request(&command_request())
        .unwrap();
    assert!(output.canceled);
    assert!(fixture.executor.job_state_path("job", 1).is_none());
    let kinds = fixture
        .executor
        .runtime()
        .invocations
        .iter()
        .map(RuntimeInvocation::kind)
        .collect::<Vec<_>>();
    assert!(kinds.ends_with(&[
        RuntimeInvocationKind::Remove,
        RuntimeInvocationKind::Exists,
        RuntimeInvocationKind::NetworkRemove,
        RuntimeInvocationKind::NetworkExists,
    ]));
    assert!(!kinds.contains(&RuntimeInvocationKind::Run));
}

#[test]
fn service_configuration_cannot_inject_runtime_flags_or_dynamic_values() {
    let mut fixture = fixture_with_config(AdmissionMode::Exact, true);
    let mut service_capsule = capsule_with_service(None);
    service_capsule.jobs[0].services[0].environment.insert(
        "PAYLOAD".to_owned(),
        ValueBinding::Literal(ScalarValue::String(
            "$(touch /tmp/pwned) --privileged --publish=8080:80".to_owned(),
        )),
    );
    fixture
        .executor
        .preflight_capsule(&service_capsule)
        .unwrap();
    fixture
        .executor
        .execute_request(&command_request())
        .unwrap();
    let service = fixture
        .executor
        .runtime()
        .invocations
        .iter()
        .find(|invocation| invocation.kind == RuntimeInvocationKind::ServiceStart)
        .unwrap();
    assert!(!service.arguments.iter().any(|argument| {
        argument.contains("touch /tmp/pwned")
            || argument == "--privileged"
            || argument.starts_with("--publish")
    }));
    assert!(fixture.executor.runtime().service_environment_files[0]
        .windows(b"--privileged".len())
        .any(|window| window == b"--privileged"));

    let fixture = fixture_with_config(AdmissionMode::Exact, true);
    let mut dynamic = capsule_with_service(None);
    dynamic.jobs[0].services[0].environment.insert(
        "TOKEN".to_owned(),
        ValueBinding::Context(runtrue_workflow_ir::ContextBinding {
            from: "secrets.database".to_owned(),
        }),
    );
    assert!(matches!(
        fixture.executor.preflight_capsule(&dynamic),
        Err(OciError::UnsupportedFeature(_))
    ));
    assert!(fixture.executor.runtime().invocations.is_empty());
}

#[test]
fn service_image_lock_must_exist_and_exactly_match_the_capsule() {
    let fixture = fixture_with(AdmissionMode::Exact);
    assert!(matches!(
        fixture
            .executor
            .preflight_capsule(&capsule_with_service(None)),
        Err(OciError::MissingServiceImageAssignment { .. })
    ));

    let fixture = fixture_with_config(AdmissionMode::Exact, true);
    let mut mismatched = capsule_with_service(None);
    mismatched.jobs[0].services[0].image = IMAGE.to_owned();
    assert!(matches!(
        fixture.executor.preflight_capsule(&mismatched),
        Err(OciError::ServiceImageReferenceMismatch { .. })
    ));
    assert!(fixture.executor.runtime().invocations.is_empty());
}
