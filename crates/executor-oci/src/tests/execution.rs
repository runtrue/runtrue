use super::*;
#[test]
fn run_command_has_mandatory_isolation_and_no_tag_or_socket_exposure() {
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let image_store = fixture._directory.path().join("images");
    fs::create_dir(&image_store).unwrap();
    fixture.executor.config.image_store = Some(image_store.clone());
    let mut request = command_request();
    request
        .environment
        .insert("TOKEN".to_owned(), "secret-value".to_owned());
    let output = fixture.executor.execute_request(&request).unwrap();
    assert!(output.succeeded());
    let runtime = fixture.executor.runtime();
    assert_eq!(runtime.invocations.len(), 3);
    let run = &runtime.invocations[0];
    assert_eq!(run.kind, RuntimeInvocationKind::Run);
    for required in [
        "--pull=never",
        "--userns=keep-id",
        "--read-only",
        "--security-opt=no-new-privileges",
        "--cap-drop=ALL",
        "--network=none",
        "--pid=private",
        "--ipc=private",
        "--ulimit=core=0:0",
    ] {
        assert!(run.arguments.iter().any(|argument| argument == required));
    }
    assert!(run
        .arguments
        .iter()
        .any(|argument| argument.starts_with("--security-opt=seccomp=")));
    assert!(run
        .arguments
        .iter()
        .any(|argument| argument == &format!("--imagestore={}", image_store.display())));
    assert!(run.arguments.iter().any(|argument| {
        argument.starts_with("--root=") && !argument.contains(&image_store.display().to_string())
    }));
    assert!(!run
        .arguments
        .iter()
        .any(|argument| argument.contains(".runtrue-runroot")));
    assert!(run.arguments.iter().any(|argument| argument == IMAGE));
    assert!(run
        .arguments
        .iter()
        .any(|argument| argument == "--entrypoint=/bin/echo"));
    let image_position = run
        .arguments
        .iter()
        .position(|argument| argument == IMAGE)
        .unwrap();
    assert_eq!(&run.arguments[image_position + 1..], &["hello"]);
    assert!(!run.arguments.iter().any(|argument| {
        argument.contains("secret-value")
            || argument.contains("docker.sock")
            || argument == "--privileged"
            || argument == "--network=host"
            || argument.starts_with("--cap-add")
    }));
    assert_eq!(
        runtime.environment_files,
        vec![b"TOKEN=secret-value\n".to_vec()]
    );
    let environment_path = run
        .arguments
        .iter()
        .find_map(|argument| argument.strip_prefix("--env-file="))
        .unwrap();
    assert!(!Path::new(environment_path).exists());
    assert_eq!(runtime.invocations[1].kind, RuntimeInvocationKind::Remove);
    assert_eq!(runtime.invocations[2].kind, RuntimeInvocationKind::Exists);
}

#[test]
fn container_action_preserves_or_overrides_image_invocation_metadata() {
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let mut image_default = request(PreparedAction::Container {
        entrypoint: None,
        args: None,
    });
    image_default
        .environment
        .insert("INPUT_CONFIG-PATH".to_owned(), "policy.yml".to_owned());
    fixture.executor.execute_request(&image_default).unwrap();
    let invocation = &fixture.executor.runtime().invocations[0];
    assert!(!invocation
        .arguments
        .iter()
        .any(|argument| argument.starts_with("--entrypoint=")));
    assert_eq!(invocation.arguments.last().map(String::as_str), Some(IMAGE));
    assert_eq!(
        fixture.executor.runtime().environment_files,
        vec![b"INPUT_CONFIG-PATH=policy.yml\n".to_vec()]
    );

    let mut fixture = fixture_with(AdmissionMode::Exact);
    let overridden = request(PreparedAction::Container {
        entrypoint: Some("/bin/action".to_owned()),
        args: Some(vec!["--mode".to_owned(), "strict".to_owned()]),
    });
    fixture.executor.execute_request(&overridden).unwrap();
    let invocation = &fixture.executor.runtime().invocations[0];
    assert!(invocation
        .arguments
        .iter()
        .any(|argument| argument == "--entrypoint=/bin/action"));
    let image = invocation
        .arguments
        .iter()
        .position(|argument| argument == IMAGE)
        .unwrap();
    assert_eq!(&invocation.arguments[image + 1..], &["--mode", "strict"]);
}

#[test]
fn cancellation_and_zero_timeout_do_not_start_the_runtime() {
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let canceled = command_request();
    canceled.cancellation.cancel();
    let output = fixture.executor.execute_request(&canceled).unwrap();
    assert!(output.canceled);
    let mut timed_out = command_request();
    timed_out.timeout_ms = Some(0);
    let output = fixture.executor.execute_request(&timed_out).unwrap();
    assert!(output.timed_out);
    assert!(fixture.executor.runtime().invocations.is_empty());
}

#[test]
fn runtime_timeout_cancellation_and_output_flags_are_preserved() {
    for (timed_out, canceled) in [(true, false), (false, true)] {
        let mut fixture = fixture_with(AdmissionMode::Exact);
        let mut result = RuntimeResult::success();
        result.exit_code = None;
        result.stdout = b"partial".to_vec();
        result.stdout_truncated = true;
        result.timed_out = timed_out;
        result.canceled = canceled;
        result.duration = Duration::from_millis(25);
        fixture.executor.runtime_mut().push(result);
        let output = fixture
            .executor
            .execute_request(&command_request())
            .unwrap();
        assert_eq!(output.timed_out, timed_out);
        assert_eq!(output.canceled, canceled);
        assert!(output.stdout_truncated);
        assert_eq!(output.stdout, "partial");
        assert_eq!(output.duration_ms, 25);
    }
}

#[test]
fn fake_runtime_cannot_return_unbounded_output_or_leaked_process_group() {
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let mut oversized = RuntimeResult::success();
    oversized.stdout = vec![b'x'; fixture.executor.config.limits.max_output_bytes + 1];
    fixture.executor.runtime_mut().push(oversized);
    assert!(matches!(
        fixture.executor.execute_request(&command_request()),
        Err(OciError::RuntimeContractViolation(_))
    ));

    let mut fixture = fixture_with(AdmissionMode::Exact);
    let mut leaked = RuntimeResult::success();
    leaked.process_group_clean = false;
    fixture.executor.runtime_mut().push(leaked);
    assert!(matches!(
        fixture.executor.execute_request(&command_request()),
        Err(OciError::ProcessGroupLeak)
    ));
    assert_eq!(fixture.executor.runtime().invocations.len(), 3);
}

#[test]
fn job_attempts_have_private_distinct_runtime_state() {
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let first = command_request();
    fixture.executor.execute_request(&first).unwrap();
    let first_path = fixture
        .executor
        .job_state_path("job", 1)
        .unwrap()
        .to_path_buf();
    let mut second = command_request();
    second.job_attempt = 2;
    fixture.executor.execute_request(&second).unwrap();
    let second_path = fixture
        .executor
        .job_state_path("job", 2)
        .unwrap()
        .to_path_buf();
    assert_ne!(first_path, second_path);
    assert!(first_path.exists() && second_path.exists());
    fixture.executor.finish_job("job", 1).unwrap();
    fixture.executor.finish_job("job", 2).unwrap();
    assert!(!first_path.exists() && !second_path.exists());
}

#[test]
fn scripts_are_digest_checked_and_passed_as_ephemeral_read_only_mounts() {
    let script = "printf safe";
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let valid = request(PreparedAction::Script {
        shell: Shell::Sh,
        script: script.to_owned(),
        script_digest: ContentDigest::sha256(script.as_bytes()),
    });
    fixture.executor.execute_request(&valid).unwrap();
    assert_eq!(
        fixture.executor.runtime().script_files,
        vec![script.as_bytes()]
    );
    let run = &fixture.executor.runtime().invocations[0];
    assert!(run.arguments.iter().any(|argument| {
        argument.contains(&format!("dst={CONTAINER_SCRIPT}")) && argument.contains(",ro,")
    }));
    assert!(run
        .arguments
        .iter()
        .any(|argument| argument == "--entrypoint=/bin/sh"));

    let mut fixture = fixture_with(AdmissionMode::Exact);
    let invalid = request(PreparedAction::Script {
        shell: Shell::Sh,
        script: script.to_owned(),
        script_digest: ContentDigest::sha256(b"different"),
    });
    assert!(matches!(
        fixture.executor.execute_request(&invalid),
        Err(OciError::ScriptDigestMismatch)
    ));
    assert!(fixture.executor.runtime().invocations.is_empty());
    fixture.executor.finish_job("job", 1).unwrap();
}
