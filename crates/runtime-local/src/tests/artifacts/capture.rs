use super::*;

#[test]
fn artifact_capture_round_trip_persists_signed_provenance() {
    let workspace = tempdir().unwrap();
    let capsule = artifact_capsule("write");
    let executor = LocalArtifactExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Write(b"artifact")),
        LocalArtifactConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(executor);
    let result = engine.execute(&capsule).unwrap();
    let mut executor = engine.into_executor();
    let captures = executor.capture_successful_jobs(&capsule, &result).unwrap();
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].output_name, "result");
    assert_eq!(
        captures[0].classification,
        StoredArtifactClassification::UntrustedBuild
    );
    assert!(captures[0].retention_until_unix_seconds > unix_seconds().unwrap());
    assert!(tree_contains_named_file(
        &workspace.path().join(".runtrue/artifacts/metadata/tickets"),
        "claim.json"
    ));

    let destination = workspace.path().join("restored");
    let handle = executor
        .materialize_artifact(&captures[0].artifact_id, &destination)
        .unwrap();
    assert_eq!(fs::read(destination).unwrap(), b"artifact");
    assert!(executor
        .materialize_artifact(&captures[0].artifact_id, workspace.path().join("restored"))
        .unwrap_err()
        .to_string()
        .contains("overwrite"));
    assert_eq!(
        handle.record.producer.capsule_digest,
        capsule.digest().unwrap()
    );
    assert_eq!(
        handle.record.producer.workflow_digest,
        capsule.workflow.digest
    );
    assert_eq!(handle.record.producer.source_commit, "test-source");
    assert_eq!(
        handle
            .record
            .provenance
            .signed
            .statement
            .outputs
            .get("result"),
        Some(&captures[0].content_digest)
    );
    assert!(handle
        .record
        .producer
        .runner_id
        .starts_with("local-native/"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(
            workspace
                .path()
                .join(".runtrue/artifacts/local-signing-key"),
        )
        .unwrap()
        .permissions()
        .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let second = LocalArtifactExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Noop),
        LocalArtifactConfig::for_workspace(workspace.path()),
    );
    second.preflight(&capsule).unwrap();
    let persisted_key_id = second
        .state
        .borrow()
        .signing_key
        .as_ref()
        .unwrap()
        .verifying_key()
        .key_id();
    assert_eq!(persisted_key_id, handle.record.provenance.signer_key_id);

    let verifying_key =
        runtrue_attest::CapsuleVerifyingKey::from_bytes(&handle.record.provenance.verifying_key)
            .unwrap();
    let mut tampered = handle.record.provenance.signed;
    tampered.statement.source_commit = "tampered".to_owned();
    assert!(verifying_key.verify_provenance(&tampered).is_err());
}

#[test]
fn absent_artifact_is_a_durable_capture_failure() {
    let workspace = tempdir().unwrap();
    let capsule = artifact_capsule("write");
    let executor = LocalArtifactExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Noop),
        LocalArtifactConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(executor);
    let result = engine.execute(&capsule).unwrap();
    let error = engine
        .executor_mut()
        .capture_successful_jobs(&capsule, &result)
        .unwrap_err();
    assert!(error.to_string().contains("does not exist"));
}

#[test]
fn later_output_failure_reports_and_retains_earlier_committed_artifacts() {
    let workspace = tempdir().unwrap();
    fs::create_dir(workspace.path().join("build")).unwrap();
    fs::write(workspace.path().join("build/first.txt"), b"first artifact").unwrap();
    let capsule = multi_artifact_capsule();
    let executor = LocalArtifactExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Noop),
        LocalArtifactConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(executor);
    let result = engine.execute(&capsule).unwrap();
    let executor = engine.executor_mut();
    let error = executor
        .capture_successful_jobs(&capsule, &result)
        .unwrap_err();
    let committed = error.committed_artifacts();
    assert_eq!(committed.len(), 1);
    assert_eq!(committed[0].output_name, "a-result");
    assert_eq!(executor.captured_artifacts(), committed);
    let message = error.to_string();
    assert!(message.contains("build.z-missing"));
    assert!(message.contains("1 earlier artifact(s) remain committed"));
    assert!(message.contains(committed[0].artifact_id.as_str()));

    let destination = workspace.path().join("recovered-first");
    executor
        .materialize_artifact(&committed[0].artifact_id, &destination)
        .unwrap();
    assert_eq!(fs::read(destination).unwrap(), b"first artifact");

    let ticket_path = find_named_file(
        &workspace.path().join(".runtrue/artifacts/metadata/tickets"),
        "ticket.json",
    )
    .unwrap();
    let ticket: runtrue_artifacts::ArtifactTicket =
        serde_json::from_slice(&fs::read(ticket_path).unwrap()).unwrap();
    assert_eq!(
        ticket.expected_content_digest.as_ref(),
        Some(&committed[0].content_digest)
    );
    assert_eq!(ticket.max_bytes, b"first artifact".len() as u64);
}

#[test]
fn failed_job_does_not_capture_declared_artifact() {
    let workspace = tempdir().unwrap();
    let capsule = artifact_capsule("write");
    let executor = LocalArtifactExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Fail),
        LocalArtifactConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(executor);
    let result = engine.execute(&capsule).unwrap();
    assert_eq!(result.jobs["build"].state, JobState::Failed);
    let captures = engine
        .executor_mut()
        .capture_successful_jobs(&capsule, &result)
        .unwrap();
    assert!(captures.is_empty());
}

#[cfg(unix)]
#[test]
fn symlink_and_special_artifact_outputs_are_rejected() {
    use std::os::unix::{fs::symlink, net::UnixListener};

    let symlink_workspace = tempdir().unwrap();
    fs::create_dir(symlink_workspace.path().join("build")).unwrap();
    fs::write(symlink_workspace.path().join("target"), b"secret").unwrap();
    symlink(
        symlink_workspace.path().join("target"),
        symlink_workspace.path().join("build/output.txt"),
    )
    .unwrap();
    let capsule = artifact_capsule("write");
    let executor = LocalArtifactExecutor::new(
        FakeExecutor::new(symlink_workspace.path(), FakeAction::Noop),
        LocalArtifactConfig::for_workspace(symlink_workspace.path()),
    );
    let mut engine = Engine::new(executor);
    let result = engine.execute(&capsule).unwrap();
    assert!(engine
        .executor_mut()
        .capture_successful_jobs(&capsule, &result)
        .unwrap_err()
        .to_string()
        .contains("symlink"));

    let ancestor_workspace = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("output.txt"), b"outside-secret").unwrap();
    symlink(outside.path(), ancestor_workspace.path().join("build")).unwrap();
    let executor = LocalArtifactExecutor::new(
        FakeExecutor::new(ancestor_workspace.path(), FakeAction::Noop),
        LocalArtifactConfig::for_workspace(ancestor_workspace.path()),
    );
    let mut engine = Engine::new(executor);
    let result = engine.execute(&capsule).unwrap();
    assert!(engine
        .executor_mut()
        .capture_successful_jobs(&capsule, &result)
        .unwrap_err()
        .to_string()
        .contains("symlink"));

    let special_workspace = tempdir().unwrap();
    fs::create_dir(special_workspace.path().join("build")).unwrap();
    let _listener = UnixListener::bind(special_workspace.path().join("build/output.txt")).unwrap();
    let executor = LocalArtifactExecutor::new(
        FakeExecutor::new(special_workspace.path(), FakeAction::Noop),
        LocalArtifactConfig::for_workspace(special_workspace.path()),
    );
    let mut engine = Engine::new(executor);
    let result = engine.execute(&capsule).unwrap();
    assert!(engine
        .executor_mut()
        .capture_successful_jobs(&capsule, &result)
        .unwrap_err()
        .to_string()
        .contains("special"));
}

#[test]
fn failed_artifact_preflight_does_not_mutate_workspace() {
    let workspace = tempdir().unwrap();
    let capsule = artifact_capsule("deny");
    let wrapper = LocalArtifactExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Noop),
        LocalArtifactConfig::for_workspace(workspace.path()),
    );
    assert!(wrapper
        .preflight(&capsule)
        .unwrap_err()
        .to_string()
        .contains("artifacts: write"));
    assert!(!workspace.path().join(".runtrue").exists());
    assert_eq!(wrapper.inner().executions.get(), 0);
}

#[test]
fn inner_preflight_veto_does_not_create_artifact_state() {
    let workspace = tempdir().unwrap();
    let capsule = artifact_capsule("write");
    let mut inner = FakeExecutor::new(workspace.path(), FakeAction::Noop);
    inner.reject_preflight = true;
    let wrapper =
        LocalArtifactExecutor::new(inner, LocalArtifactConfig::for_workspace(workspace.path()));
    assert!(wrapper
        .preflight(&capsule)
        .unwrap_err()
        .to_string()
        .contains("fake backend veto"));
    assert!(!workspace.path().join(".runtrue").exists());
    assert_eq!(wrapper.inner().executions.get(), 0);
}
