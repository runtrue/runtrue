use super::*;
#[test]
fn cleanup_must_prove_container_absence_and_retries_before_returning() {
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let state_path = fixture.executor.state_root.join(format!(
        "job-{}-1",
        short_identity(&command_request().job_id)
    ));
    fixture
        .executor
        .runtime_mut()
        .push(RuntimeResult::success());
    fixture
        .executor
        .runtime_mut()
        .push(RuntimeResult::success());
    let mut still_exists = RuntimeResult::success();
    still_exists.exit_code = Some(0);
    fixture.executor.runtime_mut().push(still_exists);
    assert!(matches!(
        fixture.executor.execute_request(&command_request()),
        Err(OciError::CleanupVerificationFailed { .. })
    ));
    assert!(!state_path.exists());
    assert!(fixture.executor.job_state_path("job", 1).is_none());
    assert_eq!(fixture.executor.runtime().invocations.len(), 5);
}

#[test]
fn engine_finalizes_services_before_starting_the_next_attempt() {
    let Fixture {
        _directory,
        mut executor,
    } = fixture_with_config(AdmissionMode::Exact, true);
    let mut execution_capsule = capsule_with_service(None);
    execution_capsule.jobs[0].retries = 1;
    let mut first_attempt = RuntimeResult::success();
    first_attempt.exit_code = Some(1);
    executor.runtime_mut().push_job_result(first_attempt);
    executor
        .runtime_mut()
        .push_job_result(RuntimeResult::success());
    let mut engine = Engine::new(executor);

    let result = engine.execute(&execution_capsule).unwrap();

    assert!(result.succeeded());
    let kinds = engine
        .executor()
        .runtime()
        .invocations
        .iter()
        .map(RuntimeInvocation::kind)
        .collect::<Vec<_>>();
    let network_creates = kinds
        .iter()
        .enumerate()
        .filter_map(|(index, kind)| {
            (*kind == RuntimeInvocationKind::NetworkCreate).then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(network_creates.len(), 2);
    assert!(kinds[..network_creates[1]].ends_with(&[
        RuntimeInvocationKind::Remove,
        RuntimeInvocationKind::Exists,
        RuntimeInvocationKind::NetworkRemove,
        RuntimeInvocationKind::NetworkExists,
    ]));
    assert_eq!(result.jobs["job"].attempts.len(), 2);
}

#[test]
fn engine_cannot_report_success_when_oci_finalization_is_unproven() {
    let Fixture {
        _directory,
        mut executor,
    } = fixture_with_config(AdmissionMode::Exact, true);
    for result in [
        RuntimeResult::success(),
        RuntimeResult::success(),
        RuntimeResult::success(),
        RuntimeResult::success(),
        {
            let mut absent = RuntimeResult::success();
            absent.exit_code = Some(1);
            absent
        },
        RuntimeResult::success(),
        RuntimeResult::success(),
    ] {
        executor.runtime_mut().push(result);
    }
    let mut still_exists = RuntimeResult::success();
    still_exists.exit_code = Some(0);
    executor.runtime_mut().push(still_exists);
    let mut engine = Engine::new(executor);

    let error = engine.execute(&capsule_with_service(None)).unwrap_err();

    assert!(matches!(
        error,
        runtrue_engine::EngineError::ExecutorFinalization {
            job_id,
            attempt: 1,
            ..
        } if job_id == "job"
    ));
    assert!(engine.executor().job_state_path("job", 1).is_some());
}
