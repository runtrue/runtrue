use super::*;
#[test]
fn cancellation_reaches_the_wasm_engine_without_backend_downgrade() {
    let fixture = Fixture::new();
    let executor = WasmJobExecutor::load(&fixture.paths).unwrap();
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let result = executor
        .execute(&fixture.lease(), fixture._directory.path(), cancellation)
        .unwrap();
    assert_eq!(result.jobs["job"].state, runtrue_engine::JobState::Canceled);
}

#[test]
fn mixed_capsule_executes_only_the_selected_wasm_job_without_reinterpreting_other_jobs() {
    let fixture = Fixture::new();
    let executor = WasmJobExecutor::load(&fixture.paths).unwrap();
    let mut lease = fixture.lease();
    let mut unrelated = lease.capsule.jobs[0].clone();
    unrelated.id = "native".to_owned();
    unrelated.base_id = "native".to_owned();
    unrelated.name = "native".to_owned();
    unrelated.runner.isolation = Isolation::Native;
    unrelated.steps[0].id = "native-step".to_owned();
    unrelated.steps[0].name = "native-step".to_owned();
    unrelated.steps[0].action = StepAction::Command {
        program: "/bin/true".to_owned(),
        args: Vec::new(),
    };
    lease.capsule.jobs.push(unrelated);
    lease.capsule_digest = lease.capsule.digest().unwrap();

    executor.preflight_lease(&lease).unwrap();
    let result = executor
        .execute(
            &lease,
            fixture._directory.path(),
            CancellationToken::default(),
        )
        .unwrap();
    assert!(result.succeeded());
    assert!(result.jobs.contains_key("job"));
    assert!(!result.jobs.contains_key("native"));
}

pub(super) const fn architecture_text(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
    }
}
