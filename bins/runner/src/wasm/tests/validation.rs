use super::*;
#[test]
fn command_services_capabilities_and_missing_lock_are_rejected() {
    let fixture = Fixture::new();
    let executor = WasmJobExecutor::load(&fixture.paths).unwrap();

    let mut command = fixture.lease();
    command.capsule.jobs[0].steps[0].action = StepAction::Command {
        program: "/bin/true".to_owned(),
        args: Vec::new(),
    };
    assert!(matches!(
        executor.preflight_lease(&command),
        Err(RunnerError::WasmManifestMismatch(message))
            if message.contains("not a component")
    ));

    let mut service = fixture.lease();
    service.capsule.jobs[0].services.push(PlannedService {
            id: "db".to_owned(),
            image: "registry.example/db@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            ports: Vec::new(),
            environment: BTreeMap::new(),
            healthcheck: None,
        });
    assert!(matches!(
        executor.preflight_lease(&service),
        Err(RunnerError::Wasm(
            runtrue_executor_wasm::WasmError::UnsupportedCapability(_)
        ))
    ));

    let mut capability = fixture.lease();
    capability.capsule.jobs[0]
        .runner
        .capabilities
        .push("ambient".to_owned());
    assert!(matches!(
        executor.preflight_lease(&capability),
        Err(RunnerError::Wasm(
            runtrue_executor_wasm::WasmError::UnsupportedCapability(_)
        ))
    ));

    let mut filesystem = fixture.lease();
    filesystem.capsule.jobs[0].steps[0]
        .capabilities
        .fs_read
        .push("src".to_owned());
    filesystem.capsule_digest = filesystem.capsule.digest().unwrap();
    executor.preflight_lease(&filesystem).unwrap();
    let missing_workspace = fixture._directory.path().join("missing-workspace");
    assert!(matches!(
        executor.execute(
            &filesystem,
            &missing_workspace,
            CancellationToken::default()
        ),
        Err(RunnerError::WasmConfiguration(message))
            if message.contains("canonicalize hydrated Wasm workspace")
    ));
    assert!(executor
        .execute(
            &filesystem,
            fixture._directory.path(),
            CancellationToken::default()
        )
        .unwrap()
        .succeeded());

    let mut unlocked = fixture.lease();
    unlocked.capsule.context.lockfile_digest = None;
    assert!(matches!(
        executor.preflight_lease(&unlocked),
        Err(RunnerError::WasmManifestMismatch(message))
            if message.contains("lockfile digest")
    ));
}
