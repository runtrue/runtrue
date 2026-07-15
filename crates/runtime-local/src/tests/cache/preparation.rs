use super::*;

#[test]
fn unavailable_store_degrades_to_warning_and_executes() {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("input.txt"), b"input").unwrap();
    let cache_file = workspace.path().join("not-a-directory");
    fs::write(&cache_file, b"x").unwrap();
    let mut config = LocalCacheConfig::for_workspace(workspace.path());
    config.cache_root = cache_file;
    let executor = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Write(b"result")),
        config,
    );
    let mut engine = Engine::new(executor);
    assert!(engine.execute(&read_write_capsule()).unwrap().succeeded());
    let executor = engine.into_executor();
    assert_eq!(executor.inner().executions.get(), 1);
    assert!(executor
        .warnings()
        .iter()
        .any(|warning| warning.message.contains("store is unavailable")));
}

#[test]
fn glob_and_missing_capability_fail_preflight() {
    let workspace = tempdir().unwrap();
    let glob = compile(&workflow(
        "          inputs: [input.txt]\n          outputs: [build/**]\n          mode: read-write",
        "{ read: run, write: quarantine }",
    ));
    let wrapper = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Noop),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    assert!(wrapper
        .preflight(&glob)
        .unwrap_err()
        .to_string()
        .contains("glob syntax"));
    assert!(!workspace.path().join(".runtrue").exists());

    let denied = compile(&workflow(
        "          inputs: [input.txt]\n          outputs: [build/output.txt]\n          mode: read-write",
        "{ read: deny, write: deny }",
    ));
    assert!(wrapper
        .preflight(&denied)
        .unwrap_err()
        .to_string()
        .contains("cache.read: run"));
}

#[test]
fn wrapped_backend_preflight_remains_a_veto() {
    let workspace = tempdir().unwrap();
    let mut inner = FakeExecutor::new(workspace.path(), FakeAction::Noop);
    inner.reject_preflight = true;
    let wrapper = LocalCacheExecutor::new(inner, LocalCacheConfig::for_workspace(workspace.path()));
    let error = wrapper.preflight(&read_write_capsule()).unwrap_err();
    assert!(error.to_string().contains("fake backend veto"));
    assert_eq!(wrapper.inner().executions.get(), 0);
}
