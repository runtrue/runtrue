use super::*;

#[test]
fn changed_declared_input_selects_a_different_cache_identity() {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("input.txt"), b"first").unwrap();
    let capsule = read_write_capsule();
    let first = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Write(b"cached")),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(first);
    assert!(engine.execute(&capsule).unwrap().succeeded());
    let first_reference = engine.into_executor().cache_references();
    fs::remove_file(workspace.path().join("build/output.txt")).unwrap();
    fs::write(workspace.path().join("input.txt"), b"second").unwrap();

    let second = LocalCacheExecutor::new(
        FakeExecutor::new(
            workspace.path(),
            FakeAction::ExpectMissingThenWrite(b"rebuilt"),
        ),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(second);
    assert!(engine.execute(&capsule).unwrap().succeeded());
    let second_reference = engine.into_executor().cache_references();
    assert_ne!(first_reference, second_reference);
}
