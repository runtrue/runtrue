use super::*;

#[test]
fn existing_outputs_are_never_overwritten() {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("input.txt"), b"input").unwrap();
    let capsule = read_write_capsule();
    let first = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Write(b"cached")),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    Engine::new(first).execute(&capsule).unwrap();
    fs::write(workspace.path().join("build/output.txt"), b"local").unwrap();

    let second = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Expect(b"local")),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(second);
    assert!(engine.execute(&capsule).unwrap().succeeded());
    let second = engine.into_executor();
    assert!(second
        .warnings()
        .iter()
        .any(|warning| warning.message.contains("never overwritten")));
    assert_eq!(
        fs::read(workspace.path().join("build/output.txt")).unwrap(),
        b"local"
    );
}

#[test]
fn partial_restore_failure_removes_every_new_destination() {
    let workspace = tempdir().unwrap();
    let stage = tempdir().unwrap();
    fs::create_dir(stage.path().join("nested")).unwrap();
    fs::write(stage.path().join("nested/first"), b"one").unwrap();
    fs::write(stage.path().join("nested/second"), b"two").unwrap();
    let calls = Cell::new(0_usize);
    let error = install_staged_outputs(
        workspace.path(),
        stage.path(),
        &["nested/first".to_owned(), "nested/second".to_owned()],
        |source, destination| {
            let call = calls.get();
            calls.set(call + 1);
            if call == 0 {
                copy_new_tree(source, destination)
            } else {
                Err("injected copy failure".to_owned())
            }
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        StagedInstallError::SafeMiss(message)
            if message.contains("injected copy failure")
    ));
    assert!(!workspace.path().join("nested/first").exists());
    assert!(!workspace.path().join("nested/second").exists());
    assert!(!workspace.path().join("nested").exists());
}

#[test]
fn corrupt_cache_degrades_to_warning_and_fallback_execution() {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("input.txt"), b"input").unwrap();
    let capsule = read_write_capsule();
    let first = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Write(b"cached")),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    Engine::new(first).execute(&capsule).unwrap();
    fs::remove_file(workspace.path().join("build/output.txt")).unwrap();

    let object = first_regular_file(&workspace.path().join(".runtrue/cache/cas/objects/sha256"))
        .expect("a successful cache save stores CAS objects");
    make_writable(&object);
    fs::write(object, b"corrupt").unwrap();

    let second = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Write(b"fallback")),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(second);
    assert!(engine.execute(&capsule).unwrap().succeeded());
    let second = engine.into_executor();
    assert_eq!(
        fs::read(workspace.path().join("build/output.txt")).unwrap(),
        b"fallback"
    );
    assert!(!second.warnings().is_empty());
}
