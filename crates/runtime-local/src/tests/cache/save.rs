use super::*;

#[test]
fn round_trip_restores_exact_output_and_records_run_private_reference() {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("input.txt"), b"input").unwrap();
    let capsule = read_write_capsule();
    let first = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Write(b"cached")),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(first);
    assert!(engine.execute(&capsule).unwrap().succeeded());
    let first = engine.into_executor();
    assert_eq!(first.cache_references().len(), 1);

    fs::remove_file(workspace.path().join("build/output.txt")).unwrap();
    let second = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Expect(b"cached")),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(second);
    assert!(engine.execute(&capsule).unwrap().succeeded());
    let second = engine.into_executor();
    assert_eq!(second.cache_references(), first.cache_references());
    assert!(second.warnings().is_empty());

    let config = LocalCacheConfig::for_workspace(workspace.path());
    let prepared = prepare_capsule(&capsule, &config).unwrap();
    let step = prepared.cache_steps.values().next().unwrap();
    let identity = build_identity(
        &config,
        &capsule.digest().unwrap(),
        step,
        ContentDigest::sha256(b"input"),
    );
    let local_material = build_key_material(&config, step, ContentDigest::sha256(b"input"));
    assert_eq!(
        local_material.digest(config.cache_limits).unwrap(),
        CacheKeyMaterial::from(&identity)
            .digest(config.cache_limits)
            .unwrap(),
        "local and remote adapters must hash identical trust-neutral material",
    );
    let TrustDomain::RunPrivate { run_id, .. } = identity.trust_domain else {
        panic!("local cache identity must be RunPrivate");
    };
    assert!(run_id.contains(capsule.digest().unwrap().as_str()));
    assert!(run_id.ends_with(":linux:amd64"));
}

#[test]
fn directory_output_is_staged_and_restored_recursively() {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("input.txt"), b"input").unwrap();
    let capsule = compile(&workflow(
        "          inputs: [input.txt]\n          outputs: [build/cache]\n          mode: read-write\n          max-size: 1MiB",
        "{ read: run, write: quarantine }",
    ));
    let first = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::WriteDirectory),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    Engine::new(first).execute(&capsule).unwrap();
    fs::remove_dir_all(workspace.path().join("build/cache")).unwrap();

    let second = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::ExpectDirectory),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(second);
    assert!(engine.execute(&capsule).unwrap().succeeded());
}

#[test]
fn max_size_skips_save_without_failing_step() {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("input.txt"), b"input").unwrap();
    let capsule = compile(&workflow(
        "          inputs: [input.txt]\n          outputs: [build/output.txt]\n          mode: write-only\n          max-size: 4B",
        "{ read: deny, write: quarantine }",
    ));
    let executor = LocalCacheExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Write(b"too-large")),
        LocalCacheConfig::for_workspace(workspace.path()),
    );
    let mut engine = Engine::new(executor);
    assert!(engine.execute(&capsule).unwrap().succeeded());
    assert!(engine
        .into_executor()
        .warnings()
        .iter()
        .any(|warning| warning.message.contains("max-size")));
}
