use super::*;
#[test]
fn exact_signed_component_dispatches_through_the_shared_engine() {
    let fixture = Fixture::new();
    let executor = WasmJobExecutor::load(&fixture.paths).unwrap();
    assert_eq!(executor.component_count(), 1);
    assert_eq!(
        executor.component_digests().unwrap(),
        [ContentDigest::sha256(&fixture.component)]
            .into_iter()
            .collect()
    );
    assert_eq!(
        executor.component_preparation_tiers().unwrap(),
        BTreeMap::from([(
            ContentDigest::sha256(&fixture.component),
            crate::daemon::PreparedContentTier::Warm,
        )])
    );
    executor.preflight_lease(&fixture.lease()).unwrap();

    let result = executor
        .execute(
            &fixture.lease(),
            fixture._directory.path(),
            CancellationToken::default(),
        )
        .unwrap();
    assert!(result.succeeded());
    assert!(executor.aot_cache().join("authenticated").is_dir());

    let mut oci_reference = Fixture::new();
    oci_reference.reference = oci_reference.reference.replacen("wasm://", "oci://", 1);
    oci_reference.write_manifest(&oci_reference.signing, |_| {});
    let executor = WasmJobExecutor::load(&oci_reference.paths).unwrap();
    executor.preflight_lease(&oci_reference.lease()).unwrap();
}

#[test]
fn missing_tampered_or_substituted_signatures_fail_before_advertisement() {
    let missing = Fixture::new();
    fs::remove_file(&missing.manifest_path).unwrap();
    assert!(matches!(
        WasmJobExecutor::load(&missing.paths),
        Err(RunnerError::WasmConfiguration(message))
            if message.contains("manifest directory is empty")
    ));

    let tampered = Fixture::new();
    let mut signed: SignedImageManifest =
        serde_json::from_slice(&fs::read(&tampered.manifest_path).unwrap()).unwrap();
    signed.manifest.payload_size_bytes += 1;
    private_file(
        &tampered.manifest_path,
        &serde_json::to_vec(&signed).unwrap(),
    );
    assert!(matches!(
        WasmJobExecutor::load(&tampered.paths),
        Err(RunnerError::ImageAttestation(_))
    ));

    let substituted = Fixture::new();
    substituted.write_manifest(&ImageSigningKey::from_seed([99; 32]), |_| {});
    assert!(matches!(
        WasmJobExecutor::load(&substituted.paths),
        Err(RunnerError::UntrustedWasmComponentKey(_))
    ));
}
#[test]
fn payload_digest_and_runtime_compatibility_are_reverified_at_startup() {
    let digest = Fixture::new();
    private_file(&digest.payload_path, b"substituted component bytes");
    assert!(matches!(
        WasmJobExecutor::load(&digest.paths),
        Err(RunnerError::Wasm(
            runtrue_executor_wasm::WasmError::ManifestMismatch
        ))
    ));

    let runtime = Fixture::new();
    runtime.write_manifest(&runtime.signing, |manifest| {
        manifest
            .compatibility
            .insert("wasmtime_version".to_owned(), "0.0.0".to_owned());
    });
    assert!(matches!(
        WasmJobExecutor::load(&runtime.paths),
        Err(RunnerError::Wasm(
            runtrue_executor_wasm::WasmError::ManifestCompatibilityMismatch
        ))
    ));
}

#[test]
fn invalid_runtime_key_and_authenticated_aot_tampering_fail_closed() {
    let invalid_key = Fixture::new();
    private_file(&invalid_key.paths.runtime_key, b"short");
    assert!(matches!(
        WasmJobExecutor::load(&invalid_key.paths),
        Err(RunnerError::WasmConfiguration(message)) if message.contains("runtime key")
    ));

    let aot = Fixture::new();
    drop(WasmJobExecutor::load(&aot.paths).unwrap());
    let authenticated = aot.paths.aot_cache.join("authenticated");
    let metadata = fs::read_dir(&authenticated)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&metadata).unwrap()).unwrap();
    value["authentication_tag"] = "00".repeat(32).into();
    private_file(&metadata, &serde_json::to_vec(&value).unwrap());
    assert!(matches!(
        WasmJobExecutor::load(&aot.paths),
        Err(RunnerError::WasmAotState(_))
    ));
}

#[test]
fn exact_reference_assignment_cannot_be_substituted_by_digest() {
    let fixture = Fixture::new();
    let executor = WasmJobExecutor::load(&fixture.paths).unwrap();
    let mut lease = fixture.lease();
    let StepAction::Component { reference } = &mut lease.capsule.jobs[0].steps[0].action else {
        unreachable!()
    };
    *reference = reference.replace("registry.example", "substitute.example");
    lease.capsule_digest = lease.capsule.digest().unwrap();

    assert!(matches!(
        executor.preflight_lease(&lease),
        Err(RunnerError::MissingWasmComponent(reference))
            if reference.contains("substitute.example")
    ));
}
