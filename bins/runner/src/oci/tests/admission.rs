use super::*;

#[test]
fn reusable_signed_image_can_satisfy_an_exact_pinned_job_image() {
    let fixture = Fixture::new(false);
    fixture.write_reusable_job_manifest();
    let executor = fixture.load(RecordingFactory::default()).unwrap();

    executor
        .preflight_lease(&fixture.lease())
        .expect("reusable image admission");
}

#[test]
fn missing_service_manifest_fails_before_runtime_or_state() {
    let fixture = Fixture::new(true);
    fixture.write_job_manifest();
    let factory = RecordingFactory::default();
    let executor = fixture.load(factory.clone()).unwrap();
    let startup_invocations = factory.invocations.lock().unwrap().len();

    assert!(matches!(
        executor.preflight_lease(&fixture.lease()),
        Err(RunnerError::MissingOciManifest {
            service_id: Some(service),
            ..
        }) if service == "db"
    ));
    assert_eq!(
        factory.invocations.lock().unwrap().len(),
        startup_invocations
    );
    assert!(fs::read_dir(executor.state_root())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn signed_job_assignment_cannot_substitute_the_planned_image() {
    let fixture = Fixture::new(false);
    fixture.write_manifest("job.json", None, SERVICE_REFERENCE);
    let factory = RecordingFactory::default();
    let executor = fixture.load(factory.clone()).unwrap();
    let startup_invocations = factory.invocations.lock().unwrap().len();

    assert!(matches!(
        executor.preflight_lease(&fixture.lease()),
        Err(RunnerError::OciManifestMismatch(message))
            if message.contains("image differs")
    ));
    assert_eq!(
        factory.invocations.lock().unwrap().len(),
        startup_invocations
    );
    assert!(fs::read_dir(executor.state_root())
        .unwrap()
        .next()
        .is_none());
}
#[test]
fn tampered_signed_manifest_prevents_oci_configuration() {
    let fixture = Fixture::new(false);
    fixture.write_job_manifest();
    let path = fixture.paths.manifest_directory.join("job.json");
    let mut signed: SignedImageManifest =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    signed.manifest.payload_size_bytes = 2;
    private_file(&path, &serde_json::to_vec(&signed).unwrap());

    assert!(matches!(
        fixture.load(RecordingFactory::default()),
        Err(RunnerError::ImageAttestation(_))
    ));
}

#[test]
fn missing_preloaded_digest_prevents_oci_advertisement() {
    let fixture = Fixture::new(false);
    fixture.write_job_manifest();
    let factory = RecordingFactory {
        missing_image: true,
        ..RecordingFactory::default()
    };

    assert!(matches!(
        fixture.load(factory),
        Err(RunnerError::Oci(
            runtrue_executor_oci::OciError::CleanupVerificationFailed { .. }
        ))
    ));
    assert!(fs::read_dir(&fixture.paths.state_root)
        .unwrap()
        .next()
        .is_none());
}
