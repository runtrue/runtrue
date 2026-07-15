use super::*;
#[test]
fn image_references_must_be_digest_only_without_tags() {
    for reference in [
            "registry.example/build:latest",
            "registry.example/build@sha256:abcd",
            "registry.example/build:latest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "docker://registry.example/build@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "registry.example/build@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(
                LockedImage::new(
                    reference,
                    "release@runtrue.example",
                    OciPlatform::linux_amd64()
                )
                .is_err(),
                "{reference}"
            );
        }
    assert_eq!(locked_image().digest().as_str(), format!("sha256:{DIGEST}"));
}

#[test]
fn preflight_admits_exact_image_and_caches_verified_identity() {
    let fixture = fixture_with(AdmissionMode::Exact);
    fixture.executor.preflight_capsule(&capsule()).unwrap();
    assert_eq!(
        fixture
            .executor
            .admission_provider
            .calls
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(fixture.executor.admitted.lock().unwrap().len(), 1);
}

#[test]
fn preflight_requires_the_exact_planned_job_image_and_rejects_legacy_oci_capsules() {
    let fixture = fixture_with(AdmissionMode::Exact);
    let mut substituted = capsule();
    substituted.jobs[0].runner.image = Some(SERVICE_IMAGE.to_owned());
    assert!(matches!(
        fixture.executor.preflight_capsule(&substituted),
        Err(OciError::JobImageReferenceMismatch(job)) if job == "job"
    ));
    assert!(fixture.executor.runtime().invocations.is_empty());

    let mut encoded = serde_json::to_value(capsule()).unwrap();
    encoded["jobs"][0]["runner"]
        .as_object_mut()
        .unwrap()
        .remove("image");
    let legacy: ExecutionCapsule = serde_json::from_value(encoded).unwrap();
    assert_eq!(legacy.jobs[0].runner.image, None);
    assert!(matches!(
        fixture.executor.preflight_capsule(&legacy),
        Err(OciError::UnsupportedFeature(message))
            if message.contains("runner image")
    ));
    assert!(fixture.executor.runtime().invocations.is_empty());
}

#[test]
fn admission_mismatch_unverified_and_denial_fail_before_runtime() {
    for mode in [
        AdmissionMode::WrongSigner,
        AdmissionMode::Unverified,
        AdmissionMode::Denied,
    ] {
        let mut fixture = fixture_with(mode);
        assert!(fixture
            .executor
            .execute_request(&command_request())
            .is_err());
        assert!(fixture.executor.runtime().invocations.is_empty());
    }
}
