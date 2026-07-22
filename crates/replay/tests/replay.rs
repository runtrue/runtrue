use runtrue_engine::{
    EngineEvent, ExecutionResult, ExecutorOutput, JobAttemptResult, JobResult, JobState, RunState,
    StepResult, StepState,
};
use runtrue_model::ContentDigest;
use runtrue_replay::{ReplayBundle, ReplayEnvelope, ReplayError};
use runtrue_workflow_ir::{
    ApprovalRequirements, CapsuleContext, ExecutionCapsule, ParityGrade, PermissionSet,
    WorkflowFrontendProvenance, WorkflowFrontendReportArtifact, WorkflowIdentity,
    CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
use std::collections::BTreeMap;

fn capsule() -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "test".to_owned(),
        workflow: WorkflowIdentity {
            name: "test".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/test.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "abc".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: Default::default(),
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            workflow_frontend: None,
            policy_version_ids: vec!["policy-v1".to_owned()],
        },
        variables: BTreeMap::new(),
        permissions: PermissionSet::default(),
        jobs: Vec::new(),
        dynamic_jobs: Vec::new(),
        approval: ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::AExact,
    }
}

fn result_with_sensitive_output() -> ExecutionResult {
    let step = StepResult {
        id: "step".to_owned(),
        state: StepState::Succeeded,
        continued_on_error: false,
        skip_reason: None,
        output: Some(ExecutorOutput {
            exit_code: Some(0),
            stdout: "super-secret-value".to_owned(),
            stderr: "private-error-detail".to_owned(),
            structured_output: None,
            credential_taint: runtrue_engine::CredentialTaint::None,
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            canceled: false,
            duration_ms: 1,
        }),
        error: Some("sensitive exception".to_owned()),
        outputs: BTreeMap::new(),
    };
    ExecutionResult {
        state: RunState::Succeeded,
        jobs: BTreeMap::from([(
            "job".to_owned(),
            JobResult {
                id: "job".to_owned(),
                state: JobState::Succeeded,
                skip_reason: None,
                attempts: vec![JobAttemptResult {
                    number: 1,
                    primary_state: JobState::Succeeded,
                    credential_taint: runtrue_engine::CredentialTaint::None,
                    steps: vec![step],
                    finalizers: Vec::new(),
                }],
                outputs: BTreeMap::new(),
            },
        )]),
        events: Vec::<EngineEvent>::new(),
        credential_taint: runtrue_engine::CredentialTaint::None,
    }
}

#[test]
fn round_trip_is_canonical_and_verifiable() {
    let envelope = ReplayBundle::new(
        capsule(),
        ContentDigest::sha256(b"approval"),
        Some(&result_with_sensitive_output()),
    )
    .unwrap()
    .seal()
    .unwrap();
    let bytes = envelope.canonical_bytes().unwrap();
    assert_eq!(
        ReplayEnvelope::from_canonical_bytes(&bytes).unwrap(),
        envelope
    );
}

#[test]
fn replay_bundle_uses_the_capsule_wire_vocabulary() {
    let capsule = capsule();
    let expected_digest = capsule.digest().unwrap();
    let bundle =
        ReplayBundle::new(capsule.clone(), ContentDigest::sha256(b"approval"), None).unwrap();

    assert_eq!(bundle.capsule(), &capsule);
    assert_eq!(bundle.capsule_digest(), &expected_digest);
    let value = serde_json::to_value(bundle).unwrap();
    assert!(value.get("capsule").is_some());
    assert!(value.get("plan").is_none());
}

#[test]
fn frontend_report_round_trips_and_must_match_signed_capsule_digest() {
    let bytes = br#"{"status":"partial"}"#.to_vec();
    let digest = ContentDigest::sha256(&bytes);
    let mut capsule = capsule();
    capsule.context.workflow_frontend = Some(WorkflowFrontendProvenance {
        frontend_id: "runtrue.github-actions".to_owned(),
        contract_generation: 1,
        frontend_generation: 2,
        configuration_digest: ContentDigest::sha256(b"frontend config"),
        input_digest: ContentDigest::sha256(b"source"),
        native_digest: ContentDigest::sha256(b"native"),
        report_digest: Some(digest.clone()),
    });
    let report = WorkflowFrontendReportArtifact {
        media_type: "application/vnd.runtrue.frontend-compatibility+json".to_owned(),
        digest,
        bytes,
    };
    let envelope = ReplayBundle::new(capsule, ContentDigest::sha256(b"approval"), None)
        .unwrap()
        .with_workflow_frontend_report(report)
        .seal()
        .unwrap();
    let canonical = envelope.canonical_bytes().unwrap();
    assert_eq!(
        ReplayEnvelope::from_canonical_bytes(&canonical).unwrap(),
        envelope
    );

    let mut tampered = envelope;
    tampered
        .bundle
        .workflow_frontend_report
        .as_mut()
        .unwrap()
        .bytes
        .push(b' ');
    assert!(matches!(
        tampered.verify(),
        Err(ReplayError::WorkflowFrontendReportMismatch)
    ));
}

#[test]
fn execution_output_and_errors_never_enter_bundle() {
    let envelope = ReplayBundle::new(
        capsule(),
        ContentDigest::sha256(b"approval"),
        Some(&result_with_sensitive_output()),
    )
    .unwrap()
    .seal()
    .unwrap();
    let encoded = String::from_utf8(envelope.canonical_bytes().unwrap()).unwrap();
    for forbidden in [
        "super-secret-value",
        "private-error-detail",
        "sensitive exception",
    ] {
        assert!(!encoded.contains(forbidden), "leaked `{forbidden}`");
    }
}

#[test]
fn credential_tainted_execution_cannot_be_published_as_replay() {
    let mut result = result_with_sensitive_output();
    let attempt = &mut result.jobs.get_mut("job").unwrap().attempts[0];
    attempt.credential_taint = runtrue_engine::CredentialTaint::CredentialReleased;
    attempt.steps[0].output.as_mut().unwrap().credential_taint =
        runtrue_engine::CredentialTaint::CredentialReleased;

    assert!(matches!(
        ReplayBundle::new(capsule(), ContentDigest::sha256(b"approval"), Some(&result)),
        Err(ReplayError::CredentialTainted)
    ));
}

#[test]
fn tampering_and_noncanonical_json_are_rejected() {
    let mut envelope = ReplayBundle::new(capsule(), ContentDigest::sha256(b"approval"), None)
        .unwrap()
        .seal()
        .unwrap();
    envelope.bundle.capsule.context.source_commit = "tampered".to_owned();
    assert!(matches!(
        envelope.verify(),
        Err(ReplayError::CapsuleDigestMismatch { .. })
    ));
    let valid = ReplayBundle::new(capsule(), ContentDigest::sha256(b"approval"), None)
        .unwrap()
        .seal()
        .unwrap();
    let pretty = serde_json::to_vec_pretty(&valid).unwrap();
    assert!(matches!(
        ReplayEnvelope::from_canonical_bytes(&pretty),
        Err(ReplayError::NonCanonical)
    ));
}
