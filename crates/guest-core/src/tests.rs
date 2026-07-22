use super::*;
use runtrue_attest::CapsuleSigningKey;
use runtrue_model::{ContentDigest, SecretReference};
use runtrue_workflow_ir::{
    ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
    OperatingSystem, ParityGrade, PermissionSet, PlannedJob, PlannedStep, RunnerRequirements,
    StepAction, StepCapabilitySet, Trust, WorkflowIdentity, CAPSULE_SCHEMA_VERSION,
    ENGINE_COMPATIBILITY_VERSION,
};
use std::collections::BTreeMap;

fn fixture() -> (
    GuestSession,
    HostSessionCodec,
    CapsuleSigningKey,
    ExecutionCapsule,
) {
    let key = CapsuleSigningKey::from_seed([9; 32]);
    let capabilities = StepCapabilitySet {
        fs_read: vec!["src".to_owned()],
        fs_write: vec!["target".to_owned()],
        secrets: vec![SecretReference {
            metadata_id: "secret-1".to_owned(),
            name: "TOKEN".to_owned(),
            purpose: Some("tests".to_owned()),
            resolution: None,
        }],
        oidc_audiences: vec!["https://cloud.example".to_owned()],
        ..StepCapabilitySet::default()
    };
    let step = PlannedStep {
        id: "build".to_owned(),
        name: "Build".to_owned(),
        condition: None,
        action: StepAction::Command {
            program: "cargo".to_owned(),
            args: Vec::new(),
        },
        inputs: BTreeMap::new(),
        environment: BTreeMap::new(),
        capabilities,
        cache: None,
        timeout_ms: Some(1_000),
        continue_on_error: false,
        outputs: BTreeMap::new(),
        working_directory: None,
    };
    let job = PlannedJob {
        id: "job".to_owned(),
        base_id: "job".to_owned(),
        name: "Job".to_owned(),
        needs: Vec::new(),
        matrix: BTreeMap::new(),
        condition: None,
        trust: Trust::TrustedOnly,
        environment: None,
        runner: RunnerRequirements {
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation: Isolation::Microvm,
            image: None,
            cpu: 1,
            memory_bytes: 256 * 1024 * 1024,
            storage_bytes: None,
            region: None,
            capabilities: Vec::new(),
        },
        permissions: PermissionSet::default(),
        timeout_ms: 5_000,
        retries: 0,
        concurrency: None,
        variables: BTreeMap::new(),
        services: Vec::new(),
        steps: vec![step],
        finalizers: Vec::new(),
        finalizer_timeout_ms: 120_000,
        value_outputs: BTreeMap::new(),
        outputs: BTreeMap::new(),
    };
    let capsule = ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "test".to_owned(),
        workflow: WorkflowIdentity {
            name: "test".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/test.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "0123456789012345678901234567890123456789".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: runtrue_workflow_ir::SourceTrust::Trusted,
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            workflow_frontend: None,
            policy_version_ids: Vec::new(),
        },
        variables: BTreeMap::new(),
        permissions: PermissionSet::default(),
        jobs: vec![job],
        dynamic_jobs: Vec::new(),
        approval: ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::AExact,
    };
    let session_key = [7; 32];
    let bootstrap = GuestBootstrap {
        protocol_version: GUEST_PROTOCOL_VERSION,
        session_id: "session".to_owned(),
        lease_id: "lease".to_owned(),
        fencing_generation: 2,
        installation_fencing_epoch: 3,
        job_id: "job".to_owned(),
        capsule_digest: capsule.digest().unwrap(),
        guest_image_digest: ContentDigest::sha256(b"guest"),
        expires_unix_ms: 10_000,
    };
    let mut trust = GuestCapsuleTrustStore::new();
    trust.insert(key.verifying_key()).unwrap();
    let session = GuestSession::new(
        bootstrap,
        GuestSessionKey::from_bytes(session_key),
        trust,
        1,
    )
    .unwrap();
    let codec = HostSessionCodec::new("session", GuestSessionKey::from_bytes(session_key)).unwrap();
    (session, codec, key, capsule)
}

fn admit(
    session: &mut GuestSession,
    codec: &mut HostSessionCodec,
    key: &CapsuleSigningKey,
    capsule: &ExecutionCapsule,
) {
    let command = HostCommand::StartJob {
        canonical_capsule: capsule.canonical_bytes().unwrap(),
        signature: key.sign_capsule(capsule).unwrap(),
    };
    let action = session.accept(codec.command(&command).unwrap(), 2).unwrap();
    let GuestAction::Send(event) = action else {
        panic!("expected response")
    };
    assert!(matches!(
        codec.verify_event(event).unwrap(),
        GuestEvent::JobAccepted { .. }
    ));
}

#[test]
fn hello_and_signed_capsule_admission_are_authenticated() {
    let (mut session, mut codec, key, capsule) = fixture();
    let hello = session.hello().unwrap();
    assert!(matches!(
        codec.verify_event(hello).unwrap(),
        GuestEvent::Hello { .. }
    ));
    admit(&mut session, &mut codec, &key, &capsule);
    assert_eq!(session.state(), GuestSessionState::Ready);
}

#[test]
fn replay_tampering_and_wrong_session_fail_closed() {
    let (mut session, mut codec, key, capsule) = fixture();
    let command = HostCommand::StartJob {
        canonical_capsule: capsule.canonical_bytes().unwrap(),
        signature: key.sign_capsule(&capsule).unwrap(),
    };
    let envelope = codec.command(&command).unwrap();
    let replay = envelope.clone();
    session.accept(envelope, 2).unwrap();
    assert!(matches!(
        session.accept(replay, 2),
        Err(GuestError::UnexpectedSequence { .. })
    ));

    let (mut other_session, mut other_codec, _, _) = fixture();
    let mut tampered = other_codec.command(&command).unwrap();
    tampered.payload[0] ^= 1;
    assert!(matches!(
        other_session.accept(tampered, 2),
        Err(GuestError::AuthenticationFailed)
    ));
    let mut wrong = other_codec.command(&command).unwrap();
    wrong.session_id = "another".to_owned();
    assert!(matches!(
        other_session.accept(wrong, 2),
        Err(GuestError::WrongSession)
    ));
}

#[test]
fn mounts_cannot_exceed_signed_filesystem_capabilities() {
    let (mut session, mut codec, key, capsule) = fixture();
    admit(&mut session, &mut codec, &key, &capsule);
    let read = HostCommand::Mount(MountDescriptor {
        mount_id: "src".to_owned(),
        guest_path: "src/vendor".to_owned(),
        content_digest: ContentDigest::sha256(b"src"),
        read_only: true,
        purpose: MountPurpose::Input,
    });
    assert!(matches!(
        session.accept(codec.command(&read).unwrap(), 3).unwrap(),
        GuestAction::Send(_)
    ));
    let write = HostCommand::Mount(MountDescriptor {
        mount_id: "forbidden".to_owned(),
        guest_path: "src/generated".to_owned(),
        content_digest: ContentDigest::sha256(b"write"),
        read_only: false,
        purpose: MountPurpose::Workspace,
    });
    assert!(matches!(
        session.accept(codec.command(&write).unwrap(), 3),
        Err(GuestError::UndeclaredMountCapability(_))
    ));
}

fn start_step(
    session: &mut GuestSession,
    codec: &mut HostSessionCodec,
    capsule: &ExecutionCapsule,
) {
    let command = HostCommand::StartStep {
        step_id: "build".to_owned(),
        attempt: 1,
        capability_digest: step_capability_digest(&capsule.jobs[0].steps[0]).unwrap(),
    };
    assert!(matches!(
        session.accept(codec.command(&command).unwrap(), 4).unwrap(),
        GuestAction::StartStep(_)
    ));
}

#[test]
fn secret_and_oidc_delivery_are_exact_step_capabilities() {
    let (mut session, mut codec, key, capsule) = fixture();
    admit(&mut session, &mut codec, &key, &capsule);
    start_step(&mut session, &mut codec, &capsule);

    let secret = HostCommand::Secret(SecretEnvelope {
        step_id: "build".to_owned(),
        metadata_id: "secret-1".to_owned(),
        name: "TOKEN".to_owned(),
        purpose: Some("tests".to_owned()),
        expires_unix_ms: 100,
        ciphertext: vec![1, 2, 3],
    });
    let material = session.accept(codec.command(&secret).unwrap(), 5).unwrap();
    let GuestAction::DeliverSecret(material) = material else {
        panic!("expected secret")
    };
    assert_eq!(material.ciphertext(), &[1, 2, 3]);
    assert!(format!("{material:?}").contains("<redacted>"));

    let oidc = HostCommand::Oidc(OidcEnvelope {
        step_id: "build".to_owned(),
        audience: "https://cloud.example".to_owned(),
        expires_unix_ms: 100,
        token: "jwt".to_owned(),
    });
    let token = session.accept(codec.command(&oidc).unwrap(), 5).unwrap();
    let GuestAction::DeliverOidc(token) = token else {
        panic!("expected OIDC token")
    };
    assert_eq!(token.expose(), "jwt");
    assert!(format!("{token:?}").contains("<redacted>"));

    let undeclared = HostCommand::Oidc(OidcEnvelope {
        step_id: "build".to_owned(),
        audience: "https://other.example".to_owned(),
        expires_unix_ms: 100,
        token: "jwt".to_owned(),
    });
    assert!(matches!(
        session.accept(codec.command(&undeclared).unwrap(), 5),
        Err(GuestError::UndeclaredOidcAudience)
    ));
}

#[test]
fn step_logs_results_and_shutdown_follow_lifecycle() {
    let (mut session, mut codec, key, capsule) = fixture();
    admit(&mut session, &mut codec, &key, &capsule);
    start_step(&mut session, &mut codec, &capsule);
    let log = session
        .record_log("build", LogStream::Stdout, b"hello".to_vec(), 5)
        .unwrap();
    assert!(matches!(
        codec.verify_event(log).unwrap(),
        GuestEvent::LogFrame(LogFrame { sequence: 0, .. })
    ));
    let result = session
        .record_step_result(
            GuestStepResult {
                step_id: "build".to_owned(),
                attempt: 1,
                exit_code: Some(0),
                timed_out: false,
                canceled: false,
                skipped: false,
            },
            6,
        )
        .unwrap();
    assert!(matches!(
        codec.verify_event(result).unwrap(),
        GuestEvent::StepResult(_)
    ));
    let job = session.finish_job(7).unwrap();
    assert!(matches!(
        codec.verify_event(job).unwrap(),
        GuestEvent::JobResult {
            succeeded: true,
            ..
        }
    ));
    assert!(matches!(
        session
            .accept(codec.command(&HostCommand::Shutdown).unwrap(), 8)
            .unwrap(),
        GuestAction::Shutdown
    ));
    assert_eq!(session.state(), GuestSessionState::Shutdown);
}

#[test]
fn capsule_and_capability_mutation_are_rejected() {
    let (mut session, mut codec, key, mut capsule) = fixture();
    let signature = key.sign_capsule(&capsule).unwrap();
    capsule.jobs[0].name = "changed".to_owned();
    let command = HostCommand::StartJob {
        canonical_capsule: capsule.canonical_bytes().unwrap(),
        signature,
    };
    assert!(matches!(
        session.accept(codec.command(&command).unwrap(), 2),
        Err(GuestError::CapsuleDigestMismatch)
    ));

    let (mut session, mut codec, key, capsule) = fixture();
    admit(&mut session, &mut codec, &key, &capsule);
    let command = HostCommand::StartStep {
        step_id: "build".to_owned(),
        attempt: 1,
        capability_digest: ContentDigest::sha256(b"different"),
    };
    assert!(matches!(
        session.accept(codec.command(&command).unwrap(), 4),
        Err(GuestError::CapabilityDigestMismatch)
    ));
}
