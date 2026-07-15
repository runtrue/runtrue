use runtrue_attest::CapsuleSigningKey;
use runtrue_engine::{CancellationToken, StepState, StepStateObservation, StepStateObserver};
use runtrue_executor_firecracker::{FramedTransport, OneJobSession};
use runtrue_guest::{serve_one_job, DirectStepExecutor};
use runtrue_guest_core::{
    GuestBootConfig, GuestBootstrap, GuestCapsuleTrustStore, GUEST_PROTOCOL_VERSION,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{
    ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
    NetworkPermission, OperatingSystem, ParityGrade, PermissionSet, PlannedJob, PlannedStep,
    RunnerRequirements, SourceTrust, StepAction, StepCapabilitySet, Trust, ValueBinding,
    WorkflowIdentity, CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::{fs::PermissionsExt as _, net::UnixStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

#[derive(Default)]
struct RecordingObserver(Mutex<Vec<StepStateObservation>>);

impl StepStateObserver for RecordingObserver {
    fn observe(&self, observation: &StepStateObservation) -> Result<(), String> {
        self.0.lock().unwrap().push(observation.clone());
        Ok(())
    }
}

#[test]
fn authenticated_one_job_runs_over_fake_vsock_without_kvm() {
    let directory = TempDir::new().unwrap();
    let workspace = directory.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let program = directory.path().join("step-program");
    fs::write(&program, "#!/bin/sh\nprintf 'guest-ok'").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();

    let step = PlannedStep {
        id: "step".to_owned(),
        name: "Step".to_owned(),
        condition: None,
        action: StepAction::Command {
            program: program.display().to_string(),
            args: vec![ValueBinding::Literal(
                runtrue_workflow_ir::ScalarValue::String("ignored".to_owned()),
            )],
        },
        inputs: BTreeMap::new(),
        environment: BTreeMap::new(),
        capabilities: StepCapabilitySet {
            network: NetworkPermission::Deny,
            ..StepCapabilitySet::default()
        },
        cache: None,
        timeout_ms: Some(2_000),
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
        compiler_version: "system-test".to_owned(),
        workflow: WorkflowIdentity {
            name: "test".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/test.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "0123456789012345678901234567890123456789".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: SourceTrust::Trusted,
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
    let signing = CapsuleSigningKey::from_seed([11; 32]);
    let signature = signing.sign_capsule(&capsule).unwrap();
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let bootstrap = GuestBootstrap {
        protocol_version: GUEST_PROTOCOL_VERSION,
        session_id: "session".to_owned(),
        lease_id: "lease".to_owned(),
        fencing_generation: 7,
        installation_fencing_epoch: 9,
        job_id: "job".to_owned(),
        capsule_digest: capsule.digest().unwrap(),
        guest_image_digest: ContentDigest::sha256(b"signed-guest"),
        expires_unix_ms: now + 60_000,
    };
    let host =
        OneJobSession::new(bootstrap, &capsule, signature, "/etc/runtrue/keys", 5000).unwrap();
    let boot_bytes = serde_json::to_vec(host.boot_config()).unwrap();
    let guest_boot: GuestBootConfig = serde_json::from_slice(&boot_bytes).unwrap();
    let mut trust = GuestCapsuleTrustStore::new();
    trust.insert(signing.verifying_key()).unwrap();
    let (host_stream, guest_stream) = UnixStream::pair().unwrap();
    host_stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    guest_stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let guest_reader = guest_stream.try_clone().unwrap();
    let executor = Arc::new(DirectStepExecutor::new(&workspace).unwrap());
    let guest = thread::spawn(move || {
        serve_one_job(guest_boot, trust, guest_reader, guest_stream, executor)
    });

    let mut transport = FramedTransport::new(host_stream);
    let observer = RecordingObserver::default();
    let report = host
        .run_with_observer(
            &mut transport,
            &CancellationToken::default(),
            Some(&observer),
        )
        .unwrap();
    assert!(report.succeeded);
    assert_eq!(report.step_results[0].exit_code, Some(0));
    assert_eq!(report.logs[0].bytes, b"guest-ok");
    assert_eq!(
        observer
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|observation| observation.to)
            .collect::<Vec<_>>(),
        vec![StepState::Created, StepState::Running, StepState::Succeeded]
    );
    guest.join().unwrap().unwrap();
}
