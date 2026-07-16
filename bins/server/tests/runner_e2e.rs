#![cfg(unix)]

use axum::{
    body::{Body, HttpBody as _},
    http::{Request, StatusCode},
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, PKCS_ED25519,
};
use runtrue_attest::CapsuleSigningKey;
use runtrue_control_plane::{
    CapsuleApiMetadata, ControlPlane, CreateRunRequest, DurableTask, DurableTaskStatus, NewJob,
    RepositoryRecord, RunnerPoolRecord, RunnerPoolStatus, ScmCheckPublishTask, SignedCapsuleRecord,
    SourceSnapshotRecord, SourceSnapshotState,
};
use runtrue_git::{GitLimits, GitRepository, SourceSnapshotLimits};
use runtrue_lifecycle::JobState;
use runtrue_model::ContentDigest;
use runtrue_policy::{ApprovalDecision, ApprovalKind, ApprovalRequest, ApprovalRule, Decision};
use runtrue_protocol::v1::{self, runner_control_client::RunnerControlClient};
use runtrue_protocol::v2::{self, runner_object_transfer_client::RunnerObjectTransferClient};
use runtrue_runner::{
    apply_authoritative_posture, load_capsule_trust_store, EndpointSecurity, NativeJobExecutor,
    RunMode, RunnerDaemon, RunnerDaemonConfig, RunnerStateStore, VerifiedInventory,
    WorkspaceManager,
};
use runtrue_runner_core::VerifiedRunnerProfile;
use runtrue_scheduler::{RunnerStatus, SchedulingRequirements};
use runtrue_server::{router, AppState, RunnerCertificateAuthority};
use runtrue_storage::{CasLimits, FsCas};
use runtrue_workflow_ir::{
    Access, ApprovalRequirements, Architecture, ArtifactClassification, ArtifactOutput,
    CacheDeclaration, CacheMode, CacheRead, CacheWrite, CapsuleContext, ExecutionCapsule,
    Isolation, OperatingSystem, ParityGrade, PermissionSet, PlannedJob, PlannedStep,
    RunnerRequirements, ScalarValue, SourceTrust, StepAction, StepCapabilitySet, Trust,
    ValueBinding, WorkflowIdentity, CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt as _,
    process::Command,
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tower::ServiceExt as _;

struct Pki {
    ca_pem: String,
    ca_key_pem: String,
    server_pem: String,
    server_key_pem: String,
}

fn pki() -> Pki {
    let ca_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca.not_before = time::OffsetDateTime::from_unix_timestamp(1).unwrap();
    ca.not_after = time::OffsetDateTime::from_unix_timestamp(4_102_444_800).unwrap();
    let ca_cert = ca.clone().self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut server = CertificateParams::default();
    server.distinguished_name = DistinguishedName::new();
    server
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server.not_before = ca.not_before;
    server.not_after = ca.not_after;
    let issuer = Issuer::from_params(&ca, &ca_key);
    let server_cert = server.signed_by(&server_key, &issuer).unwrap();
    Pki {
        ca_pem: ca_cert.pem(),
        ca_key_pem: ca_key.serialize_pem(),
        server_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
    }
}

async fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

async fn channel(address: SocketAddr, tls: ClientTlsConfig) -> Channel {
    Endpoint::from_shared(format!("https://localhost:{}", address.port()))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

fn source_capsule(commit: String, tree: ContentDigest) -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.into(),
        compiler_version: "runner-e2e".into(),
        workflow: WorkflowIdentity {
            name: "exact source".into(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/ci.yaml".into(),
        },
        context: CapsuleContext {
            source_commit: commit,
            source_tree_digest: Some(tree),
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
        permissions: PermissionSet {
            artifacts: Access::Write,
            cache_read: CacheRead::Run,
            cache_write: CacheWrite::Quarantine,
            ..PermissionSet::default()
        },
        jobs: vec![PlannedJob {
            id: "build".into(),
            base_id: "build".into(),
            name: "Build exact commit".into(),
            needs: Vec::new(),
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::TrustedOnly,
            environment: None,
            runner: RunnerRequirements {
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Native,
                image: None,
                cpu: 1,
                memory_bytes: 1,
                storage_bytes: Some(1),
                region: None,
                capabilities: Vec::new(),
            },
            permissions: PermissionSet {
                artifacts: Access::Write,
                cache_read: CacheRead::Run,
                cache_write: CacheWrite::Quarantine,
                ..PermissionSet::default()
            },
            timeout_ms: 30_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: vec![PlannedStep {
                id: "verify".into(),
                name: "Verify hydrated source".into(),
                condition: None,
                action: StepAction::Command {
                    program: "/bin/sh".into(),
                    args: vec![
                        ValueBinding::Literal(ScalarValue::String("-c".into())),
                        ValueBinding::Literal(ScalarValue::String(
                            "printf 'checked out exact commit\\n'; test \"$(cat exact.txt)\" = exact-commit"
                                .into(),
                        )),
                    ],
                },
                inputs: BTreeMap::new(),
                environment: BTreeMap::new(),
                capabilities: StepCapabilitySet {
                    cache_read: CacheRead::Run,
                    cache_write: CacheWrite::Quarantine,
                    ..StepCapabilitySet::default()
                },
                cache: Some(CacheDeclaration {
                    inputs: vec!["exact.txt".into()],
                    outputs: vec!["exact.txt".into()],
                    mode: CacheMode::WriteOnly,
                    max_size_bytes: Some(1024),
                }),
                timeout_ms: Some(10_000),
                continue_on_error: false,
                outputs: BTreeMap::new(),
                working_directory: None,
            }],
            finalizers: Vec::new(),
            finalizer_timeout_ms: 120_000,
            value_outputs: BTreeMap::new(),
            outputs: BTreeMap::from([(
                "exact-source".into(),
                ArtifactOutput {
                    path: "exact.txt".into(),
                    retention_ms: 60_000,
                    classification: ArtifactClassification::VerifiedTestOutput,
                },
            )]),
        }],
        dynamic_jobs: Vec::new(),
        approval: ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: true,
            reasons: vec!["trusted Native execution".into()],
        },
        expected_parity: ParityGrade::AExact,
    }
}

fn private_write(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn e2e_inventory() -> VerifiedInventory {
    // This integration test exercises enrollment and the data plane, not the
    // executable-size probe. A small deterministic fixture identity avoids
    // coupling the test to the size of its all-features debug test binary.
    let binary_digest = ContentDigest::sha256(b"runner-e2e-fixture-binary");
    let posture_digest = ContentDigest::sha256(b"runner-e2e-local-posture");
    let profile = VerifiedRunnerProfile {
        runner_id: "runner-e2e".to_owned(),
        os: OperatingSystem::Linux,
        architecture: Architecture::Amd64,
        logical_cpus: 2,
        memory_bytes: 1024 * 1024 * 1024,
        storage_bytes: 1024 * 1024 * 1024,
        isolation_backends: BTreeSet::from([Isolation::Native]),
        capabilities: BTreeSet::new(),
        region: None,
        posture_digest: posture_digest.clone(),
    };
    let wire_digest = v1::Digest::try_from(&binary_digest).unwrap();
    VerifiedInventory {
        profile,
        wire: v1::RunnerInventory {
            hostname: "runner-e2e.local".to_owned(),
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            logical_cpus: 2,
            memory_bytes: 1024 * 1024 * 1024,
            local_storage_bytes: 1024 * 1024 * 1024,
            isolation_backends: vec!["native".to_owned()],
            capabilities: vec![v1::Capability {
                key: "runtrue.posture.digest".to_owned(),
                json_value: serde_json::to_string(posture_digest.as_str()).unwrap(),
                evidence_source: "test-fixture".to_owned(),
            }],
            runner_binary_digest: Some(wire_digest.clone()),
            runner_image_digest: Some(wire_digest),
            runner_version: env!("CARGO_PKG_VERSION").to_owned(),
            engine_version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: runtrue_protocol::PROTOCOL_MAX,
            region: String::new(),
            labels: Default::default(),
        },
        binary_digest,
    }
}

fn bootstrap_request(method: &str, uri: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", "Bearer bootstrap")
        .header("content-type", "application/json")
        .body(body.into())
        .unwrap()
}

async fn response_bytes(response: axum::response::Response) -> Vec<u8> {
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    bytes
}

fn git(repository: &std::path::Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_data_plane_is_reached_only_over_enrolled_mtls_identity() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("control.sqlite");
    let workspace_root = directory.path().join("workspaces");
    let workspaces = WorkspaceManager::open(&workspace_root).unwrap();
    let verified_inventory = e2e_inventory();
    let control = Arc::new(ControlPlane::open(&database, "runner-e2e", 1).unwrap());
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-e2e".into(),
            tenant_id: "tenant-e2e".into(),
            name: "e2e".into(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: 1,
        })
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let token = control
        .create_enrollment_token("pool-e2e", now, now + 60_000)
        .unwrap();
    let pki = pki();
    let authority = Arc::new(
        RunnerCertificateAuthority::load(
            pki.ca_pem.as_bytes(),
            pki.ca_key_pem.as_bytes(),
            Duration::from_secs(3600),
        )
        .unwrap(),
    );
    let state = AppState::new_with_security_seed(
        Arc::clone(&control),
        "bootstrap",
        None,
        [9; 32],
        "https://localhost/oidc".into(),
    )
    .unwrap()
    .with_runner_data_plane(directory.path().join("objects"))
    .unwrap();
    let service = state.runner_control_service(authority).unwrap();

    let server_identity = Identity::from_pem(pki.server_pem.clone(), pki.server_key_pem.clone());
    let (enroll_listener, enroll_address) = listener().await;
    let enroll_tls = ServerTlsConfig::new().identity(server_identity.clone());
    let enrollment = service.enrollment_service().into_server();
    let enroll_task = tokio::spawn(async move {
        Server::builder()
            .tls_config(enroll_tls)
            .unwrap()
            .add_service(enrollment)
            .serve_with_incoming(TcpListenerStream::new(enroll_listener))
            .await
            .unwrap();
    });

    let runner_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut request_params = CertificateParams::default();
    request_params.distinguished_name = DistinguishedName::new();
    let csr = request_params.serialize_request(&runner_key).unwrap();
    let mut enrollment_client = RunnerControlClient::new(
        channel(
            enroll_address,
            ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(Certificate::from_pem(pki.ca_pem.clone())),
        )
        .await,
    );
    let enrolled = enrollment_client
        .enroll(v1::EnrollRequest {
            enrollment_token: token.token.expose().to_owned(),
            certificate_signing_request: csr.der().to_vec(),
            inventory: Some(verified_inventory.wire.clone()),
            attestation: None,
            protocol_min: runtrue_protocol::PROTOCOL_MIN,
            protocol_max: runtrue_protocol::PROTOCOL_MAX,
            ephemeral: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(enrolled.runner_pool_id, "pool-e2e");

    let source_repository = directory.path().join("source-repository");
    fs::create_dir(&source_repository).unwrap();
    git(&source_repository, &["init", "--quiet"]);
    fs::write(source_repository.join("exact.txt"), b"exact-commit\n").unwrap();
    git(&source_repository, &["add", "exact.txt"]);
    git(
        &source_repository,
        &[
            "-c",
            "user.name=Runtrue E2E",
            "-c",
            "user.email=e2e@runtrue.invalid",
            "commit",
            "--quiet",
            "-m",
            "exact source",
        ],
    );
    let exact_commit = git(&source_repository, &["rev-parse", "HEAD"]);
    assert_eq!(exact_commit.len(), 40);
    let source_digest = ContentDigest::sha256(b"exact-commit\n");
    let data_root = directory.path().join("objects");
    let cas = FsCas::open(data_root.join("cas"), CasLimits::default()).unwrap();
    let git_repository = GitRepository::open(&source_repository, GitLimits::default()).unwrap();
    let manifest = git_repository
        .build_source_manifest(
            "repo-e2e",
            &exact_commit,
            SourceSnapshotLimits::default(),
            |digest, bytes| {
                cas.put_verified_reader(bytes, digest, bytes.len() as u64, bytes.len() as u64)
                    .map(|_| ())
                    .map_err(|_| runtrue_git::GitError::InvalidGitOutput("fixture CAS publication"))
            },
        )
        .unwrap();
    assert_eq!(manifest.commit, exact_commit);
    let manifest_bytes = manifest.canonical_bytes().unwrap();
    let manifest_digest = manifest.digest().unwrap();
    cas.put_verified_reader(
        manifest_bytes.as_slice(),
        &manifest_digest,
        manifest_bytes.len() as u64,
        manifest_bytes.len() as u64,
    )
    .unwrap();
    control
        .create_repository(&RepositoryRecord {
            id: "repo-e2e".into(),
            tenant_id: "tenant-e2e".into(),
            owner: "acme".into(),
            name: "exact".into(),
            default_branch: "main".into(),
            visibility: "private".into(),
            created_unix_ms: now,
        })
        .unwrap();
    let signing_key = CapsuleSigningKey::from_seed([44; 32]);
    let capsule_value = source_capsule(exact_commit.clone(), manifest_digest.clone());
    let signature = signing_key.sign_capsule(&capsule_value).unwrap();
    let capsule_digest = signature.capsule_digest.clone();
    let approval_subject = ContentDigest::sha256(b"runner-e2e-approved-native-source");
    let approval = ApprovalRequest::create(
        "approval-e2e",
        ApprovalKind::PrivilegedExecution,
        approval_subject.clone(),
        90,
        now,
        now + 60_000,
        ApprovalRule {
            id: "e2e-review".into(),
            required_approvals: 1,
            eligible_approvers: BTreeSet::from(["reviewer-e2e".into()]),
            forbidden_approvers: BTreeSet::new(),
            one_shot: true,
        },
    )
    .unwrap();
    let signed_capsule = SignedCapsuleRecord {
        id: "capsule-e2e".into(),
        repository_id: "repo-e2e".into(),
        digest: capsule_digest.clone(),
        canonical_capsule: capsule_value.canonical_bytes().unwrap(),
        signature,
        created_unix_ms: now,
    };
    control
        .store_compiled_capsule_idempotent(
            "capsule-e2e-store",
            &signed_capsule,
            &signing_key.verifying_key(),
            &CapsuleApiMetadata {
                capsule_id: "capsule-e2e".into(),
                approval_subject_digest: approval_subject.clone(),
                risk_score: 90,
            },
            std::slice::from_ref(&approval),
        )
        .unwrap();
    control
        .decide_approval(
            &approval.id,
            ApprovalDecision {
                actor_id: "reviewer-e2e".into(),
                decision: Decision::Approve,
                reason: "approved exact source-bound Native capsule".into(),
                rule_id: "e2e-review".into(),
                subject_digest: approval_subject,
                decided_unix_ms: now + 1,
            },
            now + 1,
        )
        .unwrap();
    control
        .create_source_snapshot(&SourceSnapshotRecord {
            id: "source-e2e".into(),
            tenant_id: "tenant-e2e".into(),
            repository_id: "repo-e2e".into(),
            commit_sha: exact_commit.clone(),
            tree_manifest_digest: manifest_digest.clone(),
            state: SourceSnapshotState::Building,
            created_unix_ms: now,
            verified_unix_ms: None,
        })
        .unwrap();
    control
        .mark_source_snapshot_ready("tenant-e2e", "source-e2e", &manifest_digest, now + 1)
        .unwrap();
    fs::write(source_repository.join("exact.txt"), b"substituted-commit\n").unwrap();
    git(&source_repository, &["add", "exact.txt"]);
    git(
        &source_repository,
        &[
            "-c",
            "user.name=Runtrue E2E",
            "-c",
            "user.email=e2e@runtrue.invalid",
            "commit",
            "--quiet",
            "-m",
            "substitution",
        ],
    );
    let changed_commit = git(&source_repository, &["rev-parse", "HEAD"]);
    let changed_manifest = git_repository
        .build_source_manifest(
            "repo-e2e",
            &changed_commit,
            SourceSnapshotLimits::default(),
            |_, _| Ok(()),
        )
        .unwrap();
    let changed_digest = changed_manifest.digest().unwrap();
    assert_ne!(changed_digest, manifest_digest);
    assert!(
        control
            .mark_source_snapshot_ready("tenant-e2e", "source-e2e", &changed_digest, now + 1)
            .is_err(),
        "a changed Git commit cannot substitute for the ready source binding"
    );
    control
        .create_run_idempotent(
            "run-e2e-create",
            &CreateRunRequest {
                id: "run-e2e".into(),
                repository_id: "repo-e2e".into(),
                capsule_id: "capsule-e2e".into(),
                priority: 0,
                remote: true,
                created_unix_ms: now + 2,
                jobs: vec![NewJob {
                    id: "job-e2e".into(),
                    job_key: "build".into(),
                    attempt: 1,
                    requirements: SchedulingRequirements {
                        os: OperatingSystem::Linux,
                        arch: Architecture::Amd64,
                        isolation: Isolation::Native,
                        cpu: 1,
                        memory_bytes: 1,
                        storage_bytes: 1,
                        region: None,
                        required_capabilities: BTreeSet::new(),
                        allowed_pools: BTreeSet::new(),
                    },
                }],
            },
        )
        .unwrap();
    control
        .bind_run_source_snapshot(
            "tenant-e2e",
            "run-e2e",
            "source-e2e",
            &capsule_digest,
            now + 3,
        )
        .unwrap();
    let initial_check = ScmCheckPublishTask {
        publication_id: "publication-e2e-queued".into(),
        tenant_id: "tenant-e2e".into(),
        repository_id: "repo-e2e".into(),
        installation_id: "installation-e2e".into(),
        installation_external_id: "1234".into(),
        run_id: "run-e2e".into(),
        commit_sha: exact_commit.clone(),
        owner: "acme".into(),
        repository: "exact".into(),
        external_repository_id: "5678".into(),
        logical_name: "job:job-e2e".into(),
        external_id: "runtrue:run-e2e:job:job-e2e".into(),
        check_name: "Runtrue / build".into(),
        status: "queued".into(),
        conclusion: None,
        title: "Runtrue workflow queued".into(),
        summary: "Run `run-e2e` is queued.".into(),
        render_markdown: false,
        actions: Vec::new(),
        trusted_base_workflow: true,
    };
    control
        .enqueue_task(&DurableTask {
            id: "task-e2e-check-queued".into(),
            kind: "scm.check.publish".into(),
            payload: serde_json::to_value(&initial_check).unwrap(),
            status: DurableTaskStatus::Pending,
            available_unix_ms: now + 3,
            attempts: 0,
            lease_owner: None,
            lease_expires_unix_ms: None,
            last_error: None,
            created_unix_ms: now + 3,
            completed_unix_ms: None,
        })
        .unwrap();
    assert_eq!(control.job("job-e2e").unwrap().status, JobState::Queued);

    let (control_listener, control_address) = listener().await;
    let control_tls = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(Certificate::from_pem(pki.ca_pem.clone()));
    let control_task = tokio::spawn(async move {
        Server::builder()
            .tls_config(control_tls)
            .unwrap()
            .add_service(service.clone().into_server())
            .add_service(service.into_v2_server())
            .serve_with_incoming(TcpListenerStream::new(control_listener))
            .await
            .unwrap();
    });
    let unauthenticated_channel =
        Endpoint::from_shared(format!("https://localhost:{}", control_address.port()))
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("localhost")
                    .ca_certificate(Certificate::from_pem(pki.ca_pem.clone())),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
    let unauthenticated = RunnerControlClient::new(unauthenticated_channel)
        .fetch_execution_capsule(v1::FetchExecutionCapsuleRequest {
            lease_id: "not-disclosed".into(),
            fencing_generation: 1,
            expected_digest: Some(
                v1::Digest::try_from(ContentDigest::sha256(b"not-disclosed")).unwrap(),
            ),
        })
        .await;
    assert!(
        unauthenticated.is_err(),
        "the control listener must reject clients without an enrolled certificate"
    );
    let ca_path = directory.path().join("ca.pem");
    let cert_path = directory.path().join("runner.pem");
    let key_path = directory.path().join("runner.key");
    private_write(&ca_path, pki.ca_pem.as_bytes());
    private_write(&cert_path, &enrolled.certificate_chain_pem);
    private_write(&key_path, runner_key.serialize_pem().as_bytes());
    let keyring = directory.path().join("capsule-keys");
    fs::create_dir(&keyring).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();
    private_write(
        &keyring.join("e2e.hex"),
        hex::encode(signing_key.verifying_key().to_bytes()).as_bytes(),
    );
    let trust = load_capsule_trust_store(&keyring).unwrap();
    let mut daemon_inventory = verified_inventory;
    daemon_inventory.profile.runner_id = enrolled.runner_id.clone();
    let authoritative_posture = ContentDigest::try_from(
        enrolled
            .authoritative_posture_digest
            .as_ref()
            .expect("enrollment must return its authoritative posture binding"),
    )
    .unwrap();
    apply_authoritative_posture(&mut daemon_inventory, &authoritative_posture).unwrap();
    let transport = EndpointSecurity {
        endpoint: format!("https://localhost:{}", control_address.port()),
        ca_certificate: Some(ca_path),
        client_certificate: Some(cert_path),
        client_private_key: Some(key_path),
        insecure_loopback: false,
    }
    .connect()
    .await
    .unwrap();
    let runner_id = enrolled.runner_id.clone();
    let runner_identity = Identity::from_pem(
        enrolled.certificate_chain_pem.clone(),
        runner_key.serialize_pem(),
    );
    let daemon_task = tokio::spawn(
        RunnerDaemon::new(
            transport,
            NativeJobExecutor::new(true),
            RunnerDaemonConfig {
                runner_id,
                inventory: daemon_inventory,
                trust_store: trust.store,
                allow_trusted_native: true,
                mode: RunMode::Daemon,
                max_capsule_bytes: 16 * 1024 * 1024,
                credential_store: None,
                admission_lock: None,
            },
            RunnerStateStore::open(directory.path().join("runner-state")).unwrap(),
            workspaces,
        )
        .run(),
    );
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let cataloged = rusqlite::Connection::open(&database)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM artifacts_catalog WHERE job_id = 'job-e2e'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
                == 1;
            if control.job("job-e2e").unwrap().status.is_terminal() && cataloged {
                break;
            }
            assert!(
                !daemon_task.is_finished(),
                "real runner daemon exited early"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "real runner daemon timed out with job {:?}",
            control.job("job-e2e").unwrap()
        )
    });
    let terminal_job = control.job("job-e2e").unwrap();
    if terminal_job.status != JobState::Succeeded {
        let diagnostic = rusqlite::Connection::open(&database).unwrap();
        let transfers: i64 = diagnostic
            .query_row(
                "SELECT COUNT(*) FROM runner_object_transfers WHERE ticket_kind = 'artifact'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let commits: i64 = diagnostic
            .query_row(
                "SELECT COUNT(*) FROM runner_data_commits WHERE kind = 'artifact'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        panic!("artifact daemon failed: job={terminal_job:?}, transfers={transfers}, commits={commits}");
    }
    let terminal_check_json: String = rusqlite::Connection::open(&database)
        .unwrap()
        .query_row(
            "SELECT payload_json FROM durable_tasks
             WHERE kind = 'scm.check.publish'
               AND json_extract(payload_json, '$.run_id') = 'run-e2e'
               AND json_extract(payload_json, '$.logical_name') = 'job-result:job-e2e'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let terminal_check: ScmCheckPublishTask = serde_json::from_str(&terminal_check_json).unwrap();
    assert_eq!(terminal_check.external_id, initial_check.external_id);
    assert_eq!(terminal_check.status, "completed");
    assert_eq!(terminal_check.conclusion.as_deref(), Some("success"));
    assert!(terminal_check.summary.contains("| **Run** | `run-e2e` |"));
    assert!(terminal_check
        .summary
        .contains("| **Job** | `build` · attempt 1 |"));
    assert!(terminal_check
        .summary
        .contains("| **Status** | **succeeded** |"));
    assert!(terminal_check.summary.contains("<strong>Logs</strong>"));
    assert!(
        terminal_check.summary.contains("checked out exact commit"),
        "terminal check summary did not retain runner output:\n{}",
        terminal_check.summary
    );
    assert!(terminal_check.render_markdown);

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if control
                .runner(&enrolled.runner_id)
                .unwrap()
                .runner
                .locality
                .contains(&manifest_digest)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("runner must advertise the verified source snapshot");
    let source_transfers_before: i64 = rusqlite::Connection::open(&database)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM runner_object_transfers WHERE ticket_kind = 'source'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    let cached_approval = ApprovalRequest::create(
        "approval-e2e-cached",
        ApprovalKind::PrivilegedExecution,
        ContentDigest::sha256(b"runner-e2e-approved-native-source"),
        90,
        now + 4,
        now + 60_000,
        ApprovalRule {
            id: "e2e-review-cached".into(),
            required_approvals: 1,
            eligible_approvers: BTreeSet::from(["reviewer-e2e".into()]),
            forbidden_approvers: BTreeSet::new(),
            one_shot: true,
        },
    )
    .unwrap();
    control
        .create_approval_request("repo-e2e", "capsule-e2e", &cached_approval)
        .unwrap();
    control
        .decide_approval(
            &cached_approval.id,
            ApprovalDecision {
                actor_id: "reviewer-e2e".into(),
                decision: Decision::Approve,
                reason: "approved cached exact source-bound Native capsule".into(),
                rule_id: "e2e-review-cached".into(),
                subject_digest: cached_approval.subject_digest,
                decided_unix_ms: now + 5,
            },
            now + 5,
        )
        .unwrap();
    control
        .create_run_idempotent(
            "run-e2e-cached-create",
            &CreateRunRequest {
                id: "run-e2e-cached".into(),
                repository_id: "repo-e2e".into(),
                capsule_id: "capsule-e2e".into(),
                priority: 0,
                remote: true,
                created_unix_ms: now + 6,
                jobs: vec![NewJob {
                    id: "job-e2e-cached".into(),
                    job_key: "build".into(),
                    attempt: 1,
                    requirements: SchedulingRequirements {
                        os: OperatingSystem::Linux,
                        arch: Architecture::Amd64,
                        isolation: Isolation::Native,
                        cpu: 1,
                        memory_bytes: 1,
                        storage_bytes: 1,
                        region: None,
                        required_capabilities: BTreeSet::new(),
                        allowed_pools: BTreeSet::new(),
                    },
                }],
            },
        )
        .unwrap();
    control
        .bind_run_source_snapshot(
            "tenant-e2e",
            "run-e2e-cached",
            "source-e2e",
            &capsule_digest,
            now + 7,
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let cached_job = control.job("job-e2e-cached").unwrap();
            if cached_job.status.is_terminal() {
                assert_eq!(cached_job.status, JobState::Succeeded);
                break;
            }
            assert!(
                !daemon_task.is_finished(),
                "real runner daemon exited early"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cached source run must complete");
    let source_transfers_after: i64 = rusqlite::Connection::open(&database)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM runner_object_transfers WHERE ticket_kind = 'source'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        source_transfers_after, source_transfers_before,
        "the warm checkout must retain ticket authorization without downloading source objects"
    );

    let database_check = rusqlite::Connection::open(&database).unwrap();
    let (lease_id, fencing_generation, installation_fencing_epoch, result_digest): (
        String,
        u64,
        u64,
        String,
    ) = database_check
        .query_row(
            "SELECT id, fencing_generation, installation_fencing_epoch,
                    terminal_result_digest
             FROM leases WHERE job_id = 'job-e2e'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let committed_ids = |kind: &str| -> Vec<String> {
        let mut statement = database_check
            .prepare(
                "SELECT object_id FROM job_result_objects
                 WHERE job_id = 'job-e2e' AND job_attempt = 1 AND kind = ?1
                 ORDER BY ordinal",
            )
            .unwrap();
        statement
            .query_map([kind], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    let artifact_ids = committed_ids("artifact");
    let cache_entry_ids = committed_ids("cache");
    let completed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let exact_completion = v1::CompleteLeaseRequest {
        lease_id,
        fencing_generation,
        installation_fencing_epoch,
        final_state: "succeeded".into(),
        exit_code: Some(0),
        error_code: String::new(),
        result_digest: Some(
            v1::Digest::try_from(ContentDigest::parse(result_digest).unwrap()).unwrap(),
        ),
        artifact_ids,
        cache_entry_ids,
        completed_at: Some(prost_types::Timestamp {
            seconds: i64::try_from(completed_at.as_secs()).unwrap(),
            nanos: i32::try_from(completed_at.subsec_nanos()).unwrap(),
        }),
        final_job_attempt: 1,
        expected_log_frames: 0,
    };
    let replay_channel = channel(
        control_address,
        ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(Certificate::from_pem(pki.ca_pem.clone()))
            .identity(runner_identity),
    )
    .await;
    let result_wire = exact_completion.result_digest.clone().unwrap();
    let mut committed_objects = exact_completion
        .artifact_ids
        .iter()
        .map(|artifact_id| {
            let name = database_check
                .query_row(
                    "SELECT output_name FROM runner_data_commits
                     WHERE kind = 'artifact' AND object_id = ?1",
                    [artifact_id],
                    |row| row.get(0),
                )
                .unwrap();
            v2::CommittedObject {
                kind: v2::CommittedObjectKind::Artifact as i32,
                object_id: artifact_id.clone(),
                declaration_name: Some(name),
                job_attempt: 1,
            }
        })
        .collect::<Vec<_>>();
    committed_objects.extend(
        exact_completion
            .cache_entry_ids
            .iter()
            .map(|cache_entry_id| v2::CommittedObject {
                kind: v2::CommittedObjectKind::Cache as i32,
                object_id: cache_entry_id.clone(),
                declaration_name: None,
                job_attempt: 1,
            }),
    );
    let exact_v2_completion = v2::CompleteLeaseRequest {
        lease_id: exact_completion.lease_id.clone(),
        fencing_generation: exact_completion.fencing_generation,
        installation_fencing_epoch: exact_completion.installation_fencing_epoch,
        final_state: v2::LeaseFinalState::Succeeded as i32,
        exit_code: exact_completion.exit_code,
        error_code: exact_completion.error_code.clone(),
        result_digest_algorithm: result_wire.algorithm,
        result_digest: result_wire.value,
        committed_objects,
        completed_at: exact_completion.completed_at,
        final_job_attempt: exact_completion.final_job_attempt,
        expected_log_frames: exact_completion.expected_log_frames,
        credential_taint: v2::CredentialTaintState::None as i32,
    };
    let mut object_replay_client = RunnerObjectTransferClient::new(replay_channel.clone());
    assert!(
        object_replay_client
            .complete_lease(exact_v2_completion.clone())
            .await
            .unwrap()
            .into_inner()
            .accepted,
        "the exact typed terminal completion must replay over protocol v2"
    );
    let mut wrong_name = exact_v2_completion.clone();
    wrong_name.committed_objects[0].declaration_name = Some("substituted-output".into());
    assert_eq!(
        object_replay_client
            .complete_lease(wrong_name)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition,
        "typed declaration-name substitution must fail with the uniform binding-mismatch response before terminal replay, without disclosing artifact existence"
    );
    let mut substituted = exact_v2_completion.clone();
    substituted.committed_objects[0].object_id = "artifact-substitution".into();
    assert_eq!(
        object_replay_client
            .complete_lease(substituted)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition,
        "a changed completion object must conflict without replacing durable bindings"
    );
    let mut stale_fence = exact_v2_completion.clone();
    stale_fence.fencing_generation += 1;
    assert_eq!(
        object_replay_client
            .complete_lease(stale_fence)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition,
        "a stale or invented lease fence must be rejected"
    );
    let mut stale_attempt = exact_v2_completion;
    stale_attempt.final_job_attempt += 1;
    assert_eq!(
        object_replay_client
            .complete_lease(stale_attempt)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition,
        "completion must remain bound to the exact durable job attempt"
    );

    let application = router(state.clone());
    let artifact_id = &exact_completion.artifact_ids[0];
    let metadata = application
        .clone()
        .oneshot(bootstrap_request(
            "GET",
            &format!("/api/v1/artifacts/{artifact_id}"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    assert_eq!(metadata.headers()["cache-control"], "no-store");
    let metadata: serde_json::Value =
        serde_json::from_slice(&response_bytes(metadata).await).unwrap();
    assert_eq!(metadata["artifact_id"], artifact_id.as_str());
    assert_eq!(metadata["job_id"], "job-e2e");
    assert_eq!(metadata["output_name"], "exact-source");

    let issued = application
        .clone()
        .oneshot(bootstrap_request(
            "POST",
            &format!("/api/v1/artifacts/{artifact_id}/download-tickets"),
            serde_json::to_vec(&serde_json::json!({"ttl_seconds": 60})).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    let issued: serde_json::Value = serde_json::from_slice(&response_bytes(issued).await).unwrap();
    let download_token = issued["token"].as_str().unwrap();
    let download_uri = format!("/api/v1/artifact-downloads/{download_token}");
    let downloaded = application
        .clone()
        .oneshot(bootstrap_request("GET", &download_uri, Body::empty()))
        .await
        .unwrap();
    assert_eq!(downloaded.status(), StatusCode::OK);
    assert_eq!(downloaded.headers()["cache-control"], "no-store");
    assert_eq!(downloaded.headers()["x-content-type-options"], "nosniff");
    assert!(downloaded.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .starts_with("attachment;"));
    assert_eq!(response_bytes(downloaded).await, b"exact-commit\n");
    let replayed_download = application
        .oneshot(bootstrap_request("GET", &download_uri, Body::empty()))
        .await
        .unwrap();
    assert_eq!(replayed_download.status(), StatusCode::NOT_FOUND);

    let attacker_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-attacker".into(),
            tenant_id: "tenant-attacker".into(),
            name: "attacker".into(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: attacker_now,
        })
        .unwrap();
    let attacker_token = control
        .create_enrollment_token("pool-attacker", attacker_now, attacker_now + 60_000)
        .unwrap();
    let attacker_workspace_root = directory.path().join("attacker-workspaces");
    let attacker_workspaces = WorkspaceManager::open(&attacker_workspace_root).unwrap();
    let mut attacker_inventory = e2e_inventory();
    attacker_inventory.profile.runner_id = "runner-attacker".to_owned();
    attacker_inventory.wire.hostname = "runner-attacker.local".to_owned();
    let attacker_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut attacker_request_params = CertificateParams::default();
    attacker_request_params.distinguished_name = DistinguishedName::new();
    let attacker_csr = attacker_request_params
        .serialize_request(&attacker_key)
        .unwrap();
    let attacker_enrollment = enrollment_client
        .enroll(v1::EnrollRequest {
            enrollment_token: attacker_token.token.expose().to_owned(),
            certificate_signing_request: attacker_csr.der().to_vec(),
            inventory: Some(attacker_inventory.wire.clone()),
            attestation: None,
            protocol_min: runtrue_protocol::PROTOCOL_MIN,
            protocol_max: runtrue_protocol::PROTOCOL_MAX,
            ephemeral: false,
        })
        .await
        .unwrap()
        .into_inner();
    let attacker_ca_path = directory.path().join("attacker-ca.pem");
    let attacker_cert_path = directory.path().join("attacker-runner.pem");
    let attacker_key_path = directory.path().join("attacker-runner.key");
    private_write(&attacker_ca_path, pki.ca_pem.as_bytes());
    private_write(
        &attacker_cert_path,
        &attacker_enrollment.certificate_chain_pem,
    );
    private_write(&attacker_key_path, attacker_key.serialize_pem().as_bytes());
    attacker_inventory.profile.runner_id = attacker_enrollment.runner_id.clone();
    let attacker_posture = ContentDigest::try_from(
        attacker_enrollment
            .authoritative_posture_digest
            .as_ref()
            .expect("attacker enrollment must return authoritative posture"),
    )
    .unwrap();
    apply_authoritative_posture(&mut attacker_inventory, &attacker_posture).unwrap();
    let attacker_transport = EndpointSecurity {
        endpoint: format!("https://localhost:{}", control_address.port()),
        ca_certificate: Some(attacker_ca_path),
        client_certificate: Some(attacker_cert_path),
        client_private_key: Some(attacker_key_path),
        insecure_loopback: false,
    }
    .connect()
    .await
    .unwrap();
    let attacker_runner_id = attacker_enrollment.runner_id.clone();
    let attacker_trust = load_capsule_trust_store(&keyring).unwrap();
    let attacker_daemon = tokio::spawn(
        RunnerDaemon::new(
            attacker_transport,
            NativeJobExecutor::new(true),
            RunnerDaemonConfig {
                runner_id: attacker_runner_id.clone(),
                inventory: attacker_inventory,
                trust_store: attacker_trust.store,
                allow_trusted_native: true,
                mode: RunMode::Daemon,
                max_capsule_bytes: 16 * 1024 * 1024,
                credential_store: None,
                admission_lock: None,
            },
            RunnerStateStore::open(directory.path().join("attacker-runner-state")).unwrap(),
            attacker_workspaces,
        )
        .run(),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if control.runner(&attacker_runner_id).unwrap().runner.status == RunnerStatus::Online {
                break;
            }
            assert!(
                !attacker_daemon.is_finished(),
                "attacker daemon exited early"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("attacker runner must establish a live authenticated session");
    let source_ticket_id: String = database_check
        .query_row(
            "SELECT id FROM runner_source_tickets WHERE execution_lease_id = ?1",
            [&exact_completion.lease_id],
            |row| row.get(0),
        )
        .unwrap();
    let source_wire = v1::Digest::try_from(&manifest_digest).unwrap();
    let foreign_request = v2::ObjectDownloadRequest {
        ticket_id: source_ticket_id,
        execution_lease_id: exact_completion.lease_id.clone(),
        fencing_generation: exact_completion.fencing_generation,
        job_id: "build".into(),
        job_attempt: 1,
        digest_algorithm: source_wire.algorithm.clone(),
        digest: source_wire.value.clone(),
    };
    let attacker_channel = channel(
        control_address,
        ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(Certificate::from_pem(pki.ca_pem.clone()))
            .identity(Identity::from_pem(
                attacker_enrollment.certificate_chain_pem,
                attacker_key.serialize_pem(),
            )),
    )
    .await;
    let mut attacker_client = RunnerObjectTransferClient::new(attacker_channel);
    let valid_foreign_error = attacker_client
        .download_object(foreign_request.clone())
        .await
        .unwrap_err();
    let mut guessed_request = foreign_request;
    guessed_request.ticket_id = "guessed-source-ticket".into();
    let guessed_error = attacker_client
        .download_object(guessed_request)
        .await
        .unwrap_err();
    assert_eq!(valid_foreign_error.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        guessed_error.code(),
        valid_foreign_error.code(),
        "cross-tenant replay must be rejected before ticket or object existence is disclosed"
    );

    attacker_daemon.abort();
    daemon_task.abort();
    enroll_task.abort();
    control_task.abort();
    let _ = attacker_daemon.await;
    let _ = daemon_task.await;
    let _ = enroll_task.await;
    let _ = control_task.await;
    let reopened = ControlPlane::open(&database, "runner-e2e", now + 120_000).unwrap();
    assert_eq!(reopened.job("job-e2e").unwrap().status, JobState::Succeeded);
    let cataloged_artifact = reopened
        .artifact_for_tenant("tenant-e2e", &exact_completion.artifact_ids[0])
        .unwrap();
    assert_eq!(cataloged_artifact.job_id, "job-e2e");
    assert_eq!(cataloged_artifact.job_attempt, 1);
    assert_eq!(cataloged_artifact.output_name, "exact-source");
    assert_eq!(
        cataloged_artifact.artifact_id,
        exact_completion.artifact_ids[0]
    );
    assert!(
        reopened
            .artifact_for_tenant("tenant-attacker", &cataloged_artifact.artifact_id)
            .is_err(),
        "a foreign tenant must not discover a durable artifact catalog record"
    );
    let bound_artifacts: i64 = database_check
        .query_row(
            "SELECT COUNT(*) FROM job_result_objects jro
             JOIN runner_data_commits rdc ON rdc.object_id = jro.object_id AND rdc.kind = jro.kind
             WHERE jro.job_id = 'job-e2e' AND jro.kind = 'artifact'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        bound_artifacts, 1,
        "completion must durably bind the exact committed artifact ID"
    );
    let bound_caches: i64 = database_check
        .query_row(
            "SELECT COUNT(*) FROM job_result_objects jro
             JOIN runner_data_commits rdc ON rdc.object_id = jro.object_id AND rdc.kind = jro.kind
             WHERE jro.job_id = 'job-e2e' AND jro.kind = 'cache'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        bound_caches, 1,
        "completion must durably bind the exact committed cache ID"
    );
    let reopened_cas = FsCas::open(data_root.join("cas"), CasLimits::default()).unwrap();
    assert_eq!(
        reopened_cas.read_blob(&manifest_digest).unwrap(),
        manifest_bytes
    );
    assert_eq!(
        reopened_cas.read_blob(&source_digest).unwrap(),
        b"exact-commit\n"
    );
}
