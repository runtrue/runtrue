use super::*;
use crate::runner_broker::ENVELOPE_DELIVERY_KIND;
use crate::runner_certificates::RunnerCertificateAuthority;
use rand_core::OsRng;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519};
use runtrue_artifacts::{ArtifactClassification, ArtifactTicketRequest};
use runtrue_attest::CapsuleSigningKey;
use runtrue_cache::{
    CacheKeyMaterial, CachePlatform, CacheProducer, PromotionEvidence, TrustDomain,
};
use runtrue_control_plane::{
    CacheTrustGenerationRecord, CapsuleApiMetadata, ControlPlane, ControlPlaneError,
    CreateRunRequest, CredentialTaintState, NewJob, RepositoryRecord, RunnerPoolRecord,
    RunnerPoolStatus, SecretMetadataReference, SignedCapsuleRecord, StorageReservationState,
    TenantStorageReservation,
};
use runtrue_git::{GitTreeEntryKind, GitTreeManifest};
use runtrue_lifecycle::JobState;
use runtrue_model::{ContentDigest, SecretReference};
use runtrue_oidc::{OidcIssuer, OidcSigningKey};
use runtrue_policy::{ApprovalDecision, ApprovalKind, ApprovalRequest, ApprovalRule, Decision};
use runtrue_protocol::{
    v1::{self, control_message, runner_message},
    v2, PROTOCOL_MAX, PROTOCOL_MIN,
};
use runtrue_scheduler::{Lease, LeaseState, RunnerRecord, RunnerStatus, SchedulingRequirements};
use runtrue_scm::{GitHubPermission, GitHubPermissionLevel};
use runtrue_secrets::{MasterKey, SecretPlaintext};
use runtrue_storage::{CasLimits, FsCas};
use runtrue_workflow_ir::{
    Access, ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
    OperatingSystem, ParityGrade, PermissionSet, PlannedJob, PlannedStep, RunnerRequirements,
    StepAction, StepCapabilitySet, Trust, WorkflowIdentity, CAPSULE_SCHEMA_VERSION,
    ENGINE_COMPATIBILITY_VERSION,
};
use rustls_pki_types::{pem::PemObject as _, CertificateDer};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_stream::{wrappers::ReceiverStream, StreamExt as _};
use tonic::{Request, Status};

use super::data_plane::uploads::RunnerUploadStaging;

struct Fixture {
    control: Arc<ControlPlane>,
    service: RunnerControlService,
    lease: Lease,
    capsule: SignedCapsuleRecord,
    posture_digest: ContentDigest,
}

#[test]
fn scm_provider_permissions_preserve_status_and_review_scope_exactly() {
    let permissions =
        super::control::github_provider_permissions(&runtrue_workflow_ir::ScmPermissions {
            contents: Access::Read,
            issues: Access::Deny,
            pull_requests: Access::Write,
            checks: Access::Write,
            statuses: Access::Write,
        });
    assert_eq!(
        permissions,
        BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::Contents, GitHubPermissionLevel::Read),
            (GitHubPermission::PullRequests, GitHubPermissionLevel::Write),
            (GitHubPermission::Checks, GitHubPermissionLevel::Write),
            (GitHubPermission::Statuses, GitHubPermissionLevel::Write),
        ])
    );
    assert!(!permissions.contains_key(&GitHubPermission::Issues));
}

fn certificate_authority() -> Arc<RunnerCertificateAuthority> {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.not_before = time::OffsetDateTime::from_unix_timestamp(1).unwrap();
    params.not_after = time::OffsetDateTime::from_unix_timestamp(4_102_444_800).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    Arc::new(
        RunnerCertificateAuthority::load(
            certificate.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            Duration::from_secs(60 * 60),
        )
        .unwrap(),
    )
}

fn certificate_request() -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serialize_request(&key).unwrap().der().to_vec()
}

#[test]
fn runner_data_root_is_private_and_rejects_symlink_ancestors() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("data");
    let data =
        RunnerDataPlane::open(&root, Arc::new(CapsuleSigningKey::from_seed([91; 32]))).unwrap();
    assert_eq!(data.root, root.canonicalize().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let linked = directory.path().join("linked");
        symlink(&root, &linked).unwrap();
        assert!(RunnerDataPlane::open(
            linked.join("child"),
            Arc::new(CapsuleSigningKey::from_seed([92; 32])),
        )
        .is_err());
    }
}

#[test]
fn typed_completion_adapter_rejects_unknown_kinds_names_and_attempts() {
    let fixture = fixture();
    let valid = v2::CompleteLeaseRequest {
        lease_id: fixture.lease.id.clone(),
        fencing_generation: fixture.lease.fencing_generation,
        installation_fencing_epoch: fixture.lease.installation_fencing_epoch,
        final_state: v2::LeaseFinalState::Failed as i32,
        exit_code: None,
        error_code: "failed".to_owned(),
        result_digest_algorithm: "sha256".to_owned(),
        result_digest: vec![7; 32],
        committed_objects: Vec::new(),
        completed_at: Some(proto_timestamp(now_unix_ms().unwrap())),
        final_job_attempt: 0,
        expected_log_frames: 0,
        credential_taint: v2::CredentialTaintState::CredentialReleased as i32,
    };
    let (legacy, claims, credential_taint) =
        fixture.service.adapt_v2_completion(valid.clone()).unwrap();
    assert_eq!(legacy.final_state, "failed");
    assert!(claims.is_empty());
    assert_eq!(credential_taint, CredentialTaintState::CredentialReleased);

    let mut malformed = valid;
    malformed.final_job_attempt = 1;
    malformed.committed_objects.push(v2::CommittedObject {
        kind: v2::CommittedObjectKind::Cache as i32,
        object_id: "cache-1".to_owned(),
        declaration_name: Some("must-be-absent".to_owned()),
        job_attempt: 1,
    });
    assert_eq!(
        fixture
            .service
            .adapt_v2_completion(malformed.clone())
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    malformed.committed_objects[0].declaration_name = None;
    malformed.committed_objects[0].job_attempt = 2;
    assert_eq!(
        fixture
            .service
            .adapt_v2_completion(malformed.clone())
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    malformed.committed_objects[0].job_attempt = 1;
    malformed.committed_objects[0].kind = 99;
    assert_eq!(
        fixture
            .service
            .adapt_v2_completion(malformed)
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
}

#[tokio::test]
async fn slow_trickle_deadline_expires_and_private_staging_is_removed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(".upload-expiry-test");
    std::fs::write(&path, b"private partial bytes").unwrap();
    let staging = RunnerUploadStaging(path.clone());
    let deadline = Instant::now() + Duration::from_millis(10);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        runner_upload_wait_until(deadline).unwrap_err().code(),
        tonic::Code::DeadlineExceeded
    );
    drop(staging);
    assert!(!path.exists(), "expired upload staging must be removed");
}

#[test]
fn artifact_quota_ticket_binding_recovers_restart_and_rejects_orphans() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("control.sqlite");
    let control = ControlPlane::open(&database, "ticket-recovery", 1_000).unwrap();
    control
        .create_repository(&RepositoryRecord {
            id: "repo-ticket".to_owned(),
            tenant_id: "tenant-ticket".to_owned(),
            owner: "owner".to_owned(),
            name: "ticket".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "private".to_owned(),
            created_unix_ms: 1_000,
        })
        .unwrap();
    let data = RunnerDataPlane::open(
        directory.path().join("data"),
        Arc::new(CapsuleSigningKey::from_seed([93; 32])),
    )
    .unwrap();
    let proposed = TenantStorageReservation {
        id: "artifact-reservation-restart".to_owned(),
        tenant_id: "tenant-ticket".to_owned(),
        ticket_kind: "artifact".to_owned(),
        object_digest: Some(ContentDigest::sha256(b"expected-content")),
        reserved_bytes: 64,
        reserved_objects: 1,
        state: StorageReservationState::Reserved,
        created_unix_ms: 1_001,
        expires_unix_ms: 301_001,
        completed_unix_ms: None,
    };
    let reservation = reserve_or_recover_storage(&control, proposed.clone(), 1_001).unwrap();
    let request = ArtifactTicketRequest {
        tenant_id: reservation.tenant_id.clone(),
        repository_id: "repo-ticket".to_owned(),
        run_id: "run-ticket".to_owned(),
        job_id: "job-ticket".to_owned(),
        job_attempt: 1,
        step_id: "package".to_owned(),
        lease_id: "lease-ticket".to_owned(),
        fencing_generation: 1,
        name: "package".to_owned(),
        classification: ArtifactClassification::UntrustedBuild,
        max_bytes: 64,
        expected_content_digest: proposed.object_digest.clone(),
        issued_at_unix_seconds: reservation.created_unix_ms / 1_000,
        expires_at_unix_seconds: reservation.expires_unix_ms / 1_000,
    };
    let issued =
        issue_or_recover_artifact_ticket(&control, &data.artifacts, &reservation, &request, 1_001)
            .unwrap();
    drop(data);
    drop(control);

    let control = ControlPlane::open(&database, "ticket-recovery", 2_000).unwrap();
    let data = RunnerDataPlane::open(
        directory.path().join("data"),
        Arc::new(CapsuleSigningKey::from_seed([93; 32])),
    )
    .unwrap();
    let mut retried_proposal = proposed;
    retried_proposal.created_unix_ms = 2_000;
    retried_proposal.expires_unix_ms = 302_000;
    let recovered_reservation =
        reserve_or_recover_storage(&control, retried_proposal, 2_000).unwrap();
    let recovered_request = ArtifactTicketRequest {
        issued_at_unix_seconds: recovered_reservation.created_unix_ms / 1_000,
        expires_at_unix_seconds: recovered_reservation.expires_unix_ms / 1_000,
        ..request.clone()
    };
    let recovered = issue_or_recover_artifact_ticket(
        &control,
        &data.artifacts,
        &recovered_reservation,
        &recovered_request,
        2_000,
    )
    .unwrap();
    assert_eq!(recovered.ticket_id, issued.ticket_id);
    let mut substitution = recovered_request;
    substitution.name = "different-output".to_owned();
    assert!(issue_or_recover_artifact_ticket(
        &control,
        &data.artifacts,
        &recovered_reservation,
        &substitution,
        2_000,
    )
    .is_err());

    let orphan_reservation = TenantStorageReservation {
        id: "artifact-reservation-orphan".to_owned(),
        created_unix_ms: 2_001,
        expires_unix_ms: 302_001,
        ..recovered_reservation
    };
    control
        .reserve_tenant_storage(&orphan_reservation, 2_001)
        .unwrap();
    let orphan = data
        .artifacts
        .issue_ticket(ArtifactTicketRequest {
            issued_at_unix_seconds: 2,
            expires_at_unix_seconds: 302,
            ..request
        })
        .unwrap();
    assert!(matches!(
        control.commit_tenant_storage_ticket(
            "tenant-ticket",
            orphan.ticket_id.as_str(),
            ContentDigest::sha256(b"orphan-record").as_str(),
            10,
            1,
            2_002,
        ),
        Err(ControlPlaneError::NotFound { .. })
    ));
}

#[test]
fn cache_promotion_worker_requires_exact_evidence_and_replays_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("control.sqlite");
    let control = ControlPlane::open(&database, "installation", 1_000).unwrap();
    control
        .create_repository(&RepositoryRecord {
            id: "repo-cache".to_owned(),
            tenant_id: "tenant-cache".to_owned(),
            owner: "owner".to_owned(),
            name: "cache".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "private".to_owned(),
            created_unix_ms: 1_000,
        })
        .unwrap();
    let data = RunnerDataPlane::open(
        directory.path().join("data"),
        Arc::new(CapsuleSigningKey::from_seed([91; 32])),
    )
    .unwrap();
    let source_path = directory.path().join("source");
    std::fs::create_dir(&source_path).unwrap();
    std::fs::write(source_path.join("output"), b"verified immutable bytes").unwrap();
    let material = CacheKeyMaterial {
        tenant_id: "tenant-cache".to_owned(),
        repository_id: "repo-cache".to_owned(),
        purpose: "build.output".to_owned(),
        platform: CachePlatform {
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
        },
        toolchain: Some(ContentDigest::sha256(b"toolchain")),
        definition: ContentDigest::sha256(b"definition"),
        declared_inputs: ContentDigest::sha256(b"inputs"),
        policy_epoch: 1,
        user_suffix: None,
    };
    let source_trust = TrustDomain::PullRequestQuarantine {
        installation_id: "installation".to_owned(),
        tenant_id: "tenant-cache".to_owned(),
        repository_id: "repo-cache".to_owned(),
        change_id: "pr-17".to_owned(),
    };
    let source_identity = material.with_trust_domain(source_trust.clone());
    let source = data
        .cache
        .commit_tree(
            &source_trust,
            source_identity,
            &source_path,
            None,
            7,
            CacheProducer {
                capsule_digest: ContentDigest::sha256(b"capsule"),
                job_id: "job".to_owned(),
                step_id: "step".to_owned(),
                lease_id: "lease".to_owned(),
            },
        )
        .unwrap();
    let source_id = source.immutable_id().unwrap();
    control
        .record_cache_trust_generation(
            &CacheTrustGenerationRecord {
                cache_entry_id: source_id.to_string(),
                tenant_id: "tenant-cache".to_owned(),
                repository_id: "repo-cache".to_owned(),
                identity_digest: source.head.identity_digest.clone(),
                key_material_digest: material.digest(data.cache.limits()).unwrap(),
                key_material: serde_json::to_value(&material).unwrap(),
                trust_domain: serde_json::to_value(&source_trust).unwrap(),
                generation: source.head.generation,
                manifest_digest: source.head.manifest_digest.clone(),
                tree_manifest_digest: source.manifest.tree.manifest_digest.clone(),
                fencing_generation: source.head.fencing_generation,
                source_cache_entry_id: None,
                promotion_evidence_digest: None,
                created_unix_ms: 1_001,
            },
            None,
        )
        .unwrap();
    let target_trust = TrustDomain::RepositoryMainVerified {
        installation_id: "installation".to_owned(),
        tenant_id: "tenant-cache".to_owned(),
        repository_id: "repo-cache".to_owned(),
    };
    let evidence = PromotionEvidence {
        kind: runtrue_cache::PromotionKind::VerifiedAttestation,
        evidence_digest: ContentDigest::sha256(b"scan-and-test-evidence"),
        approval_id: None,
    };
    assert_eq!(
        data.cas
            .put_bytes(b"scan-and-test-evidence")
            .unwrap()
            .digest,
        evidence.evidence_digest
    );
    let evidence_value = serde_json::to_value(&evidence).unwrap();
    let target_identity = material.with_trust_domain(target_trust.clone());
    let mut promotion = runtrue_control_plane::CachePromotionRecord {
        id: "promotion-cache".to_owned(),
        subject_digest: ContentDigest::sha256(b"pending"),
        tenant_id: "tenant-cache".to_owned(),
        repository_id: "repo-cache".to_owned(),
        source_cache_entry_id: source_id.to_string(),
        target_identity_digest: target_identity.digest(data.cache.limits()).unwrap(),
        target_trust_domain: serde_json::to_value(target_trust).unwrap(),
        expected_target_cache_entry_id: None,
        evidence_digest: ContentDigest::sha256(serde_json::to_vec(&evidence).unwrap()),
        evidence: evidence_value,
        state: runtrue_control_plane::CachePromotionState::Pending,
        promoted_cache_entry_id: None,
        created_unix_ms: 1_002,
        completed_unix_ms: None,
        last_error: None,
    };
    promotion.subject_digest =
        runtrue_control_plane::cache_promotion_subject_digest(&promotion).unwrap();
    control
        .create_cache_promotion_idempotent(&promotion)
        .unwrap();
    let mut changed_evidence = promotion.clone();
    changed_evidence.id = "promotion-cache-changed-evidence".to_owned();
    changed_evidence.evidence_digest = ContentDigest::sha256(b"substituted evidence");
    changed_evidence.subject_digest =
        runtrue_control_plane::cache_promotion_subject_digest(&changed_evidence).unwrap();
    control
        .create_cache_promotion_idempotent(&changed_evidence)
        .unwrap();
    assert!(data
        .execute_cache_promotion(&control, "tenant-cache", &changed_evidence.id, 1_003,)
        .is_err());
    // Simulate a crash after the immutable store effect and before the
    // SQLite journal result. The worker must recognize and reconcile the
    // exact effect instead of attempting another promotion.
    let promoted_effect = data
        .cache
        .promote(
            &material.with_trust_domain(source_trust.clone()),
            target_identity,
            evidence,
            None,
            1,
        )
        .unwrap();
    let promoted = promoted_effect.immutable_id().unwrap();
    assert_eq!(
        data.execute_cache_promotion(&control, "tenant-cache", &promotion.id, 1_003)
            .unwrap(),
        promoted
    );
    drop(data);
    drop(control);
    let control = ControlPlane::open(&database, "installation", 1_004).unwrap();
    let data = RunnerDataPlane::open(
        directory.path().join("data"),
        Arc::new(CapsuleSigningKey::from_seed([91; 32])),
    )
    .unwrap();
    assert_eq!(
        data.execute_cache_promotion(&control, "tenant-cache", &promotion.id, 1_004)
            .unwrap(),
        promoted
    );
    let completed = control
        .cache_promotion("tenant-cache", &promotion.id)
        .unwrap();
    assert_eq!(
        completed.promoted_cache_entry_id,
        Some(promoted.to_string())
    );
    assert!(matches!(
        control.cache_promotion("other-tenant", &promotion.id),
        Err(ControlPlaneError::NotFound { .. })
    ));
    assert_eq!(
        data.cache
            .inspect(&material.with_trust_domain(source_trust))
            .unwrap(),
        Some(source),
        "promotion must never mutate the source generation",
    );
}

fn execution_capsule() -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "runner-service-test".to_owned(),
        workflow: WorkflowIdentity {
            name: "runner service".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/test.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "a".repeat(40),
            source_tree_digest: None,
            base_commit: None,
            source_trust: runtrue_workflow_ir::SourceTrust::Trusted,
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            policy_version_ids: Vec::new(),
        },
        variables: BTreeMap::new(),
        permissions: PermissionSet::default(),
        jobs: vec![PlannedJob {
            id: "build".to_owned(),
            base_id: "build".to_owned(),
            name: "Build".to_owned(),
            needs: Vec::new(),
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::TrustedOnly,
            environment: None,
            runner: RunnerRequirements {
                image: None,
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Native,
                cpu: 1,
                memory_bytes: 1024,
                storage_bytes: Some(1024),
                region: None,
                capabilities: Vec::new(),
            },
            permissions: PermissionSet::default(),
            timeout_ms: 60_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: Vec::new(),
            finalizers: Vec::new(),
            finalizer_timeout_ms: 120_000,
            value_outputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }],
        dynamic_jobs: Vec::new(),
        approval: ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::AExact,
    }
}

fn broker_execution_capsule() -> ExecutionCapsule {
    let mut capsule = execution_capsule();
    capsule.approval.privileged_execution = true;
    let job = capsule.jobs.first_mut().expect("build job");
    job.steps.push(PlannedStep {
        id: "publish".to_owned(),
        name: "Publish".to_owned(),
        condition: None,
        action: StepAction::Command {
            program: "true".to_owned(),
            args: Vec::new(),
        },
        inputs: BTreeMap::new(),
        environment: BTreeMap::new(),
        capabilities: StepCapabilitySet {
            secrets: vec![SecretReference {
                metadata_id: "secret-1".to_owned(),
                name: "TOKEN".to_owned(),
                purpose: Some("publish".to_owned()),
            }],
            oidc_audiences: vec!["https://registry.example".to_owned()],
            ..StepCapabilitySet::default()
        },
        cache: None,
        timeout_ms: None,
        continue_on_error: false,
        outputs: BTreeMap::new(),
        working_directory: None,
    });
    capsule
}

fn broker_fixture() -> Fixture {
    let master_key = Arc::new(MasterKey::from_bytes([31; 32]));
    let oidc = Arc::new(
        OidcIssuer::new(
            "https://issuer.example".to_owned(),
            OidcSigningKey::from_seed([41; 32]),
        )
        .expect("OIDC issuer"),
    );
    fixture_with_capsule(broker_execution_capsule(), Some((master_key, oidc)))
}

fn runner_record() -> RunnerRecord {
    RunnerRecord {
        id: "runner-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        pool_id: "pool-1".to_owned(),
        ephemeral: false,
        retired: false,
        os: OperatingSystem::Linux,
        arch: Architecture::Amd64,
        isolation_backends: BTreeSet::from([Isolation::Native]),
        logical_cpus: 2,
        memory_bytes: 4096,
        storage_bytes: 4096,
        region: None,
        verified_capabilities: BTreeSet::new(),
        self_reported_capabilities: BTreeSet::new(),
        status: RunnerStatus::Online,
        active_jobs: 0,
        used_cpus: 0,
        used_memory_bytes: 0,
        used_storage_bytes: 0,
        locality: BTreeSet::new(),
        last_heartbeat_unix_ms: 1,
    }
}

fn fixture() -> Fixture {
    fixture_with_capsule(execution_capsule(), None)
}

fn fixture_with_capsule(
    capsule_value: ExecutionCapsule,
    broker_security: Option<(Arc<MasterKey>, Arc<OidcIssuer>)>,
) -> Fixture {
    let now = now_unix_ms().expect("time");
    let control = Arc::new(ControlPlane::open_in_memory("runner-service", now).expect("open"));
    control
        .create_repository(&RepositoryRecord {
            id: "repo-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            owner: "acme".to_owned(),
            name: "project".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "private".to_owned(),
            created_unix_ms: now,
        })
        .expect("repository");
    let signing_key = CapsuleSigningKey::from_seed([7; 32]);
    let signature = signing_key.sign_capsule(&capsule_value).expect("sign");
    let capsule = SignedCapsuleRecord {
        id: "capsule-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        digest: signature.capsule_digest.clone(),
        canonical_capsule: capsule_value.canonical_bytes().expect("canonical capsule"),
        signature,
        created_unix_ms: now,
    };
    let approval_subject = ContentDigest::sha256(b"runner-service-approval-subject");
    let mut approvals = Vec::new();
    for kind in [
        capsule_value
            .approval
            .workflow_definition
            .then_some(ApprovalKind::WorkflowDefinition),
        capsule_value
            .approval
            .privileged_execution
            .then_some(ApprovalKind::PrivilegedExecution),
    ]
    .into_iter()
    .flatten()
    {
        approvals.push(
            ApprovalRequest::create(
                format!("approval-{kind:?}"),
                kind,
                approval_subject.clone(),
                90,
                now,
                now + 60_000,
                ApprovalRule {
                    id: "runner-service-review".to_owned(),
                    required_approvals: 1,
                    eligible_approvers: BTreeSet::from(["reviewer".to_owned()]),
                    forbidden_approvers: BTreeSet::new(),
                    one_shot: true,
                },
            )
            .expect("approval"),
        );
    }
    control
        .store_compiled_capsule_idempotent(
            "runner-service-capsule",
            &capsule,
            &signing_key.verifying_key(),
            &CapsuleApiMetadata {
                capsule_id: capsule.id.clone(),
                approval_subject_digest: approval_subject.clone(),
                risk_score: 90,
            },
            &approvals,
        )
        .expect("store capsule");
    for approval in &approvals {
        control
            .decide_approval(
                &approval.id,
                ApprovalDecision {
                    actor_id: "reviewer".to_owned(),
                    decision: Decision::Approve,
                    reason: "reviewed exact broker subject".to_owned(),
                    rule_id: "runner-service-review".to_owned(),
                    subject_digest: approval_subject.clone(),
                    decided_unix_ms: now,
                },
                now,
            )
            .expect("approve");
    }
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            name: "native".to_owned(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: now,
        })
        .expect("pool");
    let runner = runner_record();
    let claimed_posture = ContentDigest::sha256(b"ignored runner posture claim");
    let binding_inventory = hello(&claimed_posture, "enrollment")
        .inventory
        .expect("inventory");
    let inventory_digest =
        validate_inventory(&runner, &binding_inventory, 1).expect("inventory binding");
    let posture_digest = control
        .register_runner_with_inventory(&runner, &inventory_digest, now)
        .expect("runner");
    if let Some((master_key, _)) = &broker_security {
        control
            .create_secret_idempotent(
                "runner-service-secret",
                &SecretMetadataReference {
                    id: "secret-1".to_owned(),
                    tenant_id: "tenant-1".to_owned(),
                    scope: "repository:repo-1".to_owned(),
                    name: "TOKEN".to_owned(),
                    provider: "built-in".to_owned(),
                    provider_reference: None,
                    secret_type: "opaque".to_owned(),
                    status: "active".to_owned(),
                    current_version: Some(1),
                    created_unix_ms: now,
                    updated_unix_ms: now,
                },
                Some(&SecretPlaintext::new(b"broker-secret-value".to_vec())),
                master_key,
            )
            .expect("secret");
    }
    control
        .create_run_idempotent(
            "runner-service-run",
            &CreateRunRequest {
                id: "run-1".to_owned(),
                repository_id: "repo-1".to_owned(),
                capsule_id: "capsule-1".to_owned(),
                priority: 0,
                remote: true,
                created_unix_ms: now,
                jobs: vec![NewJob {
                    id: "job-db-1".to_owned(),
                    job_key: "build".to_owned(),
                    attempt: 1,
                    requirements: SchedulingRequirements {
                        os: OperatingSystem::Linux,
                        arch: Architecture::Amd64,
                        isolation: Isolation::Native,
                        cpu: 1,
                        memory_bytes: 1024,
                        storage_bytes: 1024,
                        region: None,
                        required_capabilities: BTreeSet::new(),
                        allowed_pools: BTreeSet::new(),
                    },
                }],
            },
        )
        .expect("run");
    let lease = control
        .offer_next_lease_for_runner("runner-1", now)
        .expect("lease");
    let lease = lease.expect("matching queued lease");
    let config = RunnerControlConfig {
        heartbeat_interval: Duration::from_millis(100),
        heartbeat_timeout: Duration::from_secs(5),
        lease_extension: Duration::from_secs(60),
        drain_grace_period: Duration::from_secs(1),
        stream_send_timeout: Duration::from_secs(1),
        certificate_overlap: Duration::from_secs(1),
        certificate_rotation_notice: Duration::from_secs(2),
        protocol_minimum: PROTOCOL_MIN,
    };
    let service = match broker_security {
        Some((master_key, oidc)) => RunnerControlService::with_optional_security(
            Arc::clone(&control),
            None,
            Some(master_key),
            Some(oidc),
            None,
            config,
        ),
        None => RunnerControlService::with_test_config(Arc::clone(&control), config),
    }
    .expect("service");
    Fixture {
        control,
        service,
        lease,
        capsule,
        posture_digest,
    }
}

fn hello(posture_digest: &ContentDigest, connection_id: &str) -> v1::RunnerHello {
    v1::RunnerHello {
        runner_id: "runner-1".to_owned(),
        connection_id: connection_id.to_owned(),
        protocol_version: 1,
        inventory: Some(v1::RunnerInventory {
            hostname: "runner.example".to_owned(),
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            logical_cpus: 2,
            memory_bytes: 4096,
            local_storage_bytes: 4096,
            isolation_backends: vec!["native".to_owned()],
            capabilities: vec![v1::Capability {
                key: "runtrue.posture.digest".to_owned(),
                json_value: serde_json::to_string(posture_digest.as_str()).expect("JSON"),
                evidence_source: "local-probe".to_owned(),
            }],
            runner_binary_digest: Some(
                v1::Digest::try_from(ContentDigest::sha256(b"runner binary")).expect("digest"),
            ),
            runner_image_digest: Some(
                v1::Digest::try_from(ContentDigest::sha256(b"runner image")).expect("digest"),
            ),
            runner_version: "test".to_owned(),
            engine_version: "test".to_owned(),
            protocol_version: 1,
            region: String::new(),
            labels: BTreeMap::new(),
        }),
    }
}

fn test_identity(runner_id: &str) -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        runner_id: runner_id.to_owned(),
        certificate_fingerprint: None,
        certificate_expires_unix_ms: None,
    }
}

fn test_certificate_identity(runner_id: &str, certificate: &[u8]) -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        runner_id: runner_id.to_owned(),
        certificate_fingerprint: Some(ContentDigest::sha256(certificate)),
        certificate_expires_unix_ms: Some(u64::MAX),
    }
}

async fn open(
    fixture: &Fixture,
    connection_id: &str,
) -> (
    mpsc::Sender<Result<v1::RunnerMessage, Status>>,
    ReceiverStream<Result<v1::ControlMessage, Status>>,
) {
    let (sender, receiver) = mpsc::channel(16);
    sender
        .send(Ok(v1::RunnerMessage {
            body: Some(runner_message::Body::Hello(hello(
                &fixture.posture_digest,
                connection_id,
            ))),
        }))
        .await
        .expect("send hello");
    let controls = fixture
        .service
        .open_authenticated(test_identity("runner-1"), ReceiverStream::new(receiver))
        .await
        .expect("open stream");
    (sender, controls)
}

async fn next_control(
    controls: &mut ReceiverStream<Result<v1::ControlMessage, Status>>,
) -> v1::ControlMessage {
    tokio::time::timeout(Duration::from_secs(1), controls.next())
        .await
        .expect("control timeout")
        .expect("control stream ended")
        .expect("control stream error")
}

async fn wait_for_lease_state(control: &ControlPlane, lease_id: &str, state: LeaseState) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if control.lease(lease_id).expect("lease").state == state {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lease state timeout");
}

async fn wait_for_job_state(control: &ControlPlane, state: JobState) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if control.jobs_for_run("run-1").expect("jobs")[0].status == state {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("job state timeout");
}

async fn wait_for_running_step(service: &RunnerControlService, lease_id: &str, step_id: &str) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let running = service
                .session("runner-1")
                .and_then(|session| {
                    Ok(session
                        .state()?
                        .running_steps
                        .get(&(lease_id.to_owned(), 1))
                        .cloned())
                })
                .ok()
                .flatten();
            if running.as_deref() == Some(step_id) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("running step timeout");
}

fn runner_message(body: runner_message::Body) -> Result<v1::RunnerMessage, Status> {
    Ok(v1::RunnerMessage { body: Some(body) })
}

#[tokio::test]
async fn open_fetch_heartbeat_cancel_and_completion_are_exact_and_idempotent() {
    let fixture = fixture();
    let (sender, mut controls) = open(&fixture, "connection-1").await;
    let first = next_control(&mut controls).await;
    assert!(matches!(
        first.body,
        Some(control_message::Body::Hello(v1::ControlHello {
            connection_id,
            installation_fencing_epoch: 1,
            ..
        })) if connection_id == "connection-1"
    ));
    let offered = match next_control(&mut controls).await.body {
        Some(control_message::Body::LeaseOffer(offer)) => *offer,
        other => panic!("expected lease offer, got {other:?}"),
    };
    assert_eq!(offered.lease_id, fixture.lease.id);
    assert_eq!(offered.job_id, "build");
    assert_eq!(offered.runner_id, "runner-1");
    assert_eq!(
        ContentDigest::try_from(offered.capsule_digest.expect("offer digest")).expect("digest"),
        fixture.capsule.digest
    );

    let fetched = fixture
        .service
        .fetch_authenticated(
            &test_identity("runner-1"),
            v1::FetchExecutionCapsuleRequest {
                lease_id: fixture.lease.id.clone(),
                fencing_generation: fixture.lease.fencing_generation,
                expected_digest: Some(
                    v1::Digest::try_from(&fixture.capsule.digest).expect("digest"),
                ),
            },
        )
        .await
        .expect("fetch capsule");
    assert_eq!(fetched.canonical_capsule, fixture.capsule.canonical_capsule);
    assert_eq!(fetched.signature, fixture.capsule.signature.signature);

    sender
        .send(runner_message(runner_message::Body::LeaseDecision(
            v1::LeaseDecision {
                lease_id: fixture.lease.id.clone(),
                fencing_generation: fixture.lease.fencing_generation,
                accepted: true,
                rejection_code: String::new(),
                detail: String::new(),
            },
        )))
        .await
        .expect("accept offer");
    wait_for_lease_state(&fixture.control, &fixture.lease.id, LeaseState::Active).await;
    sender
        .send(runner_message(runner_message::Body::JobState(
            v1::JobStateUpdate {
                lease_id: fixture.lease.id.clone(),
                fencing_generation: fixture.lease.fencing_generation,
                state: "running".to_owned(),
                observed_at: Some(proto_timestamp(now_unix_ms().expect("time"))),
                error_code: String::new(),
                detail: String::new(),
            },
        )))
        .await
        .expect("running state");
    wait_for_job_state(&fixture.control, JobState::Running).await;

    fixture
        .control
        .request_lease_cancel("job-db-1", now_unix_ms().unwrap())
        .expect("request cancellation");
    sender
        .send(runner_message(runner_message::Body::Heartbeat(
            v1::Heartbeat {
                runner_id: "runner-1".to_owned(),
                connection_id: "connection-1".to_owned(),
                active_leases: vec![v1::ActiveLease {
                    lease_id: fixture.lease.id.clone(),
                    fencing_generation: fixture.lease.fencing_generation,
                    state: "running".to_owned(),
                }],
                observed_at: Some(proto_timestamp(now_unix_ms().expect("time"))),
            },
        )))
        .await
        .expect("heartbeat");
    let cancel = match next_control(&mut controls).await.body {
        Some(control_message::Body::CancelLease(cancel)) => cancel,
        other => panic!("expected cancel, got {other:?}"),
    };
    assert_eq!(cancel.lease_id, fixture.lease.id);
    sender
        .send(runner_message(runner_message::Body::CancellationAck(
            v1::CancellationAck {
                lease_id: fixture.lease.id.clone(),
                fencing_generation: fixture.lease.fencing_generation,
                observed_at: Some(proto_timestamp(now_unix_ms().expect("time"))),
            },
        )))
        .await
        .expect("cancel ack");
    sender
        .send(runner_message(runner_message::Body::JobState(
            v1::JobStateUpdate {
                lease_id: fixture.lease.id.clone(),
                fencing_generation: fixture.lease.fencing_generation,
                state: "canceled".to_owned(),
                observed_at: Some(proto_timestamp(now_unix_ms().expect("time"))),
                error_code: "canceled".to_owned(),
                detail: String::new(),
            },
        )))
        .await
        .expect("terminal state");
    wait_for_job_state(&fixture.control, JobState::Finalizing).await;

    let result = ContentDigest::sha256(b"canceled result");
    let completion = v1::CompleteLeaseRequest {
        lease_id: fixture.lease.id.clone(),
        fencing_generation: fixture.lease.fencing_generation,
        installation_fencing_epoch: fixture.lease.installation_fencing_epoch,
        final_state: "canceled".to_owned(),
        exit_code: None,
        error_code: "canceled".to_owned(),
        result_digest: Some(v1::Digest::try_from(&result).expect("digest")),
        artifact_ids: Vec::new(),
        cache_entry_ids: Vec::new(),
        completed_at: Some(proto_timestamp(now_unix_ms().expect("time"))),
        final_job_attempt: 0,
        expected_log_frames: 0,
    };
    assert!(
        fixture
            .service
            .complete_authenticated(
                &test_identity("runner-1"),
                completion.clone(),
                CredentialTaintState::None,
            )
            .await
            .expect("complete")
            .accepted
    );
    assert!(
        fixture
            .service
            .complete_authenticated(
                &test_identity("runner-1"),
                completion.clone(),
                CredentialTaintState::None,
            )
            .await
            .expect("idempotent completion")
            .accepted
    );
    let mut conflicting = completion;
    conflicting.result_digest =
        Some(v1::Digest::try_from(ContentDigest::sha256(b"different result")).expect("digest"));
    assert_eq!(
        fixture
            .service
            .complete_authenticated(
                &test_identity("runner-1"),
                conflicting,
                CredentialTaintState::None,
            )
            .await
            .expect_err("conflicting completion")
            .code(),
        tonic::Code::AlreadyExists
    );
    drop(sender);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if fixture.service.session("runner-1").is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("disconnect cleanup");
    assert_eq!(
        fixture
            .control
            .runner("runner-1")
            .expect("runner")
            .runner
            .status,
        RunnerStatus::Offline
    );
}

#[tokio::test]
async fn stale_runner_connection_fence_and_capsule_identifiers_fail_closed() {
    let fixture = fixture();
    let (sender, mut controls) = open(&fixture, "connection-1").await;
    let _hello = next_control(&mut controls).await;
    let _offer = next_control(&mut controls).await;

    let wrong_digest = fixture
        .service
        .fetch_authenticated(
            &test_identity("runner-1"),
            v1::FetchExecutionCapsuleRequest {
                lease_id: fixture.lease.id.clone(),
                fencing_generation: fixture.lease.fencing_generation,
                expected_digest: Some(
                    v1::Digest::try_from(ContentDigest::sha256(b"wrong")).expect("digest"),
                ),
            },
        )
        .await
        .expect_err("wrong capsule digest");
    assert_eq!(wrong_digest.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        fixture
            .service
            .fetch_authenticated(
                &test_identity("runner-1"),
                v1::FetchExecutionCapsuleRequest {
                    lease_id: fixture.lease.id.clone(),
                    fencing_generation: fixture.lease.fencing_generation + 1,
                    expected_digest: Some(
                        v1::Digest::try_from(&fixture.capsule.digest).expect("digest"),
                    ),
                },
            )
            .await
            .expect_err("stale generation")
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        fixture
            .service
            .bound_lease(
                "runner-other",
                &fixture.lease.id,
                fixture.lease.fencing_generation
            )
            .expect_err("wrong runner")
            .code(),
        tonic::Code::PermissionDenied
    );
    let session = fixture.service.session("runner-1").expect("session");
    assert_eq!(
        fixture
            .service
            .handle_heartbeat(
                &session,
                &v1::Heartbeat {
                    runner_id: "runner-1".to_owned(),
                    connection_id: "connection-other".to_owned(),
                    active_leases: Vec::new(),
                    observed_at: Some(proto_timestamp(now_unix_ms().expect("time"))),
                },
            )
            .await
            .expect_err("wrong connection")
            .code(),
        tonic::Code::PermissionDenied
    );
    let completion = v1::CompleteLeaseRequest {
        lease_id: fixture.lease.id.clone(),
        fencing_generation: fixture.lease.fencing_generation + 1,
        installation_fencing_epoch: fixture.lease.installation_fencing_epoch,
        final_state: "failed".to_owned(),
        exit_code: Some(1),
        error_code: "test".to_owned(),
        result_digest: Some(
            v1::Digest::try_from(ContentDigest::sha256(b"result")).expect("digest"),
        ),
        artifact_ids: Vec::new(),
        cache_entry_ids: Vec::new(),
        completed_at: Some(proto_timestamp(now_unix_ms().expect("time"))),
        final_job_attempt: 0,
        expected_log_frames: 0,
    };
    assert_eq!(
        fixture
            .service
            .complete_authenticated(
                &test_identity("runner-1"),
                completion.clone(),
                CredentialTaintState::None,
            )
            .await
            .expect_err("stale completion generation")
            .code(),
        tonic::Code::FailedPrecondition
    );
    let mut stale_epoch = completion;
    stale_epoch.fencing_generation = fixture.lease.fencing_generation;
    stale_epoch.installation_fencing_epoch += 1;
    assert_eq!(
        fixture
            .service
            .complete_authenticated(
                &test_identity("runner-1"),
                stale_epoch,
                CredentialTaintState::None,
            )
            .await
            .expect_err("stale completion epoch")
            .code(),
        tonic::Code::FailedPrecondition
    );

    let (second_sender, second_receiver) = mpsc::channel(2);
    second_sender
        .send(runner_message(runner_message::Body::Hello(hello(
            &fixture.posture_digest,
            "connection-2",
        ))))
        .await
        .expect("second hello");
    assert_eq!(
        fixture
            .service
            .open_authenticated(
                test_identity("runner-1"),
                ReceiverStream::new(second_receiver),
            )
            .await
            .expect_err("duplicate connection")
            .code(),
        tonic::Code::AlreadyExists
    );

    let (mismatch_sender, mismatch_receiver) = mpsc::channel(2);
    let mut mismatch = hello(&fixture.posture_digest, "connection-mismatch");
    mismatch.runner_id = "runner-other".to_owned();
    mismatch_sender
        .send(runner_message(runner_message::Body::Hello(mismatch)))
        .await
        .expect("mismatched hello");
    assert_eq!(
        fixture
            .service
            .open_authenticated(
                test_identity("runner-1"),
                ReceiverStream::new(mismatch_receiver)
            )
            .await
            .expect_err("identity mismatch")
            .code(),
        tonic::Code::PermissionDenied
    );

    drop(sender);
    drop(second_sender);
    drop(mismatch_sender);
}

#[tokio::test]
async fn unary_calls_must_use_the_certificate_that_owns_the_open_session() {
    let fixture = fixture();
    let (outbound, _receiver) = mpsc::channel(2);
    let owner = test_certificate_identity("runner-1", b"certificate-a");
    let session = Arc::new(RunnerSession {
        runner_id: "runner-1".to_owned(),
        connection_id: "fingerprint-session".to_owned(),
        protocol_version: PROTOCOL_MAX,
        posture_digest: fixture.posture_digest.clone(),
        runner_image_digest: ContentDigest::sha256(b"test runner image"),
        certificate_fingerprint: owner.certificate_fingerprint.clone(),
        certificate_expires_unix_ms: owner.certificate_expires_unix_ms,
        outbound,
        state: Mutex::new(SessionState {
            offered: BTreeMap::from([(fixture.lease.id.clone(), fixture.lease.fencing_generation)]),
            accepted: BTreeMap::new(),
            cancellation_acks: BTreeSet::new(),
            log_sequences: BTreeMap::new(),
            running_steps: BTreeMap::new(),
            terminal_steps: BTreeSet::new(),
            scm_credential_leases: BTreeSet::new(),
            current_attempts: BTreeMap::new(),
            rotation_notice_sent: false,
        }),
        offer_lock: tokio::sync::Mutex::new(()),
    });
    fixture
        .service
        .register_session(Arc::clone(&session))
        .expect("register session");
    let request = v1::FetchExecutionCapsuleRequest {
        lease_id: fixture.lease.id.clone(),
        fencing_generation: fixture.lease.fencing_generation,
        expected_digest: Some(v1::Digest::try_from(&fixture.capsule.digest).expect("digest")),
    };
    fixture
        .service
        .fetch_authenticated(&owner, request.clone())
        .await
        .expect("owning certificate");
    let overlap = test_certificate_identity("runner-1", b"certificate-b");
    assert_eq!(
        fixture
            .service
            .fetch_authenticated(&overlap, request)
            .await
            .expect_err("different valid certificate")
            .code(),
        tonic::Code::PermissionDenied
    );
    fixture
        .service
        .remove_session("runner-1", "fingerprint-session");
}

#[tokio::test]
async fn secret_and_oidc_brokers_require_exact_live_step_and_are_one_use() {
    use x25519_dalek::{PublicKey, StaticSecret};

    let fixture = broker_fixture();
    let (sender, mut controls) = open(&fixture, "broker-connection").await;
    let _hello = next_control(&mut controls).await;
    let _offer = next_control(&mut controls).await;
    sender
        .send(runner_message(runner_message::Body::LeaseDecision(
            v1::LeaseDecision {
                lease_id: fixture.lease.id.clone(),
                fencing_generation: fixture.lease.fencing_generation,
                accepted: true,
                rejection_code: String::new(),
                detail: String::new(),
            },
        )))
        .await
        .expect("accept lease");
    wait_for_lease_state(&fixture.control, &fixture.lease.id, LeaseState::Active).await;

    let identity = test_identity("runner-1");
    let guest_secret = StaticSecret::random_from_rng(OsRng);
    let guest_public = PublicKey::from(&guest_secret).to_bytes();
    let secret_request = v1::SecretLeaseRequest {
        execution_lease_id: fixture.lease.id.clone(),
        fencing_generation: fixture.lease.fencing_generation,
        job_id: "build".to_owned(),
        step_id: "publish".to_owned(),
        secret_metadata_id: "secret-1".to_owned(),
        purpose: "publish".to_owned(),
        guest_session_key: Some(v1::Digest {
            algorithm: "x25519".to_owned(),
            value: guest_public.to_vec(),
        }),
        job_attempt: 1,
    };
    assert_eq!(
        fixture
            .service
            .request_secret_authenticated(&identity, secret_request.clone())
            .expect_err("step is not running")
            .code(),
        tonic::Code::FailedPrecondition
    );

    sender
        .send(runner_message(runner_message::Body::StepState(
            v1::StepStateUpdate {
                lease_id: fixture.lease.id.clone(),
                fencing_generation: fixture.lease.fencing_generation,
                step_id: "publish".to_owned(),
                state: "running".to_owned(),
                observed_at: Some(proto_timestamp(now_unix_ms().expect("time"))),
                exit_code: None,
                error_code: String::new(),
                output_digest: None,
                job_attempt: 1,
            },
        )))
        .await
        .expect("running step");
    wait_for_running_step(&fixture.service, &fixture.lease.id, "publish").await;

    let mut unsigned_attempt = secret_request.clone();
    unsigned_attempt.job_attempt = 2;
    assert_eq!(
        fixture
            .service
            .request_secret_authenticated(&identity, unsigned_attempt)
            .expect_err("attempt exceeds signed retry bound")
            .code(),
        tonic::Code::PermissionDenied
    );

    let delivered = fixture
        .service
        .request_secret_authenticated(&identity, secret_request.clone())
        .expect("secret delivery");
    assert_eq!(delivered.delivery_kind, ENVELOPE_DELIVERY_KIND);
    assert!(delivered.encrypted_envelope.starts_with(b"ANVSEC01"));
    assert_eq!(
        fixture
            .service
            .request_secret_authenticated(&identity, secret_request)
            .expect_err("secret replay")
            .code(),
        tonic::Code::AlreadyExists
    );

    let mut wrong_audience = v1::OidcTokenRequest {
        execution_lease_id: fixture.lease.id.clone(),
        fencing_generation: fixture.lease.fencing_generation,
        job_id: "build".to_owned(),
        step_id: "publish".to_owned(),
        audience: "https://evil.example".to_owned(),
        job_attempt: 1,
    };
    assert_eq!(
        fixture
            .service
            .mint_oidc_authenticated(&identity, wrong_audience.clone())
            .expect_err("undeclared audience")
            .code(),
        tonic::Code::PermissionDenied
    );
    wrong_audience.audience = "https://registry.example".to_owned();
    let token = fixture
        .service
        .mint_oidc_authenticated(&identity, wrong_audience.clone())
        .expect("OIDC token");
    assert_eq!(token.token.split('.').count(), 3);
    assert_eq!(
        fixture
            .service
            .mint_oidc_authenticated(&identity, wrong_audience)
            .expect_err("OIDC replay")
            .code(),
        tonic::Code::AlreadyExists
    );

    let revoke = v1::RevokeSecretLeaseRequest {
        secret_lease_id: delivered.secret_lease_id.clone(),
        execution_lease_id: fixture.lease.id.clone(),
        fencing_generation: fixture.lease.fencing_generation,
        job_attempt: 1,
    };
    fixture
        .service
        .revoke_secret_authenticated(&identity, revoke.clone())
        .expect("revoke");
    fixture
        .service
        .revoke_secret_authenticated(&identity, revoke)
        .expect("idempotent revoke");
    assert_eq!(
        fixture
            .service
            .revoke_secret_authenticated(
                &identity,
                v1::RevokeSecretLeaseRequest {
                    secret_lease_id: delivered.secret_lease_id,
                    execution_lease_id: fixture.lease.id,
                    fencing_generation: fixture.lease.fencing_generation + 1,
                    job_attempt: 1,
                },
            )
            .expect_err("stale revoke")
            .code(),
        tonic::Code::PermissionDenied
    );
    drop(sender);
}

#[tokio::test]
async fn draining_runner_receives_control() {
    let fixture = fixture();
    let (sender, mut controls) = open(&fixture, "connection-drain").await;
    let _hello = next_control(&mut controls).await;
    let _offer = next_control(&mut controls).await;
    fixture
        .control
        .drain_runner("runner-1", now_unix_ms().expect("time"))
        .expect("drain runner");
    sender
        .send(runner_message(runner_message::Body::Heartbeat(
            v1::Heartbeat {
                runner_id: "runner-1".to_owned(),
                connection_id: "connection-drain".to_owned(),
                active_leases: Vec::new(),
                observed_at: Some(proto_timestamp(now_unix_ms().expect("time"))),
            },
        )))
        .await
        .expect("heartbeat");
    assert!(matches!(
        next_control(&mut controls).await.body,
        Some(control_message::Body::DrainRunner(_))
    ));

    drop(sender);
}

#[tokio::test]
async fn enrollment_replay_and_rotation_are_durably_certificate_fenced() {
    let now = now_unix_ms().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("control.sqlite");
    let control = Arc::new(ControlPlane::open(&database, "installation", now).unwrap());
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            name: "enrolled".to_owned(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: now,
        })
        .unwrap();
    let issued_token = control
        .create_enrollment_token("pool-1", now, now + 60_000)
        .unwrap();
    let authority = certificate_authority();
    let service = RunnerControlService::new(Arc::clone(&control), Arc::clone(&authority)).unwrap();
    let inventory = hello(&ContentDigest::sha256(b"posture"), "unused")
        .inventory
        .unwrap();
    let response = service
        .enroll_unauthenticated(v1::EnrollRequest {
            enrollment_token: issued_token.token.expose().to_owned(),
            certificate_signing_request: certificate_request(),
            inventory: Some(inventory.clone()),
            attestation: None,
            protocol_min: 0,
            protocol_max: 0,
            ephemeral: true,
        })
        .await
        .unwrap();
    assert_eq!(response.runner_pool_id, "pool-1");
    assert_eq!(response.selected_protocol_version, PROTOCOL_MIN);
    assert_eq!(service.protocol_metrics().enrollment_selected_v1, 1);
    let enrolled = control.runner(&response.runner_id).unwrap().runner;
    assert!(enrolled.ephemeral);
    let inventory_digest = validate_inventory(&enrolled, &inventory, inventory.protocol_version)
        .expect("persisted enrollment inventory");
    let expected_posture = control
        .validate_runner_inventory_binding(&response.runner_id, &inventory_digest)
        .expect("authoritative posture");
    assert_eq!(
        ContentDigest::try_from(
            response
                .authoritative_posture_digest
                .as_ref()
                .expect("server authoritative posture")
        )
        .unwrap(),
        expected_posture
    );
    assert!(matches!(
        service
            .enroll_unauthenticated(v1::EnrollRequest {
                enrollment_token: issued_token.token.expose().to_owned(),
                certificate_signing_request: certificate_request(),
                inventory: Some(inventory),
                attestation: None,
                protocol_min: 0,
                protocol_max: 0,
                ephemeral: false,
            })
            .await,
        Err(status) if status.code() == tonic::Code::PermissionDenied
    ));

    let leaf = CertificateDer::from_pem_slice(&response.certificate_chain_pem).unwrap();
    let fingerprint = ContentDigest::sha256(leaf.as_ref());
    let authenticated = AuthenticatedIdentity {
        runner_id: response.runner_id.clone(),
        certificate_fingerprint: Some(fingerprint.clone()),
        certificate_expires_unix_ms: response
            .certificate_expires_at
            .as_ref()
            .map(|value| u64::try_from(value.seconds).unwrap() * 1_000),
    };
    assert!(matches!(
        service
            .rotate_authenticated(
                &authenticated,
                v1::RotateCertificateRequest {
                    runner_id: "runner-other".to_owned(),
                    certificate_signing_request: certificate_request(),
                    attestation: None,
                },
            )
            .await,
        Err(status) if status.code() == tonic::Code::PermissionDenied
    ));
    let runner_id = response.runner_id.clone();
    let rotation_csr = certificate_request();
    let rotated = service
        .rotate_authenticated(
            &authenticated,
            v1::RotateCertificateRequest {
                runner_id: runner_id.clone(),
                certificate_signing_request: rotation_csr.clone(),
                attestation: None,
            },
        )
        .await
        .unwrap();
    assert!(!rotated.certificate_chain_pem.is_empty());
    assert_eq!(
        rotated.csr_digest,
        Some(v1::Digest::try_from(&ContentDigest::sha256(&rotation_csr)).unwrap())
    );
    assert!(rotated.certificate_fingerprint.is_some());
    let old_certificate = control.runner_certificate(&fingerprint).unwrap();
    assert_eq!(
        old_certificate.status,
        runtrue_control_plane::RunnerCertificateStatus::Overlap
    );
    let overlap_until = old_certificate.overlap_until_unix_ms.unwrap();
    assert!(matches!(
        control.authenticate_runner_certificate(&fingerprint, overlap_until),
        Err(runtrue_control_plane::ControlPlaneError::RunnerCertificateUnauthorized)
    ));
    assert_eq!(
        control.runner_certificate(&fingerprint).unwrap().status,
        runtrue_control_plane::RunnerCertificateStatus::Revoked
    );

    let replayed = service
        .rotate_authenticated(
            &authenticated,
            v1::RotateCertificateRequest {
                runner_id: runner_id.clone(),
                certificate_signing_request: rotation_csr.clone(),
                attestation: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(replayed, rotated);
    assert!(matches!(
        service
            .rotate_authenticated(
                &authenticated,
                v1::RotateCertificateRequest {
                    runner_id: runner_id.clone(),
                    certificate_signing_request: certificate_request(),
                    attestation: None,
                },
            )
            .await,
        Err(status) if status.code() == tonic::Code::AlreadyExists
    ));

    let substituted = authority
        .issue(&certificate_request(), &runner_id, "pool-1", now)
        .unwrap();
    let changed = rusqlite::Connection::open(database)
        .unwrap()
        .execute(
            "UPDATE runner_certificate_rotations SET certificate_chain_pem = ?2
                 WHERE old_fingerprint = ?1",
            rusqlite::params![fingerprint.as_str(), substituted.certificate_chain_pem],
        )
        .unwrap();
    assert_eq!(changed, 1);
    assert!(matches!(
        service
            .rotate_authenticated(
                &authenticated,
                v1::RotateCertificateRequest {
                    runner_id,
                    certificate_signing_request: rotation_csr,
                    attestation: None,
                },
            )
            .await,
        Err(status) if status.code() == tonic::Code::Internal
    ));
}

#[tokio::test]
async fn newest_common_selection_and_security_minimum_preserve_unconsumed_token() {
    let now = now_unix_ms().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let control = Arc::new(
        ControlPlane::open(directory.path().join("control.sqlite"), "installation", now).unwrap(),
    );
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-protocol".to_owned(),
            tenant_id: "tenant-protocol".to_owned(),
            name: "protocol".to_owned(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: now,
        })
        .unwrap();
    let token = control
        .create_enrollment_token("pool-protocol", now, now + 60_000)
        .unwrap();
    let authority = certificate_authority();
    let service = RunnerControlService::with_config(
        Arc::clone(&control),
        Arc::clone(&authority),
        RunnerControlConfig {
            protocol_minimum: PROTOCOL_MAX,
            ..RunnerControlConfig::default()
        },
    )
    .unwrap();
    let inventory = hello(&ContentDigest::sha256(b"legacy-posture"), "unused")
        .inventory
        .unwrap();
    assert_eq!(inventory.protocol_version, PROTOCOL_MIN);

    let request = |protocol_min, protocol_max| v1::EnrollRequest {
        enrollment_token: token.token.expose().to_owned(),
        certificate_signing_request: certificate_request(),
        inventory: Some(inventory.clone()),
        attestation: None,
        protocol_min,
        protocol_max,
        ephemeral: false,
    };
    let malformed = service
        .enroll_unauthenticated(request(0, PROTOCOL_MAX))
        .await
        .unwrap_err();
    assert_eq!(malformed.code(), tonic::Code::InvalidArgument);
    let disjoint = service
        .enroll_unauthenticated(request(PROTOCOL_MIN, PROTOCOL_MIN))
        .await
        .unwrap_err();
    assert_eq!(disjoint.code(), tonic::Code::FailedPrecondition);

    let response = service
        .enroll_unauthenticated(request(PROTOCOL_MIN, PROTOCOL_MAX))
        .await
        .unwrap();
    assert_eq!(response.protocol_min, PROTOCOL_MAX);
    assert_eq!(response.protocol_max, PROTOCOL_MAX);
    assert_eq!(response.selected_protocol_version, PROTOCOL_MAX);
    let mut selected_inventory = inventory.clone();
    selected_inventory.protocol_version = PROTOCOL_MAX;
    let enrolled = control.runner(&response.runner_id).unwrap().runner;
    let selected_binding =
        validate_inventory(&enrolled, &selected_inventory, PROTOCOL_MAX).unwrap();
    control
        .validate_runner_inventory_binding(&response.runner_id, &selected_binding)
        .expect("selected generation is durably bound");
    assert_eq!(
        service.protocol_metrics(),
        RunnerProtocolMetricsSnapshot {
            enrollment_selected_v2: 1,
            enrollment_rejected: 2,
            ..RunnerProtocolMetricsSnapshot::default()
        }
    );

    let old_hello = v1::RunnerHello {
        runner_id: response.runner_id.clone(),
        connection_id: "old-protocol-connection".to_owned(),
        protocol_version: PROTOCOL_MIN,
        inventory: Some(inventory),
    };
    let status = service
        .open_authenticated(
            AuthenticatedIdentity {
                runner_id: response.runner_id,
                certificate_fingerprint: None,
                certificate_expires_unix_ms: None,
            },
            tokio_stream::iter([Ok(v1::RunnerMessage {
                body: Some(v1::runner_message::Body::Hello(old_hello)),
            })]),
        )
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(service.protocol_metrics().stream_version_rejected, 1);
}

#[test]
fn requests_require_mtls_identity_and_broker_rpcs_do_not_fake_success() {
    let fixture = fixture();
    let request = Request::new(v1::CacheTicketRequest::default());
    assert_eq!(
        fixture
            .service
            .authenticate(&request)
            .expect_err("missing identity")
            .code(),
        tonic::Code::Unauthenticated
    );
    let mut authenticated = Request::new(v1::CacheTicketRequest::default());
    authenticated
        .extensions_mut()
        .insert(TestRunnerIdentity("runner-1".to_owned()));
    assert_eq!(
        fixture
            .service
            .authenticate(&authenticated)
            .expect("identity")
            .runner_id,
        "runner-1"
    );
}

#[test]
fn source_object_authorization_is_manifest_scoped_before_object_lookup() {
    let directory = tempfile::tempdir().unwrap();
    let cas = FsCas::open(directory.path(), CasLimits::default()).unwrap();
    let file_bytes = b"exact source";
    let file_digest = ContentDigest::sha256(file_bytes);
    assert_eq!(
        cas.put_reader(std::io::Cursor::new(file_bytes))
            .unwrap()
            .digest,
        file_digest
    );
    let manifest = GitTreeManifest {
        version: 1,
        repository_id: "repo-1".to_owned(),
        commit: "a".repeat(40),
        entries: vec![runtrue_git::GitTreeEntry {
            path: "src/lib.rs".to_owned(),
            kind: GitTreeEntryKind::File {
                digest: file_digest.clone(),
                size_bytes: file_bytes.len() as u64,
                executable: false,
            },
        }],
    };
    let manifest_bytes = manifest.canonical_bytes().unwrap();
    let manifest_digest = manifest.digest().unwrap();
    assert_eq!(
        cas.put_reader(std::io::Cursor::new(&manifest_bytes))
            .unwrap()
            .digest,
        manifest_digest
    );
    assert_eq!(
        authorize_source_object(&cas, &manifest_digest, &manifest_digest, 1024).unwrap(),
        manifest_bytes.len() as u64
    );
    assert_eq!(
        authorize_source_object(&cas, &manifest_digest, &file_digest, 1024).unwrap(),
        file_bytes.len() as u64
    );
    let absent = ContentDigest::sha256(b"not present and not authorized");
    assert_eq!(
        authorize_source_object(&cas, &manifest_digest, &absent, 1024)
            .expect_err("unreferenced digest")
            .code(),
        tonic::Code::PermissionDenied
    );
}
