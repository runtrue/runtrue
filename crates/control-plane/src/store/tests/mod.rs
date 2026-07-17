mod identity_policy_deployment;
mod support;

use super::*;
use crate::types::{NewJob, RunnerPoolStatus};
use runtrue_attest::CapsuleSigningKey;
use runtrue_audit::{AuditPrincipal, AuditResource};
use runtrue_auth::{ApiTokenRecord, IssueApiToken, TokenHasher};
use runtrue_model::SecretReference;
use runtrue_oidc::OidcGrant;
use runtrue_policy::{ApprovalKind, ApprovalRule, Decision};
use runtrue_scheduler::SchedulingRequirements;
use runtrue_secrets::{MasterKey, SecretPlaintext};
use runtrue_workflow_ir::{
    ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
    OperatingSystem, ParityGrade, PermissionSet, PlannedJob, PlannedStep, RunnerRequirements,
    ScalarValue, StepAction, StepCapabilitySet, Trust, WorkflowIdentity, CAPSULE_SCHEMA_VERSION,
    ENGINE_COMPATIBILITY_VERSION,
};
use serde_json::json;
use std::{collections::BTreeSet, fs};
use support::*;

#[cfg(unix)]
use std::os::unix::fs::symlink;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

mod artifacts;
mod cache;
mod durable;
mod leases;
mod lifecycle;
mod runners;
mod scheduler;
mod secrets;
mod storage;
mod workflow;

const NOW: u64 = 1_000;

fn add_runner_pool_only(control: &ControlPlane) {
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            name: "trusted".to_owned(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: NOW,
        })
        .unwrap();
}

fn repository() -> RepositoryRecord {
    RepositoryRecord {
        id: "repo-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        owner: "octo".to_owned(),
        name: "runtrue".to_owned(),
        default_branch: "main".to_owned(),
        visibility: "private".to_owned(),
        created_unix_ms: NOW,
    }
}

fn execution_capsule() -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "test".to_owned(),
        workflow: WorkflowIdentity {
            name: "ci".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/ci.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "0123456789abcdef".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: Default::default(),
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
        jobs: vec![PlannedJob {
            id: "build".to_owned(),
            base_id: "build".to_owned(),
            name: "build".to_owned(),
            needs: Vec::new(),
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::UntrustedOk,
            environment: None,
            runner: RunnerRequirements {
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Microvm,
                image: None,
                cpu: 1,
                memory_bytes: 1_024,
                storage_bytes: Some(1_024),
                region: Some("test".to_owned()),
                capabilities: vec!["kvm".to_owned()],
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

fn signed_capsule() -> (SignedCapsuleRecord, runtrue_attest::CapsuleVerifyingKey) {
    let capsule = execution_capsule();
    let signing_key = CapsuleSigningKey::from_seed([9_u8; 32]);
    let signature = signing_key.sign_capsule(&capsule).unwrap();
    let canonical_capsule = capsule.canonical_bytes().unwrap();
    (
        SignedCapsuleRecord {
            id: "capsule-1".to_owned(),
            repository_id: "repo-1".to_owned(),
            digest: signature.capsule_digest.clone(),
            canonical_capsule,
            signature,
            created_unix_ms: NOW,
        },
        signing_key.verifying_key(),
    )
}

fn signed_approval_capsule(
    capsule_id: &str,
    workflow_definition: bool,
    privileged_execution: bool,
) -> (SignedCapsuleRecord, runtrue_attest::CapsuleVerifyingKey) {
    let mut capsule = execution_capsule();
    capsule.context.source_trust = runtrue_workflow_ir::SourceTrust::ProtectedBranch;
    capsule.compiler_version = format!("test:{capsule_id}");
    capsule.approval.workflow_definition = workflow_definition;
    capsule.approval.privileged_execution = privileged_execution;
    let signing_key = CapsuleSigningKey::from_seed([29_u8; 32]);
    let signature = signing_key.sign_capsule(&capsule).unwrap();
    (
        SignedCapsuleRecord {
            id: capsule_id.to_owned(),
            repository_id: "repo-1".to_owned(),
            digest: signature.capsule_digest.clone(),
            canonical_capsule: capsule.canonical_bytes().unwrap(),
            signature,
            created_unix_ms: NOW,
        },
        signing_key.verifying_key(),
    )
}

fn scm_execution_capsule() -> ExecutionCapsule {
    let mut capsule = execution_capsule();
    capsule.context.source_trust = runtrue_workflow_ir::SourceTrust::Trusted;
    capsule.jobs.clear();
    capsule.context.base_commit = Some("fedcba9876543210".to_owned());
    capsule.context.policy_version_ids = vec!["policy-v1".to_owned()];
    capsule.approval.workflow_definition = true;
    capsule.approval.privileged_execution = true;
    capsule.jobs.push(PlannedJob {
        id: "build".to_owned(),
        base_id: "build".to_owned(),
        name: "build".to_owned(),
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
            memory_bytes: 1_024,
            storage_bytes: Some(1_024),
            region: Some("test".to_owned()),
            capabilities: vec!["kvm".to_owned()],
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
    });
    capsule
}

struct PendingScmFixture {
    control: ControlPlane,
    capsule: SignedCapsuleRecord,
    key: runtrue_attest::CapsuleVerifyingKey,
    metadata: CapsuleApiMetadata,
    context: ScmContinuationContext,
    run: CreateRunRequest,
    subject: ContentDigest,
    privileged_subject: ContentDigest,
}

fn pending_scm_fixture() -> PendingScmFixture {
    pending_scm_fixture_with_reusable_privileged_approval(false)
}

fn pending_scm_fixture_with_reusable_privileged_approval(
    reusable_privileged: bool,
) -> PendingScmFixture {
    let control = ControlPlane::open_in_memory("scm-continuation", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    control
        .enqueue_task(&DurableTask {
            id: "scm-origin".to_owned(),
            kind: "scm.event".to_owned(),
            payload: json!({"event": "pull-request"}),
            status: DurableTaskStatus::Pending,
            available_unix_ms: NOW,
            attempts: 0,
            lease_owner: None,
            lease_expires_unix_ms: None,
            last_error: None,
            created_unix_ms: NOW,
            completed_unix_ms: None,
        })
        .unwrap();
    control
        .claim_task_by_kind("scm-worker", "scm.event", NOW, 1_000)
        .unwrap()
        .unwrap();
    let decoded = scm_execution_capsule();
    let signing_key = CapsuleSigningKey::from_seed([51_u8; 32]);
    let signature = signing_key.sign_capsule(&decoded).unwrap();
    let capsule = SignedCapsuleRecord {
        id: "scm-proposed-capsule".to_owned(),
        repository_id: "repo-1".to_owned(),
        digest: signature.capsule_digest.clone(),
        canonical_capsule: decoded.canonical_bytes().unwrap(),
        signature,
        created_unix_ms: NOW,
    };
    let subject = ContentDigest::sha256(b"scm-full-approval-subject");
    let privileged_subject = if reusable_privileged {
        ContentDigest::sha256(b"scm-repository-privileged-capability")
    } else {
        subject.clone()
    };
    let metadata = CapsuleApiMetadata {
        capsule_id: capsule.id.clone(),
        approval_subject_digest: subject.clone(),
        risk_score: 90,
    };
    let source_identity = ScmSourceIdentity {
        normalized_event_digest: decoded.context.normalized_event_digest.clone(),
        source_commit: decoded.context.source_commit.clone(),
        base_commit: decoded.context.base_commit.clone(),
        workflow_path: decoded.workflow.source_path.clone(),
        proposed_workflow_digest: ContentDigest::sha256(b"proposed-workflow-blob"),
        base_workflow_digest: Some(ContentDigest::sha256(b"base-workflow-blob")),
        proposed_lockfile_digest: Some(ContentDigest::sha256(b"proposed-lock")),
        base_lockfile_digest: Some(ContentDigest::sha256(b"base-lock")),
        proposed_approval_subject_digest: Some(subject.clone()),
        reusable_workflow_digests: vec![ContentDigest::sha256(b"reusable-workflow").to_string()],
        policy_version_ids: decoded.context.policy_version_ids.clone(),
    };
    let context = ScmContinuationContext {
        pending_execution_id: "scm-pending".to_owned(),
        event: json!({"normalized_digest": decoded.context.normalized_event_digest}),
        role: ScmExecutionRole::ProposedDefinition,
        source_identity: source_identity.clone(),
        analysis_id: Some("scm-analysis".to_owned()),
        source_snapshot_id: None,
        privileged_capability_digest: Some(privileged_subject.clone()),
        resolved_repository_actions: serde_json::json!({}),
    };
    let run = CreateRunRequest {
        id: "scm-run".to_owned(),
        repository_id: "repo-1".to_owned(),
        capsule_id: capsule.id.clone(),
        priority: 0,
        remote: true,
        created_unix_ms: NOW,
        jobs: vec![NewJob {
            id: "scm-job".to_owned(),
            job_key: "build".to_owned(),
            attempt: 1,
            requirements: SchedulingRequirements {
                allowed_pools: BTreeSet::new(),
                ..requirements()
            },
        }],
    };
    let approvals = vec![
        pending_approval(
            "scm-workflow-approval",
            ApprovalKind::WorkflowDefinition,
            &subject,
            true,
        ),
        pending_approval(
            "scm-privileged-approval",
            ApprovalKind::PrivilegedExecution,
            &privileged_subject,
            !reusable_privileged,
        ),
    ];
    let prepared = PreparedScmExecution {
        capsule: capsule.clone(),
        metadata: metadata.clone(),
        approvals,
        run: run.clone(),
        continuation: Some(context.clone()),
        source_snapshot: None,
        scm_fetch_id: None,
    };
    let analysis = ScmProposedAnalysisRecord {
        id: "scm-analysis".to_owned(),
        origin_task_id: "scm-origin".to_owned(),
        repository_id: "repo-1".to_owned(),
        status: ScmProposedAnalysisStatus::Valid,
        source_identity,
        analysis: Some(json!({"semantic_risk": {"score": 90}})),
        failure: None,
        proposed_capsule_id: Some(capsule.id.clone()),
        created_unix_ms: NOW,
    };
    let key = signing_key.verifying_key();
    let result = control
        .complete_scm_task_with_executions_idempotent(
            "scm-origin",
            "scm-worker",
            NOW + 1,
            "scm-origin-key",
            &[prepared],
            Some(&analysis),
            &key,
        )
        .unwrap();
    assert!(result.value.run_ids.is_empty());
    assert_eq!(result.value.pending_execution_ids, ["scm-pending"]);
    PendingScmFixture {
        control,
        capsule,
        key,
        metadata,
        context,
        run,
        subject,
        privileged_subject,
    }
}

fn pending_approval(
    id: &str,
    kind: ApprovalKind,
    subject: &ContentDigest,
    one_shot: bool,
) -> ApprovalRequest {
    ApprovalRequest::create(
        id,
        kind,
        subject.clone(),
        90,
        NOW,
        NOW + 10_000,
        ApprovalRule {
            id: "approval-rule".to_owned(),
            required_approvals: 1,
            eligible_approvers: BTreeSet::from(["reviewer".to_owned()]),
            forbidden_approvers: BTreeSet::new(),
            one_shot,
        },
    )
    .unwrap()
}

fn approve(control: &ControlPlane, id: &str, subject: &ContentDigest, at: u64) {
    control
        .decide_approval(
            id,
            ApprovalDecision {
                actor_id: "reviewer".to_owned(),
                decision: Decision::Approve,
                reason: "reviewed exact execution subject".to_owned(),
                rule_id: "approval-rule".to_owned(),
                subject_digest: subject.clone(),
                decided_unix_ms: at,
            },
            at,
        )
        .unwrap();
}

fn approval_run_request(capsule_id: &str, run_id: &str, job_id: &str, at: u64) -> CreateRunRequest {
    CreateRunRequest {
        id: run_id.to_owned(),
        repository_id: "repo-1".to_owned(),
        capsule_id: capsule_id.to_owned(),
        priority: 0,
        remote: true,
        created_unix_ms: at,
        jobs: vec![NewJob {
            id: job_id.to_owned(),
            job_key: "build".to_owned(),
            attempt: 1,
            requirements: requirements(),
        }],
    }
}

fn signed_oidc_capsule() -> (SignedCapsuleRecord, runtrue_attest::CapsuleVerifyingKey) {
    let mut capsule = execution_capsule();
    capsule.context.source_trust = runtrue_workflow_ir::SourceTrust::ProtectedBranch;
    capsule.jobs.clear();
    capsule.context.event_context.insert(
        "event.ref".to_owned(),
        ScalarValue::String("refs/heads/main".to_owned()),
    );
    let capabilities = StepCapabilitySet {
        oidc_audiences: vec!["https://registry.example".to_owned()],
        ..StepCapabilitySet::default()
    };
    capsule.jobs.push(PlannedJob {
        id: "publish".to_owned(),
        base_id: "publish".to_owned(),
        name: "publish".to_owned(),
        needs: Vec::new(),
        matrix: BTreeMap::new(),
        condition: None,
        trust: Trust::ProtectedBranchOnly,
        environment: Some("production".to_owned()),
        runner: RunnerRequirements {
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation: Isolation::Microvm,
            image: None,
            cpu: 1,
            memory_bytes: 1_024,
            storage_bytes: Some(1_024),
            region: Some("test".to_owned()),
            capabilities: vec!["kvm".to_owned()],
        },
        permissions: PermissionSet::default(),
        timeout_ms: 60_000,
        retries: 0,
        concurrency: None,
        variables: BTreeMap::new(),
        services: Vec::new(),
        steps: vec![PlannedStep {
            id: "federate".to_owned(),
            name: "federate".to_owned(),
            condition: None,
            action: StepAction::Command {
                program: "true".to_owned(),
                args: Vec::new(),
            },
            inputs: BTreeMap::new(),
            environment: BTreeMap::new(),
            capabilities,
            cache: None,
            timeout_ms: None,
            continue_on_error: false,
            outputs: BTreeMap::new(),
            working_directory: None,
        }],
        finalizers: Vec::new(),
        finalizer_timeout_ms: 120_000,
        value_outputs: BTreeMap::new(),
        outputs: BTreeMap::new(),
    });
    let signing_key = CapsuleSigningKey::from_seed([19_u8; 32]);
    let signature = signing_key.sign_capsule(&capsule).unwrap();
    (
        SignedCapsuleRecord {
            id: "capsule-oidc".to_owned(),
            repository_id: "repo-1".to_owned(),
            digest: signature.capsule_digest.clone(),
            canonical_capsule: capsule.canonical_bytes().unwrap(),
            signature,
            created_unix_ms: NOW,
        },
        signing_key.verifying_key(),
    )
}

fn signed_broker_capsule() -> (SignedCapsuleRecord, runtrue_attest::CapsuleVerifyingKey) {
    let (oidc, _) = signed_oidc_capsule();
    let mut capsule: ExecutionCapsule = serde_json::from_slice(&oidc.canonical_capsule).unwrap();
    capsule.approval.privileged_execution = true;
    capsule.jobs[0].retries = 1;
    capsule.jobs[0].steps[0]
        .capabilities
        .secrets
        .push(SecretReference {
            metadata_id: "secret-broker".to_owned(),
            name: "TOKEN".to_owned(),
            purpose: Some("publish".to_owned()),
        });
    capsule.jobs[0].steps[0]
        .capabilities
        .secrets
        .push(SecretReference {
            metadata_id: "secret-purpose-less".to_owned(),
            name: "NO_PURPOSE".to_owned(),
            purpose: None,
        });
    let signing_key = CapsuleSigningKey::from_seed([39_u8; 32]);
    let signature = signing_key.sign_capsule(&capsule).unwrap();
    (
        SignedCapsuleRecord {
            id: "capsule-broker".to_owned(),
            repository_id: "repo-1".to_owned(),
            digest: signature.capsule_digest.clone(),
            canonical_capsule: capsule.canonical_bytes().unwrap(),
            signature,
            created_unix_ms: NOW,
        },
        signing_key.verifying_key(),
    )
}

fn requirements() -> SchedulingRequirements {
    SchedulingRequirements {
        os: OperatingSystem::Linux,
        arch: Architecture::Amd64,
        isolation: Isolation::Microvm,
        cpu: 1,
        memory_bytes: 1_024,
        storage_bytes: 1_024,
        region: Some("test".to_owned()),
        required_capabilities: ["kvm".to_owned()].into_iter().collect(),
        allowed_pools: BTreeSet::new(),
    }
}

fn run_request(id: &str, job_id: &str) -> CreateRunRequest {
    CreateRunRequest {
        id: id.to_owned(),
        repository_id: "repo-1".to_owned(),
        capsule_id: "capsule-1".to_owned(),
        priority: 0,
        remote: true,
        created_unix_ms: NOW,
        jobs: vec![NewJob {
            id: job_id.to_owned(),
            job_key: "build".to_owned(),
            attempt: 1,
            requirements: requirements(),
        }],
    }
}

fn runner() -> RunnerRecord {
    RunnerRecord {
        id: "runner-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        pool_id: "pool-1".to_owned(),
        ephemeral: false,
        retired: false,
        os: OperatingSystem::Linux,
        arch: Architecture::Amd64,
        isolation_backends: [Isolation::Microvm].into_iter().collect(),
        logical_cpus: 4,
        memory_bytes: 8 * 1024,
        storage_bytes: 16 * 1024,
        region: Some("test".to_owned()),
        verified_capabilities: ["kvm".to_owned()].into_iter().collect(),
        self_reported_capabilities: BTreeSet::new(),
        status: RunnerStatus::Online,
        active_jobs: 0,
        used_cpus: 0,
        used_memory_bytes: 0,
        used_storage_bytes: 0,
        locality: BTreeSet::new(),
        last_heartbeat_unix_ms: NOW,
    }
}

fn runner_certificate(
    runner_id: &str,
    suffix: &[u8],
    issued_unix_ms: u64,
    not_after_unix_ms: u64,
) -> RunnerCertificateRecord {
    RunnerCertificateRecord {
        fingerprint: ContentDigest::sha256(suffix),
        runner_id: runner_id.to_owned(),
        pool_id: "pool-1".to_owned(),
        serial_hex: hex::encode(suffix),
        not_before_unix_ms: NOW,
        not_after_unix_ms,
        status: RunnerCertificateStatus::Active,
        issued_unix_ms,
        overlap_until_unix_ms: None,
        revoked_unix_ms: None,
    }
}

fn bootstrap(control: &ControlPlane) {
    control.create_repository(&repository()).unwrap();
    let (capsule, key) = signed_capsule();
    control.store_signed_capsule(&capsule, &key).unwrap();
}

fn add_runner(control: &ControlPlane) {
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            name: "trusted".to_owned(),
            region: Some("test".to_owned()),
            status: RunnerPoolStatus::Active,
            created_unix_ms: NOW,
        })
        .unwrap();
    control.register_runner(&runner(), NOW).unwrap();
    let inventory = ContentDigest::sha256(b"test enrolled inventory");
    let posture = authoritative_runner_posture_digest(&runner(), &inventory).unwrap();
    control
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO runner_enrollment_postures
                 (runner_id, inventory_digest, posture_digest, created_unix_ms)
                 VALUES ('runner-1', ?1, ?2, ?3)",
            params![inventory.as_str(), posture.as_str(), to_i64(NOW).unwrap()],
        )
        .unwrap();
}

fn add_runner_to_existing_pool(control: &ControlPlane, id: &str) {
    let mut value = runner();
    value.id = id.to_owned();
    let inventory = ContentDigest::sha256(format!("inventory:{id}"));
    control
        .register_runner_with_inventory(&value, &inventory, NOW)
        .unwrap();
}

fn planned_job(
    id: &str,
    needs: &[&str],
    trust: Trust,
    os: OperatingSystem,
    concurrency: Option<&str>,
) -> PlannedJob {
    PlannedJob {
        id: id.to_owned(),
        base_id: id.to_owned(),
        name: id.to_owned(),
        needs: needs.iter().map(|value| (*value).to_owned()).collect(),
        matrix: BTreeMap::new(),
        condition: None,
        trust,
        environment: None,
        runner: RunnerRequirements {
            os,
            arch: Architecture::Amd64,
            isolation: Isolation::Microvm,
            image: None,
            cpu: 1,
            memory_bytes: 1_024,
            storage_bytes: Some(1_024),
            region: Some("test".to_owned()),
            capabilities: vec!["kvm".to_owned()],
        },
        permissions: PermissionSet::default(),
        timeout_ms: 60_000,
        retries: 0,
        concurrency: concurrency.map(str::to_owned),
        variables: BTreeMap::new(),
        services: Vec::new(),
        steps: Vec::new(),
        finalizers: Vec::new(),
        finalizer_timeout_ms: 120_000,
        value_outputs: BTreeMap::new(),
        outputs: BTreeMap::new(),
    }
}

fn store_test_capsule(
    control: &ControlPlane,
    id: &str,
    mut capsule: ExecutionCapsule,
) -> SignedCapsuleRecord {
    capsule.compiler_version = format!("test:{id}");
    let mut seed = [0_u8; 32];
    for (index, byte) in id.bytes().enumerate() {
        seed[index % seed.len()] ^= byte;
    }
    let key = CapsuleSigningKey::from_seed(seed);
    let signature = key.sign_capsule(&capsule).unwrap();
    let record = SignedCapsuleRecord {
        id: id.to_owned(),
        repository_id: "repo-1".to_owned(),
        digest: signature.capsule_digest.clone(),
        canonical_capsule: capsule.canonical_bytes().unwrap(),
        signature,
        created_unix_ms: NOW,
    };
    control
        .store_signed_capsule(&record, &key.verifying_key())
        .unwrap();
    record
}

fn run_for_capsule(
    run_id: &str,
    capsule: &SignedCapsuleRecord,
    decoded: &ExecutionCapsule,
    created_unix_ms: u64,
) -> CreateRunRequest {
    CreateRunRequest {
        id: run_id.to_owned(),
        repository_id: "repo-1".to_owned(),
        capsule_id: capsule.id.clone(),
        priority: 0,
        remote: true,
        created_unix_ms,
        jobs: decoded
            .jobs
            .iter()
            .map(|planned| NewJob {
                id: format!("{run_id}-{}", planned.id),
                job_key: planned.id.clone(),
                attempt: 1,
                requirements: planned_scheduling_requirements(planned),
            })
            .collect(),
    }
}

fn audit_data(action: &str) -> AuditEventData {
    AuditEventData {
        observed_unix_ms: NOW,
        tenant_id: "tenant-1".to_owned(),
        actor: AuditPrincipal {
            kind: "user".to_owned(),
            id: "alice".to_owned(),
        },
        action: action.to_owned(),
        resource: AuditResource {
            kind: "run".to_owned(),
            id: "run-1".to_owned(),
        },
        result: "success".to_owned(),
        request_id: "request-1".to_owned(),
        decision_id: None,
        metadata: BTreeMap::new(),
    }
}

#[test]
fn audit_pages_return_at_most_one_hundred_newest_events_first() {
    let control = ControlPlane::open_in_memory("audit-page", NOW).unwrap();
    for index in 1..=105_u64 {
        let mut event = audit_data(if index.is_multiple_of(2) {
            "run.update"
        } else {
            "run.create"
        });
        event.observed_unix_ms = NOW + index;
        event.request_id = format!("request-{index}");
        control.append_audit_event(event).unwrap();
    }

    let first_page = control.audit_events_page(None, None, 100).unwrap();
    assert_eq!(first_page.len(), 100);
    assert_eq!(first_page.first().unwrap().sequence, 105);
    assert_eq!(first_page.last().unwrap().sequence, 6);

    let next_page = control
        .audit_events_page(None, Some(first_page.last().unwrap().sequence), 100)
        .unwrap();
    assert_eq!(
        next_page
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![5, 4, 3, 2, 1]
    );

    let tenant_page = control
        .audit_events_page_for_tenant("tenant-1", Some("run.update"), None, 3)
        .unwrap();
    assert_eq!(
        tenant_page
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![104, 102, 100]
    );
}

#[cfg(unix)]
#[test]
fn database_path_is_created_private_and_rejects_final_or_parent_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private.sqlite");
    let control = ControlPlane::open(&path, "installation-1", NOW).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    for suffix in ["-wal", "-shm"] {
        let sidecar = sqlite_sidecar_path(&path, suffix);
        if let Ok(metadata) = fs::metadata(sidecar) {
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        }
    }
    drop(control);

    let link = directory.path().join("database-link.sqlite");
    symlink(&path, &link).unwrap();
    assert!(matches!(
        ControlPlane::open(&link, "installation-1", NOW),
        Err(ControlPlaneError::UnsafeDatabasePath { .. })
    ));

    let real_parent = directory.path().join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = directory.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();
    assert!(matches!(
        ControlPlane::open(linked_parent.join("control.sqlite"), "installation-1", NOW),
        Err(ControlPlaneError::UnsafeDatabasePath { .. })
    ));
}

#[cfg(unix)]
#[test]
fn database_open_rejects_world_readable_files_and_insecure_sidecars() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("permissive.sqlite");
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o644);
    options.open(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        ControlPlane::open(&path, "installation-1", NOW),
        Err(ControlPlaneError::UnsafeDatabasePath { .. })
    ));

    fs::remove_file(&path).unwrap();
    ControlPlane::open(&path, "installation-1", NOW)
        .unwrap()
        .installation_fencing_epoch()
        .unwrap();
    let wal = sqlite_sidecar_path(&path, "-wal");
    if wal.exists() {
        fs::remove_file(&wal).unwrap();
    }
    options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o644);
    options.open(&wal).unwrap();
    fs::set_permissions(&wal, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        ControlPlane::open(&path, "installation-1", NOW),
        Err(ControlPlaneError::UnsafeDatabasePath { .. })
    ));
}

#[test]
fn restart_reopens_all_core_metadata_and_durable_work() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    {
        let control = ControlPlane::open(&path, "installation-1", NOW).unwrap();
        bootstrap(&control);
        let created = control
            .create_run_idempotent("create-run-1", &run_request("run-1", "job-1"))
            .unwrap();
        assert!(!created.replayed);
        control
            .enqueue_task(&DurableTask {
                id: "task-1".to_owned(),
                kind: "capsule".to_owned(),
                payload: json!({"repository_id": "repo-1"}),
                status: DurableTaskStatus::Pending,
                available_unix_ms: NOW,
                attempts: 0,
                lease_owner: None,
                lease_expires_unix_ms: None,
                last_error: None,
                created_unix_ms: NOW,
                completed_unix_ms: None,
            })
            .unwrap();
        control
            .create_variable_snapshot(
                "variables-1",
                "tenant-1",
                "repository:repo-1",
                1,
                [("MODE".to_owned(), json!("release"))]
                    .into_iter()
                    .collect(),
                NOW,
            )
            .unwrap();
        control
            .store_secret_metadata(&SecretMetadataReference {
                id: "secret-1".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                scope: "repository:repo-1".to_owned(),
                name: "registry-token".to_owned(),
                provider: "built-in".to_owned(),
                provider_reference: None,
                secret_type: "opaque".to_owned(),
                status: "active".to_owned(),
                current_version: Some(1),
                created_unix_ms: NOW,
                updated_unix_ms: NOW,
            })
            .unwrap();
        control
            .append_audit_event(audit_data("run.create"))
            .unwrap();
    }

    let reopened = ControlPlane::open(&path, "installation-1", NOW + 1).unwrap();
    assert_eq!(reopened.repository("repo-1").unwrap(), repository());
    assert_eq!(
        reopened.signed_capsule("capsule-1").unwrap().digest,
        signed_capsule().0.digest
    );
    assert_eq!(reopened.run("run-1").unwrap().status, RunState::Created);
    assert_eq!(
        reopened.task("task-1").unwrap().status,
        DurableTaskStatus::Pending
    );
    assert_eq!(
        reopened
            .latest_variable_snapshot("tenant-1", "repository:repo-1")
            .unwrap()
            .values["MODE"],
        json!("release")
    );
    assert_eq!(
        reopened.secret_metadata("secret-1").unwrap().name,
        "registry-token"
    );
    assert_eq!(reopened.audit_events().unwrap().len(), 1);
    assert!(matches!(
        ControlPlane::open(&path, "other-installation", NOW),
        Err(ControlPlaneError::InstallationMismatch { .. })
    ));
}

#[test]
fn run_pages_return_recent_runs_first_and_continue_without_gaps() {
    let control = ControlPlane::open_in_memory("installation-1", NOW).unwrap();
    bootstrap(&control);

    for (id, created_unix_ms) in [
        ("run-z-old", NOW + 1),
        ("run-m-middle", NOW + 2),
        ("run-a-new", NOW + 3),
    ] {
        let mut request = run_request(id, &format!("job-{id}"));
        request.created_unix_ms = created_unix_ms;
        control
            .create_run_idempotent(&format!("create-{id}"), &request)
            .unwrap();
    }

    let first_page = control
        .list_runs_page_for_tenant("tenant-1", Some("repo-1"), None, 2)
        .unwrap();
    assert_eq!(
        first_page
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        vec!["run-a-new", "run-m-middle"]
    );

    let second_page = control
        .list_runs_page_for_tenant("tenant-1", Some("repo-1"), Some(&first_page[1].id), 2)
        .unwrap();
    assert_eq!(
        second_page
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        vec!["run-z-old"]
    );
}

#[test]
fn run_creation_and_cancel_idempotency_replay_or_conflict_atomically() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    bootstrap(&control);
    let request = run_request("run-1", "job-1");
    let first = control.create_run_idempotent("same-key", &request).unwrap();
    let replay = control.create_run_idempotent("same-key", &request).unwrap();
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(first.value, replay.value);

    let mut changed = request.clone();
    changed.priority = 99;
    assert!(matches!(
        control.create_run_idempotent("same-key", &changed),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert_eq!(control.jobs_for_run("run-1").unwrap().len(), 1);

    let canceled = control
        .cancel_run_idempotent("cancel-key", "run-1", "operator", NOW + 1)
        .unwrap();
    assert_eq!(canceled.value.status, RunState::Canceled);
    assert!(!canceled.replayed);
    assert!(
        control
            .cancel_run_idempotent("cancel-key", "run-1", "operator", NOW + 2)
            .unwrap()
            .replayed
    );
    assert!(matches!(
        control.cancel_run_idempotent("cancel-key", "run-1", "different", NOW + 2),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
}

#[test]
fn remote_runs_require_every_exact_gate_and_record_one_shot_or_reusable_authorization() {
    let subject = ContentDigest::sha256(b"exact-approval-subject");
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    let (capsule, key) = signed_approval_capsule("capsule-both", true, true);
    let workflow = pending_approval(
        "approval-workflow",
        ApprovalKind::WorkflowDefinition,
        &subject,
        true,
    );
    let privileged = pending_approval(
        "approval-privileged",
        ApprovalKind::PrivilegedExecution,
        &subject,
        true,
    );
    control
        .store_compiled_capsule_idempotent(
            "capsule-both-key",
            &capsule,
            &key,
            &CapsuleApiMetadata {
                capsule_id: capsule.id.clone(),
                approval_subject_digest: subject.clone(),
                risk_score: 90,
            },
            &[workflow, privileged],
        )
        .unwrap();
    let request = approval_run_request("capsule-both", "run-both", "job-both", NOW + 3);
    let mut disguised_local = request.clone();
    disguised_local.id = "run-both-local".to_owned();
    disguised_local.jobs[0].id = "job-both-local".to_owned();
    disguised_local.remote = false;
    assert!(matches!(
        control.create_run_idempotent("run-both-local-key", &disguised_local),
        Err(ControlPlaneError::ApprovalRequired)
    ));
    assert!(control.run("run-both-local").is_err());
    assert!(matches!(
        control.create_run_idempotent("run-both-key", &request),
        Err(ControlPlaneError::ApprovalRequired)
    ));
    assert!(control.run("run-both").is_err());

    approve(&control, "approval-workflow", &subject, NOW + 1);
    assert!(matches!(
        control.create_run_idempotent("run-both-key", &request),
        Err(ControlPlaneError::ApprovalRequired)
    ));
    assert_eq!(
        control
            .approval_request("approval-workflow")
            .unwrap()
            .status,
        ApprovalStatus::Approved,
        "failed atomic admission must not consume an earlier gate"
    );
    approve(&control, "approval-privileged", &subject, NOW + 2);
    let created = control
        .create_run_idempotent("run-both-key", &request)
        .unwrap();
    assert!(!created.replayed);
    assert!(
        control
            .create_run_idempotent("run-both-key", &request)
            .unwrap()
            .replayed
    );
    for id in ["approval-workflow", "approval-privileged"] {
        assert_eq!(
            control.approval_request(id).unwrap().status,
            ApprovalStatus::Consumed
        );
    }
    let authorization_count: i64 = control
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM run_approval_authorizations WHERE run_id = 'run-both'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(authorization_count, 2);

    let reusable = ControlPlane::open_in_memory("reusable-installation", NOW).unwrap();
    reusable.create_repository(&repository()).unwrap();
    let (capsule, key) = signed_approval_capsule("capsule-reusable", false, true);
    let approval = pending_approval(
        "approval-reusable",
        ApprovalKind::PrivilegedExecution,
        &subject,
        false,
    );
    reusable
        .store_compiled_capsule_idempotent(
            "capsule-reusable-key",
            &capsule,
            &key,
            &CapsuleApiMetadata {
                capsule_id: capsule.id.clone(),
                approval_subject_digest: subject.clone(),
                risk_score: 90,
            },
            &[approval],
        )
        .unwrap();
    approve(&reusable, "approval-reusable", &subject, NOW + 1);
    for (offset, run_id, job_id) in [
        (2, "run-reusable-1", "job-reusable-1"),
        (3, "run-reusable-2", "job-reusable-2"),
    ] {
        reusable
            .create_run_idempotent(
                &format!("{run_id}-key"),
                &approval_run_request("capsule-reusable", run_id, job_id, NOW + offset),
            )
            .unwrap();
    }
    assert_eq!(
        reusable
            .approval_request("approval-reusable")
            .unwrap()
            .status,
        ApprovalStatus::Approved
    );
    let authorization_count: i64 = reusable
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM run_approval_authorizations
                 WHERE approval_id = 'approval-reusable'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(authorization_count, 2);

    let missing_workflow = ControlPlane::open_in_memory("missing-workflow", NOW).unwrap();
    missing_workflow.create_repository(&repository()).unwrap();
    let (capsule, key) = signed_approval_capsule("capsule-missing-workflow", true, true);
    let workflow = pending_approval(
        "missing-workflow-gate",
        ApprovalKind::WorkflowDefinition,
        &subject,
        true,
    );
    let privileged = pending_approval(
        "present-privileged-gate",
        ApprovalKind::PrivilegedExecution,
        &subject,
        true,
    );
    missing_workflow
        .store_compiled_capsule_idempotent(
            "missing-workflow-capsule-key",
            &capsule,
            &key,
            &CapsuleApiMetadata {
                capsule_id: capsule.id.clone(),
                approval_subject_digest: subject.clone(),
                risk_score: 90,
            },
            &[workflow, privileged],
        )
        .unwrap();
    approve(
        &missing_workflow,
        "present-privileged-gate",
        &subject,
        NOW + 1,
    );
    assert!(matches!(
        missing_workflow.create_run_idempotent(
            "missing-workflow-run-key",
            &approval_run_request(
                "capsule-missing-workflow",
                "run-missing-workflow",
                "job-missing-workflow",
                NOW + 2,
            ),
        ),
        Err(ControlPlaneError::ApprovalRequired)
    ));
}

#[test]
fn scm_dual_gate_continuation_is_durable_race_safe_and_run_bound() {
    let fixture = pending_scm_fixture();
    let replay_approvals = fixture
        .control
        .scm_pending_execution_approvals("scm-pending")
        .unwrap();
    let replay_analysis = fixture
        .control
        .scm_proposed_analysis_for_task("scm-origin")
        .unwrap();
    let replay = fixture
        .control
        .complete_scm_task_with_executions_idempotent(
            "scm-origin",
            "crashed-worker-restart",
            NOW + 1,
            "scm-origin-key",
            &[PreparedScmExecution {
                capsule: fixture.capsule.clone(),
                metadata: fixture.metadata.clone(),
                approvals: replay_approvals,
                run: fixture.run.clone(),
                continuation: Some(fixture.context.clone()),
                source_snapshot: None,
                scm_fetch_id: None,
            }],
            Some(&replay_analysis),
            &fixture.key,
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(
        fixture
            .control
            .scm_proposed_analysis_for_task("scm-origin")
            .unwrap()
            .proposed_capsule_id
            .as_deref(),
        Some("scm-proposed-capsule")
    );
    assert!(fixture.control.run("scm-run").is_err());
    for (index, approval_id) in ["scm-workflow-approval", "scm-privileged-approval"]
        .into_iter()
        .enumerate()
    {
        fixture
            .control
            .decide_approval_idempotent(
                &format!("scm-decision-{index}"),
                approval_id,
                ApprovalDecision {
                    actor_id: "reviewer".to_owned(),
                    decision: Decision::Approve,
                    reason: "reviewed exact SCM subject".to_owned(),
                    rule_id: "approval-rule".to_owned(),
                    subject_digest: fixture.subject.clone(),
                    decided_unix_ms: NOW + 2 + index as u64,
                },
                NOW + 2 + index as u64,
            )
            .unwrap();
    }

    let first = fixture
        .control
        .claim_task_by_kind(
            "continuation-worker-a",
            "scm.approval.continue",
            NOW + 4,
            1_000,
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        fixture
            .control
            .begin_scm_continuation(&first.id, "continuation-worker-a", "scm-pending", NOW + 4,)
            .unwrap(),
        ScmContinuationResolution::Ready(_)
    ));
    let committed = fixture
        .control
        .complete_scm_continuation_with_run_idempotent(
            &first.id,
            "continuation-worker-a",
            "scm-pending",
            NOW + 5,
            &fixture.capsule,
            &fixture.key,
            &fixture.metadata,
            &fixture.context,
            &fixture.run,
        )
        .unwrap();
    assert!(matches!(
        committed,
        ScmContinuationCommit::Run(IdempotentResult {
            replayed: false,
            ..
        })
    ));

    let second = fixture
        .control
        .claim_task_by_kind(
            "continuation-worker-b",
            "scm.approval.continue",
            NOW + 6,
            1_000,
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        fixture
            .control
            .begin_scm_continuation(&second.id, "continuation-worker-b", "scm-pending", NOW + 6,)
            .unwrap(),
        ScmContinuationResolution::RunCreated(_)
    ));
    assert_eq!(fixture.control.jobs_for_run("scm-run").unwrap().len(), 1);
    let connection = fixture.control.connection().unwrap();
    let (runs, authorizations): (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM runs WHERE id = 'scm-run'),
                        (SELECT COUNT(*) FROM run_approval_authorizations
                         WHERE run_id = 'scm-run')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((runs, authorizations), (1, 2));
    drop(connection);
    for approval_id in ["scm-workflow-approval", "scm-privileged-approval"] {
        assert_eq!(
            fixture
                .control
                .approval_request(approval_id)
                .unwrap()
                .status,
            ApprovalStatus::Consumed
        );
    }
}

#[test]
fn reusable_scm_approval_binds_exact_run_subject_and_can_be_scheduled() {
    let fixture = pending_scm_fixture_with_reusable_privileged_approval(true);
    for (index, approval_id, subject) in [
        (0_u64, "scm-workflow-approval", &fixture.subject),
        (
            1_u64,
            "scm-privileged-approval",
            &fixture.privileged_subject,
        ),
    ] {
        fixture
            .control
            .decide_approval_idempotent(
                &format!("reusable-scm-decision-{index}"),
                approval_id,
                ApprovalDecision {
                    actor_id: "reviewer".to_owned(),
                    decision: Decision::Approve,
                    reason: "reviewed repository capability".to_owned(),
                    rule_id: "approval-rule".to_owned(),
                    subject_digest: subject.clone(),
                    decided_unix_ms: NOW + 2 + index,
                },
                NOW + 2 + index,
            )
            .unwrap();
    }

    let task = fixture
        .control
        .claim_task_by_kind(
            "reusable-continuation-worker",
            "scm.approval.continue",
            NOW + 4,
            1_000,
        )
        .unwrap()
        .unwrap();
    let committed = fixture
        .control
        .complete_scm_continuation_with_run_idempotent(
            &task.id,
            "reusable-continuation-worker",
            "scm-pending",
            NOW + 5,
            &fixture.capsule,
            &fixture.key,
            &fixture.metadata,
            &fixture.context,
            &fixture.run,
        )
        .unwrap();
    assert!(matches!(committed, ScmContinuationCommit::Run(_)));

    let authorized_subject: String = fixture
        .control
        .connection()
        .unwrap()
        .query_row(
            "SELECT subject_digest FROM run_approval_authorizations
             WHERE run_id = 'scm-run' AND kind = 'privileged-execution'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(authorized_subject, fixture.subject.as_str());
    assert_ne!(authorized_subject, fixture.privileged_subject.as_str());

    // Reproduce the schema-32 row shape and prove the data migration repairs
    // already-queued work, not only newly admitted runs.
    let connection = fixture.control.connection().unwrap();
    connection
        .execute(
            "UPDATE run_approval_authorizations SET subject_digest = ?1
             WHERE run_id = 'scm-run' AND kind = 'privileged-execution'",
            [fixture.privileged_subject.as_str()],
        )
        .unwrap();
    connection.execute_batch(database::MIGRATION_33).unwrap();
    let repaired_subject: String = connection
        .query_row(
            "SELECT subject_digest FROM run_approval_authorizations
             WHERE run_id = 'scm-run' AND kind = 'privileged-execution'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(repaired_subject, fixture.subject.as_str());
    drop(connection);

    add_runner(&fixture.control);
    let lease = fixture
        .control
        .offer_next_lease_for_runner("runner-1", NOW + 6)
        .unwrap()
        .expect("an exact-bound reusable approval must be schedulable");
    assert_eq!(lease.job_id, "scm-job");
}

#[test]
fn scm_denial_and_replanning_tamper_close_without_runs() {
    let denied = pending_scm_fixture();
    denied
        .control
        .decide_approval_idempotent(
            "deny-scm",
            "scm-workflow-approval",
            ApprovalDecision {
                actor_id: "reviewer".to_owned(),
                decision: Decision::Deny,
                reason: "unsafe workflow".to_owned(),
                rule_id: "approval-rule".to_owned(),
                subject_digest: denied.subject.clone(),
                decided_unix_ms: NOW + 2,
            },
            NOW + 2,
        )
        .unwrap();
    let task = denied
        .control
        .claim_task_by_kind("deny-worker", "scm.approval.continue", NOW + 3, 1_000)
        .unwrap()
        .unwrap();
    assert!(matches!(
        denied
            .control
            .begin_scm_continuation(&task.id, "deny-worker", "scm-pending", NOW + 3)
            .unwrap(),
        ScmContinuationResolution::Closed(ScmPendingExecution {
            state: ScmPendingExecutionState::Denied,
            ..
        })
    ));
    assert!(denied.control.run("scm-run").is_err());

    let stale = pending_scm_fixture();
    for (index, approval_id) in ["scm-workflow-approval", "scm-privileged-approval"]
        .into_iter()
        .enumerate()
    {
        stale
            .control
            .decide_approval_idempotent(
                &format!("stale-decision-{index}"),
                approval_id,
                ApprovalDecision {
                    actor_id: "reviewer".to_owned(),
                    decision: Decision::Approve,
                    reason: "reviewed".to_owned(),
                    rule_id: "approval-rule".to_owned(),
                    subject_digest: stale.subject.clone(),
                    decided_unix_ms: NOW + 2 + index as u64,
                },
                NOW + 2 + index as u64,
            )
            .unwrap();
    }
    let task = stale
        .control
        .claim_task_by_kind("stale-worker", "scm.approval.continue", NOW + 4, 1_000)
        .unwrap()
        .unwrap();
    assert!(matches!(
        stale
            .control
            .begin_scm_continuation(&task.id, "stale-worker", "scm-pending", NOW + 4)
            .unwrap(),
        ScmContinuationResolution::Ready(_)
    ));
    let mut tampered_context = stale.context.clone();
    tampered_context.resolved_repository_actions = serde_json::json!({
        "ci/backport@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
            "program": {
                "kind": "component",
                "reference": "wasm://registry.example/backport@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "scm_api_url": "https://api.example.invalid",
                "signature_identity": "attacker@example.invalid",
                "wit_world": "runtrue:action/run@1.0.0"
            },
            "inputs": {}
        }
    });
    assert!(matches!(
        stale
            .control
            .complete_scm_continuation_with_run_idempotent(
                &task.id,
                "stale-worker",
                "scm-pending",
                NOW + 5,
                &stale.capsule,
                &stale.key,
                &stale.metadata,
                &tampered_context,
                &stale.run,
            )
            .unwrap(),
        ScmContinuationCommit::Closed(ScmPendingExecution {
            state: ScmPendingExecutionState::Stale,
            ..
        })
    ));
    assert!(stale.control.run("scm-run").is_err());
    assert!(stale.control.jobs_for_run("scm-run").unwrap().is_empty());

    let expired = pending_scm_fixture();
    let expiry_task = expired
        .control
        .claim_task_by_kind(
            "expiry-worker",
            "scm.approval.continue",
            NOW + 10_000,
            1_000,
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        expired
            .control
            .begin_scm_continuation(
                &expiry_task.id,
                "expiry-worker",
                "scm-pending",
                NOW + 10_000,
            )
            .unwrap(),
        ScmContinuationResolution::Closed(ScmPendingExecution {
            state: ScmPendingExecutionState::Expired,
            ..
        })
    ));
    assert!(expired.control.run("scm-run").is_err());
}

#[test]
fn policy_decisions_are_transactional_and_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("approvals.sqlite");
    let subject = ContentDigest::sha256(b"approval-subject");
    {
        let control = ControlPlane::open(&path, "installation", NOW).unwrap();
        bootstrap(&control);
        let rule = ApprovalRule {
            id: "release".to_owned(),
            required_approvals: 2,
            eligible_approvers: ["alice", "bob"].into_iter().map(str::to_owned).collect(),
            forbidden_approvers: BTreeSet::new(),
            one_shot: true,
        };
        let request = ApprovalRequest::create(
            "approval-1",
            ApprovalKind::PrivilegedExecution,
            subject.clone(),
            80,
            NOW,
            NOW + 100,
            rule,
        )
        .unwrap();
        control
            .create_approval_request("repo-1", "capsule-1", &request)
            .unwrap();
        for (offset, actor) in ["alice", "bob"].into_iter().enumerate() {
            let decided = control
                .decide_approval(
                    "approval-1",
                    ApprovalDecision {
                        actor_id: actor.to_owned(),
                        decision: Decision::Approve,
                        reason: "reviewed exact subject".to_owned(),
                        rule_id: "release".to_owned(),
                        subject_digest: subject.clone(),
                        decided_unix_ms: NOW + u64::try_from(offset).unwrap() + 1,
                    },
                    NOW + u64::try_from(offset).unwrap() + 1,
                )
                .unwrap();
            assert_eq!(decided.decisions.len(), offset + 1);
        }
        assert_eq!(
            control.approval_request("approval-1").unwrap().status,
            ApprovalStatus::Approved
        );
    }
    let reopened = ControlPlane::open(&path, "installation", NOW + 3).unwrap();
    let authorized = reopened
        .authorize_approval("approval-1", &subject, NOW + 3)
        .unwrap();
    assert_eq!(authorized.status, ApprovalStatus::Consumed);
}

#[test]
fn scm_task_capsule_run_and_completion_are_atomic_and_safe_mode_fenced() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    control
        .enqueue_task(&DurableTask {
            id: "scm-task".to_owned(),
            kind: "scm.event".to_owned(),
            payload: json!({"normalized_digest": ContentDigest::sha256(b"event")}),
            status: DurableTaskStatus::Pending,
            available_unix_ms: NOW,
            attempts: 0,
            lease_owner: None,
            lease_expires_unix_ms: None,
            last_error: None,
            created_unix_ms: NOW,
            completed_unix_ms: None,
        })
        .unwrap();
    control
        .claim_task_by_kind("scm-worker", "scm.event", NOW, 100)
        .unwrap()
        .unwrap();

    let mut execution = execution_capsule();
    execution.jobs.clear();
    execution.jobs.push(PlannedJob {
        id: "build".to_owned(),
        base_id: "build".to_owned(),
        name: "build".to_owned(),
        needs: Vec::new(),
        matrix: BTreeMap::new(),
        condition: None,
        trust: Trust::UntrustedOk,
        environment: None,
        runner: RunnerRequirements {
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation: Isolation::Microvm,
            image: None,
            cpu: 1,
            memory_bytes: 1_024,
            storage_bytes: None,
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
    });
    let signing_key = CapsuleSigningKey::from_seed([31_u8; 32]);
    let signature = signing_key.sign_capsule(&execution).unwrap();
    let capsule = SignedCapsuleRecord {
        id: "scm-capsule".to_owned(),
        repository_id: "repo-1".to_owned(),
        digest: signature.capsule_digest.clone(),
        canonical_capsule: execution.canonical_bytes().unwrap(),
        signature,
        created_unix_ms: NOW,
    };
    let metadata = CapsuleApiMetadata {
        capsule_id: capsule.id.clone(),
        approval_subject_digest: ContentDigest::sha256(b"approval subject"),
        risk_score: 0,
    };
    let request = CreateRunRequest {
        id: "scm-run".to_owned(),
        repository_id: "repo-1".to_owned(),
        capsule_id: capsule.id.clone(),
        priority: 0,
        remote: true,
        created_unix_ms: NOW,
        jobs: vec![NewJob {
            id: "scm-job".to_owned(),
            job_key: "build".to_owned(),
            attempt: 1,
            requirements: SchedulingRequirements {
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Microvm,
                cpu: 1,
                memory_bytes: 1_024,
                storage_bytes: 0,
                region: None,
                required_capabilities: BTreeSet::new(),
                allowed_pools: BTreeSet::new(),
            },
        }],
    };

    control.enter_restore_safe_mode(NOW + 1).unwrap();
    assert!(matches!(
        control.complete_scm_task_with_run_idempotent(
            "scm-task",
            "scm-worker",
            NOW + 2,
            "scm-safe-mode",
            &capsule,
            &signing_key.verifying_key(),
            &metadata,
            &request,
        ),
        Err(ControlPlaneError::InstallationSafeMode)
    ));
    assert!(matches!(
        control.signed_capsule("scm-capsule"),
        Err(ControlPlaneError::NotFound { .. })
    ));
    assert!(matches!(
        control.run("scm-run"),
        Err(ControlPlaneError::NotFound { .. })
    ));
    assert_eq!(
        control.task("scm-task").unwrap().status,
        DurableTaskStatus::Claimed
    );

    control.leave_restore_safe_mode(2).unwrap();
    let created = control
        .complete_scm_task_with_run_idempotent(
            "scm-task",
            "scm-worker",
            NOW + 3,
            "scm-safe-mode",
            &capsule,
            &signing_key.verifying_key(),
            &metadata,
            &request,
        )
        .unwrap();
    assert!(!created.replayed);
    assert_eq!(created.value.id, "scm-run");
    assert_eq!(
        control.task("scm-task").unwrap().status,
        DurableTaskStatus::Completed
    );
    assert_eq!(control.jobs_for_run("scm-run").unwrap().len(), 1);
    assert_eq!(
        control.capsule_api_metadata("scm-capsule").unwrap(),
        metadata
    );
}

#[test]
fn tenant_collection_queries_filter_in_sql_across_control_plane_resources() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    let first_repository = repository();
    let mut second_repository = first_repository.clone();
    second_repository.id = "repo-2".to_owned();
    second_repository.tenant_id = "tenant-2".to_owned();
    second_repository.name = "runtrue-two".to_owned();
    control.create_repository(&first_repository).unwrap();
    control.create_repository(&second_repository).unwrap();

    let (first_capsule, key) = signed_capsule();
    control.store_signed_capsule(&first_capsule, &key).unwrap();
    let mut second_capsule = first_capsule;
    second_capsule.id = "capsule-2".to_owned();
    second_capsule.repository_id = "repo-2".to_owned();
    control.store_signed_capsule(&second_capsule, &key).unwrap();
    control
        .create_run_idempotent("tenant-run-1", &run_request("run-1", "job-1"))
        .unwrap();
    let mut second_run = run_request("run-2", "job-2");
    second_run.repository_id = "repo-2".to_owned();
    second_run.capsule_id = "capsule-2".to_owned();
    control
        .create_run_idempotent("tenant-run-2", &second_run)
        .unwrap();

    let approval_rule = ApprovalRule {
        id: "tenant-rule".to_owned(),
        required_approvals: 1,
        eligible_approvers: BTreeSet::from(["reviewer".to_owned()]),
        forbidden_approvers: BTreeSet::new(),
        one_shot: true,
    };
    for (id, repository_id, capsule_id) in [
        ("approval-tenant-1", "repo-1", "capsule-1"),
        ("approval-tenant-2", "repo-2", "capsule-2"),
    ] {
        let request = ApprovalRequest::create(
            id,
            ApprovalKind::WorkflowDefinition,
            ContentDigest::sha256(id.as_bytes()),
            10,
            NOW,
            NOW + 100,
            approval_rule.clone(),
        )
        .unwrap();
        control
            .create_approval_request(repository_id, capsule_id, &request)
            .unwrap();
    }

    for (id, tenant_id) in [("pool-1", "tenant-1"), ("pool-2", "tenant-2")] {
        control
            .create_runner_pool(&RunnerPoolRecord {
                id: id.to_owned(),
                tenant_id: tenant_id.to_owned(),
                name: id.to_owned(),
                region: None,
                status: RunnerPoolStatus::Active,
                created_unix_ms: NOW,
            })
            .unwrap();
    }
    let first_runner = runner();
    control.register_runner(&first_runner, NOW).unwrap();
    let mut second_runner = first_runner;
    second_runner.id = "runner-2".to_owned();
    second_runner.tenant_id = "tenant-2".to_owned();
    second_runner.pool_id = "pool-2".to_owned();
    control.register_runner(&second_runner, NOW).unwrap();

    control
        .append_audit_event(audit_data("tenant-one"))
        .unwrap();
    let mut second_audit = audit_data("tenant-two");
    second_audit.tenant_id = "tenant-2".to_owned();
    second_audit.request_id = "request-2".to_owned();
    control.append_audit_event(second_audit).unwrap();

    assert_eq!(
        control
            .list_repositories_for_tenant("tenant-1")
            .unwrap()
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>(),
        vec!["repo-1"]
    );
    assert_eq!(
        control
            .list_runs_page_for_tenant("tenant-1", None, None, 10)
            .unwrap()
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>(),
        vec!["run-1"]
    );
    assert_eq!(
        control
            .list_approval_requests_page_for_tenant("tenant-1", None, None, 10)
            .unwrap()
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>(),
        vec!["approval-tenant-1"]
    );
    assert_eq!(
        control
            .list_runner_pools_for_tenant("tenant-1")
            .unwrap()
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>(),
        vec!["pool-1"]
    );
    assert_eq!(
        control
            .list_runners_for_tenant("tenant-1")
            .unwrap()
            .into_iter()
            .map(|record| record.runner.id)
            .collect::<Vec<_>>(),
        vec!["runner-1"]
    );
    assert_eq!(
        control
            .audit_events_page_for_tenant("tenant-1", None, None, 10)
            .unwrap()
            .into_iter()
            .map(|event| event.data.action)
            .collect::<Vec<_>>(),
        vec!["tenant-one"]
    );
}

#[test]
fn approval_request_pages_are_newest_first_with_stable_cursors() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    let (capsule, key) = signed_capsule();
    control.store_signed_capsule(&capsule, &key).unwrap();
    let rule = ApprovalRule {
        id: "ordered-approvals".to_owned(),
        required_approvals: 1,
        eligible_approvers: BTreeSet::from(["reviewer".to_owned()]),
        forbidden_approvers: BTreeSet::new(),
        one_shot: false,
    };
    for (id, created_unix_ms) in [("approval-z-older", NOW), ("approval-a-newer", NOW + 1)] {
        let request = ApprovalRequest::create(
            id,
            ApprovalKind::PrivilegedExecution,
            ContentDigest::sha256(id.as_bytes()),
            100,
            created_unix_ms,
            created_unix_ms + 100,
            rule.clone(),
        )
        .unwrap();
        control
            .create_approval_request("repo-1", "capsule-1", &request)
            .unwrap();
    }

    let first = control
        .list_approval_requests_page_for_tenant("tenant-1", Some("pending"), None, 1)
        .unwrap();
    assert_eq!(first[0].id, "approval-a-newer");
    let second = control
        .list_approval_requests_page_for_tenant("tenant-1", Some("pending"), Some(&first[0].id), 1)
        .unwrap();
    assert_eq!(second[0].id, "approval-z-older");
}

#[test]
fn repository_workflow_directory_is_tenant_scoped_and_canonical() {
    let control = ControlPlane::open_in_memory("repository-workflow-directory", NOW).unwrap();
    control.create_repository(&repository()).unwrap();

    assert_eq!(
        control
            .repository_workflow_directory("tenant-1", "repo-1")
            .unwrap(),
        None
    );
    assert_eq!(
        control
            .set_repository_workflow_directory("tenant-1", "repo-1", "automation/workflows", NOW,)
            .unwrap(),
        "automation/workflows"
    );
    assert_eq!(
        control
            .repository_workflow_directory("tenant-1", "repo-1")
            .unwrap()
            .as_deref(),
        Some("automation/workflows")
    );
    assert_eq!(
        control
            .repository_workflow_directory("tenant-2", "repo-1")
            .unwrap(),
        None
    );
    assert!(matches!(
        control.set_repository_workflow_directory(
            "tenant-1",
            "repo-1",
            "./automation/workflows",
            NOW + 1,
        ),
        Err(ControlPlaneError::InvalidInput(_))
    ));
    assert!(matches!(
        control.set_repository_workflow_directory("tenant-1", "repo-1", "../workflows", NOW + 1,),
        Err(ControlPlaneError::InvalidInput(_))
    ));
    assert!(matches!(
        control.set_repository_workflow_directory(
            "tenant-2",
            "repo-1",
            "automation/workflows",
            NOW + 1,
        ),
        Err(ControlPlaneError::NotFound { .. })
    ));
}

#[test]
fn remote_dag_queues_roots_unlocks_successors_and_skips_failed_descendants() {
    let control = ControlPlane::open_in_memory("dag", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    let mut decoded = execution_capsule();
    decoded.jobs = vec![
        planned_job(
            "root",
            &[],
            Trust::UntrustedOk,
            OperatingSystem::Linux,
            None,
        ),
        planned_job(
            "child",
            &["root"],
            Trust::UntrustedOk,
            OperatingSystem::Linux,
            None,
        ),
        planned_job(
            "grandchild",
            &["child"],
            Trust::UntrustedOk,
            OperatingSystem::Linux,
            None,
        ),
    ];
    let capsule = store_test_capsule(&control, "capsule-dag", decoded.clone());
    let request = run_for_capsule("run-dag", &capsule, &decoded, NOW);
    control
        .create_run_idempotent("run-dag-key", &request)
        .unwrap();
    let states = control
        .jobs_for_run("run-dag")
        .unwrap()
        .into_iter()
        .map(|job| (job.job_key, job.status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(states["root"], JobState::Queued);
    assert_eq!(states["child"], JobState::Created);
    assert_eq!(states["grandchild"], JobState::Created);

    let root = "run-dag-root";
    for (offset, state) in [
        JobState::Preparing,
        JobState::Running,
        JobState::Finalizing,
        JobState::Succeeded,
    ]
    .into_iter()
    .enumerate()
    {
        control
            .transition_job_state(root, state, NOW + 1 + offset as u64)
            .unwrap();
    }
    assert_eq!(
        control
            .jobs_for_run("run-dag")
            .unwrap()
            .into_iter()
            .find(|job| job.job_key == "child")
            .unwrap()
            .status,
        JobState::Queued
    );
    control
        .transition_job_state("run-dag-child", JobState::Preparing, NOW + 10)
        .unwrap();
    control
        .transition_job_state("run-dag-child", JobState::Failed, NOW + 11)
        .unwrap();
    let states = control
        .jobs_for_run("run-dag")
        .unwrap()
        .into_iter()
        .map(|job| (job.job_key, job.status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(states["grandchild"], JobState::Skipped);
    assert_eq!(control.run("run-dag").unwrap().status, RunState::Failed);
}

#[test]
fn source_trust_and_unsupported_retries_fail_before_queue_and_propagate() {
    let control = ControlPlane::open_in_memory("trust-floor", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    let mut decoded = execution_capsule();
    decoded.context.source_trust = runtrue_workflow_ir::SourceTrust::Untrusted;
    let mut privileged = planned_job(
        "privileged",
        &[],
        Trust::TrustedOnly,
        OperatingSystem::Linux,
        None,
    );
    privileged.retries = 1;
    decoded.jobs = vec![
        privileged,
        planned_job(
            "dependent",
            &["privileged"],
            Trust::UntrustedOk,
            OperatingSystem::Linux,
            None,
        ),
    ];
    let capsule = store_test_capsule(&control, "capsule-trust-floor", decoded.clone());
    let request = run_for_capsule("run-trust-floor", &capsule, &decoded, NOW);
    let created = control
        .create_run_idempotent("run-trust-floor-key", &request)
        .unwrap();
    assert_eq!(created.value.status, RunState::Failed);
    let states = control
        .jobs_for_run("run-trust-floor")
        .unwrap()
        .into_iter()
        .map(|job| (job.job_key, job.status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(states["privileged"], JobState::BlockedPolicy);
    assert_eq!(states["dependent"], JobState::Skipped);
}

#[test]
fn schema_one_is_upgraded_through_scm_check_schema_twenty_two() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("upgrade.sqlite");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch(MIGRATION_1).unwrap();
    connection
        .execute(
            "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (1, ?1)",
            [to_i64(NOW).unwrap()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO installation_state(singleton, installation_id, fencing_epoch)
                 VALUES (1, 'installation', 1)",
            [],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let control = ControlPlane::open(&path, "installation", NOW + 1).unwrap();
    assert!(matches!(
        control.variable("tenant", "repository:repo", "missing"),
        Err(ControlPlaneError::NotFound { .. })
    ));
    drop(control);
    let connection = Connection::open(&path).unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    let migrations: Vec<u32> = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(migrations, (1..=CURRENT_SCHEMA_VERSION).collect::<Vec<_>>());
    let credential_taint_column: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('leases')
                WHERE name = 'terminal_credential_taint'
            )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(credential_taint_column);
}

#[test]
fn file_control_plane_uses_a_non_detachable_rollback_journal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control-plane.sqlite");
    let control = ControlPlane::open(&path, "journal-safety", NOW).unwrap();

    let connection = control.connection().unwrap();
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode, "truncate");
    drop(connection);

    control.create_repository(&repository()).unwrap();
    let observer = Connection::open(&path).unwrap();
    let visible: u64 = observer
        .query_row(
            "SELECT COUNT(*) FROM repositories WHERE id = 'repo-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(visible, 1);
    assert!(!path.with_extension("sqlite-wal").exists());
}

#[test]
fn shipped_schema_sixteen_upgrades_cache_trust_before_artifact_catalog() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-sixteen.sqlite");
    let connection = Connection::open(&path).unwrap();
    for (offset, migration) in [
        MIGRATION_1,
        MIGRATION_2,
        MIGRATION_3,
        MIGRATION_4,
        MIGRATION_5,
        MIGRATION_6,
        MIGRATION_7,
        MIGRATION_8,
        MIGRATION_9,
        MIGRATION_10,
        MIGRATION_11,
        MIGRATION_12,
        MIGRATION_13,
        MIGRATION_14,
        MIGRATION_15,
        MIGRATION_16,
    ]
    .iter()
    .enumerate()
    {
        connection.execute_batch(migration).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (?1, ?2)",
                params![i64::try_from(offset + 1).unwrap(), to_i64(NOW).unwrap()],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO installation_state(singleton, installation_id, fencing_epoch)
                 VALUES (1, 'installation', 1)",
            [],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    drop(ControlPlane::open(&path, "installation", NOW + 1).unwrap());
    let connection = Connection::open(&path).unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    for table in [
        "cache_trust_generations",
        "cache_trust_current_heads",
        "cache_promotion_journal",
        "cache_access_observations",
    ] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(
                        SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
                     )",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present, "missing schema-17 table {table}");
    }
}

#[test]
fn shipped_schema_seventeen_upgrades_artifact_catalog_and_download_roots() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-seventeen.sqlite");
    let connection = Connection::open(&path).unwrap();
    for (offset, migration) in [
        MIGRATION_1,
        MIGRATION_2,
        MIGRATION_3,
        MIGRATION_4,
        MIGRATION_5,
        MIGRATION_6,
        MIGRATION_7,
        MIGRATION_8,
        MIGRATION_9,
        MIGRATION_10,
        MIGRATION_11,
        MIGRATION_12,
        MIGRATION_13,
        MIGRATION_14,
        MIGRATION_15,
        MIGRATION_16,
        MIGRATION_17,
    ]
    .iter()
    .enumerate()
    {
        connection.execute_batch(migration).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (?1, ?2)",
                params![i64::try_from(offset + 1).unwrap(), to_i64(NOW).unwrap()],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO installation_state(singleton, installation_id, fencing_epoch)
                 VALUES (1, 'installation', 1)",
            [],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    drop(ControlPlane::open(&path, "installation", NOW + 1).unwrap());
    let connection = Connection::open(&path).unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    for table in [
        "artifacts_catalog",
        "artifact_download_tickets",
        "artifact_scan_results",
        "artifact_promotions",
        "report_summaries",
    ] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(
                        SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
                     )",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present, "missing schema-18 table {table}");
    }
}

#[test]
fn shipped_schema_eighteen_upgrades_output_lifecycle_before_schema_twenty() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-eighteen.sqlite");
    let connection = Connection::open(&path).unwrap();
    for (offset, migration) in [
        MIGRATION_1,
        MIGRATION_2,
        MIGRATION_3,
        MIGRATION_4,
        MIGRATION_5,
        MIGRATION_6,
        MIGRATION_7,
        MIGRATION_8,
        MIGRATION_9,
        MIGRATION_10,
        MIGRATION_11,
        MIGRATION_12,
        MIGRATION_13,
        MIGRATION_14,
        MIGRATION_15,
        MIGRATION_16,
        MIGRATION_17,
        MIGRATION_18,
    ]
    .iter()
    .enumerate()
    {
        connection.execute_batch(migration).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (?1, ?2)",
                params![i64::try_from(offset + 1).unwrap(), to_i64(NOW).unwrap()],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO installation_state(singleton, installation_id, fencing_epoch)
                 VALUES (1, 'installation', 1)",
            [],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    drop(ControlPlane::open(&path, "installation", NOW + 1).unwrap());
    let connection = Connection::open(&path).unwrap();
    for table in [
        "tenant_storage_quotas",
        "tenant_storage_reservations",
        "artifact_scan_journal",
        "artifact_promotion_bindings",
        "backup_pins",
        "lifecycle_gc_control",
        "lifecycle_gc_marks",
        "lifecycle_gc_candidates",
        "lifecycle_gc_cycles",
    ] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(
                        SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
                     )",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present, "missing schema-19 table {table}");
    }
}

#[test]
fn shipped_schema_twelve_upgrades_completion_binding_tables() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-twelve.sqlite");
    let connection = Connection::open(&path).unwrap();
    for (offset, migration) in [
        MIGRATION_1,
        MIGRATION_2,
        MIGRATION_3,
        MIGRATION_4,
        MIGRATION_5,
        MIGRATION_6,
        MIGRATION_7,
        MIGRATION_8,
        MIGRATION_9,
        MIGRATION_10,
        MIGRATION_11,
        MIGRATION_12,
    ]
    .iter()
    .enumerate()
    {
        connection.execute_batch(migration).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (?1, ?2)",
                params![i64::try_from(offset + 1).unwrap(), to_i64(NOW).unwrap()],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO installation_state(singleton, installation_id, fencing_epoch)
                 VALUES (1, 'installation', 1)",
            [],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    drop(ControlPlane::open(&path, "installation", NOW + 1).unwrap());
    let connection = Connection::open(&path).unwrap();
    for table in ["runner_data_commits", "job_result_objects"] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(
                        SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
                     )",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present, "missing schema-13 table {table}");
    }
}

#[test]
fn shipped_schema_fifteen_upgrades_github_source_fetch_journal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-fifteen.sqlite");
    let connection = Connection::open(&path).unwrap();
    for (offset, migration) in [
        MIGRATION_1,
        MIGRATION_2,
        MIGRATION_3,
        MIGRATION_4,
        MIGRATION_5,
        MIGRATION_6,
        MIGRATION_7,
        MIGRATION_8,
        MIGRATION_9,
        MIGRATION_10,
        MIGRATION_11,
        MIGRATION_12,
        MIGRATION_13,
        MIGRATION_14,
        MIGRATION_15,
    ]
    .iter()
    .enumerate()
    {
        connection.execute_batch(migration).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (?1, ?2)",
                params![i64::try_from(offset + 1).unwrap(), to_i64(NOW).unwrap()],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO installation_state(singleton, installation_id, fencing_epoch)
                 VALUES (1, 'installation', 1)",
            [],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    drop(ControlPlane::open(&path, "installation", NOW + 1).unwrap());
    let connection = Connection::open(&path).unwrap();
    for table in [
        "scm_installations",
        "scm_repository_links",
        "scm_source_fetches",
    ] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(
                        SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
                     )",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present, "missing schema-16 table {table}");
    }
}

#[test]
fn source_snapshot_binding_is_durable_exact_and_tenant_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("source.sqlite");
    let control = ControlPlane::open(&database, "source-test", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    let tree_digest = ContentDigest::sha256(b"exact source tree");
    let mut decoded = execution_capsule();
    decoded.context.source_tree_digest = Some(tree_digest.clone());
    let mut policy_blocked = decoded.jobs[0].clone();
    policy_blocked.id = "trusted".to_owned();
    policy_blocked.base_id = "trusted".to_owned();
    policy_blocked.name = "trusted".to_owned();
    policy_blocked.trust = Trust::TrustedOnly;
    decoded.jobs.push(policy_blocked);
    let capsule = store_test_capsule(&control, "source-capsule", decoded.clone());
    let run = run_for_capsule("source-run", &capsule, &decoded, NOW + 1);
    control
        .create_run_idempotent("source-run-key", &run)
        .unwrap();
    let states = control
        .jobs_for_run(&run.id)
        .unwrap()
        .into_iter()
        .map(|job| (job.job_key, job.status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(states["build"], JobState::Created);
    assert_eq!(states["trusted"], JobState::BlockedPolicy);
    assert!(control.run_source_snapshot("tenant-1", &run.id).is_err());
    drop(control);

    let control = ControlPlane::open(&database, "source-test", NOW + 2).unwrap();
    let states = control
        .jobs_for_run(&run.id)
        .unwrap()
        .into_iter()
        .map(|job| (job.job_key, job.status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(states["build"], JobState::Created);
    assert_eq!(states["trusted"], JobState::BlockedPolicy);
    let wrong_commit = SourceSnapshotRecord {
        id: "source-snapshot-wrong-commit".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        commit_sha: "fedcba9876543210".to_owned(),
        tree_manifest_digest: tree_digest.clone(),
        state: SourceSnapshotState::Building,
        created_unix_ms: NOW,
        verified_unix_ms: None,
    };
    control.create_source_snapshot(&wrong_commit).unwrap();
    control
        .mark_source_snapshot_ready("tenant-1", &wrong_commit.id, &tree_digest, NOW + 2)
        .unwrap();
    assert!(matches!(
        control.bind_run_source_snapshot(
            "tenant-1",
            &run.id,
            &wrong_commit.id,
            &capsule.digest,
            NOW + 3,
        ),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert_eq!(
        control
            .jobs_for_run(&run.id)
            .unwrap()
            .into_iter()
            .find(|job| job.job_key == "build")
            .unwrap()
            .status,
        JobState::Created
    );
    let snapshot = SourceSnapshotRecord {
        id: "source-snapshot-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        commit_sha: decoded.context.source_commit.clone(),
        tree_manifest_digest: tree_digest.clone(),
        state: SourceSnapshotState::Building,
        created_unix_ms: NOW,
        verified_unix_ms: None,
    };
    assert!(!control.create_source_snapshot(&snapshot).unwrap().replayed);
    assert!(control.create_source_snapshot(&snapshot).unwrap().replayed);
    control
        .mark_source_snapshot_ready("tenant-1", &snapshot.id, &tree_digest, NOW + 2)
        .unwrap();
    let first = control
        .bind_run_source_snapshot("tenant-1", &run.id, &snapshot.id, &capsule.digest, NOW + 3)
        .unwrap();
    assert!(!first.replayed);
    let states = control
        .jobs_for_run(&run.id)
        .unwrap()
        .into_iter()
        .map(|job| (job.job_key, job.status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(states["build"], JobState::Queued);
    assert_eq!(states["trusted"], JobState::BlockedPolicy);
    assert!(
        control
            .bind_run_source_snapshot("tenant-1", &run.id, &snapshot.id, &capsule.digest, NOW + 3,)
            .unwrap()
            .replayed
    );
    assert!(matches!(
        control.bind_run_source_snapshot(
            "other-tenant",
            &run.id,
            &snapshot.id,
            &capsule.digest,
            NOW + 3,
        ),
        Err(ControlPlaneError::NotFound { .. })
    ));

    add_runner(&control);
    let lease = control
        .create_lease(
            "source-lease",
            "source-run-build",
            "runner-1",
            NOW + 4,
            NOW + 20,
            NOW + 100,
        )
        .unwrap();
    control
        .accept_lease(
            &lease.id,
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            NOW + 5,
        )
        .unwrap();
    let ticket = IssueRunnerSourceTicket {
        id: "source-ticket-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        runner_id: "runner-1".to_owned(),
        execution_lease_id: lease.id.clone(),
        fencing_generation: lease.fencing_generation,
        job_id: lease.job_id.clone(),
        job_attempt: 1,
        maximum_bytes: 1024 * 1024,
        issued_unix_ms: NOW + 6,
        expires_unix_ms: NOW + 50,
    };
    assert!(
        !control
            .issue_runner_source_ticket(&ticket)
            .unwrap()
            .replayed
    );
    assert!(
        control
            .issue_runner_source_ticket(&ticket)
            .unwrap()
            .replayed
    );
    let mut stale = ticket.clone();
    stale.id = "stale-source-ticket".to_owned();
    stale.fencing_generation += 1;
    assert!(matches!(
        control.issue_runner_source_ticket(&stale),
        Err(ControlPlaneError::RunnerBrokerBindingMismatch)
            | Err(ControlPlaneError::StaleLeaseGeneration { .. })
    ));
    let mut other_tenant = ticket.clone();
    other_tenant.id = "other-tenant-source-ticket".to_owned();
    other_tenant.tenant_id = "tenant-2".to_owned();
    assert!(matches!(
        control.issue_runner_source_ticket(&other_tenant),
        Err(ControlPlaneError::NotFound { .. })
    ));
    let mut substitution = ticket.clone();
    substitution.maximum_bytes += 1;
    assert!(matches!(
        control.issue_runner_source_ticket(&substitution),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    let download = RunnerSourceDownload {
        ticket_id: ticket.id.clone(),
        object_digest: ContentDigest::sha256(b"source object"),
        runner_id: ticket.runner_id.clone(),
        execution_lease_id: ticket.execution_lease_id.clone(),
        fencing_generation: ticket.fencing_generation,
        job_id: ticket.job_id.clone(),
        job_attempt: ticket.job_attempt,
        size_bytes: 100,
        recorded_unix_ms: NOW + 7,
    };
    assert!(!control.begin_runner_source_download(&download).unwrap());
    control.finish_runner_source_download(&download).unwrap();
    assert!(control.begin_runner_source_download(&download).unwrap());
    let mut cross_runner = download.clone();
    cross_runner.runner_id = "runner-other".to_owned();
    assert!(matches!(
        control.begin_runner_source_download(&cross_runner),
        Err(ControlPlaneError::WrongRunner) | Err(ControlPlaneError::RunnerBrokerBindingMismatch)
    ));
    let mut quota = download.clone();
    quota.object_digest = ContentDigest::sha256(b"quota substitution");
    quota.size_bytes = ticket.maximum_bytes;
    assert!(matches!(
        control.begin_runner_source_download(&quota),
        Err(ControlPlaneError::RunnerBrokerBindingMismatch)
    ));
    drop(control);
    let reopened = ControlPlane::open(&database, "source-test", NOW + 7).unwrap();
    let states = reopened
        .jobs_for_run(&run.id)
        .unwrap()
        .into_iter()
        .map(|job| (job.job_key, job.status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(states["build"], JobState::Preparing);
    assert_eq!(states["trusted"], JobState::BlockedPolicy);
    assert_eq!(
        reopened
            .run_source_snapshot("tenant-1", &run.id)
            .unwrap()
            .source_snapshot_id,
        snapshot.id
    );
    assert!(
        reopened
            .issue_runner_source_ticket(&ticket)
            .unwrap()
            .replayed
    );
    assert!(reopened.begin_runner_source_download(&download).unwrap());
}

#[test]
fn github_installation_links_and_fetch_replay_are_exact_and_tenant_scoped() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    let installation = ScmInstallationRecord {
        id: "github-installation-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        provider: "github".to_owned(),
        external_id: "9001".to_owned(),
        credential_reference: "provider://github-app/9001".to_owned(),
        permissions: json!({
            "checks": "write",
            "contents": "read",
            "metadata": "read",
            "pull_requests": "read"
        }),
        status: "active".to_owned(),
        created_unix_ms: NOW,
        updated_unix_ms: NOW,
    };
    assert!(
        !control
            .create_scm_installation(&installation)
            .unwrap()
            .replayed
    );
    assert!(
        control
            .create_scm_installation(&installation)
            .unwrap()
            .replayed
    );
    assert_eq!(
        control
            .scm_installation_for_tenant("tenant-1", "github-installation-1")
            .unwrap(),
        installation
    );
    assert!(matches!(
        control.scm_installation_for_tenant("tenant-other", "github-installation-1"),
        Err(ControlPlaneError::NotFound { .. })
    ));
    let link = ScmRepositoryLinkRecord {
        repository_id: "repo-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        installation_id: installation.id.clone(),
        external_repository_id: "42".to_owned(),
        clone_url: "https://github.com/octo/runtrue.git".to_owned(),
        status: "active".to_owned(),
        created_unix_ms: NOW,
        updated_unix_ms: NOW,
    };
    control.link_scm_repository(&link).unwrap();
    assert!(control
        .scm_webhook_events_for_repository("tenant-1", "repo-1", None, 50)
        .unwrap()
        .is_empty());
    let (resolved, _, resolved_link) = control
        .github_repository_for_event("9001", "42", "octo", "runtrue")
        .unwrap();
    assert_eq!(resolved.id, "repo-1");
    assert_eq!(resolved_link, link);
    assert!(matches!(
        control.github_repository_for_event("9001", "attacker", "octo", "runtrue"),
        Err(ControlPlaneError::NotFound { .. })
    ));
    let mut other = repository();
    other.id = "repo-other-tenant".to_owned();
    other.tenant_id = "tenant-other".to_owned();
    control.create_repository(&other).unwrap();
    let mut cross_tenant = link.clone();
    cross_tenant.repository_id = other.id;
    cross_tenant.tenant_id = other.tenant_id;
    cross_tenant.external_repository_id = "84".to_owned();
    assert!(matches!(
        control.link_scm_repository(&cross_tenant),
        Err(ControlPlaneError::NotFound { .. })
    ));

    control
        .enqueue_task(&DurableTask {
            id: "github-fetch-task".to_owned(),
            kind: "scm.event".to_owned(),
            payload: json!({"bounded": true}),
            status: DurableTaskStatus::Pending,
            available_unix_ms: NOW,
            attempts: 0,
            lease_owner: None,
            lease_expires_unix_ms: None,
            last_error: None,
            created_unix_ms: NOW,
            completed_unix_ms: None,
        })
        .unwrap();
    let request = ReserveScmSourceFetch {
        id: "fetch-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        installation_id: installation.id.clone(),
        origin_task_id: "github-fetch-task".to_owned(),
        normalized_event_digest: ContentDigest::sha256(b"event"),
        source_commit: "a".repeat(40),
        base_commit: Some("b".repeat(40)),
        origin_digest: ContentDigest::sha256(link.clone_url.as_bytes()),
        now_unix_ms: NOW,
    };
    assert!(!control.reserve_scm_source_fetch(&request).unwrap().replayed);
    let replay = control.reserve_scm_source_fetch(&request).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.value.attempts, 2);
    let mut substituted = request;
    substituted.origin_digest = ContentDigest::sha256(b"https://attacker.invalid/repo.git");
    assert!(matches!(
        control.reserve_scm_source_fetch(&substituted),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert!(matches!(
        control.scm_source_fetch("tenant-other", "fetch-1"),
        Err(ControlPlaneError::NotFound { .. })
    ));

    let (capsule, key) = signed_capsule();
    control.store_signed_capsule(&capsule, &key).unwrap();
    control
        .create_run_idempotent("check-run-create", &run_request("run-check", "job-check"))
        .unwrap();
    control
        .enqueue_task(&DurableTask {
            id: "scm-check-task-1".to_owned(),
            kind: "scm.check.publish".to_owned(),
            payload: json!({"public": "projection"}),
            status: DurableTaskStatus::Pending,
            available_unix_ms: NOW,
            attempts: 0,
            lease_owner: None,
            lease_expires_unix_ms: None,
            last_error: None,
            created_unix_ms: NOW,
            completed_unix_ms: None,
        })
        .unwrap();
    control
        .claim_task_by_kind("check-worker", "scm.check.publish", NOW, 1_000)
        .unwrap()
        .unwrap();
    let check = ReserveScmCheckPublication {
        id: "scm-check-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        installation_id: installation.id,
        run_id: "run-check".to_owned(),
        task_id: "scm-check-task-1".to_owned(),
        worker_id: "check-worker".to_owned(),
        commit_sha: "c".repeat(40),
        logical_name: "workflow".to_owned(),
        external_id: "runtrue:run-check:workflow".to_owned(),
        request_digest: ContentDigest::sha256(b"exact public check request"),
        annotation_count: 2,
        now_unix_ms: NOW,
    };
    assert!(
        !control
            .reserve_scm_check_publication(&check)
            .unwrap()
            .replayed
    );
    assert!(
        control
            .reserve_scm_check_publication(&check)
            .unwrap()
            .replayed
    );
    let mut substituted_check = check.clone();
    substituted_check.request_digest = ContentDigest::sha256(b"substituted request");
    assert!(matches!(
        control.reserve_scm_check_publication(&substituted_check),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert!(matches!(
        control.scm_check_publication("tenant-other", &check.id),
        Err(ControlPlaneError::NotFound { .. })
    ));
    let progress = RecordScmCheckProgress {
        tenant_id: check.tenant_id.clone(),
        publication_id: check.id.clone(),
        task_id: check.task_id.clone(),
        worker_id: check.worker_id.clone(),
        provider_check_run_id: 9001,
        confirmed_annotations: 2,
        now_unix_ms: NOW + 1,
    };
    let progress_record = control.record_scm_check_progress(&progress).unwrap();
    assert_eq!(progress_record.provider_check_run_id, Some(9001));
    let mut stale = progress.clone();
    stale.worker_id = "stale-worker".to_owned();
    assert!(matches!(
        control.record_scm_check_progress(&stale),
        Err(ControlPlaneError::TaskNotOwned)
    ));
    let published = control
        .mark_scm_check_published(
            &check.tenant_id,
            &check.id,
            &check.task_id,
            &check.worker_id,
            NOW + 2,
        )
        .unwrap();
    assert_eq!(published.state, ScmCheckPublicationState::Published);
    let mut replayed_progress = progress;
    replayed_progress.now_unix_ms = NOW + 3;
    assert!(
        control
            .record_scm_check_progress(&replayed_progress)
            .is_ok(),
        "exact progress replay remains idempotent while task lease is active"
    );

    control
        .enqueue_task(&DurableTask {
            id: "scm-check-task-2".to_owned(),
            kind: "scm.check.publish".to_owned(),
            payload: json!({"public": "updated projection"}),
            status: DurableTaskStatus::Pending,
            available_unix_ms: NOW + 3,
            attempts: 0,
            lease_owner: None,
            lease_expires_unix_ms: None,
            last_error: None,
            created_unix_ms: NOW + 3,
            completed_unix_ms: None,
        })
        .unwrap();
    control
        .claim_task_by_kind("check-worker", "scm.check.publish", NOW + 3, 1_000)
        .unwrap()
        .unwrap();
    let revision = ReserveScmCheckPublication {
        id: "scm-check-2".to_owned(),
        task_id: "scm-check-task-2".to_owned(),
        request_digest: ContentDigest::sha256(b"updated public check request"),
        now_unix_ms: NOW + 3,
        ..check.clone()
    };
    assert!(
        !control
            .reserve_scm_check_publication(&revision)
            .unwrap()
            .replayed
    );
    control
        .record_scm_check_progress(&RecordScmCheckProgress {
            tenant_id: revision.tenant_id.clone(),
            publication_id: revision.id.clone(),
            task_id: revision.task_id.clone(),
            worker_id: revision.worker_id.clone(),
            provider_check_run_id: 9001,
            confirmed_annotations: 2,
            now_unix_ms: NOW + 4,
        })
        .unwrap();
    control
        .mark_scm_check_published(
            &revision.tenant_id,
            &revision.id,
            &revision.task_id,
            &revision.worker_id,
            NOW + 5,
        )
        .unwrap();
    assert_eq!(
        control
            .scm_check_publication_by_provider_run(
                &revision.tenant_id,
                &revision.repository_id,
                &revision.installation_id,
                9001,
            )
            .unwrap()
            .id,
        revision.id
    );
}

#[test]
fn shipped_schema_seven_upgrades_token_ancestry_and_lease_deadlines() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-seven.sqlite");
    let connection = Connection::open(&path).unwrap();
    for (version, migration) in [
        (1_u32, MIGRATION_1),
        (2, MIGRATION_2),
        (3, MIGRATION_3),
        (4, MIGRATION_4),
        (5, MIGRATION_5),
        (6, MIGRATION_6),
        (7, MIGRATION_7),
    ] {
        connection.execute_batch(migration).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (?1, ?2)",
                params![i64::from(version), to_i64(NOW).unwrap()],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO installation_state(singleton, installation_id, fencing_epoch)
                 VALUES (1, 'installation', 1)",
            [],
        )
        .unwrap();
    let ancestry_before: bool = connection
        .query_row(
            "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('api_tokens') WHERE name = 'parent_token_id'
                 )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!ancestry_before, "schema 7 must remain immutable");
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    drop(ControlPlane::open(&path, "installation", NOW + 1).unwrap());
    let connection = Connection::open(&path).unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    for (table, column) in [
        ("api_tokens", "parent_token_id"),
        ("leases", "hard_deadline_unix_ms"),
    ] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(
                        SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2
                     )",
                params![table, column],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present, "missing {table}.{column} after schema-7 upgrade");
    }
}

#[test]
fn shipped_schema_eight_upgrades_rotation_replay_journal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-eight.sqlite");
    let connection = Connection::open(&path).unwrap();
    for (version, migration) in [
        (1_u32, MIGRATION_1),
        (2, MIGRATION_2),
        (3, MIGRATION_3),
        (4, MIGRATION_4),
        (5, MIGRATION_5),
        (6, MIGRATION_6),
        (7, MIGRATION_7),
        (8, MIGRATION_8),
    ] {
        connection.execute_batch(migration).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (?1, ?2)",
                params![i64::from(version), to_i64(NOW).unwrap()],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO installation_state(singleton, installation_id, fencing_epoch)
                 VALUES (1, 'installation', 1)",
            [],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    drop(ControlPlane::open(&path, "installation", NOW + 1).unwrap());
    let connection = Connection::open(&path).unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    let journal_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table' AND name = 'runner_certificate_rotations'
                 )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(journal_exists);
}

#[test]
fn restore_safe_mode_advances_the_fence_and_requires_exact_activation() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    assert_eq!(
        control.recovery_state().unwrap(),
        InstallationRecoveryState {
            fencing_epoch: 1,
            safe_mode: false,
            last_restore_unix_ms: None,
        }
    );
    let restored = control.enter_restore_safe_mode(NOW + 1).unwrap();
    assert_eq!(restored.fencing_epoch, 2);
    assert!(restored.safe_mode);
    assert_eq!(restored.last_restore_unix_ms, Some(NOW + 1));
    assert!(matches!(
        control.leave_restore_safe_mode(1),
        Err(ControlPlaneError::RestoreEpochMismatch { .. })
    ));
    assert!(!control.leave_restore_safe_mode(2).unwrap().safe_mode);
    assert!(matches!(
        control.leave_restore_safe_mode(2),
        Err(ControlPlaneError::NotInRestoreSafeMode)
    ));
}

#[test]
fn oidc_grants_require_the_exact_durable_run_job_step_capsule_and_fence() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    let (capsule, key) = signed_oidc_capsule();
    let capsule_digest = capsule.digest.clone();
    control.store_signed_capsule(&capsule, &key).unwrap();
    add_runner(&control);
    control
        .create_run_idempotent(
            "oidc-run-key",
            &CreateRunRequest {
                id: "run-oidc".to_owned(),
                repository_id: "repo-1".to_owned(),
                capsule_id: "capsule-oidc".to_owned(),
                priority: 0,
                remote: true,
                created_unix_ms: NOW,
                jobs: vec![NewJob {
                    id: "job-oidc".to_owned(),
                    job_key: "publish".to_owned(),
                    attempt: 1,
                    requirements: requirements(),
                }],
            },
        )
        .unwrap();
    control
        .transition_job_state("job-oidc", JobState::Queued, NOW + 1)
        .unwrap();
    let offered = control
        .create_lease(
            "lease-oidc",
            "job-oidc",
            "runner-1",
            NOW + 2,
            NOW + 20,
            NOW + 120_000,
        )
        .unwrap();
    let active = control
        .accept_lease(
            "lease-oidc",
            "runner-1",
            offered.fencing_generation,
            offered.installation_fencing_epoch,
            NOW + 3,
        )
        .unwrap();
    let grant = OidcGrant {
        grant_id: "grant-oidc".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        run_id: "run-oidc".to_owned(),
        job_id: "job-oidc".to_owned(),
        step_id: "federate".to_owned(),
        capsule_digest,
        execution_lease_id: "lease-oidc".to_owned(),
        fencing_generation: active.fencing_generation,
        trust: "protected-branch".to_owned(),
        runner_pool_id: Some("pool-1".to_owned()),
        environment: Some("production".to_owned()),
        ref_name: Some("refs/heads/main".to_owned()),
        source_commit: "0123456789abcdef".to_owned(),
        approval_subject_digest: None,
        runner_posture_digest: Some(
            authoritative_runner_posture_digest(
                &runner(),
                &ContentDigest::sha256(b"test enrolled inventory"),
            )
            .unwrap(),
        ),
        allowed_audiences: BTreeSet::from(["https://registry.example".to_owned()]),
        expires_unix_seconds: (NOW + 100_000) / 1000,
    };
    control.store_oidc_grant(&grant).unwrap();
    assert_eq!(
        control
            .authorize_oidc_grant(
                "grant-oidc",
                "lease-oidc",
                active.fencing_generation,
                active.installation_fencing_epoch,
                "job-oidc",
                "federate",
                NOW + 4,
            )
            .unwrap(),
        grant
    );
    assert!(matches!(
        control.authorize_oidc_grant(
            "grant-oidc",
            "lease-oidc",
            active.fencing_generation,
            active.installation_fencing_epoch,
            "job-oidc",
            "other-step",
            NOW + 4,
        ),
        Err(ControlPlaneError::StaleOidcGrant)
    ));

    let mut overbroad = grant.clone();
    "grant-overbroad".clone_into(&mut overbroad.grant_id);
    overbroad
        .allowed_audiences
        .insert("https://evil.example".to_owned());
    assert!(matches!(
        control.store_oidc_grant(&overbroad),
        Err(ControlPlaneError::StaleOidcGrant)
    ));
}

#[test]
fn api_tokens_are_indexed_by_keyed_digest_scoped_and_revocable() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    let hasher = TokenHasher::from_key([17; 32]);
    let issued = ApiTokenRecord::issue(
        &hasher,
        IssueApiToken {
            id: "api-1".to_owned(),
            principal_id: "service-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            name: "deploy automation".to_owned(),
            scopes: BTreeSet::from(["api:read".to_owned()]),
            created_unix_ms: NOW,
            expires_unix_ms: NOW + 60_000,
        },
    )
    .unwrap();
    let plaintext = issued.token.expose().to_owned();
    control
        .create_api_token(
            &issued.record,
            AuditPrincipal {
                kind: "service".to_owned(),
                id: "issuer".to_owned(),
            },
            "request-token-create",
        )
        .unwrap();

    let context = control
        .authenticate_api_token(&hasher, &plaintext, "api:read", NOW + 1)
        .unwrap();
    assert_eq!(context.principal_id, "service-1");
    assert_eq!(
        control.api_token("api-1").unwrap().last_used_unix_ms,
        Some(NOW + 1)
    );
    assert!(matches!(
        control.authenticate_api_token(&hasher, &plaintext, "api:write", NOW + 2),
        Err(ControlPlaneError::Auth(AuthError::InsufficientScope(_)))
    ));
    assert!(matches!(
        control.authenticate_api_token(&hasher, &"A".repeat(64), "api:read", NOW + 2),
        Err(ControlPlaneError::Auth(AuthError::InvalidCredential))
    ));

    let revoked = control
        .revoke_api_token(
            "api-1",
            AuditPrincipal {
                kind: "service".to_owned(),
                id: "issuer".to_owned(),
            },
            "request-token-revoke",
            NOW + 3,
        )
        .unwrap();
    assert_eq!(revoked.revoked_unix_ms, Some(NOW + 3));
    assert!(matches!(
        control.authenticate_api_token(&hasher, &plaintext, "api:read", NOW + 4),
        Err(ControlPlaneError::Auth(AuthError::Revoked))
    ));
    assert_eq!(control.list_api_tokens("tenant-1").unwrap().len(), 1);
    let audit = control.audit_events().unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].data.action, "api_token.create");
    assert_eq!(audit[1].data.action, "api_token.revoke");
}

#[test]
fn schema_nineteen_upgrades_through_output_lifecycle_integrity_schema_twenty_one() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    let migrations = [
        MIGRATION_1,
        MIGRATION_2,
        MIGRATION_3,
        MIGRATION_4,
        MIGRATION_5,
        MIGRATION_6,
        MIGRATION_7,
        MIGRATION_8,
        MIGRATION_9,
        MIGRATION_10,
        MIGRATION_11,
        MIGRATION_12,
        MIGRATION_13,
        MIGRATION_14,
        MIGRATION_15,
        MIGRATION_16,
        MIGRATION_17,
        MIGRATION_18,
        MIGRATION_19,
    ];
    for (offset, migration) in migrations.iter().enumerate() {
        apply_migration(
            &mut connection,
            migration,
            u32::try_from(offset + 1).unwrap(),
            NOW,
        )
        .unwrap();
    }
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let control = ControlPlane::open(&path, "schema-upgrade", NOW + 1).unwrap();
    let connection = control.connection().unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    for table in [
        "expanded_job_sets",
        "normalized_trigger_events",
        "schedule_trigger_cursors",
        "tenant_storage_ticket_bindings",
        "tenant_storage_objects",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                                   WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing migration-20/21 table {table}");
    }
}

#[test]
fn shipped_schema_twenty_one_upgrades_scm_check_reconciliation_journal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-twenty-one.sqlite");
    let mut connection = Connection::open(&path).unwrap();
    let migrations = [
        MIGRATION_1,
        MIGRATION_2,
        MIGRATION_3,
        MIGRATION_4,
        MIGRATION_5,
        MIGRATION_6,
        MIGRATION_7,
        MIGRATION_8,
        MIGRATION_9,
        MIGRATION_10,
        MIGRATION_11,
        MIGRATION_12,
        MIGRATION_13,
        MIGRATION_14,
        MIGRATION_15,
        MIGRATION_16,
        MIGRATION_17,
        MIGRATION_18,
        MIGRATION_19,
        MIGRATION_20,
        MIGRATION_21,
    ];
    for (offset, migration) in migrations.iter().enumerate() {
        apply_migration(
            &mut connection,
            migration,
            u32::try_from(offset + 1).unwrap(),
            NOW,
        )
        .unwrap();
    }
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let control = ControlPlane::open(&path, "schema-upgrade", NOW + 1).unwrap();
    let connection = control.connection().unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    let present: bool = connection
        .query_row(
            "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table' AND name = 'scm_check_publications'
                 )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(present);
}

#[test]
fn schema_twenty_four_upgrades_github_installation_lifecycle() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-twenty-four.sqlite");
    let connection = Connection::open(&path).unwrap();
    let migrations = [
        MIGRATION_1,
        MIGRATION_2,
        MIGRATION_3,
        MIGRATION_4,
        MIGRATION_5,
        MIGRATION_6,
        MIGRATION_7,
        MIGRATION_8,
        MIGRATION_9,
        MIGRATION_10,
        MIGRATION_11,
        MIGRATION_12,
        MIGRATION_13,
        MIGRATION_14,
        MIGRATION_15,
        MIGRATION_16,
        MIGRATION_17,
        MIGRATION_18,
        MIGRATION_19,
        MIGRATION_20,
        MIGRATION_21,
        MIGRATION_22,
        MIGRATION_23,
        MIGRATION_24,
    ];
    for (offset, migration) in migrations.iter().enumerate() {
        connection.execute_batch(migration).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (?1, ?2)",
                params![i64::try_from(offset + 1).unwrap(), to_i64(NOW).unwrap()],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO installation_state(singleton, installation_id, fencing_epoch)
                 VALUES (1, 'installation', 1)",
            [],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    drop(ControlPlane::open(&path, "installation", NOW + 1).unwrap());
    let connection = Connection::open(&path).unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    for table in [
        "github_app_setup_transactions",
        "github_installation_profiles",
        "github_repository_catalog",
        "github_lifecycle_deliveries",
    ] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(
                         SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
                     )",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present, "missing schema-25 table {table}");
    }
    for (table, column) in [
        ("github_app_setup_transactions", "github_web_origin"),
        ("github_app_setup_transactions", "github_api_origin"),
        ("github_installation_profiles", "web_origin"),
        ("github_installation_profiles", "api_origin"),
        ("github_repository_catalog", "web_origin"),
        ("github_repository_catalog", "api_origin"),
    ] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(
                         SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2
                     )",
                params![table, column],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present, "missing schema-25 column {table}.{column}");
    }
}

#[test]
fn github_enterprise_origins_are_canonical_and_clone_urls_are_exact() {
    assert!(validate_github_origins(
        "https://github.example.com",
        "https://github.example.com/api/v3",
    )
    .is_ok());
    assert!(validate_github_origins("https://github.com", "https://api.github.com").is_ok());
    for (web_origin, api_origin) in [
        (
            "http://github.example.com",
            "https://github.example.com/api/v3",
        ),
        (
            "https://GitHub.example.com",
            "https://github.example.com/api/v3",
        ),
        (
            "https://github.example.com/",
            "https://github.example.com/api/v3",
        ),
        (
            "https://github.example.com/path",
            "https://github.example.com/api/v3",
        ),
        (
            "https://github.example.com",
            "https://user@github.example.com/api/v3",
        ),
        (
            "https://github.example.com",
            "https://github.example.com/api/../v3",
        ),
    ] {
        assert!(
            validate_github_origins(web_origin, api_origin).is_err(),
            "accepted non-canonical origins {web_origin} and {api_origin}",
        );
    }
    let repository = GitHubSelectedRepository {
        external_repository_id: "42".to_owned(),
        owner: "octo-org".to_owned(),
        name: "runtrue".to_owned(),
        full_name: "octo-org/runtrue".to_owned(),
        clone_url: "https://github.example.com/octo-org/runtrue.git".to_owned(),
        visibility: "private".to_owned(),
        default_branch: "main".to_owned(),
    };
    assert!(validate_github_selected_repository(&repository, "https://github.example.com").is_ok());
    assert!(validate_github_selected_repository(&repository, "https://github.com").is_err());
}

#[test]
fn github_setup_installation_and_repository_lifecycle_is_durable_and_tenant_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("github-lifecycle.sqlite");
    let control = ControlPlane::open(&path, "github-lifecycle", NOW).unwrap();
    control
        .put_tenant_identity(&r9_tenant("tenant-github"), None)
        .unwrap();
    control
        .put_tenant_identity(&r9_tenant("tenant-other"), None)
        .unwrap();
    add_r9_user(&control, "tenant-github", "github-admin", "tenant-admin");
    add_r9_user(&control, "tenant-other", "other-admin", "tenant-admin");

    let mut setup = CreateGitHubSetupTransaction {
        id: "github-setup-1".to_owned(),
        tenant_id: "tenant-github".to_owned(),
        principal_id: "github-admin".to_owned(),
        idempotency_key: "github-install-idempotency".to_owned(),
        request_digest: ContentDigest::sha256(b"placeholder"),
        state_digest: ContentDigest::sha256(b"opaque setup state"),
        github_web_origin: "https://github.example.com".to_owned(),
        github_api_origin: "https://github.example.com/api/v3".to_owned(),
        return_path: "/settings/github".to_owned(),
        expires_unix_ms: NOW + 10 * 60 * 1_000,
        created_unix_ms: NOW,
    };
    setup.request_digest = setup.expected_request_digest().unwrap();
    let created = control.create_github_setup_transaction(&setup).unwrap();
    assert!(!created.replayed);
    assert_eq!(created.value.status, GitHubSetupStatus::Pending);

    let mut retry = setup.clone();
    retry.id = "ignored-new-id".to_owned();
    retry.state_digest = ContentDigest::sha256(b"ignored derived retry state");
    retry.created_unix_ms += 50;
    retry.expires_unix_ms += 50;
    retry.request_digest = retry.expected_request_digest().unwrap();
    let replay = control.create_github_setup_transaction(&retry).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.value.id, setup.id);
    assert_eq!(replay.value.expires_unix_ms, setup.expires_unix_ms);
    assert_eq!(replay.value.state_digest, setup.state_digest);
    assert_eq!(replay.value.github_web_origin, setup.github_web_origin);
    assert_eq!(replay.value.github_api_origin, setup.github_api_origin);

    let mut origin_substitution = setup.clone();
    origin_substitution.github_web_origin = "https://other.example.com".to_owned();
    origin_substitution.github_api_origin = "https://other.example.com/api/v3".to_owned();
    origin_substitution.request_digest = origin_substitution.expected_request_digest().unwrap();
    assert!(matches!(
        control.create_github_setup_transaction(&origin_substitution),
        Err(ControlPlaneError::IdempotencyConflict)
    ));

    assert!(matches!(
        control.begin_github_setup_by_state(&ContentDigest::sha256(b"wrong state"), NOW + 1),
        Err(ControlPlaneError::InvalidGitHubSetupState)
    ));
    let beginning = control
        .begin_github_setup_by_state(&setup.state_digest, NOW + 1)
        .unwrap();
    assert!(!beginning.replayed);
    assert_eq!(beginning.value.status, GitHubSetupStatus::Exchanging);
    assert_eq!(beginning.value.attempts, 1);
    let cross_tenant = BeginGitHubSetupTransaction {
        tenant_id: "tenant-other".to_owned(),
        principal_id: "other-admin".to_owned(),
        transaction_id: setup.id.clone(),
        state_digest: setup.state_digest.clone(),
        now_unix_ms: NOW + 2,
    };
    assert!(matches!(
        control.begin_github_setup_transaction(&cross_tenant),
        Err(ControlPlaneError::InvalidGitHubSetupState)
    ));
    drop(control);

    let control = ControlPlane::open(&path, "github-lifecycle", NOW + 2).unwrap();
    let resumed = control
        .begin_github_setup_by_state(&setup.state_digest, NOW + 2)
        .unwrap();
    assert!(resumed.replayed);
    assert_eq!(resumed.value.attempts, 2);
    let installation = GitHubInstallationRecord {
        installation: ScmInstallationRecord {
            id: "github-installation-9001".to_owned(),
            tenant_id: "tenant-github".to_owned(),
            provider: "github".to_owned(),
            external_id: "9001".to_owned(),
            credential_reference: "provider://github-app/default".to_owned(),
            permissions: json!({
                "checks":"write",
                "contents":"read",
                "metadata":"read",
                "pull_requests":"read"
            }),
            status: "active".to_owned(),
            created_unix_ms: NOW + 3,
            updated_unix_ms: NOW + 3,
        },
        web_origin: setup.github_web_origin.clone(),
        api_origin: setup.github_api_origin.clone(),
        account_external_id: "7001".to_owned(),
        account_login: "octo-org".to_owned(),
        account_kind: GitHubAccountKind::Organization,
        repository_selection: GitHubRepositorySelection::Selected,
        lifecycle_generation: 1,
        synchronized_unix_ms: NOW + 3,
        suspended_unix_ms: None,
        revoked_unix_ms: None,
        version: 1,
    };
    let selected = GitHubSelectedRepository {
        external_repository_id: "42".to_owned(),
        owner: "octo-org".to_owned(),
        name: "runtrue".to_owned(),
        full_name: "octo-org/runtrue".to_owned(),
        clone_url: "https://github.example.com/octo-org/runtrue.git".to_owned(),
        visibility: "private".to_owned(),
        default_branch: "main".to_owned(),
    };
    let completion = CompleteGitHubSetupTransaction {
        tenant_id: setup.tenant_id.clone(),
        principal_id: setup.principal_id.clone(),
        transaction_id: setup.id.clone(),
        state_digest: setup.state_digest.clone(),
        reconciliation: ReconcileGitHubInstallation {
            installation: installation.clone(),
            selected_repositories: vec![selected.clone()],
            expected_version: None,
            now_unix_ms: NOW + 3,
        },
        now_unix_ms: NOW + 3,
    };
    let mut completion_origin_substitution = completion.clone();
    completion_origin_substitution
        .reconciliation
        .installation
        .web_origin = "https://other.example.com".to_owned();
    completion_origin_substitution
        .reconciliation
        .installation
        .api_origin = "https://other.example.com/api/v3".to_owned();
    completion_origin_substitution
        .reconciliation
        .selected_repositories[0]
        .clone_url = "https://other.example.com/octo-org/runtrue.git".to_owned();
    assert!(matches!(
        control.complete_github_setup_transaction(&completion_origin_substitution),
        Err(ControlPlaneError::InvalidGitHubSetupState)
    ));
    assert!(
        !control
            .complete_github_setup_transaction(&completion)
            .unwrap()
            .replayed
    );
    assert!(
        control
            .complete_github_setup_transaction(&completion)
            .unwrap()
            .replayed
    );
    let mut substituted = completion.clone();
    substituted.reconciliation.selected_repositories[0].external_repository_id = "43".to_owned();
    assert!(matches!(
        control.complete_github_setup_transaction(&substituted),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert_eq!(
        control
            .github_installation_by_external_id(
                &installation.web_origin,
                &installation.api_origin,
                "9001",
            )
            .unwrap(),
        installation
    );
    assert!(matches!(
        control.github_installation_by_external_id(
            "https://other.example.com",
            &installation.api_origin,
            "9001",
        ),
        Err(ControlPlaneError::NotFound { .. })
    ));
    assert!(matches!(
        control.github_installation_by_external_id(
            &installation.web_origin,
            "https://other.example.com/api/v3",
            "9001",
        ),
        Err(ControlPlaneError::NotFound { .. })
    ));
    assert!(matches!(
        control.github_installation_for_tenant("tenant-other", &installation.installation.id),
        Err(ControlPlaneError::NotFound { .. })
    ));
    assert_eq!(
        control
            .list_github_installations_for_tenant("tenant-github", None, 10)
            .unwrap()
            .len(),
        1
    );

    let link_request = LinkSelectedGitHubRepository {
        tenant_id: "tenant-github".to_owned(),
        installation_id: installation.installation.id.clone(),
        external_repository_id: selected.external_repository_id.clone(),
        repository: RepositoryRecord {
            id: "repo-github-runtrue".to_owned(),
            tenant_id: "tenant-github".to_owned(),
            owner: selected.owner.clone(),
            name: selected.name.clone(),
            default_branch: selected.default_branch.clone(),
            visibility: selected.visibility.clone(),
            created_unix_ms: NOW + 4,
        },
        now_unix_ms: NOW + 4,
    };
    assert!(
        !control
            .link_selected_github_repository(&link_request)
            .unwrap()
            .replayed
    );
    assert!(
        control
            .link_selected_github_repository(&link_request)
            .unwrap()
            .replayed
    );
    let mut repository_substitution = link_request.clone();
    repository_substitution.repository.id = "repo-substitution".to_owned();
    assert!(matches!(
        control.link_selected_github_repository(&repository_substitution),
        Err(ControlPlaneError::IdempotencyConflict)
    ));

    let suspended = control
        .suspend_github_repository_link(
            "tenant-github",
            &link_request.repository.id,
            "github-admin",
            "request-unlink",
            NOW + 5,
        )
        .unwrap();
    assert!(!suspended.replayed);
    assert_eq!(suspended.value.status, "suspended");
    assert!(
        control
            .suspend_github_repository_link(
                "tenant-github",
                &link_request.repository.id,
                "github-admin",
                "request-unlink-replay",
                NOW + 5,
            )
            .unwrap()
            .replayed
    );
    let mut relink_request = link_request.clone();
    relink_request.now_unix_ms = NOW + 5;
    assert!(
        !control
            .link_selected_github_repository(&relink_request)
            .unwrap()
            .replayed
    );

    let mut changed_installation = installation.clone();
    changed_installation.lifecycle_generation = 2;
    changed_installation.version = 2;
    changed_installation.installation.updated_unix_ms = NOW + 5;
    changed_installation.synchronized_unix_ms = NOW + 5;
    let removal = ReconcileGitHubInstallation {
        installation: changed_installation.clone(),
        selected_repositories: Vec::new(),
        expected_version: Some(1),
        now_unix_ms: NOW + 5,
    };
    let reconciled = control.reconcile_github_installation(&removal).unwrap();
    assert_eq!(reconciled.value.repositories.removed, 1);
    assert_eq!(
        control
            .list_github_repository_links_for_tenant(
                "tenant-github",
                &installation.installation.id,
                None,
                10,
            )
            .unwrap()[0]
            .status,
        "suspended"
    );
    let suspended = control
        .set_github_installation_status(&SetGitHubInstallationStatus {
            tenant_id: "tenant-github".to_owned(),
            installation_id: installation.installation.id.clone(),
            expected_version: 2,
            status: "suspended".to_owned(),
            lifecycle_generation: 3,
            now_unix_ms: NOW + 6,
        })
        .unwrap();
    assert_eq!(suspended.value.installation.status, "suspended");
    let revoke = SetGitHubInstallationStatus {
        tenant_id: "tenant-github".to_owned(),
        installation_id: installation.installation.id.clone(),
        expected_version: 3,
        status: "revoked".to_owned(),
        lifecycle_generation: 4,
        now_unix_ms: NOW + 7,
    };
    assert!(
        !control
            .set_github_installation_status(&revoke)
            .unwrap()
            .replayed
    );
    assert!(
        control
            .set_github_installation_status(&revoke)
            .unwrap()
            .replayed
    );
    let mut forbidden_reactivation = revoke.clone();
    forbidden_reactivation.expected_version = 4;
    forbidden_reactivation.lifecycle_generation = 5;
    forbidden_reactivation.status = "active".to_owned();
    forbidden_reactivation.now_unix_ms += 1;
    assert!(matches!(
        control.set_github_installation_status(&forbidden_reactivation),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert_eq!(
        control
            .list_github_repository_links_for_tenant(
                "tenant-github",
                &installation.installation.id,
                None,
                10,
            )
            .unwrap()[0]
            .status,
        "revoked"
    );

    let mut expiring = setup.clone();
    expiring.id = "github-setup-expiring".to_owned();
    expiring.idempotency_key = "github-expiring-idempotency".to_owned();
    expiring.state_digest = ContentDigest::sha256(b"expiring setup state");
    expiring.expires_unix_ms = NOW + 100;
    expiring.request_digest = expiring.expected_request_digest().unwrap();
    control.create_github_setup_transaction(&expiring).unwrap();
    assert!(matches!(
        control.begin_github_setup_by_state(&expiring.state_digest, expiring.expires_unix_ms),
        Err(ControlPlaneError::InvalidGitHubSetupState)
    ));
    let connection = control.connection().unwrap();
    let expired: String = connection
        .query_row(
            "SELECT status FROM github_app_setup_transactions WHERE id = ?1",
            [&expiring.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(expired, "expired");
    drop(connection);

    let audit = format!("{:?}", control.audit_events().unwrap());
    assert!(!audit.contains(setup.state_digest.as_str()));
    assert!(!audit.contains(&selected.clone_url));
    assert!(!audit.contains(&setup.github_web_origin));
    assert!(!audit.contains(&setup.github_api_origin));
    assert!(!audit.contains(&installation.installation.credential_reference));
    verify_chain(&control.audit_events().unwrap()).unwrap();
    drop(control);

    let reopened = ControlPlane::open(&path, "github-lifecycle", NOW + 8).unwrap();
    assert_eq!(
        reopened
            .github_installation_for_tenant("tenant-github", &installation.installation.id,)
            .unwrap()
            .installation
            .status,
        "revoked"
    );
    verify_chain(&reopened.audit_events().unwrap()).unwrap();
}

#[test]
fn github_lifecycle_delivery_replay_restart_fencing_and_exhaustion_are_durable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("github-deliveries.sqlite");
    let control = ControlPlane::open(&path, "github-deliveries", NOW).unwrap();
    control
        .put_tenant_identity(&r9_tenant("tenant-github-delivery"), None)
        .unwrap();
    control
        .put_tenant_identity(&r9_tenant("tenant-other-delivery"), None)
        .unwrap();
    let installation = GitHubInstallationRecord {
        installation: ScmInstallationRecord {
            id: "github-delivery-installation".to_owned(),
            tenant_id: "tenant-github-delivery".to_owned(),
            provider: "github".to_owned(),
            external_id: "88001".to_owned(),
            credential_reference: "provider://github-app/default".to_owned(),
            permissions: json!({
                "checks":"write",
                "contents":"read",
                "metadata":"read",
                "pull_requests":"read"
            }),
            status: "active".to_owned(),
            created_unix_ms: NOW,
            updated_unix_ms: NOW,
        },
        web_origin: "https://github.example.com".to_owned(),
        api_origin: "https://github.example.com/api/v3".to_owned(),
        account_external_id: "77001".to_owned(),
        account_login: "delivery-org".to_owned(),
        account_kind: GitHubAccountKind::Organization,
        repository_selection: GitHubRepositorySelection::Selected,
        lifecycle_generation: 1,
        synchronized_unix_ms: NOW,
        suspended_unix_ms: None,
        revoked_unix_ms: None,
        version: 1,
    };
    control
        .reconcile_github_installation(&ReconcileGitHubInstallation {
            installation: installation.clone(),
            selected_repositories: Vec::new(),
            expected_version: None,
            now_unix_ms: NOW,
        })
        .unwrap();
    let reservation = ReserveGitHubLifecycleDelivery {
        delivery_id: "delivery-0001".to_owned(),
        tenant_id: installation.installation.tenant_id.clone(),
        installation_id: installation.installation.id.clone(),
        installation_external_id: installation.installation.external_id.clone(),
        event_name: "installation_repositories".to_owned(),
        action: "added".to_owned(),
        payload_digest: ContentDigest::sha256(b"signed normalized lifecycle payload"),
        now_unix_ms: NOW + 1,
    };
    assert!(
        !control
            .reserve_github_lifecycle_delivery(&reservation)
            .unwrap()
            .replayed
    );
    assert!(
        control
            .reserve_github_lifecycle_delivery(&reservation)
            .unwrap()
            .replayed
    );
    let mut substitution = reservation.clone();
    substitution.action = "removed".to_owned();
    assert!(matches!(
        control.reserve_github_lifecycle_delivery(&substitution),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    let mut cross_tenant = reservation.clone();
    cross_tenant.tenant_id = "tenant-other-delivery".to_owned();
    assert!(matches!(
        control.reserve_github_lifecycle_delivery(&cross_tenant),
        Err(ControlPlaneError::NotFound { .. })
    ));

    let first_claim = ClaimGitHubLifecycleDelivery {
        tenant_id: reservation.tenant_id.clone(),
        delivery_id: reservation.delivery_id.clone(),
        worker_id: "lifecycle-worker-a".to_owned(),
        now_unix_ms: NOW + 2,
        lease_duration_ms: 100,
    };
    let first = control
        .claim_github_lifecycle_delivery(&first_claim)
        .unwrap()
        .unwrap();
    assert!(!first.replayed);
    assert_eq!(first.value.lease_generation, 1);
    assert!(
        control
            .claim_github_lifecycle_delivery(&first_claim)
            .unwrap()
            .unwrap()
            .replayed
    );
    drop(control);

    let control = ControlPlane::open(&path, "github-deliveries", NOW + 103).unwrap();
    let recovered = control
        .claim_next_github_lifecycle_delivery("lifecycle-worker-b", NOW + 103, 100)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.tenant_id, reservation.tenant_id);
    assert_eq!(recovered.delivery_id, reservation.delivery_id);
    assert_eq!(recovered.lease_generation, 2);
    assert_eq!(recovered.attempts, 2);
    let stale = CompleteGitHubLifecycleDelivery {
        tenant_id: reservation.tenant_id.clone(),
        delivery_id: reservation.delivery_id.clone(),
        worker_id: first_claim.worker_id,
        lease_generation: 1,
        completion_digest: ContentDigest::sha256(b"stale completion"),
        now_unix_ms: NOW + 104,
    };
    assert!(matches!(
        control.complete_github_lifecycle_delivery(&stale),
        Err(ControlPlaneError::GitHubLifecycleLeaseLost)
    ));
    let failure = FailGitHubLifecycleDelivery {
        tenant_id: reservation.tenant_id.clone(),
        delivery_id: reservation.delivery_id.clone(),
        worker_id: "lifecycle-worker-b".to_owned(),
        lease_generation: 2,
        error_digest: ContentDigest::sha256(b"bounded provider outage"),
        retry_unix_ms: Some(NOW + 200),
        now_unix_ms: NOW + 104,
    };
    assert!(
        !control
            .fail_github_lifecycle_delivery(&failure)
            .unwrap()
            .replayed
    );
    assert!(
        control
            .fail_github_lifecycle_delivery(&failure)
            .unwrap()
            .replayed
    );
    let mut changed_failure = failure.clone();
    changed_failure.error_digest = ContentDigest::sha256(b"substituted failure");
    assert!(matches!(
        control.fail_github_lifecycle_delivery(&changed_failure),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert!(control
        .claim_next_github_lifecycle_delivery("too-early-worker", NOW + 199, 100)
        .unwrap()
        .is_none());
    let final_claim = control
        .claim_next_github_lifecycle_delivery("lifecycle-worker-c", NOW + 200, 100)
        .unwrap()
        .unwrap();
    assert_eq!(final_claim.lease_generation, 3);
    let completion = CompleteGitHubLifecycleDelivery {
        tenant_id: reservation.tenant_id.clone(),
        delivery_id: reservation.delivery_id.clone(),
        worker_id: "lifecycle-worker-c".to_owned(),
        lease_generation: 3,
        completion_digest: ContentDigest::sha256(b"exact lifecycle projection"),
        now_unix_ms: NOW + 201,
    };
    assert!(
        !control
            .complete_github_lifecycle_delivery(&completion)
            .unwrap()
            .replayed
    );
    assert!(
        control
            .complete_github_lifecycle_delivery(&completion)
            .unwrap()
            .replayed
    );
    let mut changed_completion = completion.clone();
    changed_completion.completion_digest = ContentDigest::sha256(b"substitution");
    assert!(matches!(
        control.complete_github_lifecycle_delivery(&changed_completion),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert!(control
        .claim_next_github_lifecycle_delivery("no-completed-reclaim", NOW + 1_000, 100)
        .unwrap()
        .is_none());

    let mut exhaustion = reservation.clone();
    exhaustion.delivery_id = "delivery-exhaustion".to_owned();
    exhaustion.payload_digest = ContentDigest::sha256(b"exhaustion payload");
    exhaustion.now_unix_ms = NOW + 1_000;
    control
        .reserve_github_lifecycle_delivery(&exhaustion)
        .unwrap();
    let mut current_time = NOW + 1_001;
    for attempt in 1..=MAX_GITHUB_LIFECYCLE_ATTEMPTS {
        let worker = format!("exhaustion-worker-{attempt}");
        let claim = control
            .claim_next_github_lifecycle_delivery(&worker, current_time, 100)
            .unwrap()
            .unwrap();
        assert_eq!(claim.attempts, attempt);
        let failed = control
            .fail_github_lifecycle_delivery(&FailGitHubLifecycleDelivery {
                tenant_id: exhaustion.tenant_id.clone(),
                delivery_id: exhaustion.delivery_id.clone(),
                worker_id: worker,
                lease_generation: claim.lease_generation,
                error_digest: ContentDigest::sha256(format!("failure-{attempt}")),
                retry_unix_ms: Some(current_time + 2),
                now_unix_ms: current_time + 1,
            })
            .unwrap();
        if attempt == MAX_GITHUB_LIFECYCLE_ATTEMPTS {
            assert_eq!(failed.value.state, GitHubLifecycleDeliveryState::Failed);
        } else {
            assert_eq!(failed.value.state, GitHubLifecycleDeliveryState::Pending);
        }
        current_time += 2;
    }
    assert!(control
        .claim_next_github_lifecycle_delivery("exhausted-worker", current_time + 1_000, 100)
        .unwrap()
        .is_none());
    verify_chain(&control.audit_events().unwrap()).unwrap();
}
