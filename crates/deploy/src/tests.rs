use super::*;
use runtrue_artifacts::ArtifactClassification;
use runtrue_model::ContentDigest;
use runtrue_policy::{
    ApprovalDecision, ApprovalKind, ApprovalRule, ApprovalStatus, Decision, PolicyError,
    MAX_APPROVAL_REASON_BYTES,
};
use std::collections::{BTreeMap, BTreeSet};

fn environment() -> EnvironmentPolicy {
    EnvironmentPolicy {
        id: "environment-production".to_owned(),
        version: 1,
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        name: "production".to_owned(),
        status: EnvironmentStatus::Active,
        allowed_refs: BTreeSet::from(["refs/heads/main".to_owned()]),
        allowed_trust: BTreeSet::from(["protected_branch".to_owned()]),
        allowed_artifact_classifications: BTreeSet::from([
            ArtifactClassification::ReleaseCandidate,
            ArtifactClassification::PromotedRelease,
        ]),
        approval_rule: ApprovalRule {
            id: "production-owners".to_owned(),
            required_approvals: 1,
            eligible_approvers: BTreeSet::from(["alice".to_owned(), "author".to_owned()]),
            forbidden_approvers: BTreeSet::from(["author".to_owned()]),
            one_shot: true,
        },
        approval_ttl_ms: 1000,
        wait_timer_ms: 10,
        concurrency_limit: 1,
        require_provenance: true,
    }
}

fn subject(environment: &EnvironmentPolicy) -> DeploymentSubject {
    DeploymentSubject {
        subject_version: DEPLOYMENT_SUBJECT_VERSION,
        tenant_id: environment.tenant_id.clone(),
        repository_id: environment.repository_id.clone(),
        environment_id: environment.id.clone(),
        environment_policy_digest: environment.digest().expect("environment digest"),
        run_id: "run-1".to_owned(),
        job_id: "deploy".to_owned(),
        capsule_digest: ContentDigest::sha256(b"capsule"),
        source_commit: "a".repeat(40),
        ref_name: "refs/heads/main".to_owned(),
        trust: "protected_branch".to_owned(),
        artifact_id: ContentDigest::sha256(b"artifact record"),
        artifact_content_digest: ContentDigest::sha256(b"artifact bytes"),
        artifact_classification: ArtifactClassification::ReleaseCandidate,
        provenance_statement_digest: Some(ContentDigest::sha256(b"provenance")),
        deployment_target_digest: ContentDigest::sha256(b"target"),
        policy_version_ids: vec!["environment-policy-v1".to_owned()],
        rollback_of: None,
    }
}

fn create(
    _environment: &EnvironmentPolicy,
    id: &str,
    key: &str,
    mut subject: DeploymentSubject,
) -> CreateDeploymentRequest {
    subject.run_id = format!("run-{id}");
    CreateDeploymentRequest {
        id: id.to_owned(),
        idempotency_key: key.to_owned(),
        approval_request_id: format!("approval-{id}"),
        subject,
        risk_score: 75,
        created_unix_ms: 100,
    }
}

fn approve(
    gate: &mut DeploymentGate,
    request_id: &str,
    subject_digest: ContentDigest,
    now: u64,
) -> DeploymentRequestStatus {
    gate.decide(
        request_id,
        ApprovalDecision {
            actor_id: "alice".to_owned(),
            decision: Decision::Approve,
            reason: "Reviewed exact artifact, target, and environment policy".to_owned(),
            rule_id: "production-owners".to_owned(),
            subject_digest,
            decided_unix_ms: now,
        },
        now,
    )
    .expect("approve")
}

#[test]
fn exact_subject_approval_wait_timer_and_deployment_lifecycle() {
    let environment = environment();
    let mut gate = DeploymentGate::new();
    gate.register_environment(environment.clone())
        .expect("environment");
    let created = gate
        .create_request(create(
            &environment,
            "request-1",
            "key-1",
            subject(&environment),
        ))
        .expect("request");
    assert!(!created.replayed);
    assert_eq!(
        approve(&mut gate, "request-1", created.request.subject_digest, 110),
        DeploymentRequestStatus::Waiting
    );
    assert_eq!(
        gate.refresh("request-1", 119).expect("refresh"),
        DeploymentRequestStatus::Waiting
    );
    let deployment = gate
        .start("request-1", "deployment-1".to_owned(), 120)
        .expect("start");
    assert_eq!(deployment.status, DeploymentStatus::InProgress);
    assert_eq!(
        gate.request("request-1").expect("request").approval.status,
        ApprovalStatus::Consumed
    );
    let finished = gate
        .finish(
            "deployment-1",
            true,
            Some("provider-deployment-42".to_owned()),
            BTreeMap::from([("region".to_owned(), "us-test-1".to_owned())]),
            None,
            130,
        )
        .expect("finish");
    assert_eq!(finished.status, DeploymentStatus::Succeeded);
    assert_eq!(
        gate.request("request-1").expect("request").status,
        DeploymentRequestStatus::Succeeded
    );
    assert_eq!(
        gate.last_successful_deployment(&environment.id)
            .expect("last")
            .id,
        "deployment-1"
    );
}

#[test]
fn idempotency_replays_only_the_identical_subject() {
    let environment = environment();
    let mut gate = DeploymentGate::new();
    gate.register_environment(environment.clone())
        .expect("environment");
    let request = create(&environment, "request-1", "same-key", subject(&environment));
    let first = gate.create_request(request.clone()).expect("first");
    let replay = gate.create_request(request).expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(first.request, replay.request);

    let mut changed_subject = subject(&environment);
    changed_subject.artifact_content_digest = ContentDigest::sha256(b"other bytes");
    let conflict = gate
        .create_request(create(
            &environment,
            "request-2",
            "same-key",
            changed_subject,
        ))
        .expect_err("conflict");
    assert!(matches!(conflict, DeploymentError::IdempotencyConflict));
}

#[test]
fn ref_trust_classification_and_provenance_fail_closed() {
    let environment = environment();
    for mutation in 0..4 {
        let mut changed = subject(&environment);
        match mutation {
            0 => changed.ref_name = "refs/heads/feature".to_owned(),
            1 => changed.trust = "pull_request".to_owned(),
            2 => {
                changed.artifact_classification = ArtifactClassification::Quarantined;
            }
            3 => changed.provenance_statement_digest = None,
            _ => unreachable!(),
        }
        assert!(changed.validate(&environment).is_err());
    }
}

#[test]
fn separation_of_duties_and_denial_are_terminal() {
    let environment = environment();
    let mut gate = DeploymentGate::new();
    gate.register_environment(environment.clone())
        .expect("environment");
    let created = gate
        .create_request(create(
            &environment,
            "request-1",
            "key-1",
            subject(&environment),
        ))
        .expect("request");
    let author = ApprovalDecision {
        actor_id: "author".to_owned(),
        decision: Decision::Approve,
        reason: "attempt self approval".to_owned(),
        rule_id: "production-owners".to_owned(),
        subject_digest: created.request.subject_digest.clone(),
        decided_unix_ms: 110,
    };
    assert!(matches!(
        gate.decide("request-1", author, 110),
        Err(DeploymentError::Approval(PolicyError::SeparationOfDuties(
            _
        )))
    ));
    let status = gate
        .decide(
            "request-1",
            ApprovalDecision {
                actor_id: "alice".to_owned(),
                decision: Decision::Deny,
                reason: "artifact scan evidence is insufficient".to_owned(),
                rule_id: "production-owners".to_owned(),
                subject_digest: created.request.subject_digest,
                decided_unix_ms: 111,
            },
            111,
        )
        .expect("deny");
    assert_eq!(status, DeploymentRequestStatus::Denied);
    assert!(matches!(
        gate.start("request-1", "deployment-1".to_owned(), 120),
        Err(DeploymentError::InvalidState(
            DeploymentRequestStatus::Denied
        ))
    ));
}

#[test]
fn concurrency_is_checked_before_consuming_approval() {
    let environment = environment();
    let mut gate = DeploymentGate::new();
    gate.register_environment(environment.clone())
        .expect("environment");
    let first = gate
        .create_request(create(
            &environment,
            "request-1",
            "key-1",
            subject(&environment),
        ))
        .expect("first");
    let second = gate
        .create_request(create(
            &environment,
            "request-2",
            "key-2",
            subject(&environment),
        ))
        .expect("second");
    approve(&mut gate, "request-1", first.request.subject_digest, 110);
    approve(&mut gate, "request-2", second.request.subject_digest, 110);
    gate.start("request-1", "deployment-1".to_owned(), 120)
        .expect("first start");
    assert!(matches!(
        gate.start("request-2", "deployment-2".to_owned(), 120),
        Err(DeploymentError::ConcurrencyLimit)
    ));
    assert_eq!(
        gate.request("request-2")
            .expect("second request")
            .approval
            .status,
        ApprovalStatus::Approved
    );
    gate.finish("deployment-1", true, None, BTreeMap::new(), None, 130)
        .expect("finish first");
    gate.start("request-2", "deployment-2".to_owned(), 131)
        .expect("second start");
}

#[test]
fn expired_approval_never_becomes_ready_and_cancel_is_idempotent() {
    let mut environment = environment();
    environment.approval_ttl_ms = 5;
    let mut gate = DeploymentGate::new();
    gate.register_environment(environment.clone())
        .expect("environment");
    gate.create_request(create(
        &environment,
        "request-expired",
        "key-expired",
        subject(&environment),
    ))
    .expect("request");
    assert_eq!(
        gate.refresh("request-expired", 105).expect("expire"),
        DeploymentRequestStatus::Expired
    );

    gate.create_request(create(
        &environment,
        "request-cancel",
        "key-cancel",
        subject(&environment),
    ))
    .expect("request");
    assert!(gate.cancel("request-cancel", 102).expect("cancel"));
    assert!(!gate.cancel("request-cancel", 103).expect("repeat"));
}

#[test]
fn rollback_is_a_fresh_exact_subject_and_never_reuses_prior_approval() {
    let environment = environment();
    let mut rollback = subject(&environment);
    rollback.rollback_of = Some("deployment-bad".to_owned());
    rollback.artifact_id = ContentDigest::sha256(b"previous artifact record");
    rollback.artifact_content_digest = ContentDigest::sha256(b"previous artifact bytes");
    rollback.deployment_target_digest = ContentDigest::sha256(b"rollback target");
    let mut gate = DeploymentGate::new();
    gate.register_environment(environment.clone())
        .expect("environment");
    let created = gate
        .create_request(create(
            &environment,
            "rollback-request",
            "rollback-key",
            rollback,
        ))
        .expect("rollback");
    assert_eq!(
        created.request.status,
        DeploymentRequestStatus::PendingApproval
    );
    assert_eq!(
        created.request.approval.kind,
        ApprovalKind::EnvironmentDeployment
    );
    assert_ne!(
        created.request.subject_digest,
        subject(&environment)
            .digest(&environment)
            .expect("normal digest")
    );
}

#[test]
fn completion_metadata_and_approval_reasons_are_bounded() {
    let environment = environment();
    let mut gate = DeploymentGate::new();
    gate.register_environment(environment.clone())
        .expect("environment");
    let created = gate
        .create_request(create(
            &environment,
            "request-1",
            "key-1",
            subject(&environment),
        ))
        .expect("request");
    let too_long = "x".repeat(MAX_APPROVAL_REASON_BYTES + 1);
    assert!(gate
        .decide(
            "request-1",
            ApprovalDecision {
                actor_id: "alice".to_owned(),
                decision: Decision::Approve,
                reason: too_long,
                rule_id: "production-owners".to_owned(),
                subject_digest: created.request.subject_digest,
                decided_unix_ms: 110,
            },
            110,
        )
        .is_err());
    let metadata = BTreeMap::from([("key".to_owned(), "x".repeat(MAX_METADATA_VALUE_BYTES + 1))]);
    assert!(matches!(
        validate_metadata(&metadata),
        Err(DeploymentError::InvalidMetadata)
    ));
}
