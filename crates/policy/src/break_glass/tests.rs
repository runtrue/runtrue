use super::*;
use runtrue_model::ContentDigest;

fn new(second: bool) -> NewBreakGlassRequest {
    NewBreakGlassRequest {
        id: "break-1".to_owned(),
        tenant_id: "tenant".to_owned(),
        requester_id: "alice".to_owned(),
        action: "DrainRunnerPool".to_owned(),
        resource_kind: "RunnerPool".to_owned(),
        resource_id: "pool-1".to_owned(),
        reason: "contain suspected runner compromise".to_owned(),
        incident_reference: "INC-123".to_owned(),
        requested_unix_ms: 1_000,
        requester_mfa_unix_ms: 900,
        expires_unix_ms: 10_000,
        require_second_approver: second,
        eligible_approvers: ["bob"].into_iter().map(str::to_owned).collect(),
    }
}

fn notify(request: &mut BreakGlassRequest, now: u64) {
    request
        .record_notification(
            BreakGlassNotificationReceipt {
                subject_digest: request.subject_digest.clone(),
                channel: "security-pager".to_owned(),
                delivery_id: "notification-1".to_owned(),
                notified_unix_ms: now,
            },
            now,
        )
        .unwrap();
}

#[test]
fn exact_subject_requires_independent_approval_notification_and_fresh_mfa() {
    let mut request = BreakGlassRequest::create(new(true)).unwrap();
    assert_eq!(request.status, BreakGlassStatus::PendingApproval);
    request
        .decide(
            BreakGlassApproval {
                actor_id: "bob".to_owned(),
                approve: true,
                reason: "incident confirmed".to_owned(),
                subject_digest: request.subject_digest.clone(),
                decided_unix_ms: 1_100,
                actor_mfa_unix_ms: 1_000,
            },
            1_100,
        )
        .unwrap();
    assert_eq!(request.status, BreakGlassStatus::PendingNotification);
    notify(&mut request, 1_200);
    let use_record = request
        .authorize_once(
            "alice",
            "DrainRunnerPool",
            "RunnerPool",
            "pool-1",
            &request.subject_digest.clone(),
            1_250,
            1_300,
        )
        .unwrap();
    assert_eq!(use_record.incident_reference, "INC-123");
    assert_eq!(request.status, BreakGlassStatus::Consumed);
    assert!(matches!(
        request.authorize_once(
            "alice",
            "DrainRunnerPool",
            "RunnerPool",
            "pool-1",
            &request.subject_digest.clone(),
            1_300,
            1_301
        ),
        Err(BreakGlassError::InvalidState(BreakGlassStatus::Consumed))
    ));
}

#[test]
fn self_approval_mutation_expiry_and_missing_notification_fail_closed() {
    let mut invalid = new(true);
    invalid.eligible_approvers.insert("alice".to_owned());
    assert!(matches!(
        BreakGlassRequest::create(invalid),
        Err(BreakGlassError::InvalidApproverSet)
    ));

    let mut request = BreakGlassRequest::create(new(false)).unwrap();
    assert!(matches!(
        request.authorize_once(
            "alice",
            "DifferentAction",
            "RunnerPool",
            "pool-1",
            &request.subject_digest.clone(),
            1_000,
            1_001
        ),
        Err(BreakGlassError::InvalidState(
            BreakGlassStatus::PendingNotification
        ))
    ));
    notify(&mut request, 1_100);
    let wrong = ContentDigest::sha256(b"wrong");
    assert!(matches!(
        request.authorize_once(
            "alice",
            "DrainRunnerPool",
            "RunnerPool",
            "pool-1",
            &wrong,
            1_100,
            1_101
        ),
        Err(BreakGlassError::SubjectMismatch)
    ));
    request.refresh_expiry(10_000);
    assert_eq!(request.status, BreakGlassStatus::Expired);
}

#[test]
fn permanently_forbidden_actions_and_long_windows_are_rejected() {
    let mut forbidden = new(false);
    "DeleteAuditEvent".clone_into(&mut forbidden.action);
    assert!(matches!(
        BreakGlassRequest::create(forbidden),
        Err(BreakGlassError::PermanentlyForbiddenAction(_))
    ));
    let mut long = new(false);
    long.expires_unix_ms = long.requested_unix_ms + MAX_BREAK_GLASS_DURATION_MS + 1;
    assert!(matches!(
        BreakGlassRequest::create(long),
        Err(BreakGlassError::InvalidDuration)
    ));
}

#[test]
fn persisted_status_and_evidence_tampering_is_detected() {
    let mut request = BreakGlassRequest::create(new(false)).unwrap();
    notify(&mut request, 1_100);
    request.verify_integrity().unwrap();
    request.status = BreakGlassStatus::Consumed;
    assert!(matches!(
        request.verify_integrity(),
        Err(BreakGlassError::IntegrityMismatch)
    ));

    let mut request = BreakGlassRequest::create(new(true)).unwrap();
    request.approval = Some(BreakGlassApproval {
        actor_id: "alice".to_owned(),
        approve: true,
        reason: "forged".to_owned(),
        subject_digest: request.subject_digest.clone(),
        decided_unix_ms: 1_100,
        actor_mfa_unix_ms: 1_000,
    });
    request.status = BreakGlassStatus::PendingNotification;
    assert!(matches!(
        request.verify_integrity(),
        Err(BreakGlassError::IntegrityMismatch)
    ));
}
