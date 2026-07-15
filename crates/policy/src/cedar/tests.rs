use super::*;
use crate::DenyFirstPolicy;
use crate::EmergencyDeny;
use std::collections::BTreeSet;

fn request(action: CedarAction) -> CedarAuthorizationRequest {
    CedarAuthorizationRequest {
        principal: CedarPrincipal {
            kind: CedarPrincipalKind::User,
            id: "alice".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            groups: BTreeSet::from(["security".to_owned()]),
        },
        action,
        resource: CedarResource {
            kind: CedarResourceKind::ApprovalRequest,
            id: "approval-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            repository_id: Some("repo-1".to_owned()),
            author_id: Some("author".to_owned()),
            risk_score: 50,
            privileged: false,
            untrusted: true,
        },
        context: CedarRequestContext {
            mfa_age_seconds: Some(60),
            reauthentication_age_seconds: Some(60),
            break_glass: false,
        },
    }
}

#[test]
fn default_deny_and_group_permit_are_enforced() {
    let deny = CedarAuthorizationEngine::new("", DenyFirstPolicy::default()).unwrap();
    assert!(
        !deny
            .authorize(&request(CedarAction::ApproveWorkflow))
            .unwrap()
            .allowed
    );

    let permit = CedarAuthorizationEngine::new(
        r#"permit (
                principal in Team::"security",
                action == Action::"ApproveWorkflow",
                resource
            ) when {
                resource is ApprovalRequest &&
                resource has author_id &&
                resource.author_id != principal.id &&
                resource.risk_score < 90 &&
                context has mfa_age_seconds &&
                context.mfa_age_seconds < 300
            };"#,
        DenyFirstPolicy::default(),
    )
    .unwrap();
    let decision = permit
        .authorize(&request(CedarAction::ApproveWorkflow))
        .unwrap();
    assert!(decision.allowed);
    assert_eq!(decision.determining_policy_ids, vec!["policy0"]);
}

#[test]
fn forbid_overrides_permit_and_self_approval_is_denied() {
    let engine = CedarAuthorizationEngine::new(
            r#"
            permit (principal, action == Action::"ApproveWorkflow", resource);
            forbid (principal, action == Action::"ApproveWorkflow", resource)
            when { resource is ApprovalRequest && resource has author_id && resource.author_id == principal.id };
            "#,
            DenyFirstPolicy::default(),
        )
        .unwrap();
    let mut self_approval = request(CedarAction::ApproveWorkflow);
    self_approval.resource.author_id = Some("alice".to_owned());
    assert!(!engine.authorize(&self_approval).unwrap().allowed);
}

#[test]
fn schema_validation_rejects_unknown_attributes_and_actions() {
    let error = CedarAuthorizationEngine::new(
        r#"permit (principal, action, resource) when { resource.typo == true };"#,
        DenyFirstPolicy::default(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CedarAuthorizationError::PolicyValidation { .. }
    ));
}

#[test]
fn emergency_deny_precedes_cedar_permit() {
    let engine = CedarAuthorizationEngine::new(
        "permit (principal, action, resource);",
        DenyFirstPolicy {
            emergency_denies: vec![EmergencyDeny {
                id: "halt-untrusted".to_owned(),
                actions: BTreeSet::from(["ApproveWorkflow".to_owned()]),
                repository_id: Some("repo-1".to_owned()),
                minimum_risk_score: None,
                deny_privileged: false,
                deny_untrusted: true,
            }],
        },
    )
    .unwrap();
    let decision = engine
        .authorize(&request(CedarAction::ApproveWorkflow))
        .unwrap();
    assert!(!decision.allowed);
    assert_eq!(
        decision.emergency_deny_id.as_deref(),
        Some("halt-untrusted")
    );
}

#[test]
fn cross_tenant_and_oversized_group_requests_fail_closed() {
    let engine = CedarAuthorizationEngine::new(
        "permit (principal, action, resource);",
        DenyFirstPolicy::default(),
    )
    .unwrap();
    let mut invalid = request(CedarAction::ViewRepository);
    "other".clone_into(&mut invalid.resource.tenant_id);
    assert_eq!(
        engine.authorize(&invalid),
        Err(CedarAuthorizationError::CrossTenantRequest)
    );
    "tenant-1".clone_into(&mut invalid.resource.tenant_id);
    invalid.principal.groups = (0..=MAX_GROUPS)
        .map(|index| format!("group-{index}"))
        .collect();
    assert_eq!(
        engine.authorize(&invalid),
        Err(CedarAuthorizationError::GroupLimit)
    );
}

#[test]
fn shipped_authorization_policy_validates_against_the_embedded_schema() {
    let engine = CedarAuthorizationEngine::new(
        include_str!("../../../../examples/policies/approval-policy.cedar"),
        DenyFirstPolicy::default(),
    )
    .expect("shipped Cedar policy must remain schema-valid");
    assert!(engine.schema_digest().to_string().starts_with("sha256:"));
}
