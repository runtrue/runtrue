use super::*;
use crate::{
    CedarAction, CedarPrincipal, CedarPrincipalKind, CedarRequestContext, CedarResource,
    CedarResourceKind, EmergencyDeny,
};
use crate::{CedarAuthorizationRequest, DenyFirstPolicy};
use std::collections::BTreeSet;

const PERMIT: &str = r#"
        permit (
            principal,
            action == Action::"ViewRepository",
            resource is Repository
        );
    "#;

fn request(tenant: &str) -> CedarAuthorizationRequest {
    CedarAuthorizationRequest {
        principal: CedarPrincipal {
            kind: CedarPrincipalKind::User,
            id: "alice".to_owned(),
            tenant_id: tenant.to_owned(),
            groups: BTreeSet::new(),
        },
        action: CedarAction::ViewRepository,
        resource: CedarResource {
            kind: CedarResourceKind::Repository,
            id: "repo-1".to_owned(),
            tenant_id: tenant.to_owned(),
            repository_id: Some("repo-1".to_owned()),
            author_id: None,
            risk_score: 0,
            privileged: false,
            untrusted: false,
        },
        context: CedarRequestContext::default(),
    }
}

fn case(id: &str, tenant: &str, expected: bool) -> PolicySimulationCase {
    PolicySimulationCase {
        id: id.to_owned(),
        request: request(tenant),
        expected_allowed: Some(expected),
    }
}

fn draft() -> PolicyBundleDraft {
    PolicyBundleDraft::new("draft-1", "tenant-1", "author", PERMIT, 100).expect("draft")
}

#[test]
fn canonical_draft_ignores_caller_formatting_and_rejects_invalid_source() {
    let first = draft();
    let second = PolicyBundleDraft::new(
        "draft-2",
        "tenant-1",
        "author",
        "permit(principal,action==Action::\"ViewRepository\",resource is Repository);",
        100,
    )
    .expect("canonical draft");
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.canonical_policy_json, second.canonical_policy_json);
    assert!(PolicyBundleDraft::new(
        "draft-3",
        "tenant-1",
        "author",
        "permit(principal, action, resource) when { resource.typo == true };",
        100,
    )
    .is_err());
}

#[test]
fn simulation_shadow_activation_and_exact_replay_are_bound() {
    let mut state = ActivePolicyBundleState::new("tenant-1").expect("state");
    let mut draft = draft();
    let simulation = state
        .simulate(&mut draft, &[case("stored", "tenant-1", true)], &[])
        .expect("simulate");
    assert!(simulation.activation_eligible());
    draft
        .enter_shadow(&simulation.report_digest)
        .expect("shadow");
    let shadow = state
        .compare_shadow(&draft, &[case("request", "tenant-1", true)])
        .expect("compare");
    assert!(!shadow.results[0].active_allowed);
    assert!(shadow.results[0].shadow_allowed);
    assert!(
        !state
            .snapshot()
            .expect("snapshot")
            .authorize(&request("tenant-1"))
            .expect("authorize")
            .allowed
    );

    let self_activation = ActivatePolicyBundle {
        draft_digest: draft.digest.clone(),
        simulation_digest: simulation.report_digest.clone(),
        expected_policy_epoch: 0,
        approval_id: "approval-1".to_owned(),
        approved_by: "author".to_owned(),
        approved_unix_ms: 200,
    };
    assert_eq!(
        state.activate(&mut draft, &self_activation),
        Err(ActivePolicyError::SeparationOfDuties)
    );
    let mut activation = ActivatePolicyBundle {
        approved_by: "security-reviewer".to_owned(),
        ..self_activation
    };
    activation.expected_policy_epoch = 9;
    assert_eq!(
        state.activate(&mut draft, &activation),
        Err(ActivePolicyError::StalePolicyEpoch {
            expected: 0,
            actual: 9,
        })
    );
    activation.expected_policy_epoch = 0;
    let active = state.activate(&mut draft, &activation).expect("activate");
    assert_eq!(active.policy_epoch, 1);
    assert_eq!(
        state
            .activate(&mut draft, &activation)
            .expect("exact replay"),
        active
    );
    assert!(
        state
            .snapshot()
            .expect("snapshot")
            .authorize(&request("tenant-1"))
            .expect("authorize")
            .allowed
    );
}

#[test]
fn emergency_deny_precedes_active_permit_and_invalidates_cache_generation() {
    let mut state = ActivePolicyBundleState::new("tenant-1").expect("state");
    let mut draft = draft();
    let simulation = state
        .simulate(&mut draft, &[case("stored", "tenant-1", true)], &[])
        .expect("simulate");
    draft
        .enter_shadow(&simulation.report_digest)
        .expect("shadow");
    let draft_digest = draft.digest.clone();
    state
        .activate(
            &mut draft,
            &ActivatePolicyBundle {
                draft_digest,
                simulation_digest: simulation.report_digest,
                expected_policy_epoch: 0,
                approval_id: "approval-1".to_owned(),
                approved_by: "reviewer".to_owned(),
                approved_unix_ms: 200,
            },
        )
        .expect("activate");
    let generation = state.decision_cache_generation;
    assert!(state
        .replace_emergency_denies(
            DenyFirstPolicy {
                emergency_denies: vec![EmergencyDeny {
                    id: "halt-view".to_owned(),
                    actions: BTreeSet::from(["ViewRepository".to_owned()]),
                    repository_id: Some("repo-1".to_owned()),
                    minimum_risk_score: None,
                    deny_privileged: false,
                    deny_untrusted: false,
                }],
            },
            generation,
        )
        .expect("replace"));
    assert_eq!(state.decision_cache_generation, generation + 1);
    let updated_generation = state.decision_cache_generation;
    let emergency_replay = state.emergency_denies.clone();
    assert!(!state
        .replace_emergency_denies(emergency_replay, generation)
        .expect("exact emergency replay"));
    assert_eq!(state.decision_cache_generation, updated_generation);
    let decision = state
        .snapshot()
        .expect("snapshot")
        .authorize(&request("tenant-1"))
        .expect("authorize");
    assert!(!decision.allowed);
    assert_eq!(decision.emergency_deny_id.as_deref(), Some("halt-view"));
}

#[test]
fn simulation_bounds_tenants_errors_and_activation_epoch() {
    let state = ActivePolicyBundleState::new("tenant-1").expect("state");
    let mut other = PolicyBundleDraft::new("draft", "tenant-2", "author", PERMIT, 100)
        .expect("other tenant draft");
    assert_eq!(
        state.simulate(&mut other, &[case("stored", "tenant-2", true)], &[]),
        Err(ActivePolicyError::CrossTenantDraft)
    );
    let mut draft = draft();
    let too_many = (0..=MAX_CALLER_SIMULATION_CASES)
        .map(|index| case(&format!("case-{index}"), "tenant-1", true))
        .collect::<Vec<_>>();
    assert_eq!(
        state.simulate(&mut draft, &[], &too_many),
        Err(ActivePolicyError::SimulationCaseLimit)
    );

    let mut invalid_case = case("invalid", "tenant-1", false);
    invalid_case.request.resource.tenant_id = "tenant-2".to_owned();
    let report = state
        .simulate(&mut draft, &[invalid_case], &[])
        .expect("fail-closed simulation report");
    assert_eq!(report.evaluation_error_count, 1);
    assert!(!report.activation_eligible());
    draft.enter_shadow(&report.report_digest).expect("shadow");
    let mut state = state;
    let draft_digest = draft.digest.clone();
    assert_eq!(
        state.activate(
            &mut draft,
            &ActivatePolicyBundle {
                draft_digest,
                simulation_digest: report.report_digest,
                expected_policy_epoch: 0,
                approval_id: "approval".to_owned(),
                approved_by: "reviewer".to_owned(),
                approved_unix_ms: 200,
            }
        ),
        Err(ActivePolicyError::InvalidLifecycleTransition)
    );
}
