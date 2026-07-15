//! Exact-subject approval and deny-first policy primitives.
//!
//! This crate deliberately contains no HTTP, database, SCM, or executor code.
//! A control plane persists these immutable requests and serializes decisions
//! transactionally, while the same state machine remains usable in tests and
//! local administration tools.

mod active_bundle;
mod break_glass;
mod cedar;
mod lifecycle;
mod seal;

pub use active_bundle::*;
pub use break_glass::*;
pub use cedar::*;
pub use lifecycle::*;
pub use seal::*;

use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const MAX_APPROVAL_REASON_BYTES: usize = 2_000;
pub const MAX_APPROVERS: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalKind {
    WorkflowDefinition,
    PrivilegedExecution,
    EnvironmentDeployment,
    ArtifactPromotion,
    BreakGlass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRule {
    pub id: String,
    pub required_approvals: u16,
    pub eligible_approvers: BTreeSet<String>,
    pub forbidden_approvers: BTreeSet<String>,
    pub one_shot: bool,
}

impl ApprovalRule {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.id.is_empty() || self.id.contains('\0') {
            return Err(PolicyError::InvalidRule("rule id"));
        }
        if self.required_approvals == 0 {
            return Err(PolicyError::InvalidRule(
                "required approvals must be greater than zero",
            ));
        }
        let permitted_approvers = self
            .eligible_approvers
            .len()
            .saturating_sub(self.forbidden_approvers.len());
        if self.eligible_approvers.is_empty()
            || self.eligible_approvers.len() > MAX_APPROVERS
            || usize::from(self.required_approvals) > permitted_approvers
        {
            return Err(PolicyError::InvalidRule(
                "approval threshold exceeds the bounded eligible set",
            ));
        }
        if !self.forbidden_approvers.is_subset(&self.eligible_approvers) {
            return Err(PolicyError::InvalidRule(
                "forbidden approvers must be members of the eligible set",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecision {
    pub actor_id: String,
    pub decision: Decision,
    pub reason: String,
    pub rule_id: String,
    pub subject_digest: ContentDigest,
    pub decided_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub id: String,
    pub kind: ApprovalKind,
    pub subject_digest: ContentDigest,
    pub risk_score: u32,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub rule: ApprovalRule,
    pub status: ApprovalStatus,
    pub decisions: BTreeMap<String, ApprovalDecision>,
}

impl ApprovalRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: impl Into<String>,
        kind: ApprovalKind,
        subject_digest: ContentDigest,
        risk_score: u32,
        created_unix_ms: u64,
        expires_unix_ms: u64,
        rule: ApprovalRule,
    ) -> Result<Self, PolicyError> {
        rule.validate()?;
        let id = id.into();
        if id.is_empty() || id.contains('\0') {
            return Err(PolicyError::InvalidRequest("request id"));
        }
        if expires_unix_ms <= created_unix_ms {
            return Err(PolicyError::InvalidRequest("expiry must be after creation"));
        }
        Ok(Self {
            id,
            kind,
            subject_digest,
            risk_score,
            created_unix_ms,
            expires_unix_ms,
            rule,
            status: ApprovalStatus::Pending,
            decisions: BTreeMap::new(),
        })
    }

    pub fn decide(
        &mut self,
        decision: ApprovalDecision,
        now_unix_ms: u64,
    ) -> Result<ApprovalStatus, PolicyError> {
        self.refresh_expiry(now_unix_ms);
        if self.status != ApprovalStatus::Pending {
            return Err(PolicyError::RequestNotPending(self.status));
        }
        if decision.subject_digest != self.subject_digest {
            return Err(PolicyError::SubjectConflict {
                expected: self.subject_digest.clone(),
                actual: decision.subject_digest,
            });
        }
        if decision.rule_id != self.rule.id {
            return Err(PolicyError::RuleConflict);
        }
        if decision.decided_unix_ms > now_unix_ms || decision.decided_unix_ms < self.created_unix_ms
        {
            return Err(PolicyError::InvalidDecisionTime);
        }
        validate_reason(&decision.reason)?;
        if !self.rule.eligible_approvers.contains(&decision.actor_id) {
            return Err(PolicyError::IneligibleApprover(decision.actor_id));
        }
        if self.rule.forbidden_approvers.contains(&decision.actor_id) {
            return Err(PolicyError::SeparationOfDuties(decision.actor_id));
        }
        if self.decisions.contains_key(&decision.actor_id) {
            return Err(PolicyError::DuplicateDecision(decision.actor_id));
        }

        let denied = decision.decision == Decision::Deny;
        self.decisions.insert(decision.actor_id.clone(), decision);
        if denied {
            self.status = ApprovalStatus::Denied;
        } else {
            let approvals = self
                .decisions
                .values()
                .filter(|decision| decision.decision == Decision::Approve)
                .count();
            if approvals >= usize::from(self.rule.required_approvals) {
                self.status = ApprovalStatus::Approved;
            }
        }
        Ok(self.status)
    }

    pub fn authorize(
        &mut self,
        subject_digest: &ContentDigest,
        now_unix_ms: u64,
    ) -> Result<(), PolicyError> {
        self.refresh_expiry(now_unix_ms);
        if subject_digest != &self.subject_digest {
            return Err(PolicyError::SubjectConflict {
                expected: self.subject_digest.clone(),
                actual: subject_digest.clone(),
            });
        }
        if self.status != ApprovalStatus::Approved {
            return Err(PolicyError::NotAuthorized(self.status));
        }
        if self.rule.one_shot {
            self.status = ApprovalStatus::Consumed;
        }
        Ok(())
    }

    pub fn refresh_expiry(&mut self, now_unix_ms: u64) {
        if matches!(
            self.status,
            ApprovalStatus::Pending | ApprovalStatus::Approved
        ) && now_unix_ms >= self.expires_unix_ms
        {
            self.status = ApprovalStatus::Expired;
        }
    }
}

fn validate_reason(reason: &str) -> Result<(), PolicyError> {
    if reason.trim().is_empty() || reason.len() > MAX_APPROVAL_REASON_BYTES || reason.contains('\0')
    {
        return Err(PolicyError::InvalidReason);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionContext {
    pub action: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub risk_score: u32,
    pub privileged: bool,
    pub untrusted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencyDeny {
    pub id: String,
    pub actions: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_risk_score: Option<u32>,
    pub deny_privileged: bool,
    pub deny_untrusted: bool,
}

impl EmergencyDeny {
    #[must_use]
    pub fn matches(&self, context: &AdmissionContext) -> bool {
        (self.actions.is_empty() || self.actions.contains(&context.action))
            && self
                .repository_id
                .as_ref()
                .is_none_or(|repository| repository == &context.repository_id)
            && self
                .minimum_risk_score
                .is_none_or(|minimum| context.risk_score >= minimum)
            && (!self.deny_privileged || context.privileged)
            && (!self.deny_untrusted || context.untrusted)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyFirstPolicy {
    pub emergency_denies: Vec<EmergencyDeny>,
}

impl DenyFirstPolicy {
    pub fn admit(&self, context: &AdmissionContext) -> Result<(), PolicyError> {
        if let Some(rule) = self
            .emergency_denies
            .iter()
            .find(|rule| rule.matches(context))
        {
            return Err(PolicyError::EmergencyDenied(rule.id.clone()));
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("invalid approval rule: {0}")]
    InvalidRule(&'static str),
    #[error("invalid approval request: {0}")]
    InvalidRequest(&'static str),
    #[error("approval request is not pending; current status is {0:?}")]
    RequestNotPending(ApprovalStatus),
    #[error("approval subject changed: expected {expected}, found {actual}")]
    SubjectConflict {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("approval rule changed while the request was pending")]
    RuleConflict,
    #[error("approval decision has an invalid timestamp")]
    InvalidDecisionTime,
    #[error("approval reason must contain 1..={MAX_APPROVAL_REASON_BYTES} safe bytes")]
    InvalidReason,
    #[error("actor `{0}` is not eligible to approve this request")]
    IneligibleApprover(String),
    #[error("actor `{0}` is forbidden by separation-of-duties policy")]
    SeparationOfDuties(String),
    #[error("actor `{0}` already decided this request")]
    DuplicateDecision(String),
    #[error("approval does not authorize execution; status is {0:?}")]
    NotAuthorized(ApprovalStatus),
    #[error("approval kind {0:?} is not bound to an Capsule")]
    NotCapsuleApproval(ApprovalKind),
    #[error("approval is not a Seal; current status is {0:?}")]
    NotSealed(ApprovalStatus),
    #[error("invalid Capsule Seal: {0}")]
    InvalidSeal(&'static str),
    #[error("emergency deny rule `{0}` rejected admission")]
    EmergencyDenied(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(threshold: u16) -> ApprovalRule {
        ApprovalRule {
            id: "release-rule".to_owned(),
            required_approvals: threshold,
            eligible_approvers: ["author", "alice", "bob"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            forbidden_approvers: ["author"].into_iter().map(str::to_owned).collect(),
            one_shot: true,
        }
    }

    fn decision(actor: &str, subject: &ContentDigest, value: Decision) -> ApprovalDecision {
        ApprovalDecision {
            actor_id: actor.to_owned(),
            decision: value,
            reason: "reviewed exact capsule".to_owned(),
            rule_id: "release-rule".to_owned(),
            subject_digest: subject.clone(),
            decided_unix_ms: 2,
        }
    }

    #[test]
    fn exact_subject_n_of_m_and_one_shot_are_enforced() {
        let subject = ContentDigest::sha256(b"subject");
        let mut request = ApprovalRequest::create(
            "approval-1",
            ApprovalKind::PrivilegedExecution,
            subject.clone(),
            80,
            1,
            100,
            rule(2),
        )
        .unwrap();
        assert_eq!(
            request
                .decide(decision("alice", &subject, Decision::Approve), 2)
                .unwrap(),
            ApprovalStatus::Pending
        );
        assert_eq!(
            request
                .decide(decision("bob", &subject, Decision::Approve), 2)
                .unwrap(),
            ApprovalStatus::Approved
        );
        request.authorize(&subject, 3).unwrap();
        assert_eq!(request.status, ApprovalStatus::Consumed);
        assert!(matches!(
            request.authorize(&subject, 4),
            Err(PolicyError::NotAuthorized(ApprovalStatus::Consumed))
        ));
    }

    #[test]
    fn author_duplicate_deny_and_subject_changes_fail_closed() {
        let subject = ContentDigest::sha256(b"subject");
        let changed = ContentDigest::sha256(b"changed");
        let mut request = ApprovalRequest::create(
            "approval-1",
            ApprovalKind::WorkflowDefinition,
            subject.clone(),
            20,
            1,
            100,
            rule(1),
        )
        .unwrap();
        assert!(matches!(
            request.decide(decision("author", &subject, Decision::Approve), 2),
            Err(PolicyError::SeparationOfDuties(_))
        ));
        assert!(matches!(
            request.decide(decision("alice", &changed, Decision::Approve), 2),
            Err(PolicyError::SubjectConflict { .. })
        ));
        assert_eq!(
            request
                .decide(decision("alice", &subject, Decision::Deny), 2)
                .unwrap(),
            ApprovalStatus::Denied
        );
        assert!(matches!(
            request.decide(decision("bob", &subject, Decision::Approve), 3),
            Err(PolicyError::RequestNotPending(ApprovalStatus::Denied))
        ));
    }

    #[test]
    fn emergency_denies_override_other_admission() {
        let policy = DenyFirstPolicy {
            emergency_denies: vec![EmergencyDeny {
                id: "stop-privileged".to_owned(),
                actions: ["run.execute".to_owned()].into_iter().collect(),
                repository_id: None,
                minimum_risk_score: None,
                deny_privileged: true,
                deny_untrusted: false,
            }],
        };
        let context = AdmissionContext {
            action: "run.execute".to_owned(),
            tenant_id: "tenant".to_owned(),
            repository_id: "repo".to_owned(),
            risk_score: 1,
            privileged: true,
            untrusted: false,
        };
        assert_eq!(
            policy.admit(&context),
            Err(PolicyError::EmergencyDenied("stop-privileged".to_owned()))
        );
    }

    #[test]
    fn expiration_invalidates_approved_request() {
        let subject = ContentDigest::sha256(b"subject");
        let mut request = ApprovalRequest::create(
            "approval-1",
            ApprovalKind::PrivilegedExecution,
            subject.clone(),
            1,
            1,
            5,
            rule(1),
        )
        .unwrap();
        request
            .decide(decision("alice", &subject, Decision::Approve), 2)
            .unwrap();
        assert!(matches!(
            request.authorize(&subject, 5),
            Err(PolicyError::NotAuthorized(ApprovalStatus::Expired))
        ));
    }
}
