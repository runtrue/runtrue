use crate::{
    validate_reason, ApprovalKind, ApprovalRequest, ApprovalStatus, Decision, PolicyError,
};
use runtrue_model::ContentDigest;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

/// An immutable approval artifact bound to one exact Capsule.
///
/// A Seal can only be created from an approved (or already consumed)
/// workflow-definition or privileged-execution request. Its transparent wire
/// representation is intentionally identical to the validated approval
/// request, so introducing the public term does not alter persisted or signed
/// material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CapsuleSeal(ApprovalRequest);

impl CapsuleSeal {
    /// Return the exact Capsule digest authorized by this Seal.
    #[must_use]
    pub const fn capsule_digest(&self) -> &ContentDigest {
        &self.0.subject_digest
    }

    /// Return the validated approval evidence carried by this Seal.
    #[must_use]
    pub const fn approval(&self) -> &ApprovalRequest {
        &self.0
    }

    /// Consume the facade without changing the underlying approval record.
    #[must_use]
    pub fn into_approval(self) -> ApprovalRequest {
        self.0
    }

    /// Revalidate the complete evidence represented by this Seal.
    pub fn verify(&self) -> Result<(), PolicyError> {
        validate_seal(&self.0)
    }
}

impl TryFrom<ApprovalRequest> for CapsuleSeal {
    type Error = PolicyError;

    fn try_from(request: ApprovalRequest) -> Result<Self, Self::Error> {
        validate_seal(&request)?;
        Ok(Self(request))
    }
}

impl<'de> Deserialize<'de> for CapsuleSeal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let request = ApprovalRequest::deserialize(deserializer)?;
        Self::try_from(request).map_err(D::Error::custom)
    }
}

fn validate_seal(request: &ApprovalRequest) -> Result<(), PolicyError> {
    if !matches!(
        request.kind,
        ApprovalKind::WorkflowDefinition | ApprovalKind::PrivilegedExecution
    ) {
        return Err(PolicyError::NotCapsuleApproval(request.kind));
    }
    if !matches!(
        request.status,
        ApprovalStatus::Approved | ApprovalStatus::Consumed
    ) {
        return Err(PolicyError::NotSealed(request.status));
    }
    if request.status == ApprovalStatus::Consumed && !request.rule.one_shot {
        return Err(PolicyError::InvalidSeal(
            "only one-shot approval evidence can be consumed",
        ));
    }
    request.rule.validate()?;
    if request.id.is_empty() || request.id.contains('\0') {
        return Err(PolicyError::InvalidSeal("approval id"));
    }
    if request.expires_unix_ms <= request.created_unix_ms {
        return Err(PolicyError::InvalidSeal("expiry must be after creation"));
    }

    let mut approvals = 0_usize;
    for (actor_id, decision) in &request.decisions {
        if actor_id != &decision.actor_id {
            return Err(PolicyError::InvalidSeal(
                "decision map key does not match actor id",
            ));
        }
        if decision.decision != Decision::Approve {
            return Err(PolicyError::InvalidSeal(
                "approved evidence contains a denial",
            ));
        }
        if decision.subject_digest != request.subject_digest {
            return Err(PolicyError::InvalidSeal("decision Capsule digest changed"));
        }
        if decision.rule_id != request.rule.id {
            return Err(PolicyError::InvalidSeal("decision rule changed"));
        }
        if decision.decided_unix_ms < request.created_unix_ms
            || decision.decided_unix_ms >= request.expires_unix_ms
        {
            return Err(PolicyError::InvalidSeal("decision timestamp"));
        }
        validate_reason(&decision.reason)?;
        if !request.rule.eligible_approvers.contains(actor_id)
            || request.rule.forbidden_approvers.contains(actor_id)
        {
            return Err(PolicyError::InvalidSeal("ineligible decision actor"));
        }
        approvals += 1;
    }
    if approvals < usize::from(request.rule.required_approvals) {
        return Err(PolicyError::InvalidSeal(
            "approval threshold was not satisfied",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApprovalDecision, ApprovalRule};
    use std::collections::BTreeSet;

    fn approved_request(kind: ApprovalKind) -> ApprovalRequest {
        let digest = ContentDigest::sha256(b"capsule");
        let mut request = ApprovalRequest::create(
            "seal-1",
            kind,
            digest.clone(),
            50,
            1,
            100,
            ApprovalRule {
                id: "exact-capsule".to_owned(),
                required_approvals: 1,
                eligible_approvers: BTreeSet::from(["reviewer".to_owned()]),
                forbidden_approvers: BTreeSet::new(),
                one_shot: true,
            },
        )
        .unwrap();
        request
            .decide(
                ApprovalDecision {
                    actor_id: "reviewer".to_owned(),
                    decision: Decision::Approve,
                    reason: "reviewed exact Capsule".to_owned(),
                    rule_id: "exact-capsule".to_owned(),
                    subject_digest: digest,
                    decided_unix_ms: 2,
                },
                2,
            )
            .unwrap();
        request
    }

    #[test]
    fn seal_is_exact_digest_bound_and_wire_compatible() {
        let request = approved_request(ApprovalKind::PrivilegedExecution);
        let expected_digest = request.subject_digest.clone();
        let request_json = serde_json::to_value(&request).unwrap();
        let seal = CapsuleSeal::try_from(request).unwrap();

        assert_eq!(seal.capsule_digest(), &expected_digest);
        assert_eq!(serde_json::to_value(&seal).unwrap(), request_json);
        assert_eq!(
            serde_json::from_value::<CapsuleSeal>(request_json).unwrap(),
            seal
        );
    }

    #[test]
    fn generic_or_pending_approvals_are_not_seals() {
        let generic = approved_request(ApprovalKind::ArtifactPromotion);
        assert_eq!(
            CapsuleSeal::try_from(generic).unwrap_err(),
            PolicyError::NotCapsuleApproval(ApprovalKind::ArtifactPromotion)
        );

        let mut pending = approved_request(ApprovalKind::WorkflowDefinition);
        pending.status = ApprovalStatus::Pending;
        assert_eq!(
            CapsuleSeal::try_from(pending).unwrap_err(),
            PolicyError::NotSealed(ApprovalStatus::Pending)
        );
    }

    #[test]
    fn deserialization_rejects_forged_approval_evidence() {
        let request = approved_request(ApprovalKind::PrivilegedExecution);
        let mut value = serde_json::to_value(request).unwrap();
        value["decisions"]["reviewer"]["subject_digest"] =
            serde_json::to_value(ContentDigest::sha256(b"another-capsule")).unwrap();

        assert!(serde_json::from_value::<CapsuleSeal>(value).is_err());
    }
}
