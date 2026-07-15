use super::{
    canonical::{canonical_bytes, domain_digest},
    model::{
        ActivePolicyBundleState, PolicyBundleDraft, PolicyBundleDraftStatus, PolicyShadowReport,
        PolicyShadowResult, PolicySimulationCase, PolicySimulationReport, PolicySimulationResult,
        CORPUS_DIGEST_DOMAIN, MAX_CALLER_SIMULATION_CASES, MAX_SHADOW_CASES,
        MAX_SIMULATION_CORPUS_BYTES, MAX_STORED_SIMULATION_CASES, REPORT_DIGEST_DOMAIN,
    },
    snapshot::{engine_from_json, engine_from_json_optional},
    validation::{validate_cases, validate_identifier},
    ActivePolicyError,
};
use crate::{CedarAuthorizationEngine, CedarAuthorizationRequest};
use std::collections::BTreeMap;
impl PolicySimulationReport {
    #[must_use]
    pub const fn activation_eligible(&self) -> bool {
        self.evaluation_error_count == 0 && self.expectation_mismatch_count == 0
    }

    pub fn verify(&self) -> Result<(), ActivePolicyError> {
        let expected_count = self
            .stored_case_count
            .checked_add(self.caller_case_count)
            .ok_or(ActivePolicyError::InvalidSimulationReport)?;
        let mut ids = BTreeMap::new();
        if self.stored_case_count > MAX_STORED_SIMULATION_CASES
            || self.caller_case_count > MAX_CALLER_SIMULATION_CASES
            || self.results.len() != expected_count
            || self.results.iter().any(|result| {
                validate_identifier("policy simulation result id", &result.case_id).is_err()
                    || ids.insert(result.case_id.as_str(), ()).is_some()
                    || result.evaluation_error && result.allowed
                    || result.evaluation_error && result.expectation_matched == Some(true)
            })
            || self.evaluation_error_count
                != self
                    .results
                    .iter()
                    .filter(|result| result.evaluation_error)
                    .count()
            || self.expectation_mismatch_count
                != self
                    .results
                    .iter()
                    .filter(|result| result.expectation_matched == Some(false))
                    .count()
        {
            return Err(ActivePolicyError::InvalidSimulationReport);
        }
        let material = (
            &self.policy_digest,
            &self.corpus_digest,
            self.stored_case_count,
            self.caller_case_count,
            &self.results,
        );
        if domain_digest(REPORT_DIGEST_DOMAIN, &canonical_bytes(&material)?) != self.report_digest {
            return Err(ActivePolicyError::InvalidSimulationReport);
        }
        Ok(())
    }
}

impl ActivePolicyBundleState {
    pub fn simulate(
        &self,
        draft: &mut PolicyBundleDraft,
        stored_cases: &[PolicySimulationCase],
        caller_cases: &[PolicySimulationCase],
    ) -> Result<PolicySimulationReport, ActivePolicyError> {
        self.ensure_draft_tenant(draft)?;
        if !matches!(
            draft.status,
            PolicyBundleDraftStatus::Draft | PolicyBundleDraftStatus::Simulated
        ) {
            return Err(ActivePolicyError::InvalidLifecycleTransition);
        }
        if stored_cases.len() > MAX_STORED_SIMULATION_CASES
            || caller_cases.len() > MAX_CALLER_SIMULATION_CASES
            || stored_cases.is_empty() && caller_cases.is_empty()
        {
            return Err(ActivePolicyError::SimulationCaseLimit);
        }
        validate_cases(stored_cases, caller_cases)?;
        let corpus_bytes = canonical_bytes(&(stored_cases, caller_cases))?;
        if corpus_bytes.len() > MAX_SIMULATION_CORPUS_BYTES {
            return Err(ActivePolicyError::SimulationByteLimit);
        }
        let corpus_digest = domain_digest(CORPUS_DIGEST_DOMAIN, &corpus_bytes);
        let engine = engine_from_json(&draft.canonical_policy_json, self.emergency_denies.clone())?;
        let mut results = Vec::with_capacity(stored_cases.len() + caller_cases.len());
        for case in stored_cases.iter().chain(caller_cases) {
            let (allowed, evaluation_error) = evaluate(&engine, &case.request);
            results.push(PolicySimulationResult {
                case_id: case.id.clone(),
                allowed,
                evaluation_error,
                expectation_matched: case
                    .expected_allowed
                    .map(|expected| !evaluation_error && expected == allowed),
            });
        }
        let evaluation_error_count = results
            .iter()
            .filter(|result| result.evaluation_error)
            .count();
        let expectation_mismatch_count = results
            .iter()
            .filter(|result| result.expectation_matched == Some(false))
            .count();
        let report_material = (
            &draft.digest,
            &corpus_digest,
            stored_cases.len(),
            caller_cases.len(),
            &results,
        );
        let report_digest =
            domain_digest(REPORT_DIGEST_DOMAIN, &canonical_bytes(&report_material)?);
        let report = PolicySimulationReport {
            policy_digest: draft.digest.clone(),
            corpus_digest,
            report_digest: report_digest.clone(),
            stored_case_count: stored_cases.len(),
            caller_case_count: caller_cases.len(),
            evaluation_error_count,
            expectation_mismatch_count,
            results,
        };
        draft.status = PolicyBundleDraftStatus::Simulated;
        draft.simulation_digest = Some(report_digest);
        draft.simulation_passed = report.activation_eligible();
        Ok(report)
    }

    pub fn compare_shadow(
        &self,
        draft: &PolicyBundleDraft,
        cases: &[PolicySimulationCase],
    ) -> Result<PolicyShadowReport, ActivePolicyError> {
        self.ensure_draft_tenant(draft)?;
        if draft.status != PolicyBundleDraftStatus::Shadow {
            return Err(ActivePolicyError::InvalidLifecycleTransition);
        }
        if cases.is_empty() || cases.len() > MAX_SHADOW_CASES {
            return Err(ActivePolicyError::ShadowCaseLimit);
        }
        validate_cases(cases, &[])?;
        if canonical_bytes(cases)?.len() > MAX_SIMULATION_CORPUS_BYTES {
            return Err(ActivePolicyError::SimulationByteLimit);
        }
        let active_engine = engine_from_json_optional(
            self.active
                .as_ref()
                .map(|active| active.canonical_policy_json.as_str()),
            self.emergency_denies.clone(),
        )?;
        let shadow_engine =
            engine_from_json(&draft.canonical_policy_json, self.emergency_denies.clone())?;
        let results = cases
            .iter()
            .map(|case| {
                let (active_allowed, active_evaluation_error) =
                    evaluate(&active_engine, &case.request);
                let (shadow_allowed, shadow_evaluation_error) =
                    evaluate(&shadow_engine, &case.request);
                PolicyShadowResult {
                    case_id: case.id.clone(),
                    active_allowed,
                    active_evaluation_error,
                    shadow_allowed,
                    shadow_evaluation_error,
                }
            })
            .collect();
        Ok(PolicyShadowReport {
            active_policy_digest: self.active.as_ref().map(|active| active.digest.clone()),
            shadow_policy_digest: draft.digest.clone(),
            policy_epoch: self.policy_epoch,
            results,
        })
    }
}
fn evaluate(
    engine: &CedarAuthorizationEngine,
    request: &CedarAuthorizationRequest,
) -> (bool, bool) {
    match engine.authorize(request) {
        Ok(decision) => (decision.allowed, false),
        Err(_) => (false, true),
    }
}
