use super::{
    entities::entities_json,
    model::{CedarAuthorizationDecision, CedarAuthorizationRequest, MAX_POLICIES},
    request::{context_json, entity_uid},
    schema::runtrue_schema,
    validation::{bounded, validate_emergency_rules, validate_policy_source, validate_request},
    CedarAuthorizationError,
};
use crate::{AdmissionContext, DenyFirstPolicy, PolicyError};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, PolicySet, Request, Schema, ValidationMode, Validator,
};
use runtrue_model::ContentDigest;
use std::{fmt, str::FromStr as _};
pub struct CedarAuthorizationEngine {
    schema: Schema,
    schema_digest: ContentDigest,
    policies: PolicySet,
    policy_digest: ContentDigest,
    emergency: DenyFirstPolicy,
}

impl CedarAuthorizationEngine {
    pub fn new(
        policy_source: &str,
        emergency: DenyFirstPolicy,
    ) -> Result<Self, CedarAuthorizationError> {
        validate_policy_source(policy_source)?;
        validate_emergency_rules(&emergency)?;
        let schema_json = runtrue_schema();
        let schema_bytes = serde_json::to_vec(&schema_json)
            .map_err(|error| CedarAuthorizationError::Schema(bounded(error)))?;
        let schema_digest = ContentDigest::sha256(schema_bytes);
        let schema = Schema::from_json_value(schema_json)
            .map_err(|error| CedarAuthorizationError::Schema(bounded(error)))?;
        let policies = PolicySet::from_str(policy_source)
            .map_err(|error| CedarAuthorizationError::PolicyParse(bounded(error)))?;
        let policy_count = policies.policies().count();
        if policy_count > MAX_POLICIES || policies.templates().next().is_some() {
            return Err(CedarAuthorizationError::PolicyLimit);
        }
        let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed_without_warnings() {
            return Err(CedarAuthorizationError::PolicyValidation {
                errors: validation.validation_errors().count(),
                warnings: validation.validation_warnings().count(),
            });
        }
        Ok(Self {
            schema,
            schema_digest,
            policies,
            policy_digest: ContentDigest::sha256(policy_source.as_bytes()),
            emergency,
        })
    }

    #[must_use]
    pub const fn policy_digest(&self) -> &ContentDigest {
        &self.policy_digest
    }

    #[must_use]
    pub const fn schema_digest(&self) -> &ContentDigest {
        &self.schema_digest
    }

    pub fn authorize(
        &self,
        request: &CedarAuthorizationRequest,
    ) -> Result<CedarAuthorizationDecision, CedarAuthorizationError> {
        validate_request(request)?;
        let admission = AdmissionContext {
            action: request.action.as_str().to_owned(),
            tenant_id: request.resource.tenant_id.clone(),
            repository_id: request
                .resource
                .repository_id
                .clone()
                .unwrap_or_else(|| request.resource.id.clone()),
            risk_score: request.resource.risk_score,
            privileged: request.resource.privileged,
            untrusted: request.resource.untrusted,
        };
        if let Err(PolicyError::EmergencyDenied(id)) = self.emergency.admit(&admission) {
            return Ok(CedarAuthorizationDecision {
                allowed: false,
                policy_digest: self.policy_digest.clone(),
                determining_policy_ids: Vec::new(),
                evaluation_error_count: 0,
                emergency_deny_id: Some(id),
            });
        }

        let principal = entity_uid(request.principal.kind.entity_type(), &request.principal.id)?;
        let action = entity_uid("Action", request.action.as_str())?;
        let resource = entity_uid(request.resource.kind.as_str(), &request.resource.id)?;
        let entities = Entities::from_json_value(entities_json(request), Some(&self.schema))
            .map_err(|error| CedarAuthorizationError::Entities(bounded(error)))?;
        let context = Context::from_json_value(
            context_json(&request.context)?,
            Some((&self.schema, &action)),
        )
        .map_err(|error| CedarAuthorizationError::Context(bounded(error)))?;
        let cedar_request = Request::new(principal, action, resource, context, Some(&self.schema))
            .map_err(|error| CedarAuthorizationError::Request(bounded(error)))?;
        let response = Authorizer::new().is_authorized(&cedar_request, &self.policies, &entities);
        let evaluation_error_count = response.diagnostics().errors().count();
        let mut determining_policy_ids = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        determining_policy_ids.sort();
        Ok(CedarAuthorizationDecision {
            allowed: response.decision() == Decision::Allow && evaluation_error_count == 0,
            policy_digest: self.policy_digest.clone(),
            determining_policy_ids,
            evaluation_error_count,
            emergency_deny_id: None,
        })
    }
}

impl fmt::Debug for CedarAuthorizationEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CedarAuthorizationEngine")
            .field("schema_digest", &self.schema_digest)
            .field("policy_digest", &self.policy_digest)
            .field("policies", &self.policies.policies().count())
            .field("emergency_denies", &self.emergency.emergency_denies.len())
            .finish()
    }
}
