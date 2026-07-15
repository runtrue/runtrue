use crate::{
    validation::{idempotency_scope, validate_identifier, validate_metadata},
    CreateDeploymentRequest, CreateDeploymentResult, DeploymentError, DeploymentRecord,
    DeploymentRequest, DeploymentRequestStatus, DeploymentStatus, EnvironmentPolicy,
    EnvironmentStatus,
};
use runtrue_policy::{ApprovalDecision, ApprovalKind, ApprovalRequest, ApprovalStatus};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct DeploymentGate {
    environments: BTreeMap<String, EnvironmentPolicy>,
    requests: BTreeMap<String, DeploymentRequest>,
    deployments: BTreeMap<String, DeploymentRecord>,
    idempotency: BTreeMap<String, String>,
}

impl DeploymentGate {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_environment(
        &mut self,
        environment: EnvironmentPolicy,
    ) -> Result<(), DeploymentError> {
        environment.validate()?;
        if self.environments.contains_key(&environment.id) {
            return Err(DeploymentError::EnvironmentExists(environment.id));
        }
        self.environments
            .insert(environment.id.clone(), environment);
        Ok(())
    }

    pub fn environment(&self, id: &str) -> Result<&EnvironmentPolicy, DeploymentError> {
        self.environments
            .get(id)
            .ok_or_else(|| DeploymentError::EnvironmentNotFound(id.to_owned()))
    }

    pub fn create_request(
        &mut self,
        create: CreateDeploymentRequest,
    ) -> Result<CreateDeploymentResult, DeploymentError> {
        for (kind, value) in [
            ("deployment request id", create.id.as_str()),
            ("idempotency key", create.idempotency_key.as_str()),
            ("approval request id", create.approval_request_id.as_str()),
        ] {
            validate_identifier(kind, value)?;
        }
        let environment = self.environment(&create.subject.environment_id)?;
        if environment.status != EnvironmentStatus::Active {
            return Err(DeploymentError::EnvironmentDisabled);
        }
        let subject_digest = create.subject.digest(environment)?;
        let idempotency_scope = idempotency_scope(environment, &create.idempotency_key)?;
        if let Some(existing_id) = self.idempotency.get(&idempotency_scope) {
            let existing = self
                .requests
                .get(existing_id)
                .ok_or(DeploymentError::CorruptState)?;
            if existing.subject_digest != subject_digest {
                return Err(DeploymentError::IdempotencyConflict);
            }
            return Ok(CreateDeploymentResult {
                request: existing.clone(),
                replayed: true,
            });
        }
        if self.requests.contains_key(&create.id) {
            return Err(DeploymentError::RequestExists(create.id));
        }
        let approval_expires = create
            .created_unix_ms
            .checked_add(environment.approval_ttl_ms)
            .ok_or(DeploymentError::InvalidTimestamp)?;
        let approval = ApprovalRequest::create(
            create.approval_request_id,
            ApprovalKind::EnvironmentDeployment,
            subject_digest.clone(),
            create.risk_score,
            create.created_unix_ms,
            approval_expires,
            environment.approval_rule.clone(),
        )?;
        let request = DeploymentRequest {
            id: create.id.clone(),
            idempotency_key: create.idempotency_key,
            subject: create.subject,
            subject_digest,
            status: DeploymentRequestStatus::PendingApproval,
            approval,
            created_unix_ms: create.created_unix_ms,
            ready_unix_ms: None,
            started_unix_ms: None,
            completed_unix_ms: None,
            deployment_id: None,
            failure_code: None,
        };
        self.idempotency
            .insert(idempotency_scope, create.id.clone());
        self.requests.insert(create.id, request.clone());
        Ok(CreateDeploymentResult {
            request,
            replayed: false,
        })
    }

    pub fn decide(
        &mut self,
        request_id: &str,
        decision: ApprovalDecision,
        now_unix_ms: u64,
    ) -> Result<DeploymentRequestStatus, DeploymentError> {
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| DeploymentError::RequestNotFound(request_id.to_owned()))?;
        if request.status != DeploymentRequestStatus::PendingApproval {
            return Err(DeploymentError::InvalidState(request.status));
        }
        let status = request.approval.decide(decision, now_unix_ms)?;
        if status == ApprovalStatus::Approved {
            let latest_decision = request
                .approval
                .decisions
                .values()
                .map(|decision| decision.decided_unix_ms)
                .max()
                .unwrap_or(now_unix_ms);
            let wait_timer = self
                .environments
                .get(&request.subject.environment_id)
                .ok_or(DeploymentError::CorruptState)?
                .wait_timer_ms;
            let ready = latest_decision
                .checked_add(wait_timer)
                .ok_or(DeploymentError::InvalidTimestamp)?;
            request.ready_unix_ms = Some(ready);
            request.status = if now_unix_ms >= ready {
                DeploymentRequestStatus::Ready
            } else {
                DeploymentRequestStatus::Waiting
            };
        } else if status == ApprovalStatus::Denied {
            request.status = DeploymentRequestStatus::Denied;
            request.completed_unix_ms = Some(now_unix_ms);
            request.failure_code = Some("approval_denied".to_owned());
        }
        Ok(request.status)
    }

    pub fn refresh(
        &mut self,
        request_id: &str,
        now_unix_ms: u64,
    ) -> Result<DeploymentRequestStatus, DeploymentError> {
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| DeploymentError::RequestNotFound(request_id.to_owned()))?;
        request.approval.refresh_expiry(now_unix_ms);
        if request.approval.status == ApprovalStatus::Expired
            && matches!(
                request.status,
                DeploymentRequestStatus::PendingApproval
                    | DeploymentRequestStatus::Waiting
                    | DeploymentRequestStatus::Ready
            )
        {
            request.status = DeploymentRequestStatus::Expired;
            request.completed_unix_ms = Some(now_unix_ms);
            request.failure_code = Some("approval_expired".to_owned());
        } else if request.status == DeploymentRequestStatus::Waiting
            && request
                .ready_unix_ms
                .is_some_and(|ready| now_unix_ms >= ready)
        {
            request.status = DeploymentRequestStatus::Ready;
        }
        Ok(request.status)
    }

    pub fn start(
        &mut self,
        request_id: &str,
        deployment_id: String,
        now_unix_ms: u64,
    ) -> Result<DeploymentRecord, DeploymentError> {
        validate_identifier("deployment id", &deployment_id)?;
        self.refresh(request_id, now_unix_ms)?;
        let (environment_id, subject_digest) = {
            let request = self
                .requests
                .get(request_id)
                .ok_or_else(|| DeploymentError::RequestNotFound(request_id.to_owned()))?;
            if request.status != DeploymentRequestStatus::Ready {
                return Err(DeploymentError::InvalidState(request.status));
            }
            (
                request.subject.environment_id.clone(),
                request.subject_digest.clone(),
            )
        };
        if self.deployments.contains_key(&deployment_id) {
            return Err(DeploymentError::DeploymentExists(deployment_id));
        }
        let environment = self.environment(&environment_id)?;
        if environment.status != EnvironmentStatus::Active {
            return Err(DeploymentError::EnvironmentDisabled);
        }
        let active = self
            .deployments
            .values()
            .filter(|deployment| {
                deployment.environment_id == environment_id
                    && deployment.status == DeploymentStatus::InProgress
            })
            .count();
        if active >= usize::from(environment.concurrency_limit) {
            return Err(DeploymentError::ConcurrencyLimit);
        }
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| DeploymentError::RequestNotFound(request_id.to_owned()))?;
        request.approval.authorize(&subject_digest, now_unix_ms)?;
        request.status = DeploymentRequestStatus::InProgress;
        request.started_unix_ms = Some(now_unix_ms);
        request.deployment_id = Some(deployment_id.clone());
        let deployment = DeploymentRecord {
            id: deployment_id.clone(),
            request_id: request.id.clone(),
            environment_id,
            artifact_id: request.subject.artifact_id.clone(),
            artifact_content_digest: request.subject.artifact_content_digest.clone(),
            target_digest: request.subject.deployment_target_digest.clone(),
            status: DeploymentStatus::InProgress,
            started_unix_ms: now_unix_ms,
            completed_unix_ms: None,
            external_reference: None,
            rollback_of: request.subject.rollback_of.clone(),
            metadata: BTreeMap::new(),
        };
        self.deployments.insert(deployment_id, deployment.clone());
        Ok(deployment)
    }

    pub fn finish(
        &mut self,
        deployment_id: &str,
        succeeded: bool,
        external_reference: Option<String>,
        metadata: BTreeMap<String, String>,
        failure_code: Option<String>,
        now_unix_ms: u64,
    ) -> Result<DeploymentRecord, DeploymentError> {
        validate_metadata(&metadata)?;
        if let Some(reference) = &external_reference {
            validate_identifier("external deployment reference", reference)?;
        }
        if succeeded && failure_code.is_some() || !succeeded && failure_code.is_none() {
            return Err(DeploymentError::InvalidCompletion);
        }
        if let Some(code) = &failure_code {
            validate_identifier("deployment failure code", code)?;
        }
        let deployment = self
            .deployments
            .get_mut(deployment_id)
            .ok_or_else(|| DeploymentError::DeploymentNotFound(deployment_id.to_owned()))?;
        if deployment.status != DeploymentStatus::InProgress
            || now_unix_ms < deployment.started_unix_ms
        {
            return Err(DeploymentError::InvalidDeploymentState);
        }
        deployment.status = if succeeded {
            DeploymentStatus::Succeeded
        } else {
            DeploymentStatus::Failed
        };
        deployment.completed_unix_ms = Some(now_unix_ms);
        deployment.external_reference = external_reference;
        deployment.metadata = metadata;
        let request = self
            .requests
            .get_mut(&deployment.request_id)
            .ok_or(DeploymentError::CorruptState)?;
        request.status = if succeeded {
            DeploymentRequestStatus::Succeeded
        } else {
            DeploymentRequestStatus::Failed
        };
        request.completed_unix_ms = Some(now_unix_ms);
        request.failure_code = failure_code;
        Ok(deployment.clone())
    }

    pub fn cancel(&mut self, request_id: &str, now_unix_ms: u64) -> Result<bool, DeploymentError> {
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| DeploymentError::RequestNotFound(request_id.to_owned()))?;
        match request.status {
            DeploymentRequestStatus::PendingApproval
            | DeploymentRequestStatus::Waiting
            | DeploymentRequestStatus::Ready => {
                request.status = DeploymentRequestStatus::Canceled;
                request.completed_unix_ms = Some(now_unix_ms);
                Ok(true)
            }
            DeploymentRequestStatus::Canceled => Ok(false),
            status => Err(DeploymentError::InvalidState(status)),
        }
    }

    pub fn request(&self, id: &str) -> Result<&DeploymentRequest, DeploymentError> {
        self.requests
            .get(id)
            .ok_or_else(|| DeploymentError::RequestNotFound(id.to_owned()))
    }

    pub fn deployment(&self, id: &str) -> Result<&DeploymentRecord, DeploymentError> {
        self.deployments
            .get(id)
            .ok_or_else(|| DeploymentError::DeploymentNotFound(id.to_owned()))
    }

    #[must_use]
    pub fn last_successful_deployment(&self, environment_id: &str) -> Option<&DeploymentRecord> {
        self.deployments
            .values()
            .filter(|deployment| {
                deployment.environment_id == environment_id
                    && deployment.status == DeploymentStatus::Succeeded
            })
            .max_by_key(|deployment| deployment.completed_unix_ms)
    }
}
