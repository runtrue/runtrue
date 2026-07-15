use crate::app::{
    control_plane_problem, internal_problem, invalid_object_problem, problem_response,
    valid_return_to, AppState, GitHubInstallationState, GitHubSetupView, HmacSha256, RequestId,
    RequestPrincipal, GITHUB_SETUP_TTL_MS,
};
use axum::http::StatusCode;
use axum::response::Response;
use base64ct::Base64UrlUnpadded;
use runtrue_audit::AuditPrincipal;
use runtrue_auth::AuthError;
use runtrue_control_plane::{ControlPlaneError, CreateGitHubSetupTransaction, GitHubSetupStatus};
use runtrue_model::ContentDigest;
use runtrue_policy::{
    ActivePolicyBundleState, CedarAction, CedarAuthorizationRequest, CedarPrincipal,
    CedarPrincipalKind, CedarRequestContext, CedarResource, CedarResourceKind,
};
use sha2::Sha256;
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
pub(in crate::app) fn principal_can_delegate(
    principal: &RequestPrincipal,
    tenant_id: &str,
    requested_scopes: &BTreeSet<String>,
) -> bool {
    match principal {
        RequestPrincipal::Bootstrap => true,
        RequestPrincipal::ApiToken(context) => {
            context.tenant_id == tenant_id && requested_scopes.is_subset(&context.scopes)
        }
    }
}

pub(in crate::app) fn principal_matches_tenant(
    principal: &RequestPrincipal,
    tenant_id: &str,
) -> bool {
    match principal {
        RequestPrincipal::Bootstrap => true,
        RequestPrincipal::ApiToken(context) => context.tenant_id == tenant_id,
    }
}

#[derive(Clone, Copy)]
pub(in crate::app) struct ServerResource<'a> {
    kind: CedarResourceKind,
    id: &'a str,
    tenant_id: &'a str,
    repository_id: Option<&'a str>,
    author_id: Option<&'a str>,
    risk_score: u32,
    privileged: bool,
    untrusted: bool,
}

impl<'a> ServerResource<'a> {
    pub(in crate::app) const fn new(
        kind: CedarResourceKind,
        id: &'a str,
        tenant_id: &'a str,
    ) -> Self {
        Self {
            kind,
            id,
            tenant_id,
            repository_id: None,
            author_id: None,
            risk_score: 0,
            privileged: false,
            untrusted: false,
        }
    }

    pub(in crate::app) const fn in_repository(mut self, repository_id: &'a str) -> Self {
        self.repository_id = Some(repository_id);
        self
    }

    pub(in crate::app) const fn with_risk(
        mut self,
        risk_score: u32,
        privileged: bool,
        untrusted: bool,
    ) -> Self {
        self.risk_score = risk_score;
        self.privileged = privileged;
        self.untrusted = untrusted;
        self
    }
}

#[allow(clippy::result_large_err)]
pub(in crate::app) fn authorize_resource(
    state: &AppState,
    request_id: &RequestId,
    principal: &RequestPrincipal,
    action: CedarAction,
    resource: ServerResource<'_>,
) -> Result<(), Response> {
    let active = match state.control_plane.active_policy_state(resource.tenant_id) {
        Ok(active) => active,
        Err(ControlPlaneError::NotFound { kind: "tenant", id }) if id == resource.tenant_id => {
            ActivePolicyBundleState::new(resource.tenant_id).map_err(|_| {
                if let Some(human) = &state.human_oidc {
                    human.metrics.live_policy_failure();
                }
                internal_problem(request_id)
            })?
        }
        Err(_) => {
            if let Some(human) = &state.human_oidc {
                human.metrics.live_policy_failure();
            }
            return Err(internal_problem(request_id));
        }
    };
    let has_durable_policy = active.active.is_some() || active.decision_cache_generation != 0;
    if matches!(principal, RequestPrincipal::Bootstrap) && !has_durable_policy {
        return Ok(());
    }
    let (principal_id, principal_tenant, principal_kind) = match principal {
        RequestPrincipal::Bootstrap => (
            "bootstrap".to_owned(),
            resource.tenant_id.to_owned(),
            CedarPrincipalKind::ServiceAccount,
        ),
        RequestPrincipal::ApiToken(context) => (
            context.principal_id.clone(),
            context.tenant_id.clone(),
            CedarPrincipalKind::ServiceAccount,
        ),
    };
    let cross_tenant = principal_tenant != resource.tenant_id;
    let request = CedarAuthorizationRequest {
        principal: CedarPrincipal {
            kind: principal_kind,
            id: principal_id,
            tenant_id: principal_tenant,
            groups: BTreeSet::new(),
        },
        action,
        resource: CedarResource {
            kind: resource.kind,
            id: resource.id.to_owned(),
            tenant_id: resource.tenant_id.to_owned(),
            repository_id: resource.repository_id.map(str::to_owned),
            author_id: resource.author_id.map(str::to_owned),
            risk_score: resource.risk_score,
            privileged: resource.privileged,
            untrusted: resource.untrusted,
        },
        context: CedarRequestContext::default(),
    };
    let decision = if has_durable_policy {
        let snapshot = active.snapshot().map_err(|_| {
            if let Some(human) = &state.human_oidc {
                human.metrics.live_policy_failure();
            }
            internal_problem(request_id)
        })?;
        if let Some(human) = &state.human_oidc {
            human.metrics.live_policy_snapshot();
        }
        snapshot.authorize(&request).map_err(|_| {
            if let Some(human) = &state.human_oidc {
                human.metrics.live_policy_failure();
            }
            problem_response(
                request_id,
                StatusCode::FORBIDDEN,
                "Forbidden",
                "the active authorization policy could not authorize this operation",
            )
        })
    } else {
        state.authorization.authorize(&request).map_err(|_| {
            problem_response(
                request_id,
                StatusCode::FORBIDDEN,
                "Forbidden",
                "the bootstrap authorization policy could not authorize this operation",
            )
        })
    };
    match decision {
        Ok(decision) if decision.allowed => Ok(()),
        _ if cross_tenant => Err(problem_response(
            request_id,
            StatusCode::NOT_FOUND,
            "Resource not found",
            "the requested resource was not found",
        )),
        _ => Err(problem_response(
            request_id,
            StatusCode::FORBIDDEN,
            "Forbidden",
            "the authorization policy denied this operation",
        )),
    }
}

#[allow(clippy::result_large_err)]
pub(in crate::app) fn authorize_tenant_collection(
    state: &AppState,
    request_id: &RequestId,
    principal: &RequestPrincipal,
    action: CedarAction,
    tenant_id: &str,
) -> Result<(), Response> {
    authorize_resource(
        state,
        request_id,
        principal,
        action,
        ServerResource::new(CedarResourceKind::Tenant, tenant_id, tenant_id),
    )
}

pub(in crate::app) fn api_token_tenant(principal: &RequestPrincipal) -> Option<&str> {
    match principal {
        RequestPrincipal::Bootstrap => None,
        RequestPrincipal::ApiToken(context) => Some(&context.tenant_id),
    }
}

#[allow(clippy::result_large_err)]
pub(in crate::app) fn github_api_tenant(
    request_id: &RequestId,
    principal: &RequestPrincipal,
    requested: Option<&str>,
) -> Result<String, Response> {
    match principal {
        RequestPrincipal::Bootstrap => requested
            .filter(|tenant| !tenant.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                invalid_object_problem(
                    request_id,
                    "tenant_id is required for bootstrap GitHub administration",
                )
            }),
        RequestPrincipal::ApiToken(context) => {
            if requested.is_some_and(|tenant| tenant != context.tenant_id) {
                Err(problem_response(
                    request_id,
                    StatusCode::NOT_FOUND,
                    "Resource not found",
                    "the requested resource was not found",
                ))
            } else {
                Ok(context.tenant_id.clone())
            }
        }
    }
}

pub(in crate::app) fn github_setup_id(
    tenant_id: &str,
    principal_id: &str,
    idempotency_key: &str,
) -> String {
    use sha2::Digest as _;
    let mut digest = Sha256::new();
    digest.update(b"runtrue.github-app.setup-id.v1\0");
    for value in [tenant_id, principal_id, idempotency_key] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    format!("github-setup-{}", hex::encode(digest.finalize()))
}

pub(in crate::app) fn github_setup_state(
    github: &GitHubInstallationState,
    setup_id: &str,
) -> String {
    let mut mac = HmacSha256::new_from_slice(github.setup_key.as_ref())
        .expect("HMAC-SHA-256 accepts a 32-byte key");
    mac.update(b"runtrue.github-app.setup-state.v1\0");
    mac.update(setup_id.as_bytes());
    Base64UrlUnpadded::encode_string(&mac.finalize().into_bytes())
}

pub(in crate::app) fn github_setup_state_digest(state: &str) -> ContentDigest {
    let mut material = b"runtrue.github-app.setup-state-digest.v1\0".to_vec();
    material.extend_from_slice(state.as_bytes());
    ContentDigest::sha256(material)
}

pub(in crate::app) struct GitHubSetupRequest<'a> {
    pub(in crate::app) tenant_id: &'a str,
    pub(in crate::app) principal_id: &'a str,
    pub(in crate::app) idempotency_key: &'a str,
    pub(in crate::app) return_path: &'a str,
    pub(in crate::app) now_unix_ms: u64,
    pub(in crate::app) repository_preselection: Option<(u64, &'a [u64])>,
}

#[allow(clippy::result_large_err)]
pub(in crate::app) fn start_github_setup_service(
    state: &AppState,
    request_id: &RequestId,
    request: GitHubSetupRequest<'_>,
) -> Result<GitHubSetupView, Response> {
    let GitHubSetupRequest {
        tenant_id,
        principal_id,
        idempotency_key,
        return_path,
        now_unix_ms,
        repository_preselection,
    } = request;
    let github = state.github_installation.as_ref().ok_or_else(|| {
        problem_response(
            request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "GitHub App unavailable",
            "GitHub App installation is not configured",
        )
    })?;
    if state.webhook.is_none() {
        return Err(problem_response(
            request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "GitHub App unavailable",
            "signed GitHub webhook ingestion must be configured before installation",
        ));
    }
    if !valid_return_to(return_path) {
        return Err(invalid_object_problem(
            request_id,
            "return_path must be a bounded local path",
        ));
    }
    let setup_id = github_setup_id(tenant_id, principal_id, idempotency_key);
    let raw_state = github_setup_state(github, &setup_id);
    let state_digest = github_setup_state_digest(&raw_state);
    let expires_unix_ms = now_unix_ms
        .checked_add(GITHUB_SETUP_TTL_MS)
        .ok_or_else(|| internal_problem(request_id))?;
    let mut request = CreateGitHubSetupTransaction {
        id: setup_id,
        tenant_id: tenant_id.to_owned(),
        principal_id: principal_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        request_digest: ContentDigest::sha256(b"pending GitHub setup request digest"),
        state_digest,
        github_web_origin: github.public_config.web_origin().to_owned(),
        github_api_origin: github.public_config.api_origin().to_owned(),
        return_path: return_path.to_owned(),
        expires_unix_ms,
        created_unix_ms: now_unix_ms,
    };
    request.request_digest = request
        .expected_request_digest()
        .map_err(|_| internal_problem(request_id))?;
    let result = state
        .control_plane
        .create_github_setup_transaction(&request)
        .map_err(|error| control_plane_problem(request_id, error))?;
    if !matches!(
        result.value.status,
        GitHubSetupStatus::Pending | GitHubSetupStatus::Exchanging
    ) || now_unix_ms >= result.value.expires_unix_ms
    {
        return Err(problem_response(
            request_id,
            StatusCode::CONFLICT,
            "GitHub setup is no longer pending",
            "use a new idempotency key to start another installation",
        ));
    }
    let install_url = match repository_preselection {
        Some((target_id, repository_ids)) => github
            .public_config
            .installation_url_for_repositories(&raw_state, target_id, repository_ids),
        None => github.public_config.installation_url(&raw_state),
    }
    .map_err(|_| internal_problem(request_id))?;
    if !result.replayed {
        github.metrics.setup_started.fetch_add(1, Ordering::Relaxed);
    }
    Ok(GitHubSetupView {
        id: result.value.id,
        install_url,
        expires_unix_ms: result.value.expires_unix_ms,
        replayed: result.replayed,
    })
}

#[allow(clippy::result_large_err)]
pub(in crate::app) fn require_bootstrap(
    request_id: &RequestId,
    principal: &RequestPrincipal,
) -> Result<(), Response> {
    if matches!(principal, RequestPrincipal::Bootstrap) {
        Ok(())
    } else {
        Err(problem_response(
            request_id,
            StatusCode::FORBIDDEN,
            "Forbidden",
            "this resource has no tenant ownership and requires bootstrap administration",
        ))
    }
}

pub(in crate::app) fn approval_actor_id(principal: &RequestPrincipal) -> String {
    match principal {
        RequestPrincipal::Bootstrap => "bootstrap".to_owned(),
        RequestPrincipal::ApiToken(context) => context.principal_id.clone(),
    }
}

pub(in crate::app) fn request_audit_principal(principal: &RequestPrincipal) -> AuditPrincipal {
    match principal {
        RequestPrincipal::Bootstrap => AuditPrincipal {
            kind: "bootstrap".to_owned(),
            id: "bootstrap".to_owned(),
        },
        RequestPrincipal::ApiToken(context) => AuditPrincipal {
            kind: "api_token".to_owned(),
            id: context
                .credential_id
                .clone()
                .unwrap_or_else(|| context.principal_id.clone()),
        },
    }
}

pub(in crate::app) fn request_credential_id(principal: &RequestPrincipal) -> Option<&str> {
    match principal {
        RequestPrincipal::Bootstrap => None,
        RequestPrincipal::ApiToken(context) => context.credential_id.as_deref(),
    }
}

pub(in crate::app) fn auth_input_problem(request_id: &RequestId, error: AuthError) -> Response {
    problem_response(
        request_id,
        StatusCode::BAD_REQUEST,
        "Invalid API token request",
        error.to_string(),
    )
}
use base64ct::Encoding as _;
use hmac::Mac as _;
