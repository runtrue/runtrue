use super::{cookies::clear_browser_authentication, sessions::authenticated_browser_session};
use crate::app::{
    internal_problem, now_unix_ms, problem_response, protect_sensitive_response, AppState,
    HumanOidcState, RequestId, POLICY_READ_SCOPE, SESSION_READ_SCOPE,
};
use axum::{
    extract::{Extension, State},
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use runtrue_auth::AuthContext;
use runtrue_model::ContentDigest;
use runtrue_policy::{
    CedarAction, CedarAuthorizationRequest, CedarPrincipal, CedarPrincipalKind,
    CedarRequestContext, CedarResource, CedarResourceKind,
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Serialize)]
pub(in crate::app) struct BrowserSessionStatusView {
    principal_id: String,
    tenant_id: String,
    device_id: String,
    access_generation: u64,
    access_expires_unix_ms: u64,
    refresh_expires_unix_ms: u64,
    absolute_expires_unix_ms: u64,
    mfa_authenticated_unix_ms: Option<u64>,
    csrf_token: String,
}

impl Drop for BrowserSessionStatusView {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.csrf_token.zeroize();
    }
}

#[derive(Serialize)]
pub(in crate::app) struct BrowserPolicyStatusView {
    tenant_id: String,
    policy_epoch: u64,
    decision_cache_generation: u64,
    active_policy_digest: Option<ContentDigest>,
}

pub(in crate::app) async fn browser_session_status(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    match browser_session_status_service(&state, &request_id, &headers).await {
        Ok(status) => {
            let mut response = Json(status).into_response();
            protect_sensitive_response(&mut response);
            response
        }
        Err(response) => *response,
    }
}

pub(in crate::app) async fn browser_policy_status(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    match browser_policy_status_service(&state, &request_id, &headers).await {
        Ok(status) => Json(status).into_response(),
        Err(response) => *response,
    }
}

pub(in crate::app) async fn browser_session_page(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    match browser_session_status_service(&state, &request_id, &headers).await {
        Ok(status) => html_response(format!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Runtrue session</title><main><h1>Session</h1><dl><dt>Tenant</dt><dd>{}</dd><dt>Principal</dt><dd>{}</dd><dt>Device</dt><dd>{}</dd><dt>Access generation</dt><dd>{}</dd></dl><form method=\"post\" action=\"/auth/session/logout\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log out</button></form><p><a href=\"/ui/policy\">Policy status</a></p></main></html>",
            escape_html(&status.tenant_id),
            escape_html(&status.principal_id),
            escape_html(&status.device_id),
            status.access_generation,
            escape_html(&status.csrf_token),
        )),
        Err(response) => *response,
    }
}

pub(in crate::app) async fn browser_policy_page(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    match browser_policy_status_service(&state, &request_id, &headers).await {
        Ok(status) => html_response(format!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Runtrue policy</title><main><h1>Active policy</h1><dl><dt>Tenant</dt><dd>{}</dd><dt>Policy epoch</dt><dd>{}</dd><dt>Decision-cache generation</dt><dd>{}</dd><dt>Digest</dt><dd>{}</dd></dl><p><a href=\"/ui/session\">Session</a></p></main></html>",
            escape_html(&status.tenant_id),
            status.policy_epoch,
            status.decision_cache_generation,
            escape_html(
                status
                    .active_policy_digest
                    .as_ref()
                    .map(ContentDigest::as_str)
                    .unwrap_or("none")
            ),
        )),
        Err(response) => *response,
    }
}

pub(in crate::app) async fn browser_session_status_service(
    state: &AppState,
    request_id: &RequestId,
    headers: &HeaderMap,
) -> Result<BrowserSessionStatusView, Box<Response>> {
    let now = now_unix_ms(request_id)?;
    let (_, record, csrf) =
        authenticated_browser_session(state, request_id, headers, SESSION_READ_SCOPE, None, now)
            .await?;
    Ok(BrowserSessionStatusView {
        principal_id: record.principal_id,
        tenant_id: record.tenant_id,
        device_id: record.device_id,
        access_generation: record.access_generation,
        access_expires_unix_ms: record.access_expires_unix_ms,
        refresh_expires_unix_ms: record.refresh_expires_unix_ms,
        absolute_expires_unix_ms: record.absolute_expires_unix_ms,
        mfa_authenticated_unix_ms: record.mfa_authenticated_unix_ms,
        csrf_token: csrf,
    })
}

pub(in crate::app) async fn browser_policy_status_service(
    state: &AppState,
    request_id: &RequestId,
    headers: &HeaderMap,
) -> Result<BrowserPolicyStatusView, Box<Response>> {
    let now = now_unix_ms(request_id)?;
    let (context, _, _) =
        authenticated_browser_session(state, request_id, headers, POLICY_READ_SCOPE, None, now)
            .await?;
    let active = state
        .store
        .active_state(&context.tenant_id)
        .await
        .map_err(|_| internal_problem(request_id))?;
    let snapshot = active.snapshot().map_err(|_| {
        if let Some(human) = &state.human_oidc {
            human.metrics.live_policy_failure();
        }
        internal_problem(request_id)
    })?;
    let request = CedarAuthorizationRequest {
        principal: CedarPrincipal {
            kind: CedarPrincipalKind::User,
            id: context.principal_id,
            tenant_id: context.tenant_id.clone(),
            groups: BTreeSet::new(),
        },
        action: CedarAction::ManagePolicy,
        resource: CedarResource {
            kind: CedarResourceKind::Policy,
            id: "active".to_owned(),
            tenant_id: context.tenant_id.clone(),
            repository_id: None,
            author_id: None,
            risk_score: 0,
            privileged: false,
            untrusted: false,
        },
        context: CedarRequestContext::default(),
    };
    let has_durable_policy = active.active.is_some() || active.decision_cache_generation != 0;
    let allowed = if has_durable_policy {
        if let Some(human) = &state.human_oidc {
            human.metrics.live_policy_snapshot();
        }
        snapshot
            .authorize(&request)
            .map(|decision| decision.allowed)
            .map_err(|_| ())
    } else {
        state
            .authorization
            .authorize(&request)
            .map(|decision| decision.allowed)
            .map_err(|_| ())
    };
    match allowed {
        Ok(true) => Ok(BrowserPolicyStatusView {
            tenant_id: snapshot.tenant_id,
            policy_epoch: snapshot.policy_epoch,
            decision_cache_generation: snapshot.decision_cache_generation,
            active_policy_digest: snapshot.policy_digest,
        }),
        _ => {
            if has_durable_policy {
                if let Some(human) = &state.human_oidc {
                    human.metrics.live_policy_failure();
                }
            }
            Err(problem_response(
                request_id,
                StatusCode::FORBIDDEN,
                "Forbidden",
                "the active authorization policy denied this operation",
            )
            .into())
        }
    }
}

#[allow(clippy::result_large_err)]
pub(in crate::app) async fn authorize_browser_tenant(
    state: &AppState,
    request_id: &RequestId,
    context: &AuthContext,
    action: CedarAction,
) -> Result<(), Box<Response>> {
    authorize_browser_resource(
        state,
        request_id,
        context,
        action,
        CedarResource {
            kind: CedarResourceKind::Tenant,
            id: context.tenant_id.clone(),
            tenant_id: context.tenant_id.clone(),
            repository_id: None,
            author_id: None,
            risk_score: 0,
            privileged: false,
            untrusted: false,
        },
    )
    .await
}

#[allow(clippy::result_large_err)]
pub(in crate::app) async fn authorize_browser_resource(
    state: &AppState,
    request_id: &RequestId,
    context: &AuthContext,
    action: CedarAction,
    resource: CedarResource,
) -> Result<(), Box<Response>> {
    let active = state
        .store
        .active_state(&context.tenant_id)
        .await
        .map_err(|_| internal_problem(request_id))?;
    let request = CedarAuthorizationRequest {
        principal: CedarPrincipal {
            kind: CedarPrincipalKind::User,
            id: context.principal_id.clone(),
            tenant_id: context.tenant_id.clone(),
            groups: BTreeSet::new(),
        },
        action,
        resource,
        context: CedarRequestContext::default(),
    };
    let has_durable_policy = active.active.is_some() || active.decision_cache_generation != 0;
    let allowed = if has_durable_policy {
        active
            .snapshot()
            .and_then(|snapshot| snapshot.authorize(&request))
            .map(|decision| decision.allowed)
            .map_err(|_| ())
    } else {
        state
            .authorization
            .authorize(&request)
            .map(|decision| decision.allowed)
            .map_err(|_| ())
    };
    match allowed {
        Ok(true) => Ok(()),
        _ => Err(problem_response(
            request_id,
            StatusCode::FORBIDDEN,
            "Forbidden",
            "the active authorization policy denied this browser operation",
        )
        .into()),
    }
}

pub(in crate::app) fn hidden_login_resource(request_id: &RequestId) -> Response {
    problem_response(
        request_id,
        StatusCode::NOT_FOUND,
        "Login provider not found",
        "the requested login provider was not found",
    )
}

pub(in crate::app) fn callback_failure(human: &HumanOidcState, request_id: &RequestId) -> Response {
    human.metrics.callback_failed();
    let response = problem_response(
        request_id,
        StatusCode::UNAUTHORIZED,
        "Login failed",
        "the browser login could not be completed; start a new login",
    );
    clear_browser_authentication(response)
}

pub(in crate::app) fn human_oidc_unavailable(request_id: &RequestId) -> Response {
    problem_response(
        request_id,
        StatusCode::SERVICE_UNAVAILABLE,
        "Login temporarily unavailable",
        "the bounded OIDC exchange capacity is currently exhausted",
    )
}

pub(in crate::app) fn html_response(body: String) -> Response {
    let mut response = body.into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    protect_sensitive_response(&mut response);
    response
}

pub(in crate::app) fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            character => escaped.push(character),
        }
    }
    escaped
}

#[derive(Serialize)]
pub(in crate::app) struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: [&'static str; 1],
}

pub(in crate::app) async fn oidc_discovery(State(state): State<AppState>) -> Json<OidcDiscovery> {
    let issuer = state.oidc.issuer().to_owned();
    Json(OidcDiscovery {
        issuer: issuer.clone(),
        jwks_uri: format!("{issuer}/jwks.json"),
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["EdDSA"],
    })
}

pub(in crate::app) async fn oidc_jwks(State(state): State<AppState>) -> Response {
    Json(state.oidc.jwks()).into_response()
}
