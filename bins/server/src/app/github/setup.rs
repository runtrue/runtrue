use crate::app::{
    approval_actor_id, authenticated_browser_session, authorize_tenant_collection,
    control_plane_problem, escape_html, github_api_tenant, github_setup_state_digest,
    html_response, idempotency_key, internal_problem, now_unix_ms, problem_response,
    protect_sensitive_response, required_json, start_github_setup_service, valid_return_to,
    AppState, GitHubSetupRequest, RequestId, RequestPrincipal, IDEMPOTENCY_REPLAYED,
    SCM_READ_SCOPE,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Query, State};
use axum::http::header::LOCATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_control_plane::CompleteGitHubSetupTransaction;
use runtrue_policy::CedarAction;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct CreateGitHubSetupBody {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    return_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct GitHubSetupCallbackQuery {
    #[serde(default)]
    state: Option<String>,
    installation_id: u64,
    #[serde(default)]
    setup_action: Option<String>,
}
#[derive(Debug, Serialize)]
pub(in crate::app) struct GitHubSetupView {
    pub(in crate::app) id: String,
    pub(in crate::app) install_url: String,
    pub(in crate::app) expires_unix_ms: u64,
    pub(in crate::app) replayed: bool,
}
pub(in crate::app) async fn create_github_setup(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: CreateGitHubSetupBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let tenant_id = match github_api_tenant(&request_id, &principal, body.tenant_id.as_deref()) {
        Ok(tenant_id) => tenant_id,
        Err(response) => return response,
    };
    if let Err(response) = authorize_tenant_collection(
        &state,
        &request_id,
        &principal,
        CedarAction::EditWorkflowSettings,
        &tenant_id,
    ) {
        return response;
    }
    let idempotency_key = match idempotency_key(&request_id, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let principal_id = approval_actor_id(&principal);
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let return_path = body
        .return_path
        .as_deref()
        .unwrap_or("/ui/github/installations?github=installed");
    match start_github_setup_service(
        &state,
        &request_id,
        GitHubSetupRequest {
            tenant_id: &tenant_id,
            principal_id: &principal_id,
            idempotency_key: &idempotency_key,
            return_path,
            now_unix_ms: now,
            repository_preselection: None,
        },
    ) {
        Ok(view) => {
            let replayed = view.replayed;
            let mut response = (StatusCode::CREATED, Json(view)).into_response();
            response.headers_mut().insert(
                IDEMPOTENCY_REPLAYED.clone(),
                HeaderValue::from_static(if replayed { "true" } else { "false" }),
            );
            response
        }
        Err(response) => response,
    }
}

pub(in crate::app) fn github_callback_rejected(
    state: &AppState,
    request_id: &RequestId,
) -> Response {
    if let Some(github) = &state.github_installation {
        github
            .metrics
            .callbacks_rejected
            .fetch_add(1, Ordering::Relaxed);
    }
    github_callback_response(problem_response(
        request_id,
        StatusCode::UNAUTHORIZED,
        "GitHub installation rejected",
        "the installation callback binding was invalid, expired, or already consumed",
    ))
}

pub(in crate::app) fn github_callback_response(mut response: Response) -> Response {
    protect_sensitive_response(&mut response);
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

pub(in crate::app) async fn finish_github_installation(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<GitHubSetupCallbackQuery>,
) -> Response {
    let Some(github) = state.github_installation.as_ref() else {
        return github_callback_response(StatusCode::NOT_FOUND.into_response());
    };
    match state.control_plane.recovery_state() {
        Ok(recovery) if !recovery.safe_mode => {}
        Ok(_) => {
            return github_callback_response(problem_response(
                &request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                "Restore safe mode",
                "GitHub installation callbacks are disabled during restore verification",
            ))
        }
        Err(_) => return github_callback_response(internal_problem(&request_id)),
    }
    if query.state.is_none() {
        if query.installation_id == 0 {
            return github_callback_rejected(&state, &request_id);
        }
        let now = match now_unix_ms(&request_id) {
            Ok(now) => now,
            Err(response) => return github_callback_response(response),
        };
        let snapshot = match inspect_github_installation(
            &state,
            &request_id,
            query.installation_id,
            now,
        )
        .await
        {
            Ok(snapshot) => snapshot,
            Err(response) => return github_callback_response(response),
        };
        let body = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>GitHub App installed</title></head><body><main><h1>GitHub App installed</h1><p>The installation for <strong>{}</strong> was verified. An authorized Runtrue user must now select and onboard repositories from the dashboard.</p><p><a href=\"/\">Open Runtrue dashboard</a></p></main></body></html>",
            escape_html(&snapshot.account.login)
        );
        return github_callback_response(html_response(body));
    }
    let callback_state = query.state.as_deref().unwrap_or_default();
    if query.installation_id == 0
        || query
            .setup_action
            .as_deref()
            .is_some_and(|action| !matches!(action, "install" | "update"))
        || github
            .public_config
            .installation_url(callback_state)
            .is_err()
    {
        return github_callback_rejected(&state, &request_id);
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return github_callback_response(response),
    };
    let state_digest = github_setup_state_digest(callback_state);
    let setup = match state
        .control_plane
        .begin_github_setup_by_state(&state_digest, now)
    {
        Ok(setup) => setup.value,
        Err(_) => return github_callback_rejected(&state, &request_id),
    };
    if setup.github_web_origin != github.public_config.web_origin()
        || setup.github_api_origin != github.public_config.api_origin()
    {
        return github_callback_rejected(&state, &request_id);
    }
    let snapshot =
        match inspect_github_installation(&state, &request_id, query.installation_id, now).await {
            Ok(snapshot) => snapshot,
            Err(response) => return github_callback_response(response),
        };
    if setup.principal_id.starts_with("github-") {
        let (context, session, _) = match authenticated_browser_session(
            &state,
            &request_id,
            &headers,
            SCM_READ_SCOPE,
            None,
            now,
        ) {
            Ok(authenticated) => authenticated,
            Err(_) => return github_callback_rejected(&state, &request_id),
        };
        if context.tenant_id != setup.tenant_id || context.principal_id != setup.principal_id {
            return github_callback_rejected(&state, &request_id);
        }
        let account_visible = match github_catalog_for_browser_session(&state, &headers, &session)
            .await
        {
            GitHubCatalogLoad::Ready {
                viewer_login,
                catalog,
            } => {
                viewer_login.eq_ignore_ascii_case(&snapshot.account.login)
                    || catalog.organizations.iter().any(|organization| {
                        organization.eq_ignore_ascii_case(&snapshot.account.login)
                    })
            }
            GitHubCatalogLoad::ReauthenticationRequired | GitHubCatalogLoad::Unavailable => false,
        };
        if !account_visible {
            return github_callback_rejected(&state, &request_id);
        }
    }
    let permission_ready = snapshot.validate_runtrue_ci_permissions().is_ok();
    let reconciliation =
        match github_reconciliation_from_snapshot(&state, &setup.tenant_id, snapshot, now) {
            Ok(reconciliation) => reconciliation,
            Err(_) => return github_callback_rejected(&state, &request_id),
        };
    let completion = CompleteGitHubSetupTransaction {
        tenant_id: setup.tenant_id.clone(),
        principal_id: setup.principal_id.clone(),
        transaction_id: setup.id.clone(),
        state_digest,
        reconciliation: reconciliation.clone(),
        now_unix_ms: now,
    };
    let completed = match state
        .control_plane
        .complete_github_setup_transaction(&completion)
    {
        Ok(completed) => completed,
        Err(_) => return github_callback_rejected(&state, &request_id),
    };
    if let Err(error) = provision_selected_github_repositories(&state, &reconciliation) {
        return github_callback_response(control_plane_problem(&request_id, error));
    }
    github
        .metrics
        .callbacks_completed
        .fetch_add(u64::from(!completed.replayed), Ordering::Relaxed);
    let return_path = if permission_ready {
        completed.value.return_path
    } else {
        "/ui/github/installations?github=permissions".to_owned()
    };
    let location = match HeaderValue::from_str(&return_path) {
        Ok(location) if valid_return_to(&return_path) => location,
        _ => return github_callback_response(internal_problem(&request_id)),
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(LOCATION, location);
    github_callback_response(response)
}
use super::installations::{
    github_reconciliation_from_snapshot, inspect_github_installation,
    provision_selected_github_repositories,
};
use super::ui::{github_catalog_for_browser_session, GitHubCatalogLoad};
use axum::response::IntoResponse as _;
