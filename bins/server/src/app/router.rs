use crate::app::{
    begin_github_oauth_login, begin_human_oidc_login, browser_decide_workflow_approval,
    browser_organization_settings, browser_policy_page, browser_policy_status,
    browser_repository_settings, browser_run_detail, browser_session_page, browser_session_status,
    cancel_run, create_api_token, create_artifact_download_ticket, create_capsule,
    create_enrollment_token, create_github_setup, create_policy_version, create_replay_bundle,
    create_repository, create_run, create_runner_pool, create_secret, decide_approval,
    delete_browser_organization_secret, delete_browser_organization_variable,
    delete_browser_repository_secret, delete_browser_repository_variable, delete_secret,
    delete_variable, download_artifact, drain_runner, finish_github_installation,
    finish_github_oauth_login, finish_human_oidc_login, get_approval, get_artifact,
    get_artifact_provenance, get_capsule, get_replay_bundle, get_repository, get_run, get_run_logs,
    get_runner, get_runner_capsule_trust_key, get_runner_pool, get_secret_metadata, get_variable,
    github_app_status, github_browser_state, github_webhook, health,
    link_github_repository_from_ui, list_api_tokens, list_approvals, list_audit_events,
    list_repositories, list_runner_pools, list_runners, list_runs, list_secret_metadata,
    logout_browser_session, oidc_discovery, oidc_jwks, promote_artifact, promote_cache,
    put_variable, readiness, refresh_browser_session, request_context, require_bearer,
    require_writable_control_plane, require_writable_human_auth, revoke_api_token,
    revoke_github_installation, rotate_secret, route_not_found, save_browser_organization_secret,
    save_browser_organization_variable, save_browser_repository_secret,
    save_browser_repository_variable, save_browser_repository_workflow_directory,
    start_github_installation_from_ui, sync_github_installation, uninstall_browser_repository,
    AppState, API_BODY_BYTES, BROWSER_MUTATION_BODY_BYTES, MAX_CREATE_CAPSULE_BODY_BYTES,
};
use axum::extract::DefaultBodyLimit;
use axum::middleware::{self as axum_middleware};
use axum::routing::{get, post};
use axum::Router;
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route(
            "/api/v1/repositories",
            get(list_repositories).post(create_repository),
        )
        .route("/api/v1/repositories/:repository_id", get(get_repository))
        .route(
            "/api/v1/repositories/:repository_id/capsules",
            post(create_capsule).layer(DefaultBodyLimit::max(MAX_CREATE_CAPSULE_BODY_BYTES)),
        )
        .route("/api/v1/capsules/:capsule_id", get(get_capsule))
        .route("/api/v1/capsules/:capsule_id/runs", post(create_run))
        .route("/api/v1/runs", get(list_runs))
        .route("/api/v1/runs/:run_id", get(get_run))
        .route("/api/v1/runs/:run_id/logs", get(get_run_logs))
        .route("/api/v1/runs/:run_id/cancel", post(cancel_run))
        .route(
            "/api/v1/runs/:run_id/replay-bundle",
            get(get_replay_bundle).post(create_replay_bundle),
        )
        .route("/api/v1/approval-requests", get(list_approvals))
        .route("/api/v1/approval-requests/:approval_id", get(get_approval))
        .route(
            "/api/v1/approval-requests/:approval_id/decisions",
            post(decide_approval),
        )
        .route(
            "/api/v1/runner-pools",
            get(list_runner_pools).post(create_runner_pool),
        )
        .route(
            "/api/v1/runner-pools/trust/capsule-key",
            get(get_runner_capsule_trust_key),
        )
        .route("/api/v1/runner-pools/:pool_id", get(get_runner_pool))
        .route("/api/v1/runners", get(list_runners))
        .route("/api/v1/runners/:runner_id", get(get_runner))
        .route("/api/v1/runners/:runner_id/drain", post(drain_runner))
        .route(
            "/api/v1/runner-pools/:pool_id/enrollment-tokens",
            post(create_enrollment_token),
        )
        .route(
            "/api/v1/scopes/:scope/secrets",
            get(list_secret_metadata).post(create_secret),
        )
        .route(
            "/api/v1/scopes/:scope/secrets/:name",
            get(get_secret_metadata)
                .put(rotate_secret)
                .delete(delete_secret),
        )
        .route(
            "/api/v1/scopes/:scope/variables/:name",
            get(get_variable).put(put_variable).delete(delete_variable),
        )
        .route(
            "/api/v1/cache/entries/:entry_id/promote",
            post(promote_cache),
        )
        .route(
            "/api/v1/artifacts/:artifact_id/promote",
            post(promote_artifact),
        )
        .route("/api/v1/artifacts/:artifact_id", get(get_artifact))
        .route(
            "/api/v1/artifacts/:artifact_id/provenance",
            get(get_artifact_provenance),
        )
        .route(
            "/api/v1/artifacts/:artifact_id/download-tickets",
            post(create_artifact_download_ticket),
        )
        .route("/api/v1/artifact-downloads/:token", get(download_artifact))
        .route(
            "/api/v1/policies/:policy_id/versions",
            post(create_policy_version),
        )
        .route("/api/v1/scm/github", get(github_app_status))
        .route(
            "/api/v1/scm/github/setup-transactions",
            post(create_github_setup),
        )
        .route(
            "/api/v1/scm/github/installations/:installation_id/sync",
            post(sync_github_installation),
        )
        .route(
            "/api/v1/scm/github/installations/:installation_id",
            axum::routing::delete(revoke_github_installation),
        )
        .route("/api/v1/audit-events", get(list_audit_events))
        .route(
            "/api/v1/api-tokens",
            get(list_api_tokens).post(create_api_token),
        )
        .route(
            "/api/v1/api-tokens/:token_id",
            axum::routing::delete(revoke_api_token),
        )
        .layer(DefaultBodyLimit::max(API_BODY_BYTES))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            require_writable_control_plane,
        ))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));

    let webhook = Router::new()
        .route("/webhooks/github", post(github_webhook))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            require_writable_control_plane,
        ))
        .layer(DefaultBodyLimit::max(state.webhook_limits.max_body_bytes));

    let browser = if state.human_oidc.is_some() {
        let mutations = Router::new()
            .route("/auth/oidc/login", get(begin_human_oidc_login))
            .route("/auth/oidc/callback", get(finish_human_oidc_login))
            .route("/auth/login", get(begin_github_oauth_login))
            .route("/auth/callback", get(finish_github_oauth_login))
            .route("/auth/session/refresh", post(refresh_browser_session))
            .route("/auth/session/logout", post(logout_browser_session))
            .route(
                "/ui/github/installations/start",
                post(start_github_installation_from_ui),
            )
            .route(
                "/ui/github/repositories/link",
                post(link_github_repository_from_ui),
            )
            .route(
                "/api/v1/ui/organization/secrets",
                post(save_browser_organization_secret),
            )
            .route(
                "/api/v1/ui/organization/secrets/delete",
                post(delete_browser_organization_secret),
            )
            .route(
                "/api/v1/ui/organization/variables",
                post(save_browser_organization_variable),
            )
            .route(
                "/api/v1/ui/organization/variables/delete",
                post(delete_browser_organization_variable),
            )
            .route(
                "/api/v1/ui/repositories/:repository_id/secrets",
                post(save_browser_repository_secret),
            )
            .route(
                "/api/v1/ui/repositories/:repository_id/secrets/delete",
                post(delete_browser_repository_secret),
            )
            .route(
                "/api/v1/ui/repositories/:repository_id/variables",
                post(save_browser_repository_variable),
            )
            .route(
                "/api/v1/ui/repositories/:repository_id/variables/delete",
                post(delete_browser_repository_variable),
            )
            .route(
                "/api/v1/ui/repositories/:repository_id/workflow-directory",
                post(save_browser_repository_workflow_directory),
            )
            .route(
                "/api/v1/ui/repositories/:repository_id/uninstall",
                post(uninstall_browser_repository),
            )
            .route(
                "/api/v1/ui/approvals/:approval_id/decisions",
                post(browser_decide_workflow_approval),
            )
            .layer(DefaultBodyLimit::max(BROWSER_MUTATION_BODY_BYTES))
            .layer(axum_middleware::from_fn_with_state(
                state.clone(),
                require_writable_human_auth,
            ));
        Router::new()
            .route("/api/v1/session", get(browser_session_status))
            .route("/api/v1/policy-status", get(browser_policy_status))
            .route("/ui/session", get(browser_session_page))
            .route("/ui/policy", get(browser_policy_page))
            .route("/api/v1/ui/github", get(github_browser_state))
            .route(
                "/api/v1/ui/organization/settings",
                get(browser_organization_settings),
            )
            .route("/api/v1/ui/runs/:run_id", get(browser_run_detail))
            .route(
                "/api/v1/ui/repositories/:repository_id/settings",
                get(browser_repository_settings),
            )
            .merge(mutations)
    } else {
        Router::new()
    };

    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/oidc/jwks.json", get(oidc_jwks))
        .route("/auth/github/app/callback", get(finish_github_installation))
        .merge(api)
        .merge(webhook)
        .merge(browser)
        .fallback(route_not_found)
        .with_state(state.clone())
        .layer(axum_middleware::from_fn(move |request, next| {
            request_context(request, next, state.request_timeout)
        }))
}
