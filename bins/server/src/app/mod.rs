use axum::http::HeaderName;
use hmac::Hmac;
use runtrue_auth::AuthContext;
#[cfg(test)]
use runtrue_control_plane::ControlPlane;
use serde::Serialize;
use sha2::Sha256;
#[cfg(test)]
use std::sync::Arc;
use std::{sync::atomic::AtomicU64, time::Duration};
type HmacSha256 = Hmac<Sha256>;

const AUTH_DOMAIN: &[u8] = b"runtrue.server.bootstrap-token.v1\0";
const API_BODY_BYTES: usize = 1024 * 1024;
const MAX_CREATE_CAPSULE_BODY_BYTES: usize = 40 * 1024 * 1024;
const MAX_CAPSULE_WORKFLOW_BYTES: usize = 1024 * 1024;
const MAX_CAPSULE_EVENT_BYTES: usize = 1024 * 1024;
const MAX_CAPSULE_TEXT_BYTES: usize = 8192;
const SERVER_POLICY_VERSION_ID: &str = "server-default-deny-v1";
const MAX_REQUEST_TARGET_BYTES: usize = 16 * 1024;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BOOTSTRAP_TOKEN_BYTES: usize = 4096;
const MAX_API_TOKEN_TTL_MS: u64 = 365 * 24 * 60 * 60 * 1000;
const MAX_REQUEST_ID_BYTES: usize = 128;
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const LOGIN_COOKIE: &str = "runtrue_login";
const GITHUB_CREDENTIAL_COOKIE: &str = "runtrue_github_credential";
const ACCESS_COOKIE: &str = "runtrue_access";
const REFRESH_COOKIE: &str = "runtrue_refresh";
const CSRF_COOKIE: &str = "runtrue_csrf";
const OIDC_LOGIN_TTL_MS: u64 = 10 * 60 * 1000;
const BROWSER_MUTATION_BODY_BYTES: usize = 8 * 1024;
const MAX_RETURN_TO_BYTES: usize = 2048;
const MAX_COOKIE_HEADER_BYTES: usize = 16 * 1024;
const SESSION_READ_SCOPE: &str = "session:read";
const SESSION_WRITE_SCOPE: &str = "session:write";
const POLICY_READ_SCOPE: &str = "policy:read";
const SCM_READ_SCOPE: &str = "scm:read";
const SCM_WRITE_SCOPE: &str = "scm:write";
const GITHUB_SETUP_TTL_MS: u64 = 15 * 60 * 1000;
const GITHUB_SETUP_MAX_CONCURRENCY: usize = 4;
const GITHUB_LIFECYCLE_LEASE_MS: u64 = 2 * 60 * 1000;
const GITHUB_LIFECYCLE_RETRY_BASE_MS: u64 = 1_000;
const GITHUB_LIFECYCLE_RETRY_MAX_MS: u64 = 60 * 1_000;
const BUILTIN_SERVER_AUTHORIZATION_POLICY: &str = r#"
permit (principal, action, resource)
when { principal.tenant_id == resource.tenant_id };
"#;
static IDEMPOTENCY_REPLAYED: HeaderName = HeaderName::from_static("idempotency-replayed");
static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

static FALLBACK_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct RequestId(String);

#[derive(Debug, Clone)]
enum RequestPrincipal {
    Bootstrap,
    ApiToken(AuthContext),
}

#[derive(Serialize)]
struct Problem {
    r#type: String,
    title: &'static str,
    status: u16,
    detail: String,
    request_id: String,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

mod audit;
mod authorization;
mod browser;
mod github;
mod middleware;
mod problem;
mod router;
mod routes;
mod state;

use audit::{invalid_object_problem, list_audit_events};
use authorization::{
    api_token_tenant, approval_actor_id, auth_input_problem, authorize_resource,
    authorize_tenant_collection, github_api_tenant, github_setup_state_digest,
    principal_can_delegate, principal_matches_tenant, request_audit_principal,
    request_credential_id, require_bootstrap, start_github_setup_service, GitHubSetupRequest,
    ServerResource,
};
use browser::{
    authenticated_browser_session, authorize_browser_resource, authorize_browser_tenant,
    begin_github_oauth_login, begin_human_oidc_login, browser_csrf_input, browser_policy_page,
    browser_policy_status, browser_session_page, browser_session_status, escape_html,
    finish_github_oauth_login, finish_human_oidc_login, form_value, github_credential_cookie,
    html_response, logout_browser_session, oidc_discovery, oidc_jwks, refresh_browser_session,
    valid_return_to,
};
use github::{
    browser_decide_workflow_approval, browser_organization_settings, browser_repository_settings,
    browser_run_detail, create_github_setup, delete_browser_organization_secret,
    delete_browser_organization_variable, delete_browser_repository_secret,
    delete_browser_repository_variable, finish_github_installation, github_app_status,
    github_browser_state, github_webhook, link_github_repository_from_ui,
    reconcile_claimed_github_lifecycle, revoke_github_installation,
    save_browser_organization_secret, save_browser_organization_variable,
    save_browser_repository_secret, save_browser_repository_variable,
    save_browser_repository_workflow_directory, start_github_installation_from_ui,
    sync_github_installation, uninstall_browser_repository, GitHubSetupView,
};
use middleware::{
    authentication_problem, request_context, require_bearer, require_writable_control_plane,
    require_writable_human_auth,
};
use problem::{
    control_plane_problem, idempotency_key, internal_problem, now_unix_ms, optional_json,
    payload_too_large_problem, problem_response, random_id, randomness_problem, required_json,
    scm_problem, timestamp, wall_clock_unix_ms,
};
pub use router::router;
use routes::{
    cancel_run, create_api_token, create_artifact_download_ticket, create_capsule,
    create_enrollment_token, create_policy_version, create_promotion_response,
    create_replay_bundle, create_repository, create_run, create_runner_pool, create_secret,
    decide_approval, delete_secret, delete_variable, download_artifact, drain_runner, get_approval,
    get_artifact, get_artifact_provenance, get_capsule, get_replay_bundle, get_repository, get_run,
    get_run_logs, get_runner, get_runner_capsule_trust_key, get_runner_pool, get_secret_metadata,
    get_variable, health, list_api_tokens, list_approvals, list_repositories, list_runner_pools,
    list_runners, list_runs, list_secret_metadata, promote_artifact, promote_cache,
    protect_sensitive_response, put_variable, readiness, revoke_api_token, rotate_secret,
    route_not_found, scope_tenant, scoped_resource, Items,
};
use state::{authentication_tag, GitHubInstallationState, HumanOidcState};
pub use state::{
    AppState, BootstrapAuth, GitHubInstallationMetricsSnapshot, GitHubLifecycleWorkerError,
    GitHubOauthQuickstartConfig, ServerBuildError,
};
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_token_is_verified_without_retaining_it() {
        let auth = BootstrapAuth::new("correct-token").unwrap();
        assert!(auth.verify("correct-token"));
        assert!(!auth.verify("wrong-token"));
        assert!(!format!("{auth:?}").contains("correct-token"));
    }

    #[test]
    fn state_can_override_timeout_for_server_tests() {
        let control_plane = Arc::new(ControlPlane::open_in_memory("test", 1).unwrap());
        let state = AppState::new(control_plane, "token", None)
            .unwrap()
            .with_request_timeout(Duration::from_millis(1));
        assert_eq!(state.request_timeout, Duration::from_millis(1));
    }

    #[test]
    fn github_oauth_scopes_are_canonical_and_sorted() {
        let scopes = state::github_oauth_scopes();
        assert_eq!(scopes, ["read:org", "read:user", "repo"]);
        assert!(scopes.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn browser_return_forms_and_html_are_strictly_local_and_escaped() {
        assert!(valid_return_to("/ui/session?tab=active"));
        for invalid in [
            "https://attacker.example",
            "//attacker.example",
            "/safe#https://attacker.example",
            "/safe\\redirect",
            "/safe\nredirect",
        ] {
            assert!(!valid_return_to(invalid), "{invalid}");
        }
        assert_eq!(
            form_value(b"csrf_token=secret%2Btoken%3D", "csrf_token").unwrap(),
            Some("secret+token=".to_owned())
        );
        assert!(form_value(b"csrf_token=one&csrf_token=two", "csrf_token").is_err());
        assert_eq!(
            escape_html("<script>'&\""),
            "&lt;script&gt;&#39;&amp;&quot;"
        );
    }
}
