use crate::app::{
    authorize_tenant_collection, control_plane_problem, github_api_tenant, internal_problem,
    now_unix_ms, problem_response, AppState, GitHubInstallationMetricsSnapshot, RequestId,
    RequestPrincipal,
};
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use runtrue_control_plane::{
    ControlPlaneError, GitHubAccountKind, GitHubInstallationRecord, GitHubRepositorySelection,
    LinkSelectedGitHubRepository, ReconcileGitHubInstallation, ScmInstallationRecord,
    SetGitHubInstallationStatus,
};
use runtrue_policy::CedarAction;
use runtrue_scm::{
    GitHubAppPublicConfig, GitHubError, GitHubInstallationRepository, GitHubInstallationSnapshot,
    GitHubRepositoryVisibility,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct GitHubTenantQuery {
    #[serde(default)]
    tenant_id: Option<String>,
}
#[derive(Debug, Serialize)]
pub(in crate::app) struct GitHubInstallationPublicView {
    pub(in crate::app) id: String,
    pub(in crate::app) external_id: String,
    pub(in crate::app) web_origin: String,
    pub(in crate::app) api_origin: String,
    pub(in crate::app) account_external_id: String,
    pub(in crate::app) account_login: String,
    pub(in crate::app) account_kind: GitHubAccountKind,
    pub(in crate::app) repository_selection: GitHubRepositorySelection,
    pub(in crate::app) permissions: Value,
    pub(in crate::app) status: String,
    pub(in crate::app) lifecycle_generation: u64,
    pub(in crate::app) synchronized_unix_ms: u64,
    pub(in crate::app) version: u64,
}

impl From<GitHubInstallationRecord> for GitHubInstallationPublicView {
    fn from(value: GitHubInstallationRecord) -> Self {
        Self {
            id: value.installation.id,
            external_id: value.installation.external_id,
            web_origin: value.web_origin,
            api_origin: value.api_origin,
            account_external_id: value.account_external_id,
            account_login: value.account_login,
            account_kind: value.account_kind,
            repository_selection: value.repository_selection,
            permissions: value.installation.permissions,
            status: value.installation.status,
            lifecycle_generation: value.lifecycle_generation,
            synchronized_unix_ms: value.synchronized_unix_ms,
            version: value.version,
        }
    }
}

#[derive(Debug, Serialize)]
pub(in crate::app) struct GitHubRepositoryPublicView {
    pub(in crate::app) installation_id: String,
    pub(in crate::app) external_repository_id: String,
    pub(in crate::app) web_origin: String,
    pub(in crate::app) api_origin: String,
    pub(in crate::app) owner: String,
    pub(in crate::app) name: String,
    pub(in crate::app) full_name: String,
    pub(in crate::app) visibility: String,
    pub(in crate::app) default_branch: String,
    pub(in crate::app) status: String,
    pub(in crate::app) linked_repository_id: Option<String>,
    pub(in crate::app) selection_generation: u64,
    pub(in crate::app) version: u64,
}

#[derive(Debug, Serialize)]
pub(in crate::app) struct GitHubAppStatusView {
    pub(in crate::app) configured: bool,
    pub(in crate::app) app_id: Option<u64>,
    pub(in crate::app) app_slug: Option<String>,
    pub(in crate::app) web_origin: Option<String>,
    pub(in crate::app) api_origin: Option<String>,
    pub(in crate::app) provider_host: Option<String>,
    pub(in crate::app) webhook_configured: bool,
    pub(in crate::app) installations: Vec<GitHubInstallationPublicView>,
    pub(in crate::app) repositories: Vec<GitHubRepositoryPublicView>,
    pub(in crate::app) metrics: GitHubInstallationMetricsSnapshot,
}
pub(in crate::app) fn github_status_service(
    state: &AppState,
    tenant_id: &str,
) -> Result<GitHubAppStatusView, ControlPlaneError> {
    let Some(github) = &state.github_installation else {
        return Ok(GitHubAppStatusView {
            configured: false,
            app_id: None,
            app_slug: None,
            web_origin: None,
            api_origin: None,
            provider_host: None,
            webhook_configured: state.webhook.is_some(),
            installations: Vec::new(),
            repositories: Vec::new(),
            metrics: GitHubInstallationMetricsSnapshot::default(),
        });
    };
    let installations = state
        .control_plane
        .list_github_installations_for_tenant(tenant_id, None, 100)?;
    let mut repositories = Vec::new();
    for installation in &installations {
        let catalog = state
            .control_plane
            .list_github_repository_catalog_for_tenant(
                tenant_id,
                &installation.installation.id,
                true,
                None,
                100,
            )?;
        let links = state
            .control_plane
            .list_github_repository_links_for_tenant(
                tenant_id,
                &installation.installation.id,
                None,
                100,
            )?;
        for repository in catalog {
            let linked_repository_id = links
                .iter()
                .find(|link| {
                    link.external_repository_id == repository.external_repository_id
                        && link.status == "active"
                })
                .map(|link| link.repository_id.clone());
            repositories.push(GitHubRepositoryPublicView {
                installation_id: repository.installation_id,
                external_repository_id: repository.external_repository_id,
                web_origin: repository.web_origin,
                api_origin: repository.api_origin,
                owner: repository.owner,
                name: repository.name,
                full_name: repository.full_name,
                visibility: repository.visibility,
                default_branch: repository.default_branch,
                status: repository.status,
                linked_repository_id,
                selection_generation: repository.selection_generation,
                version: repository.version,
            });
        }
    }
    Ok(GitHubAppStatusView {
        configured: true,
        app_id: Some(github.public_config.app_id()),
        app_slug: Some(github.public_config.app_slug().to_owned()),
        web_origin: Some(github.public_config.web_origin().to_owned()),
        api_origin: Some(github.public_config.api_origin().to_owned()),
        provider_host: Some(github.public_config.provider_host().to_owned()),
        webhook_configured: state.webhook.is_some(),
        installations: installations
            .into_iter()
            .map(GitHubInstallationPublicView::from)
            .collect(),
        repositories,
        metrics: github.metrics.snapshot(),
    })
}

pub(in crate::app) async fn github_app_status(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Query(query): Query<GitHubTenantQuery>,
) -> Response {
    let tenant_id = match github_api_tenant(&request_id, &principal, query.tenant_id.as_deref()) {
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
    match github_status_service(&state, &tenant_id) {
        Ok(status) => Json(status).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}
pub(in crate::app) fn github_installation_internal_id(external_id: u64) -> String {
    format!("github-installation-{external_id}")
}

pub(in crate::app) fn github_repository_internal_id(external_id: u64) -> String {
    format!("github-repository-{external_id}")
}

pub(in crate::app) fn github_reconciliation_from_snapshot(
    state: &AppState,
    tenant_id: &str,
    snapshot: GitHubInstallationSnapshot,
    now_unix_ms: u64,
) -> Result<ReconcileGitHubInstallation, ControlPlaneError> {
    let github = state
        .github_installation
        .as_ref()
        .ok_or(ControlPlaneError::InvalidInput(
            "GitHub App installation is not configured",
        ))?;
    let installation_id = github_installation_internal_id(snapshot.installation_id);
    let existing = match state
        .control_plane
        .github_installation_for_tenant(tenant_id, &installation_id)
    {
        Ok(existing) => Some(existing),
        Err(ControlPlaneError::NotFound { .. }) => None,
        Err(error) => return Err(error),
    };
    if existing.as_ref().is_some_and(|existing| {
        existing.installation.external_id != snapshot.installation_id.to_string()
            || existing.account_external_id != snapshot.account.id.to_string()
            || existing.web_origin != github.public_config.web_origin()
            || existing.api_origin != github.public_config.api_origin()
    }) {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let permissions = serde_json::to_value(&snapshot.permissions)?;
    let permission_ready = snapshot.validate_runtrue_ci_permissions().is_ok();
    let active = snapshot.suspended_at.is_none() && permission_ready;
    let (created_unix_ms, lifecycle_generation, version, expected_version) = existing
        .as_ref()
        .map_or((now_unix_ms, 1, 1, None), |existing| {
            (
                existing.installation.created_unix_ms,
                existing.lifecycle_generation.saturating_add(1),
                existing.version.saturating_add(1),
                Some(existing.version),
            )
        });
    let installation = ScmInstallationRecord {
        id: installation_id,
        tenant_id: tenant_id.to_owned(),
        provider: "github".to_owned(),
        external_id: snapshot.installation_id.to_string(),
        credential_reference: github.credential_reference.clone(),
        permissions,
        status: if active { "active" } else { "suspended" }.to_owned(),
        created_unix_ms,
        updated_unix_ms: now_unix_ms,
    };
    let selected_repositories = if snapshot.repository_catalog_complete {
        snapshot
            .repositories
            .iter()
            .filter(|repository| !repository.disabled)
            .map(|repository| github_selected_repository(&github.public_config, repository))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    Ok(ReconcileGitHubInstallation {
        installation: GitHubInstallationRecord {
            installation,
            web_origin: github.public_config.web_origin().to_owned(),
            api_origin: github.public_config.api_origin().to_owned(),
            account_external_id: snapshot.account.id.to_string(),
            account_login: snapshot.account.login,
            account_kind: match snapshot.account.kind {
                runtrue_scm::GitHubAccountKind::Organization => GitHubAccountKind::Organization,
                runtrue_scm::GitHubAccountKind::User => GitHubAccountKind::User,
            },
            repository_selection: match snapshot.repository_selection {
                runtrue_scm::GitHubRepositorySelection::All => GitHubRepositorySelection::All,
                runtrue_scm::GitHubRepositorySelection::Selected => {
                    GitHubRepositorySelection::Selected
                }
            },
            lifecycle_generation,
            synchronized_unix_ms: now_unix_ms,
            suspended_unix_ms: (!active).then_some(now_unix_ms),
            revoked_unix_ms: None,
            version,
        },
        selected_repositories,
        expected_version,
        now_unix_ms,
    })
}

pub(in crate::app) fn github_selected_repository(
    public_config: &GitHubAppPublicConfig,
    repository: &GitHubInstallationRepository,
) -> Result<runtrue_control_plane::GitHubSelectedRepository, ControlPlaneError> {
    let default_branch =
        repository
            .default_branch
            .clone()
            .ok_or(ControlPlaneError::InvalidInput(
                "GitHub repository has no provider-verified default branch",
            ))?;
    let visibility = match repository.visibility {
        GitHubRepositoryVisibility::Public => "public",
        GitHubRepositoryVisibility::Private => "private",
        GitHubRepositoryVisibility::Internal => "internal",
    };
    Ok(runtrue_control_plane::GitHubSelectedRepository {
        external_repository_id: repository.id.to_string(),
        owner: repository.owner.login.clone(),
        name: repository.name.clone(),
        full_name: repository.full_name.clone(),
        clone_url: public_config
            .repository_clone_url(&repository.owner.login, &repository.name)
            .map_err(|_| ControlPlaneError::InvalidInput("invalid GitHub repository identity"))?,
        visibility: visibility.to_owned(),
        default_branch,
    })
}

pub(in crate::app) fn provision_selected_github_repositories(
    state: &AppState,
    reconciliation: &ReconcileGitHubInstallation,
) -> Result<(), ControlPlaneError> {
    if reconciliation.installation.installation.status != "active" {
        return Ok(());
    }
    let tenant_id = &reconciliation.installation.installation.tenant_id;
    let existing = state
        .control_plane
        .list_repositories_for_tenant(tenant_id)?;
    for selected in &reconciliation.selected_repositories {
        let matches = existing
            .iter()
            .filter(|repository| {
                repository.owner == selected.owner && repository.name == selected.name
            })
            .collect::<Vec<_>>();
        let repository = match matches.as_slice() {
            // Provider selection populates the catalog but never onboards a
            // new repository implicitly. A tenant administrator must choose
            // it through the authenticated dashboard action.
            [] => continue,
            [repository]
                if repository.default_branch == selected.default_branch
                    && repository.visibility == selected.visibility =>
            {
                (*repository).clone()
            }
            _ => continue,
        };
        state
            .control_plane
            .link_selected_github_repository(&LinkSelectedGitHubRepository {
                tenant_id: tenant_id.clone(),
                installation_id: reconciliation.installation.installation.id.clone(),
                external_repository_id: selected.external_repository_id.clone(),
                repository,
                now_unix_ms: reconciliation.now_unix_ms,
            })?;
    }
    Ok(())
}

pub(in crate::app) async fn inspect_github_installation(
    state: &AppState,
    request_id: &RequestId,
    installation_id: u64,
    now_unix_ms: u64,
) -> Result<GitHubInstallationSnapshot, Response> {
    let github = state.github_installation.as_ref().ok_or_else(|| {
        problem_response(
            request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "GitHub App unavailable",
            "GitHub App installation is not configured",
        )
    })?;
    let permit = Arc::clone(&github.admission)
        .try_acquire_owned()
        .map_err(|_| {
            problem_response(
                request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                "GitHub App temporarily unavailable",
                "the bounded GitHub installation inspection capacity is exhausted",
            )
        })?;
    let provider = Arc::clone(&github.provider);
    let inspected = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        for attempt in 0..3 {
            let result = provider.inspect_installation(installation_id, now_unix_ms / 1000);
            match result {
                Err(GitHubError::Transport | GitHubError::JwtProvider)
                | Err(GitHubError::UnexpectedStatus(500..=599))
                    if attempt < 2 =>
                {
                    std::thread::sleep(Duration::from_millis(100 * (attempt + 1)));
                }
                result => return result,
            }
        }
        unreachable!("bounded provider retry loop always returns")
    })
    .await;
    match inspected {
        Ok(Ok(snapshot)) => Ok(snapshot),
        Ok(Err(GitHubError::InsufficientInstallationPermissions)) => Err(problem_response(
            request_id,
            StatusCode::CONFLICT,
            "GitHub App permissions are incomplete",
            "the installation does not grant the permissions required for Runtrue CI",
        )),
        _ => {
            github
                .metrics
                .provider_failures
                .fetch_add(1, Ordering::Relaxed);
            Err(problem_response(
                request_id,
                StatusCode::BAD_GATEWAY,
                "GitHub provider unavailable",
                "the installation could not be verified through the bounded GitHub provider adapter",
            ))
        }
    }
}

pub(in crate::app) async fn sync_github_installation(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(installation_id): Path<String>,
    Query(query): Query<GitHubTenantQuery>,
) -> Response {
    let tenant_id = match github_api_tenant(&request_id, &principal, query.tenant_id.as_deref()) {
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
    let current = match state
        .control_plane
        .github_installation_for_tenant(&tenant_id, &installation_id)
    {
        Ok(current) => current,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let Some(github) = state.github_installation.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if current.web_origin != github.public_config.web_origin()
        || current.api_origin != github.public_config.api_origin()
    {
        return problem_response(
            &request_id,
            StatusCode::CONFLICT,
            "GitHub provider binding changed",
            "the installation belongs to a different configured GitHub provider origin",
        );
    }
    let external_id = match current.installation.external_id.parse::<u64>() {
        Ok(value) if value != 0 => value,
        _ => return internal_problem(&request_id),
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let snapshot = match inspect_github_installation(&state, &request_id, external_id, now).await {
        Ok(snapshot) => snapshot,
        Err(response) => return response,
    };
    let reconciliation =
        match github_reconciliation_from_snapshot(&state, &tenant_id, snapshot, now) {
            Ok(reconciliation) => reconciliation,
            Err(error) => return control_plane_problem(&request_id, error),
        };
    let result = match state
        .control_plane
        .reconcile_github_installation(&reconciliation)
    {
        Ok(result) => result,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if let Err(error) = provision_selected_github_repositories(&state, &reconciliation) {
        return control_plane_problem(&request_id, error);
    }
    if let Some(github) = &state.github_installation {
        github
            .metrics
            .reconciliations
            .fetch_add(1, Ordering::Relaxed);
    }
    Json(GitHubInstallationPublicView::from(
        result.value.installation,
    ))
    .into_response()
}

pub(in crate::app) async fn revoke_github_installation(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(installation_id): Path<String>,
    Query(query): Query<GitHubTenantQuery>,
) -> Response {
    let tenant_id = match github_api_tenant(&request_id, &principal, query.tenant_id.as_deref()) {
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
    let current = match state
        .control_plane
        .github_installation_for_tenant(&tenant_id, &installation_id)
    {
        Ok(current) => current,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let request = SetGitHubInstallationStatus {
        tenant_id,
        installation_id,
        expected_version: current.version,
        status: "revoked".to_owned(),
        lifecycle_generation: current.lifecycle_generation.saturating_add(1),
        now_unix_ms: now,
    };
    match state.control_plane.set_github_installation_status(&request) {
        Ok(result) => {
            if !result.replayed {
                if let Some(github) = &state.github_installation {
                    github
                        .metrics
                        .installations_revoked
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}
use axum::response::IntoResponse as _;
