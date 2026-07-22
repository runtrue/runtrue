#![allow(clippy::result_large_err)]

use crate::app::{
    authenticated_browser_session, authorize_browser_resource, browser_csrf_input,
    control_plane_problem, form_value, invalid_object_problem, now_unix_ms,
    protect_sensitive_response, random_id, randomness_problem, AppState, RequestId, SCM_READ_SCOPE,
    SCM_WRITE_SCOPE,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use runtrue_audit::{AuditEventData, AuditPrincipal, AuditResource, AuditValue};
use runtrue_auth::AuthContext;
use runtrue_control_plane::{
    ConfigurationProjectTarget, ConfigurationProjectTargetKind, PutConfigurationProject,
    SecretMetadataReference, SecretScope, SecretScopeKind,
};
use runtrue_policy::{CedarAction, CedarResource, CedarResourceKind};
use runtrue_secrets::SecretPlaintext;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;

fn secret_resource(
    context: &AuthContext,
    scope: &SecretScope,
    name: Option<&str>,
) -> CedarResource {
    CedarResource {
        kind: CedarResourceKind::Secret,
        id: name.map_or_else(
            || scope.durable_key(),
            |name| format!("{}/{name}", scope.durable_key()),
        ),
        tenant_id: context.tenant_id.clone(),
        repository_id: (scope.kind == SecretScopeKind::Repository).then(|| scope.id.clone()),
        author_id: None,
        risk_score: 0,
        privileged: false,
        untrusted: false,
    }
}

fn parse_scope(kind: &str, id: String) -> Result<SecretScope, &'static str> {
    if id.is_empty() || id.len() > 8 * 1024 || id.contains('\0') {
        return Err("invalid secret scope id");
    }
    let kind = match kind {
        "workspace" => SecretScopeKind::Workspace,
        "scm_account" => SecretScopeKind::ScmAccount,
        "project" => SecretScopeKind::Project,
        "repository" => SecretScopeKind::Repository,
        _ => return Err("invalid secret scope kind"),
    };
    Ok(SecretScope { kind, id })
}

fn parse_durable_scope(value: &str) -> Option<SecretScope> {
    let (kind, id) = value.split_once(':')?;
    let scope = parse_scope(
        match kind {
            "tenant" => "workspace",
            "scm-account" => "scm_account",
            "project" => "project",
            "repository" => "repository",
            _ => return None,
        },
        id.to_owned(),
    )
    .ok()?;
    (scope.durable_key() == value).then_some(scope)
}

async fn authorize_scope(
    state: &AppState,
    request_id: &RequestId,
    context: &AuthContext,
    scope: &SecretScope,
    action: CedarAction,
) -> Result<(), Response> {
    let valid = match scope.kind {
        SecretScopeKind::Workspace => scope.id == context.tenant_id,
        SecretScopeKind::Repository => state
            .store
            .repository(&scope.id)
            .await
            .is_ok_and(|repository| repository.tenant_id == context.tenant_id),
        SecretScopeKind::Project => state
            .store
            .project(&context.tenant_id, &scope.id)
            .await
            .is_ok(),
        SecretScopeKind::ScmAccount => state
            .store
            .github_installations_for_tenant(&context.tenant_id, None, 100)
            .await
            .is_ok_and(|installations| {
                installations
                    .iter()
                    .any(|installation| installation.account_external_id == scope.id)
            }),
    };
    if !valid {
        return Err(crate::app::problem_response(
            request_id,
            StatusCode::NOT_FOUND,
            "Secret scope not found",
            "the requested secret scope was not found",
        ));
    }
    authorize_browser_resource(
        state,
        request_id,
        context,
        action,
        secret_resource(context, scope, None),
    )
    .await
    .map_err(|response| *response)
}

async fn can_read_scope(
    state: &AppState,
    request_id: &RequestId,
    context: &AuthContext,
    readable_scopes: &mut BTreeMap<String, bool>,
    scope: &SecretScope,
) -> bool {
    let key = scope.durable_key();
    if let Some(readable) = readable_scopes.get(&key) {
        return *readable;
    }
    let readable = authorize_scope(
        state,
        request_id,
        context,
        scope,
        CedarAction::ReadSecretMetadata,
    )
    .await
    .is_ok();
    readable_scopes.insert(key, readable);
    readable
}

#[allow(clippy::too_many_arguments)]
async fn append_browser_audit(
    state: &AppState,
    context: &AuthContext,
    request_id: &RequestId,
    now: u64,
    action: &str,
    resource_kind: &str,
    resource_id: String,
    metadata: BTreeMap<String, AuditValue>,
) -> Result<(), Response> {
    state
        .store
        .append_event(AuditEventData {
            observed_unix_ms: now,
            tenant_id: context.tenant_id.clone(),
            actor: AuditPrincipal {
                kind: "human-session".to_owned(),
                id: context.principal_id.clone(),
            },
            action: action.to_owned(),
            resource: AuditResource {
                kind: resource_kind.to_owned(),
                id: resource_id,
            },
            result: "succeeded".to_owned(),
            request_id: request_id.0.clone(),
            decision_id: None,
            metadata,
        })
        .await
        .map(|_| ())
        .map_err(|error| control_plane_problem(request_id, error))
}

pub(in crate::app) async fn browser_secret_inventory(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let (context, _, _) = match authenticated_browser_session(
        &state,
        &request_id,
        &headers,
        SCM_READ_SCOPE,
        None,
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let mut secrets = Vec::new();
    let projects = match state.store.projects(&context.tenant_id).await {
        Ok(projects) => projects,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let repositories = match state
        .store
        .repositories_for_tenant(&context.tenant_id)
        .await
    {
        Ok(repositories) => repositories,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let accounts = match state
        .store
        .github_installations_for_tenant(&context.tenant_id, None, 100)
        .await
    {
        Ok(installations) => installations
            .into_iter()
            .map(|installation| {
                json!({
                    "id": installation.account_external_id,
                    "name": installation.account_login,
                    "kind": installation.account_kind,
                })
            })
            .collect::<Vec<_>>(),
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let mut scope_keys = BTreeMap::new();
    scope_keys.insert(
        SecretScope {
            kind: SecretScopeKind::Workspace,
            id: context.tenant_id.clone(),
        }
        .durable_key(),
        (),
    );
    for repository in &repositories {
        scope_keys.insert(
            SecretScope {
                kind: SecretScopeKind::Repository,
                id: repository.id.clone(),
            }
            .durable_key(),
            (),
        );
    }
    for project in &projects {
        scope_keys.insert(
            SecretScope {
                kind: SecretScopeKind::Project,
                id: project.id.clone(),
            }
            .durable_key(),
            (),
        );
        for target in &project.targets {
            scope_keys.insert(
                SecretScope {
                    kind: match target.kind {
                        ConfigurationProjectTargetKind::ScmAccount => SecretScopeKind::ScmAccount,
                        ConfigurationProjectTargetKind::Repository => SecretScopeKind::Repository,
                    },
                    id: target.id.clone(),
                }
                .durable_key(),
                (),
            );
        }
    }
    for account in &accounts {
        if let Some(id) = account.get("id").and_then(serde_json::Value::as_str) {
            scope_keys.insert(
                SecretScope {
                    kind: SecretScopeKind::ScmAccount,
                    id: id.to_owned(),
                }
                .durable_key(),
                (),
            );
        }
    }
    for scope in scope_keys.keys() {
        match state.store.secrets(&context.tenant_id, scope).await {
            Ok(mut scoped) => secrets.append(&mut scoped),
            Err(error) => return control_plane_problem(&request_id, error),
        }
    }
    let mut readable_scopes = BTreeMap::<String, bool>::new();
    let mut readable_secrets = Vec::new();
    for metadata in secrets {
        let Some(scope) = parse_durable_scope(&metadata.scope) else {
            continue;
        };
        if can_read_scope(&state, &request_id, &context, &mut readable_scopes, &scope).await {
            readable_secrets.push(metadata);
        }
    }
    let secrets = readable_secrets;

    let mut readable_projects = Vec::new();
    for project in projects {
        let project_scope = SecretScope {
            kind: SecretScopeKind::Project,
            id: project.id.clone(),
        };
        if !can_read_scope(
            &state,
            &request_id,
            &context,
            &mut readable_scopes,
            &project_scope,
        )
        .await
        {
            continue;
        }
        let mut targets_readable = true;
        for target in &project.targets {
            let target_scope = SecretScope {
                kind: match target.kind {
                    ConfigurationProjectTargetKind::ScmAccount => SecretScopeKind::ScmAccount,
                    ConfigurationProjectTargetKind::Repository => SecretScopeKind::Repository,
                },
                id: target.id.clone(),
            };
            if !can_read_scope(
                &state,
                &request_id,
                &context,
                &mut readable_scopes,
                &target_scope,
            )
            .await
            {
                targets_readable = false;
                break;
            }
        }
        if targets_readable {
            readable_projects.push(project);
        }
    }
    let projects = readable_projects;

    let mut readable_repositories = Vec::new();
    for repository in repositories {
        let scope = SecretScope {
            kind: SecretScopeKind::Repository,
            id: repository.id.clone(),
        };
        if can_read_scope(&state, &request_id, &context, &mut readable_scopes, &scope).await {
            readable_repositories.push(repository);
        }
    }
    let repositories = readable_repositories;

    let mut readable_accounts = Vec::new();
    for account in accounts {
        let Some(id) = account.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let scope = SecretScope {
            kind: SecretScopeKind::ScmAccount,
            id: id.to_owned(),
        };
        if can_read_scope(&state, &request_id, &context, &mut readable_scopes, &scope).await {
            readable_accounts.push(account);
        }
    }
    let accounts = readable_accounts;
    let mut response = Json(json!({
        "workspace_id": context.tenant_id,
        "secrets": secrets,
        "projects": projects,
        "scm_accounts": accounts,
        "repositories": repositories,
    }))
    .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    protect_sensitive_response(&mut response);
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectTargetInput {
    kind: ConfigurationProjectTargetKind,
    id: String,
}

pub(in crate::app) async fn save_browser_configuration_project(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the project form is invalid"),
    };
    let csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(csrf) => csrf,
        Err(response) => return *response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let (context, _, _) = match authenticated_browser_session(
        &state,
        &request_id,
        &headers,
        SCM_WRITE_SCOPE,
        Some(&csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let name = match form_value(&body, "name") {
        Ok(Some(name)) if !name.trim().is_empty() => name,
        _ => return invalid_object_problem(&request_id, "project name is required"),
    };
    let description = form_value(&body, "description")
        .ok()
        .flatten()
        .unwrap_or_default();
    let id = match form_value(&body, "id") {
        Ok(Some(id)) if !id.is_empty() => id,
        _ => match random_id("project") {
            Ok(id) => id,
            Err(()) => return randomness_problem(&request_id),
        },
    };
    let expected_version = match form_value(&body, "expected_version") {
        Ok(Some(version)) => match version.parse::<u64>() {
            Ok(version) => version,
            Err(_) => return invalid_object_problem(&request_id, "invalid project version"),
        },
        _ => 0,
    };
    let raw_targets = form_value(&body, "targets")
        .ok()
        .flatten()
        .unwrap_or_else(|| "[]".to_owned());
    let targets: Vec<ProjectTargetInput> = match serde_json::from_str(&raw_targets) {
        Ok(targets) => targets,
        Err(_) => return invalid_object_problem(&request_id, "invalid project targets"),
    };
    let scope = SecretScope {
        kind: SecretScopeKind::Project,
        id: id.clone(),
    };
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::WriteSecret,
        secret_resource(&context, &scope, None),
    )
    .await
    {
        return *response;
    }
    let mut target_scopes = BTreeMap::<String, SecretScope>::new();
    if expected_version > 0 {
        let existing = match state.store.project(&context.tenant_id, &id).await {
            Ok(existing) => existing,
            Err(error) => return control_plane_problem(&request_id, error),
        };
        for target in existing.targets {
            let scope = SecretScope {
                kind: match target.kind {
                    ConfigurationProjectTargetKind::ScmAccount => SecretScopeKind::ScmAccount,
                    ConfigurationProjectTargetKind::Repository => SecretScopeKind::Repository,
                },
                id: target.id,
            };
            target_scopes.insert(scope.durable_key(), scope);
        }
    }
    for target in &targets {
        let target_scope = SecretScope {
            kind: match target.kind {
                ConfigurationProjectTargetKind::ScmAccount => SecretScopeKind::ScmAccount,
                ConfigurationProjectTargetKind::Repository => SecretScopeKind::Repository,
            },
            id: target.id.clone(),
        };
        target_scopes.insert(target_scope.durable_key(), target_scope);
    }
    for target_scope in target_scopes.values() {
        if let Err(response) = authorize_scope(
            &state,
            &request_id,
            &context,
            target_scope,
            CedarAction::WriteSecret,
        )
        .await
        {
            return response;
        }
    }
    let input = PutConfigurationProject {
        id: id.clone(),
        tenant_id: context.tenant_id.clone(),
        name,
        description,
        status: "active".to_owned(),
        expected_version,
        targets: targets
            .into_iter()
            .map(|target| ConfigurationProjectTarget {
                kind: target.kind,
                id: target.id,
                created_unix_ms: now,
            })
            .collect(),
        updated_unix_ms: now,
    };
    let project = match state.store.put_project(&input).await {
        Ok(project) => project,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "version".to_owned(),
        AuditValue::Integer(project.version.try_into().unwrap_or(i64::MAX)),
    );
    metadata.insert(
        "target_count".to_owned(),
        AuditValue::Integer(project.targets.len().try_into().unwrap_or(i64::MAX)),
    );
    if let Err(response) = append_browser_audit(
        &state,
        &context,
        &request_id,
        now,
        if expected_version == 0 {
            "configuration-project.create"
        } else {
            "configuration-project.update"
        },
        "configuration-project",
        id,
        metadata,
    )
    .await
    {
        return response;
    }
    Json(project).into_response()
}

pub(in crate::app) async fn save_browser_scoped_secret(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    mutate_browser_scoped_secret(state, request_id, headers, body, false).await
}

pub(in crate::app) async fn delete_browser_scoped_secret(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    mutate_browser_scoped_secret(state, request_id, headers, body, true).await
}

async fn mutate_browser_scoped_secret(
    state: AppState,
    request_id: RequestId,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
    delete: bool,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the secret form is invalid"),
    };
    let csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(csrf) => csrf,
        Err(response) => return *response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let (context, _, _) = match authenticated_browser_session(
        &state,
        &request_id,
        &headers,
        SCM_WRITE_SCOPE,
        Some(&csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let kind = form_value(&body, "scope_kind")
        .ok()
        .flatten()
        .unwrap_or_default();
    let id = form_value(&body, "scope_id")
        .ok()
        .flatten()
        .unwrap_or_default();
    let scope = match parse_scope(&kind, id) {
        Ok(scope) => scope,
        Err(message) => return invalid_object_problem(&request_id, message),
    };
    if let Err(response) = authorize_scope(
        &state,
        &request_id,
        &context,
        &scope,
        CedarAction::ReadSecretMetadata,
    )
    .await
    {
        return response;
    }
    let name = match form_value(&body, "name") {
        Ok(Some(name)) if !name.trim().is_empty() => name,
        _ => return invalid_object_problem(&request_id, "secret name is required"),
    };
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::WriteSecret,
        secret_resource(&context, &scope, Some(&name)),
    )
    .await
    {
        return *response;
    }
    let durable_scope = scope.durable_key();
    let metadata = if delete {
        match state
            .store
            .delete_secret_configuration(
                &context.tenant_id,
                &durable_scope,
                &name,
                &state.secret_master_key,
                now,
            )
            .await
        {
            Ok(metadata) => metadata,
            Err(error) => return control_plane_problem(&request_id, error),
        }
    } else {
        let value = match form_value(&body, "value") {
            Ok(Some(value)) if !value.is_empty() => value,
            _ => return invalid_object_problem(&request_id, "secret value is required"),
        };
        let idempotency_key = match form_value(&body, "idempotency_key") {
            Ok(Some(key)) if !key.is_empty() => key,
            _ => return invalid_object_problem(&request_id, "idempotency key is required"),
        };
        let plaintext = SecretPlaintext::new(value.into_bytes());
        let result = if state
            .store
            .secret_by_name(&context.tenant_id, &durable_scope, &name)
            .await
            .is_ok()
        {
            state
                .store
                .rotate_secret(
                    &idempotency_key,
                    &context.tenant_id,
                    &durable_scope,
                    &name,
                    &plaintext,
                    &state.secret_master_key,
                    now,
                )
                .await
        } else {
            let id = match random_id("secret") {
                Ok(id) => id,
                Err(()) => return randomness_problem(&request_id),
            };
            state
                .store
                .create_secret(
                    &idempotency_key,
                    &SecretMetadataReference {
                        id,
                        tenant_id: context.tenant_id.clone(),
                        scope: durable_scope.clone(),
                        name: name.clone(),
                        provider: "built-in".to_owned(),
                        provider_reference: None,
                        secret_type: "opaque".to_owned(),
                        status: "active".to_owned(),
                        current_version: Some(1),
                        created_unix_ms: now,
                        updated_unix_ms: now,
                    },
                    Some(&plaintext),
                    &state.secret_master_key,
                )
                .await
        };
        match result {
            Ok(result) => result.value,
            Err(error) => return control_plane_problem(&request_id, error),
        }
    };
    let mut audit_metadata = BTreeMap::new();
    audit_metadata.insert(
        "scope_kind".to_owned(),
        AuditValue::String(scope.kind.as_str().to_owned()),
    );
    audit_metadata.insert("name".to_owned(), AuditValue::String(name));
    if let Some(version) = metadata.current_version {
        audit_metadata.insert(
            "version".to_owned(),
            AuditValue::Integer(version.try_into().unwrap_or(i64::MAX)),
        );
    }
    if let Err(response) = append_browser_audit(
        &state,
        &context,
        &request_id,
        now,
        if delete {
            "secret.delete"
        } else {
            "secret.put"
        },
        "secret",
        metadata.id.clone(),
        audit_metadata,
    )
    .await
    {
        return response;
    }
    let mut response = Json(metadata).into_response();
    protect_sensitive_response(&mut response);
    response
}
