#![allow(clippy::result_large_err)]
// Axum handlers deliberately propagate the framework's concrete Response type.

use crate::app::{
    authenticated_browser_session, authorize_browser_resource, authorize_browser_tenant,
    browser_csrf_input, control_plane_problem, form_value, github_credential_cookie,
    internal_problem, invalid_object_problem, now_unix_ms, problem_response,
    protect_sensitive_response, random_id, randomness_problem, start_github_setup_service,
    timestamp, AppState, GitHubSetupRequest, RequestId, SCM_READ_SCOPE, SCM_WRITE_SCOPE,
};
use crate::github_install_ui::{
    github_installations_payload, repository_url, ComponentHealth,
    GitHubAccountKind as UiGitHubAccountKind, GitHubAppHealth, GitHubInstallAction,
    GitHubInstallationState as UiGitHubInstallationState, GitHubInstallationView,
    GitHubInstallationsPage, GitHubPermission as UiGitHubPermission,
    GitHubRepositoryCandidateAction, GitHubRepositoryEventView, GitHubRepositoryLinkView,
    GitHubUiAlert, RepositoryLinkState, RepositorySelection, RepositoryVisibility,
    GITHUB_BROWSER_API_CACHE_CONTROL,
};
use crate::human_oidc::{GitHubUserCatalog, HumanOidcError};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, LOCATION};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_auth::AuthContext;
use runtrue_control_plane::{
    ControlPlaneError, DurableEventRecord, DurableEventSource, GitHubAccountKind,
    GitHubRepositorySelection, LinkSelectedGitHubRepository, RepositoryRecord,
    SecretMetadataReference,
};
use runtrue_model::ContentDigest;
use runtrue_policy::{
    ApprovalDecision, ApprovalKind, ApprovalRequest, CedarAction, CedarResource, CedarResourceKind,
    Decision,
};
use runtrue_scm::{EventEnvelope, ProviderKind};
use runtrue_secrets::SecretPlaintext;
use runtrue_workflow_ir::ExecutionCapsule;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

const BROWSER_RUN_LOG_FRAME_LIMIT: usize = 1_000;
const BROWSER_RUN_LOG_BYTE_LIMIT: usize = 2 * 1024 * 1024;
const BROWSER_PENDING_APPROVAL_LIMIT: usize = 100;
const BROWSER_RESOLVED_APPROVAL_LIMIT: usize = 100;

struct BrowserResponse(Box<Response>);

impl BrowserResponse {
    fn into_response(self) -> Response {
        *self.0
    }
}

impl From<Response> for BrowserResponse {
    fn from(response: Response) -> Self {
        Self(Box::new(response))
    }
}

pub(in crate::app) async fn browser_decide_workflow_approval(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(approval_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "invalid approval decision form"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(token) => token,
        Err(response) => return *response,
    };
    let idempotency_key = match form_value(&body, "idempotency_key") {
        Ok(Some(value)) if !value.is_empty() => value,
        _ => return invalid_object_problem(&request_id, "invalid approval idempotency key"),
    };
    let presented_subject = match form_value(&body, "subject_digest") {
        Ok(Some(value)) if !value.is_empty() => value,
        _ => return invalid_object_problem(&request_id, "approval subject is required"),
    };
    let decision = match form_value(&body, "decision") {
        Ok(Some(value)) if value == "approve" => Decision::Approve,
        Ok(Some(value)) if value == "deny" => Decision::Deny,
        _ => return invalid_object_problem(&request_id, "invalid approval decision"),
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
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let approval = match state.store.approval_request(&approval_id).await {
        Ok(approval) => approval,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let tenant = match state.store.approval_request_tenant(&approval_id).await {
        Ok(tenant) => tenant,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let (repository_id, _) = match state.store.approval_request_binding(&approval_id).await {
        Ok(binding) => binding,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let Some(action) = browser_approval_action(approval.kind) else {
        return problem_response(
            &request_id,
            StatusCode::NOT_FOUND,
            "Approval not found",
            "this approval cannot be decided from the repository UI",
        );
    };
    if tenant != context.tenant_id || approval.subject_digest.to_string() != presented_subject {
        return problem_response(
            &request_id,
            StatusCode::NOT_FOUND,
            "Approval not found",
            "the approval was not found",
        );
    }
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        action,
        browser_approval_resource(&approval, &tenant, &repository_id),
    )
    .await
    {
        return *response;
    }
    match state
        .store
        .decide_approval_idempotent(
            &idempotency_key,
            &approval_id,
            ApprovalDecision {
                actor_id: "runtrue-workflow-approver".to_owned(),
                decision,
                reason: format!("Runtrue UI decision by principal {}", context.principal_id),
                rule_id: approval.rule.id.clone(),
                subject_digest: approval.subject_digest,
                decided_unix_ms: now,
            },
            now,
        )
        .await
    {
        Ok(result) => Json(json!({
            "id": result.value.id,
            "status": result.value.status,
            "replayed": result.replayed,
        }))
        .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

const fn browser_approval_action(kind: ApprovalKind) -> Option<CedarAction> {
    match kind {
        ApprovalKind::WorkflowDefinition => Some(CedarAction::ApproveWorkflow),
        ApprovalKind::PrivilegedExecution => Some(CedarAction::ApprovePrivilegedRun),
        ApprovalKind::EnvironmentDeployment
        | ApprovalKind::ArtifactPromotion
        | ApprovalKind::BreakGlass => None,
    }
}

fn browser_approval_resource(
    approval: &ApprovalRequest,
    tenant_id: &str,
    repository_id: &str,
) -> CedarResource {
    CedarResource {
        kind: CedarResourceKind::ApprovalRequest,
        id: approval.id.clone(),
        tenant_id: tenant_id.to_owned(),
        repository_id: Some(repository_id.to_owned()),
        author_id: None,
        risk_score: approval.risk_score,
        privileged: approval.kind == ApprovalKind::PrivilegedExecution,
        untrusted: approval.kind == ApprovalKind::WorkflowDefinition,
    }
}

async fn browser_repository(
    state: &AppState,
    request_id: &RequestId,
    context: &AuthContext,
    repository_id: &str,
) -> Result<RepositoryRecord, BrowserResponse> {
    if is_unlinked_github_repository_id(repository_id) {
        return Err(problem_response(
            request_id,
            StatusCode::CONFLICT,
            "Repository not connected",
            "this GitHub repository is not connected to Runtrue; import it before managing repository settings",
        )
        .into());
    }
    let repository = state
        .store
        .repository(repository_id)
        .await
        .map_err(|error| control_plane_problem(request_id, error))?;
    if repository.tenant_id != context.tenant_id {
        return Err(problem_response(
            request_id,
            StatusCode::NOT_FOUND,
            "Repository not found",
            "the requested repository was not found",
        )
        .into());
    }
    Ok(repository)
}

fn is_unlinked_github_repository_id(repository_id: &str) -> bool {
    repository_id
        .strip_prefix("github:")
        .is_some_and(|external_id| {
            external_id != "0"
                && !external_id.is_empty()
                && external_id.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn repository_setting_resource(
    context: &AuthContext,
    repository_id: &str,
    kind: CedarResourceKind,
    id: String,
) -> CedarResource {
    CedarResource {
        kind,
        id,
        tenant_id: context.tenant_id.clone(),
        repository_id: Some(repository_id.to_owned()),
        author_id: None,
        risk_score: 0,
        privileged: false,
        untrusted: false,
    }
}

fn organization_setting_resource(
    context: &AuthContext,
    kind: CedarResourceKind,
    id: String,
) -> CedarResource {
    CedarResource {
        kind,
        id,
        tenant_id: context.tenant_id.clone(),
        repository_id: None,
        author_id: None,
        risk_score: 0,
        privileged: false,
        untrusted: false,
    }
}

pub(in crate::app) async fn browser_organization_settings(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response.into_response(),
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
    let scope = format!("tenant:{}", context.tenant_id);
    for (action, kind) in [
        (CedarAction::ReadSecretMetadata, CedarResourceKind::Secret),
        (CedarAction::ReadVariable, CedarResourceKind::Variable),
    ] {
        if let Err(response) = authorize_browser_resource(
            &state,
            &request_id,
            &context,
            action,
            organization_setting_resource(&context, kind, scope.clone()),
        )
        .await
        {
            return *response;
        }
    }
    let secrets = match state.store.secrets(&context.tenant_id, &scope).await {
        Ok(items) => items,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let variables = match state
        .store
        .variable_records(&context.tenant_id, &scope)
        .await
    {
        Ok(items) => items,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let mut response = Json(json!({ "secrets": secrets, "variables": variables })).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    protect_sensitive_response(&mut response);
    response
}

pub(in crate::app) async fn save_browser_organization_secret(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the form body is invalid"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response.into_response(),
    };
    let (context, _, _) = match authenticated_browser_session(
        &state,
        &request_id,
        &headers,
        SCM_WRITE_SCOPE,
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let name = match form_value(&body, "name") {
        Ok(Some(value)) if !value.trim().is_empty() => value,
        _ => return invalid_object_problem(&request_id, "secret name is required"),
    };
    let value = match form_value(&body, "value") {
        Ok(Some(value)) if !value.is_empty() => value,
        _ => return invalid_object_problem(&request_id, "secret value is required"),
    };
    let idempotency_key = match form_value(&body, "idempotency_key") {
        Ok(Some(value)) => value,
        _ => return invalid_object_problem(&request_id, "idempotency key is required"),
    };
    let scope = format!("tenant:{}", context.tenant_id);
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::WriteSecret,
        organization_setting_resource(
            &context,
            CedarResourceKind::Secret,
            format!("{scope}/{name}"),
        ),
    )
    .await
    {
        return *response;
    }
    let plaintext = SecretPlaintext::new(value.into_bytes());
    let result = if state
        .store
        .secret_by_name(&context.tenant_id, &scope, &name)
        .await
        .is_ok()
    {
        state
            .store
            .rotate_secret(
                &idempotency_key,
                &context.tenant_id,
                &scope,
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
        let metadata = SecretMetadataReference {
            id,
            tenant_id: context.tenant_id.clone(),
            scope,
            name,
            provider: "built-in".to_owned(),
            provider_reference: None,
            secret_type: "opaque".to_owned(),
            status: "active".to_owned(),
            current_version: Some(1),
            created_unix_ms: now,
            updated_unix_ms: now,
        };
        state
            .store
            .create_secret(
                &idempotency_key,
                &metadata,
                Some(&plaintext),
                &state.secret_master_key,
            )
            .await
    };
    match result {
        Ok(result) => {
            let mut response = Json(result.value).into_response();
            protect_sensitive_response(&mut response);
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn delete_browser_organization_secret(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the form body is invalid"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response.into_response(),
    };
    let (context, _, _) = match authenticated_browser_session(
        &state,
        &request_id,
        &headers,
        SCM_WRITE_SCOPE,
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let name = match form_value(&body, "name") {
        Ok(Some(value)) if !value.trim().is_empty() => value,
        _ => return invalid_object_problem(&request_id, "secret name is required"),
    };
    let scope = format!("tenant:{}", context.tenant_id);
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::WriteSecret,
        organization_setting_resource(
            &context,
            CedarResourceKind::Secret,
            format!("{scope}/{name}"),
        ),
    )
    .await
    {
        return *response;
    }
    match state
        .store
        .delete_secret_configuration(
            &context.tenant_id,
            &scope,
            &name,
            &state.secret_master_key,
            now,
        )
        .await
    {
        Ok(metadata) => {
            let mut response = Json(metadata).into_response();
            protect_sensitive_response(&mut response);
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn save_browser_organization_variable(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the form body is invalid"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response.into_response(),
    };
    let (context, _, _) = match authenticated_browser_session(
        &state,
        &request_id,
        &headers,
        SCM_WRITE_SCOPE,
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let name = match form_value(&body, "name") {
        Ok(Some(value)) if !value.trim().is_empty() => value,
        _ => return invalid_object_problem(&request_id, "variable name is required"),
    };
    let value = match form_value(&body, "value") {
        Ok(Some(value)) => value,
        _ => return invalid_object_problem(&request_id, "variable value is required"),
    };
    let idempotency_key = match form_value(&body, "idempotency_key") {
        Ok(Some(value)) => value,
        _ => return invalid_object_problem(&request_id, "idempotency key is required"),
    };
    let scope = format!("tenant:{}", context.tenant_id);
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::WriteVariable,
        organization_setting_resource(
            &context,
            CedarResourceKind::Variable,
            format!("{scope}/{name}"),
        ),
    )
    .await
    {
        return *response;
    }
    match state
        .store
        .put_variable(
            &idempotency_key,
            &context.tenant_id,
            &scope,
            &name,
            Value::String(value),
            now,
        )
        .await
    {
        Ok(result) => Json(result.value).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn delete_browser_organization_variable(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the form body is invalid"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response.into_response(),
    };
    let (context, _, _) = match authenticated_browser_session(
        &state,
        &request_id,
        &headers,
        SCM_WRITE_SCOPE,
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let name = match form_value(&body, "name") {
        Ok(Some(value)) if !value.trim().is_empty() => value,
        _ => return invalid_object_problem(&request_id, "variable name is required"),
    };
    let scope = format!("tenant:{}", context.tenant_id);
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::WriteVariable,
        organization_setting_resource(
            &context,
            CedarResourceKind::Variable,
            format!("{scope}/{name}"),
        ),
    )
    .await
    {
        return *response;
    }
    match state
        .store
        .delete_variable_record(&context.tenant_id, &scope, &name)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn browser_repository_settings(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(repository_id): Path<String>,
) -> Response {
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response.into_response(),
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
    let repository = match browser_repository(&state, &request_id, &context, &repository_id).await {
        Ok(repository) => repository,
        Err(response) => return response.into_response(),
    };
    for (action, kind) in [
        (CedarAction::ReadSecretMetadata, CedarResourceKind::Secret),
        (CedarAction::ReadVariable, CedarResourceKind::Variable),
    ] {
        if let Err(response) = authorize_browser_resource(
            &state,
            &request_id,
            &context,
            action,
            repository_setting_resource(
                &context,
                &repository.id,
                kind,
                format!("repository:{}", repository.id),
            ),
        )
        .await
        {
            return *response;
        }
    }
    let scope = format!("repository:{}", repository.id);
    let secrets = match state.store.secrets(&context.tenant_id, &scope).await {
        Ok(items) => items,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let variables = match state
        .store
        .variable_records(&context.tenant_id, &scope)
        .await
    {
        Ok(items) => items,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let workflow_directory_override = match state
        .store
        .repository_workflow_directory(&context.tenant_id, &repository.id)
        .await
    {
        Ok(path) => path,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let workflow_directory_inherited = workflow_directory_override.is_none();
    let workflow_directory =
        workflow_directory_override.unwrap_or_else(|| state.scm_workflow_directory.clone());
    let mut response = Json(json!({
        "secrets": secrets,
        "variables": variables,
        "workflow_directory": workflow_directory,
        "workflow_directory_inherited": workflow_directory_inherited,
    }))
    .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    protect_sensitive_response(&mut response);
    response
}

pub(in crate::app) async fn save_browser_repository_workflow_directory(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(repository_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the form body is invalid"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
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
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let repository = match browser_repository(&state, &request_id, &context, &repository_id).await {
        Ok(repository) => repository,
        Err(response) => return response.into_response(),
    };
    let workflow_directory = match form_value(&body, "workflow_directory") {
        Ok(Some(value)) if !value.is_empty() && value.len() <= 1024 => value,
        _ => return invalid_object_problem(&request_id, "workflow directory is required"),
    };
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::EditWorkflowSettings,
        CedarResource {
            kind: CedarResourceKind::Repository,
            id: repository.id.clone(),
            tenant_id: context.tenant_id.clone(),
            repository_id: Some(repository.id.clone()),
            author_id: None,
            risk_score: 0,
            privileged: false,
            untrusted: false,
        },
    )
    .await
    {
        return *response;
    }
    match state
        .store
        .set_repository_workflow_directory(
            &context.tenant_id,
            &repository.id,
            &workflow_directory,
            now,
        )
        .await
    {
        Ok(workflow_directory) => Json(json!({
            "repository_id": repository.id,
            "workflow_directory": workflow_directory,
            "workflow_directory_inherited": false,
        }))
        .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn uninstall_browser_repository(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(repository_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the form body is invalid"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
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
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let repository = match browser_repository(&state, &request_id, &context, &repository_id).await {
        Ok(repository) => repository,
        Err(response) => return response.into_response(),
    };
    let expected_repository = format!("{}/{}", repository.owner, repository.name);
    match form_value(&body, "repository") {
        Ok(Some(value)) if value == expected_repository => {}
        _ => return invalid_object_problem(&request_id, "repository confirmation does not match"),
    }
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::EditWorkflowSettings,
        CedarResource {
            kind: CedarResourceKind::Repository,
            id: repository.id.clone(),
            tenant_id: context.tenant_id.clone(),
            repository_id: Some(repository.id.clone()),
            author_id: None,
            risk_score: 0,
            privileged: false,
            untrusted: false,
        },
    )
    .await
    {
        return *response;
    }
    match state
        .store
        .suspend_github_repository_link(
            &context.tenant_id,
            &repository.id,
            &context.principal_id,
            &request_id.0,
            now,
        )
        .await
    {
        Ok(result) => Json(json!({
            "repository_id": result.value.repository_id,
            "status": result.value.status,
            "replayed": result.replayed,
        }))
        .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn save_browser_repository_secret(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(repository_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the form body is invalid"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
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
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let repository = match browser_repository(&state, &request_id, &context, &repository_id).await {
        Ok(repository) => repository,
        Err(response) => return response.into_response(),
    };
    let name = match form_value(&body, "name") {
        Ok(Some(value)) if !value.trim().is_empty() => value,
        _ => return invalid_object_problem(&request_id, "secret name is required"),
    };
    let value = match form_value(&body, "value") {
        Ok(Some(value)) if !value.is_empty() => value,
        _ => return invalid_object_problem(&request_id, "secret value is required"),
    };
    let idempotency_key = match form_value(&body, "idempotency_key") {
        Ok(Some(value)) => value,
        _ => return invalid_object_problem(&request_id, "idempotency key is required"),
    };
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::WriteSecret,
        repository_setting_resource(
            &context,
            &repository.id,
            CedarResourceKind::Secret,
            format!("repository:{}/{}", repository.id, name),
        ),
    )
    .await
    {
        return *response;
    }
    let scope = format!("repository:{}", repository.id);
    let plaintext = SecretPlaintext::new(value.into_bytes());
    let result = if state
        .store
        .secret_by_name(&context.tenant_id, &scope, &name)
        .await
        .is_ok()
    {
        state
            .store
            .rotate_secret(
                &idempotency_key,
                &context.tenant_id,
                &scope,
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
        let metadata = SecretMetadataReference {
            id,
            tenant_id: context.tenant_id.clone(),
            scope,
            name,
            provider: "built-in".to_owned(),
            provider_reference: None,
            secret_type: "opaque".to_owned(),
            status: "active".to_owned(),
            current_version: Some(1),
            created_unix_ms: now,
            updated_unix_ms: now,
        };
        state
            .store
            .create_secret(
                &idempotency_key,
                &metadata,
                Some(&plaintext),
                &state.secret_master_key,
            )
            .await
    };
    match result {
        Ok(result) => {
            let mut response = Json(result.value).into_response();
            protect_sensitive_response(&mut response);
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn delete_browser_repository_secret(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(repository_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the form body is invalid"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
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
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let repository = match browser_repository(&state, &request_id, &context, &repository_id).await {
        Ok(repository) => repository,
        Err(response) => return response.into_response(),
    };
    let name = match form_value(&body, "name") {
        Ok(Some(value)) if !value.trim().is_empty() => value,
        _ => return invalid_object_problem(&request_id, "secret name is required"),
    };
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::WriteSecret,
        repository_setting_resource(
            &context,
            &repository.id,
            CedarResourceKind::Secret,
            format!("repository:{}/{}", repository.id, name),
        ),
    )
    .await
    {
        return *response;
    }
    let scope = format!("repository:{}", repository.id);
    match state
        .store
        .delete_secret_configuration(
            &context.tenant_id,
            &scope,
            &name,
            &state.secret_master_key,
            now,
        )
        .await
    {
        Ok(metadata) => {
            let mut response = Json(metadata).into_response();
            protect_sensitive_response(&mut response);
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn save_browser_repository_variable(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(repository_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the form body is invalid"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
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
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let repository = match browser_repository(&state, &request_id, &context, &repository_id).await {
        Ok(repository) => repository,
        Err(response) => return response.into_response(),
    };
    let name = match form_value(&body, "name") {
        Ok(Some(value)) if !value.trim().is_empty() => value,
        _ => return invalid_object_problem(&request_id, "variable name is required"),
    };
    let value = match form_value(&body, "value") {
        Ok(Some(value)) => value,
        _ => return invalid_object_problem(&request_id, "variable value is required"),
    };
    let idempotency_key = match form_value(&body, "idempotency_key") {
        Ok(Some(value)) => value,
        _ => return invalid_object_problem(&request_id, "idempotency key is required"),
    };
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::WriteVariable,
        repository_setting_resource(
            &context,
            &repository.id,
            CedarResourceKind::Variable,
            format!("repository:{}/{}", repository.id, name),
        ),
    )
    .await
    {
        return *response;
    }
    let scope = format!("repository:{}", repository.id);
    match state
        .store
        .put_variable(
            &idempotency_key,
            &context.tenant_id,
            &scope,
            &name,
            Value::String(value),
            now,
        )
        .await
    {
        Ok(result) => Json(result.value).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn delete_browser_repository_variable(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(repository_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "the form body is invalid"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
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
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let repository = match browser_repository(&state, &request_id, &context, &repository_id).await {
        Ok(repository) => repository,
        Err(response) => return response.into_response(),
    };
    let name = match form_value(&body, "name") {
        Ok(Some(value)) if !value.trim().is_empty() => value,
        _ => return invalid_object_problem(&request_id, "variable name is required"),
    };
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::WriteVariable,
        repository_setting_resource(
            &context,
            &repository.id,
            CedarResourceKind::Variable,
            format!("repository:{}/{}", repository.id, name),
        ),
    )
    .await
    {
        return *response;
    }
    let scope = format!("repository:{}", repository.id);
    match state
        .store
        .delete_variable_record(&context.tenant_id, &scope, &name)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct GitHubUiQuery {
    #[serde(default)]
    github: Option<String>,
    #[serde(default)]
    catalog: bool,
    #[serde(default)]
    organization: Option<String>,
}
pub(in crate::app) fn ui_github_permissions(value: &Value) -> Vec<UiGitHubPermission> {
    let mut permissions = Vec::new();
    let Some(values) = value.as_object() else {
        return permissions;
    };
    for (name, read, write) in [
        ("metadata", Some(UiGitHubPermission::MetadataRead), None),
        (
            "contents",
            Some(UiGitHubPermission::ContentsRead),
            Some(UiGitHubPermission::ContentsWrite),
        ),
        (
            "pull_requests",
            Some(UiGitHubPermission::PullRequestsRead),
            Some(UiGitHubPermission::PullRequestsWrite),
        ),
        ("checks", None, Some(UiGitHubPermission::ChecksWrite)),
        (
            "statuses",
            None,
            Some(UiGitHubPermission::CommitStatusesWrite),
        ),
        ("issues", None, Some(UiGitHubPermission::IssuesWrite)),
        ("actions", Some(UiGitHubPermission::ActionsRead), None),
    ] {
        let permission = match values.get(name).and_then(Value::as_str) {
            Some("read") => read,
            Some("write") => write,
            _ => None,
        };
        if let Some(permission) = permission {
            permissions.push(permission);
        }
    }
    permissions
}

pub(in crate::app) fn github_ui_alert(value: Option<&str>) -> Option<GitHubUiAlert> {
    match value {
        Some("installed") => Some(GitHubUiAlert::InstallationQueued),
        Some("linked") => Some(GitHubUiAlert::RepositoryLinked),
        Some("permissions") => Some(GitHubUiAlert::PermissionMismatch),
        Some("provider-unavailable") => Some(GitHubUiAlert::ProviderUnavailable),
        Some("rejected") => Some(GitHubUiAlert::CallbackRejected),
        _ => None,
    }
}

pub(super) enum GitHubCatalogLoad {
    Ready {
        viewer_login: String,
        catalog: GitHubUserCatalog,
    },
    ReauthenticationRequired,
    Unavailable,
}

pub(super) async fn github_catalog_for_browser_session(
    state: &AppState,
    headers: &HeaderMap,
    session: &runtrue_auth::SessionRecord,
) -> GitHubCatalogLoad {
    let Some(human) = state.human_oidc.as_ref() else {
        return GitHubCatalogLoad::Unavailable;
    };
    let Some(github) = human.github_oauth.as_ref() else {
        return GitHubCatalogLoad::Unavailable;
    };
    let credential = match github_credential_cookie(headers, human, session) {
        Ok(credential) => credential,
        Err(_) => return GitHubCatalogLoad::ReauthenticationRequired,
    };
    let permit = match Arc::clone(&human.exchange_admission).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return GitHubCatalogLoad::Unavailable,
    };
    let adapter = Arc::clone(&github.adapter);
    let viewer_login = credential.login.clone();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        adapter.authorized_catalog(&credential.access_token)
    })
    .await
    {
        Ok(Ok(catalog)) => GitHubCatalogLoad::Ready {
            viewer_login,
            catalog,
        },
        Ok(Err(HumanOidcError::ProviderApiRejected)) => GitHubCatalogLoad::ReauthenticationRequired,
        _ => GitHubCatalogLoad::Unavailable,
    }
}

async fn github_organizations_for_browser_session(
    state: &AppState,
    headers: &HeaderMap,
    session: &runtrue_auth::SessionRecord,
) -> GitHubCatalogLoad {
    let Some(human) = state.human_oidc.as_ref() else {
        return GitHubCatalogLoad::Unavailable;
    };
    let Some(github) = human.github_oauth.as_ref() else {
        return GitHubCatalogLoad::Unavailable;
    };
    let credential = match github_credential_cookie(headers, human, session) {
        Ok(credential) => credential,
        Err(_) => return GitHubCatalogLoad::ReauthenticationRequired,
    };
    let permit = match Arc::clone(&human.exchange_admission).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return GitHubCatalogLoad::Unavailable,
    };
    let adapter = Arc::clone(&github.adapter);
    let viewer_login = credential.login.clone();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        adapter.authorized_organizations(&credential.access_token)
    })
    .await
    {
        Ok(Ok(organizations)) => GitHubCatalogLoad::Ready {
            viewer_login,
            catalog: GitHubUserCatalog {
                organizations,
                repositories: Vec::new(),
            },
        },
        Ok(Err(HumanOidcError::ProviderApiRejected)) => GitHubCatalogLoad::ReauthenticationRequired,
        _ => GitHubCatalogLoad::Unavailable,
    }
}

async fn github_repositories_for_browser_session(
    state: &AppState,
    headers: &HeaderMap,
    session: &runtrue_auth::SessionRecord,
    organization: &str,
) -> GitHubCatalogLoad {
    let Some(human) = state.human_oidc.as_ref() else {
        return GitHubCatalogLoad::Unavailable;
    };
    let Some(github) = human.github_oauth.as_ref() else {
        return GitHubCatalogLoad::Unavailable;
    };
    let credential = match github_credential_cookie(headers, human, session) {
        Ok(credential) => credential,
        Err(_) => return GitHubCatalogLoad::ReauthenticationRequired,
    };
    let permit = match Arc::clone(&human.exchange_admission).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return GitHubCatalogLoad::Unavailable,
    };
    let adapter = Arc::clone(&github.adapter);
    let viewer_login = credential.login.clone();
    let selected_organization = organization.to_owned();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        adapter.authorized_repositories(
            &credential.access_token,
            &selected_organization,
            &credential.login,
        )
    })
    .await
    {
        Ok(Ok(repositories)) => GitHubCatalogLoad::Ready {
            viewer_login,
            catalog: GitHubUserCatalog {
                organizations: vec![organization.to_owned()],
                repositories,
            },
        },
        Ok(Err(HumanOidcError::ProviderApiRejected)) => GitHubCatalogLoad::ReauthenticationRequired,
        _ => GitHubCatalogLoad::Unavailable,
    }
}

fn github_catalog_initials(name: &str) -> String {
    let initials = name
        .split(|character: char| !character.is_alphanumeric())
        .filter_map(|part| part.chars().next())
        .take(2)
        .collect::<String>();
    if initials.is_empty() {
        "GH".to_owned()
    } else {
        initials.to_uppercase()
    }
}

fn github_user_organization_catalog(
    viewer_login: &str,
    catalog: &GitHubUserCatalog,
    page: &GitHubInstallationsPage,
) -> Value {
    let candidates = page
        .repository_candidates
        .iter()
        .map(|candidate| (candidate.external_repository_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let linked = page
        .repositories
        .iter()
        .filter(|repository| repository.control_plane_id.is_some())
        .map(|repository| repository.repository_id)
        .collect::<std::collections::BTreeSet<_>>();
    let active_installation_accounts = page
        .installations
        .iter()
        .filter(|installation| installation.state == UiGitHubInstallationState::Active)
        .map(|installation| installation.account_login.to_ascii_lowercase())
        .collect::<std::collections::BTreeSet<_>>();
    let mut organizations = BTreeMap::<String, (String, BTreeMap<String, Value>)>::new();
    organizations
        .entry(viewer_login.to_ascii_lowercase())
        .or_insert_with(|| (viewer_login.to_owned(), BTreeMap::new()));
    for installation in page
        .installations
        .iter()
        .filter(|installation| installation.state == UiGitHubInstallationState::Active)
    {
        organizations
            .entry(installation.account_login.to_ascii_lowercase())
            .or_insert_with(|| (installation.account_login.clone(), BTreeMap::new()));
    }
    for organization in &catalog.organizations {
        organizations
            .entry(organization.to_ascii_lowercase())
            .or_insert_with(|| (organization.clone(), BTreeMap::new()));
    }
    // The App installation is the authority for repositories that can be
    // linked. Keep those candidates visible even when an organization's OAuth
    // policy hides it from /user/orgs or /user/repos.
    for candidate in &page.repository_candidates {
        let external_id = candidate.external_repository_id.clone();
        organizations
            .entry(candidate.owner.to_ascii_lowercase())
            .or_insert_with(|| (candidate.owner.clone(), BTreeMap::new()))
            .1
            .insert(
                format!("{}:{external_id}", candidate.name),
                json!({
                    "name": candidate.name,
                    "visibility": match candidate.visibility {
                        RepositoryVisibility::Public => "Public",
                        RepositoryVisibility::Internal => "Internal",
                        RepositoryVisibility::Private => "Private",
                    },
                    "defaultBranch": candidate.default_branch,
                    "externalRepositoryId": external_id,
                    "installationId": candidate.installation_id,
                    "csrfToken": candidate.csrf_token,
                    "state": "available",
                }),
            );
    }
    for repository in &catalog.repositories {
        let external_id = repository.repository_id.to_string();
        let candidate = candidates.get(external_id.as_str()).copied();
        let state = if linked.contains(&repository.repository_id) {
            "added"
        } else if candidate.is_some() {
            "available"
        } else if active_installation_accounts.contains(&repository.owner.to_ascii_lowercase()) {
            "existing_installation"
        } else {
            "needs_installation"
        };
        organizations
            .entry(repository.owner.to_ascii_lowercase())
            .or_insert_with(|| (repository.owner.clone(), BTreeMap::new()))
            .1
            .insert(
                format!("{}:{external_id}", repository.name),
                json!({
                    "name": repository.name,
                    "visibility": match repository.visibility.as_str() {
                        "public" => "Public",
                        "internal" => "Internal",
                        _ => "Private",
                    },
                    "defaultBranch": repository.default_branch,
                    "externalRepositoryId": external_id,
                    "ownerId": repository.owner_id.to_string(),
                    "installationId": candidate.map(|value| value.installation_id.clone()),
                    "csrfToken": candidate.map(|value| value.csrf_token.clone()),
                    "state": state,
                }),
            );
    }
    Value::Array(
        organizations
            .into_iter()
            .map(|(_, (name, repositories))| {
                json!({
                    "id": name,
                    "name": name,
                    "initials": github_catalog_initials(&name),
                    "repositories": repositories.into_values().collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

pub(in crate::app) async fn github_browser_state(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<GitHubUiQuery>,
) -> Response {
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let (context, session, csrf) = match authenticated_browser_session(
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
    if let Err(response) =
        authorize_browser_tenant(&state, &request_id, &context, CedarAction::ViewRepository).await
    {
        return *response;
    }
    let status = match github_status_service(&state, &context.tenant_id).await {
        Ok(status) => status,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let tenant_name = state
        .store
        .tenant_identity(&context.tenant_id)
        .await
        .map(|tenant| tenant.name)
        .unwrap_or_else(|_| context.tenant_id.clone());
    let principal_name = state
        .store
        .human_user(&context.tenant_id, &context.principal_id)
        .await
        .map(|user| user.display_name)
        .unwrap_or_else(|_| context.principal_id.clone());
    let installation_accounts = status
        .installations
        .iter()
        .map(|installation| (installation.id.clone(), installation.account_login.clone()))
        .collect::<BTreeMap<_, _>>();
    let installations = status
        .installations
        .iter()
        .map(|installation| GitHubInstallationView {
            installation_id: installation.external_id.parse::<u64>().unwrap_or(0),
            account_login: installation.account_login.clone(),
            account_kind: match installation.account_kind {
                GitHubAccountKind::Organization => UiGitHubAccountKind::Organization,
                GitHubAccountKind::User => UiGitHubAccountKind::User,
            },
            state: match installation.status.as_str() {
                "active" => UiGitHubInstallationState::Active,
                "suspended" => UiGitHubInstallationState::Suspended,
                "revoked" => UiGitHubInstallationState::Removed,
                _ => UiGitHubInstallationState::Pending,
            },
            repository_selection: match installation.repository_selection {
                GitHubRepositorySelection::All => RepositorySelection::All,
                GitHubRepositorySelection::Selected => RepositorySelection::Selected(
                    status
                        .repositories
                        .iter()
                        .filter(|repository| {
                            repository.installation_id == installation.id
                                && repository.status == "selected"
                        })
                        .count() as u64,
                ),
            },
            permissions: ui_github_permissions(&installation.permissions),
        })
        .collect::<Vec<_>>();
    let repositories = status
        .repositories
        .iter()
        .map(|repository| GitHubRepositoryLinkView {
            repository_id: repository
                .external_repository_id
                .parse::<u64>()
                .unwrap_or(0),
            control_plane_id: repository.linked_repository_id.clone(),
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            web_origin: repository.web_origin.clone(),
            visibility: match repository.visibility.as_str() {
                "public" => RepositoryVisibility::Public,
                "internal" => RepositoryVisibility::Internal,
                _ => RepositoryVisibility::Private,
            },
            installation_account: installation_accounts
                .get(&repository.installation_id)
                .cloned()
                .unwrap_or_else(|| "Unavailable".to_owned()),
            default_branch: repository.default_branch.clone(),
            state: if repository.status != "selected" {
                RepositoryLinkState::SelectionRequired
            } else if repository.linked_repository_id.is_some() {
                RepositoryLinkState::Ready
            } else {
                RepositoryLinkState::AwaitingEvent
            },
        })
        .collect::<Vec<_>>();
    let repository_candidates = status
        .repositories
        .iter()
        .filter(|repository| {
            repository.status == "selected"
                && repository.linked_repository_id.is_none()
                && status.installations.iter().any(|installation| {
                    installation.id == repository.installation_id && installation.status == "active"
                })
        })
        .map(|repository| GitHubRepositoryCandidateAction {
            installation_id: repository.installation_id.clone(),
            external_repository_id: repository.external_repository_id.clone(),
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            visibility: match repository.visibility.as_str() {
                "public" => RepositoryVisibility::Public,
                "internal" => RepositoryVisibility::Internal,
                _ => RepositoryVisibility::Private,
            },
            default_branch: repository.default_branch.clone(),
            csrf_token: csrf.clone(),
        })
        .collect::<Vec<_>>();
    let mut events = Vec::new();
    for repository in &status.repositories {
        let Some(linked_repository_id) = repository.linked_repository_id.as_deref() else {
            continue;
        };
        let records = match state
            .store
            .scm_webhook_events_for_repository(&context.tenant_id, linked_repository_id, None, 10)
            .await
        {
            Ok(records) => records,
            Err(error) => return control_plane_problem(&request_id, error),
        };
        for event in records {
            events.push(GitHubRepositoryEventView {
                delivery_id: event.delivery_id,
                repository: repository.full_name.clone(),
                provider_event_name: event.provider_event_name,
                event_kind: event.event_kind,
                actor_login: event.actor_login,
                ref_name: event.ref_name,
                received_at: match timestamp(event.received_unix_ms) {
                    Ok(value) => value,
                    Err(()) => return internal_problem(&request_id),
                },
            });
        }
    }
    events.sort_by(|left, right| {
        right
            .received_at
            .cmp(&left.received_at)
            .then_with(|| right.delivery_id.cmp(&left.delivery_id))
    });
    events.truncate(50);
    let configured = status.configured;
    let app_ready = configured && status.webhook_configured;
    let idempotency_key = match random_id("github-install") {
        Ok(value) => value,
        Err(()) => return randomness_problem(&request_id),
    };
    let page = GitHubInstallationsPage {
        tenant_name,
        principal_name,
        session_csrf_token: csrf.clone(),
        app: GitHubAppHealth {
            app_id: status.app_id,
            app_slug: status.app_slug,
            provider_host: status
                .provider_host
                .unwrap_or_else(|| "github.com".to_owned()),
            app: if configured {
                ComponentHealth::Ready
            } else {
                ComponentHealth::Missing
            },
            signer: if configured {
                ComponentHealth::Ready
            } else {
                ComponentHealth::Missing
            },
            webhook: if status.webhook_configured {
                ComponentHealth::Ready
            } else {
                ComponentHealth::Missing
            },
            callback: if configured {
                ComponentHealth::Ready
            } else {
                ComponentHealth::Missing
            },
        },
        installations,
        repositories,
        repository_candidates,
        events,
        alert: github_ui_alert(query.github.as_deref())
            .or_else(|| (!app_ready).then_some(GitHubUiAlert::ConfigurationIncomplete)),
        install_action: app_ready.then_some(GitHubInstallAction {
            csrf_token: csrf,
            idempotency_key,
        }),
    };
    let mut payload = github_installations_payload(&page);
    if query.catalog {
        if query.organization.as_ref().is_some_and(|organization| {
            organization.is_empty()
                || organization.len() > 255
                || organization.chars().any(char::is_control)
        }) {
            return invalid_object_problem(&request_id, "invalid GitHub organization");
        }
        let catalog = match query.organization.as_deref() {
            Some(organization) => {
                github_repositories_for_browser_session(&state, &headers, &session, organization)
                    .await
            }
            None => github_organizations_for_browser_session(&state, &headers, &session).await,
        };
        match catalog {
            GitHubCatalogLoad::Ready {
                viewer_login,
                catalog,
            } => {
                payload["organizations"] =
                    github_user_organization_catalog(&viewer_login, &catalog, &page);
                payload["userCatalog"] = json!({"status": "ready"});
            }
            GitHubCatalogLoad::ReauthenticationRequired => {
                payload["userCatalog"] = json!({"status": "reauthentication_required"});
            }
            GitHubCatalogLoad::Unavailable => {
                payload["userCatalog"] = json!({"status": "unavailable"});
            }
        }
    } else {
        payload["organizations"] = json!([]);
        payload["userCatalog"] = json!({"status": "not_loaded"});
    }
    let sections = match browser_dashboard_sections(&state, &request_id, &context, &page).await {
        Ok(sections) => sections,
        Err(response) => return response.into_response(),
    };
    if let (Some(payload), Some(sections)) = (payload.as_object_mut(), sections.as_object()) {
        payload.extend(sections.clone());
    }
    let mut response = Json(payload).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static(GITHUB_BROWSER_API_CACHE_CONTROL),
    );
    protect_sensitive_response(&mut response);
    response
}

pub(in crate::app) async fn browser_run_detail(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
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
    if let Err(response) =
        authorize_browser_tenant(&state, &request_id, &context, CedarAction::ViewRun).await
    {
        return *response;
    }

    let run = match state.store.run(&run_id).await {
        Ok(run) => run,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let repository = match state.store.repository(&run.repository_id).await {
        Ok(repository) => repository,
        Err(_) => return internal_problem(&request_id),
    };
    if repository.tenant_id != context.tenant_id {
        return problem_response(
            &request_id,
            StatusCode::NOT_FOUND,
            "Run not found",
            "the requested run was not found",
        );
    }

    let jobs = match state.store.jobs_for_run(&run.id).await {
        Ok(jobs) => jobs,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let signed_capsule = match state.store.signed_capsule(&run.capsule_id).await {
        Ok(capsule) => capsule,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let capsule: ExecutionCapsule = match serde_json::from_slice(&signed_capsule.canonical_capsule)
    {
        Ok(capsule) => capsule,
        Err(_) => return internal_problem(&request_id),
    };
    let capsule_jobs = capsule
        .jobs
        .into_iter()
        .map(|job| {
            let mut steps = job
                .steps
                .into_iter()
                .map(|step| json!({"id": step.id, "name": step.name, "finalizer": false}))
                .collect::<Vec<_>>();
            steps.extend(job.finalizers.into_iter().map(|finalizer| {
                json!({
                    "id": finalizer.step.id,
                    "name": finalizer.step.name,
                    "finalizer": true,
                })
            }));
            (job.id, (job.name, steps))
        })
        .collect::<BTreeMap<_, _>>();
    let frames = match state
        .store
        .runner_logs_for_run(&run.id, BROWSER_RUN_LOG_FRAME_LIMIT + 1)
        .await
    {
        Ok(frames) => frames,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let frame_limit_reached = frames.len() > BROWSER_RUN_LOG_FRAME_LIMIT;
    let mut included_bytes = 0_usize;
    let mut byte_limit_reached = false;
    let mut lease_jobs: BTreeMap<String, String> = BTreeMap::new();
    let mut logs = Vec::new();
    for frame in frames.into_iter().take(BROWSER_RUN_LOG_FRAME_LIMIT) {
        if included_bytes.saturating_add(frame.payload.len()) > BROWSER_RUN_LOG_BYTE_LIMIT {
            byte_limit_reached = true;
            break;
        }
        included_bytes += frame.payload.len();
        let job_id = if let Some(job_id) = lease_jobs.get(&frame.execution_lease_id) {
            job_id.clone()
        } else {
            let lease = match state
                .store
                .runner_execution_lease(&frame.execution_lease_id)
                .await
            {
                Ok(lease) => lease,
                Err(error) => return control_plane_problem(&request_id, error),
            };
            lease_jobs.insert(frame.execution_lease_id.clone(), lease.job_id.clone());
            lease.job_id
        };
        logs.push(json!({
            "jobId": job_id,
            "stepId": frame.step_id,
            "attempt": frame.job_attempt,
            "stream": frame.stream,
            "sequence": frame.sequence,
            "timestamp": match timestamp(frame.wall_time_unix_ms) {
                Ok(value) => value,
                Err(()) => return internal_problem(&request_id),
            },
            "payload": String::from_utf8_lossy(&frame.payload),
            "redactionState": frame.redaction_state,
        }));
    }
    let jobs = match jobs
        .into_iter()
        .map(|job| {
            let planned = capsule_jobs.get(&job.job_key);
            let name = planned
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| job.job_key.clone());
            let steps = planned
                .map(|(_, steps)| steps.as_slice())
                .unwrap_or_default();
            Ok(json!({
                "id": job.id,
                "key": job.job_key,
                "name": name,
                "steps": steps,
                "attempt": job.attempt,
                "status": job.status,
                "requirements": job.requirements,
                "createdAt": timestamp(job.created_unix_ms).map_err(|()| internal_problem(&request_id))?,
                "completedAt": job.completed_unix_ms.map(timestamp).transpose().map_err(|()| internal_problem(&request_id))?,
            }))
        })
        .collect::<Result<Vec<_>, Response>>()
    {
        Ok(jobs) => jobs,
        Err(response) => return response,
    };
    let payload = json!({
        "jobs": jobs,
        "logs": logs,
        "logsTruncated": frame_limit_reached || byte_limit_reached,
    });
    let mut response = Json(payload).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    protect_sensitive_response(&mut response);
    response
}

pub(in crate::app) async fn browser_retry_run(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "invalid run retry form"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(token) => token,
        Err(response) => return *response,
    };
    let idempotency_key = match form_value(&body, "idempotency_key") {
        Ok(Some(value)) if !value.is_empty() => value,
        _ => return invalid_object_problem(&request_id, "invalid run retry idempotency key"),
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
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let run = match state.store.run(&run_id).await {
        Ok(run) => run,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let repository = match state.store.repository(&run.repository_id).await {
        Ok(repository) => repository,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if repository.tenant_id != context.tenant_id {
        return problem_response(
            &request_id,
            StatusCode::NOT_FOUND,
            "Run not found",
            "the requested run was not found",
        );
    }
    if !run.remote || !run.status.is_terminal() {
        return problem_response(
            &request_id,
            StatusCode::CONFLICT,
            "Run cannot be retried",
            "only completed remote runs can be retried",
        );
    }
    let signed_capsule = match state.store.signed_capsule(&run.capsule_id).await {
        Ok(capsule) => capsule,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if signed_capsule.repository_id != repository.id {
        return internal_problem(&request_id);
    }
    let capsule: ExecutionCapsule = match serde_json::from_slice(&signed_capsule.canonical_capsule)
    {
        Ok(capsule) => capsule,
        Err(_) => return internal_problem(&request_id),
    };
    let Some(mut retry_envelope) = browser_scm_event(&capsule) else {
        return problem_response(
            &request_id,
            StatusCode::CONFLICT,
            "Run cannot be retried",
            "only runs created from a verified GitHub webhook can be retried",
        );
    };
    if retry_envelope.repository.owner != repository.owner
        || retry_envelope.repository.name != repository.name
        || retry_envelope.repository.full_name
            != format!("{}/{}", repository.owner, repository.name)
    {
        return problem_response(
            &request_id,
            StatusCode::CONFLICT,
            "Run cannot be retried",
            "the original webhook repository binding does not match this run",
        );
    }
    let original_event_id = durable_scm_event_id(&retry_envelope.event_id);
    let original_event = match state.store.event(&original_event_id).await {
        Ok(event) => event,
        Err(ControlPlaneError::NotFound { .. }) => {
            return problem_response(
                &request_id,
                StatusCode::CONFLICT,
                "Run cannot be retried",
                "the original verified webhook event is no longer available",
            )
        }
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let original_payload = match serde_json::to_value(&retry_envelope) {
        Ok(payload) => runtrue_workflow_ir::canonicalize_value(payload),
        Err(_) => return internal_problem(&request_id),
    };
    let original_payload_digest = match serde_json::to_vec(&original_payload) {
        Ok(payload) => ContentDigest::sha256(payload),
        Err(_) => return internal_problem(&request_id),
    };
    if original_event.tenant_id != context.tenant_id
        || original_event.handler_kind != "scm.event"
        || original_event.idempotency_identity != retry_envelope.event_id
        || original_event.payload != original_payload
        || original_event.payload_digest != original_payload_digest
    {
        return problem_response(
            &request_id,
            StatusCode::CONFLICT,
            "Run cannot be retried",
            "the original webhook event does not match the signed run context",
        );
    }
    if let Err(response) = authorize_browser_resource(
        &state,
        &request_id,
        &context,
        CedarAction::ReplayEvent,
        browser_event_resource(&context, &original_event.id, &repository.id),
    )
    .await
    {
        return *response;
    }

    let retry_identity = ContentDigest::sha256(
        format!(
            "runtrue.browser.run.retry.v1\0{}\0{}\0{}\0{}\0{}",
            context.tenant_id, run.id, original_event.id, context.principal_id, idempotency_key,
        )
        .as_bytes(),
    );
    let retry_suffix = retry_identity.as_str().trim_start_matches("sha256:");
    retry_envelope.event_id = format!("retry-{retry_suffix}");
    retry_envelope.received_unix_ms = now;
    retry_envelope.normalized_digest = match retry_envelope.canonical_normalized_bytes() {
        Ok(bytes) => ContentDigest::sha256(bytes),
        Err(_) => return internal_problem(&request_id),
    };
    if retry_envelope.verify(Default::default()).is_err() {
        return internal_problem(&request_id);
    }
    let retry_payload = match serde_json::to_value(&retry_envelope) {
        Ok(payload) => runtrue_workflow_ir::canonicalize_value(payload),
        Err(_) => return internal_problem(&request_id),
    };
    let retry_payload_digest = match serde_json::to_vec(&retry_payload) {
        Ok(payload) => ContentDigest::sha256(payload),
        Err(_) => return internal_problem(&request_id),
    };
    let event_id = durable_scm_event_id(&retry_envelope.event_id);
    let event_digest = ContentDigest::sha256(retry_envelope.event_id.as_bytes());
    let task_id = format!(
        "scm-github-{}",
        event_digest.as_str().trim_start_matches("sha256:")
    );
    let retry_event = DurableEventRecord {
        id: event_id,
        tenant_id: context.tenant_id.clone(),
        source: DurableEventSource::Frontend,
        kind: format!("{}.retry", original_event.kind),
        handler_kind: "scm.event".to_owned(),
        payload: retry_payload,
        payload_digest: retry_payload_digest,
        idempotency_identity: retry_envelope.event_id.clone(),
        actor_identity: context.principal_id.clone(),
        task_id,
        created_unix_ms: now,
    };
    let (queued, replayed) = match state.store.record_event(&retry_event).await {
        Ok(result) => (result.value, result.replayed),
        Err(ControlPlaneError::IdempotencyConflict) => {
            let existing = match state.store.event(&retry_event.id).await {
                Ok(existing) => existing,
                Err(error) => return control_plane_problem(&request_id, error),
            };
            if !equivalent_browser_retry(&existing, &retry_event, &retry_envelope) {
                return problem_response(
                    &request_id,
                    StatusCode::CONFLICT,
                    "Run retry conflict",
                    "the retry idempotency key was already used for different event data",
                );
            }
            (existing, true)
        }
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let mut response = (
        StatusCode::ACCEPTED,
        Json(json!({
            "eventId": queued.id,
            "taskId": queued.task_id,
            "retryOf": run.id,
            "replayed": replayed,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    protect_sensitive_response(&mut response);
    response
}

async fn browser_dashboard_sections(
    state: &AppState,
    request_id: &RequestId,
    context: &AuthContext,
    page: &GitHubInstallationsPage,
) -> Result<Value, BrowserResponse> {
    let can_view_runs = authorize_browser_tenant(state, request_id, context, CedarAction::ViewRun)
        .await
        .is_ok();
    let can_retry_runs =
        authorize_browser_tenant(state, request_id, context, CedarAction::ReplayEvent)
            .await
            .is_ok();
    let can_view_approvals =
        authorize_browser_tenant(state, request_id, context, CedarAction::ApproveWorkflow)
            .await
            .is_ok()
            || authorize_browser_tenant(
                state,
                request_id,
                context,
                CedarAction::ApprovePrivilegedRun,
            )
            .await
            .is_ok();
    let can_view_runners =
        authorize_browser_tenant(state, request_id, context, CedarAction::ManageRunnerPool)
            .await
            .is_ok();
    let can_view_tokens =
        authorize_browser_tenant(state, request_id, context, CedarAction::ManageApiToken)
            .await
            .is_ok();
    let can_view_audit =
        authorize_browser_tenant(state, request_id, context, CedarAction::ReadAudit)
            .await
            .is_ok();
    let can_manage_identity =
        authorize_browser_tenant(state, request_id, context, CedarAction::ManageUser)
            .await
            .is_ok()
            && authorize_browser_tenant(state, request_id, context, CedarAction::ManageTeam)
                .await
                .is_ok();

    let repository_names = page
        .repositories
        .iter()
        .filter_map(|repository| {
            repository.control_plane_id.as_ref().map(|id| {
                (
                    id.clone(),
                    format!("{}/{}", repository.owner, repository.name),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    let repository_urls = page
        .repositories
        .iter()
        .filter_map(|repository| {
            repository
                .control_plane_id
                .as_ref()
                .map(|id| (id.clone(), repository_url(repository)))
        })
        .collect::<BTreeMap<_, _>>();

    let runs = if can_view_runs {
        let records = state
            .store
            .list_runs_page_for_tenant(&context.tenant_id, None, None, 100)
            .await
            .map_err(|error| control_plane_problem(request_id, error))?;
        let mut browser_runs = Vec::with_capacity(records.len());
        for record in records {
            let signed_capsule = state
                .store
                .signed_capsule(&record.capsule_id)
                .await
                .map_err(|error| control_plane_problem(request_id, error))?;
            let capsule: ExecutionCapsule =
                serde_json::from_slice(&signed_capsule.canonical_capsule)
                    .map_err(|_| internal_problem(request_id))?;
            let source = browser_run_source(
                &capsule,
                repository_urls
                    .get(&record.repository_id)
                    .map(String::as_str),
            );
            let can_retry = can_retry_runs
                && record.remote
                && record.status.is_terminal()
                && browser_scm_event(&capsule).is_some();
            browser_runs.push(json!({
                "id": record.id,
                "repositoryId": record.repository_id,
                "repository": repository_names
                    .get(&record.repository_id)
                    .cloned()
                    .unwrap_or_else(|| record.repository_id.clone()),
                "repositoryUrl": repository_urls.get(&record.repository_id),
                "planId": record.capsule_id,
                "status": record.status,
                "priority": record.priority,
                "remote": record.remote,
                "createdAt": timestamp(record.created_unix_ms).map_err(|()| internal_problem(request_id))?,
                "startedAt": record.started_unix_ms.map(timestamp).transpose().map_err(|()| internal_problem(request_id))?,
                "completedAt": record.completed_unix_ms.map(timestamp).transpose().map_err(|()| internal_problem(request_id))?,
                "cancelReason": record.cancel_reason,
                "canRetry": can_retry,
                "source": source,
            }));
        }
        Some(browser_runs)
    } else {
        None
    };

    let approvals = if can_view_approvals {
        let mut records = state
            .store
            .list_approval_requests_page_for_tenant(
                &context.tenant_id,
                Some("pending"),
                None,
                BROWSER_PENDING_APPROVAL_LIMIT,
            )
            .await
            .map_err(|error| control_plane_problem(request_id, error))?;
        let recent = state
            .store
            .list_approval_requests_page_for_tenant(
                &context.tenant_id,
                None,
                None,
                BROWSER_RESOLVED_APPROVAL_LIMIT,
            )
            .await
            .map_err(|error| control_plane_problem(request_id, error))?;
        records.extend(
            recent
                .into_iter()
                .filter(|candidate| candidate.status != runtrue_policy::ApprovalStatus::Pending),
        );
        let mut views = Vec::with_capacity(records.len());
        for record in records {
            match browser_approval_view(state, request_id, context, &repository_names, record).await
            {
                Ok(Some(view)) => views.push(view),
                Ok(None) => {}
                // Approval history can outlive the Capsule schema that
                // produced it. A single legacy or otherwise unreadable
                // record must not make the whole authenticated dashboard
                // unavailable.
                Err(_) => {}
            }
        }
        Some(views)
    } else {
        None
    };

    let runners = if can_view_runners {
        let pools = state
            .store
            .runner_pools_for_tenant(&context.tenant_id)
            .await
            .map_err(|error| control_plane_problem(request_id, error))?;
        let pool_names = pools
            .iter()
            .map(|pool| (pool.id.clone(), pool.name.clone()))
            .collect::<BTreeMap<_, _>>();
        let records = state
            .store
            .pool_runners_for_tenant(&context.tenant_id)
            .await
            .map_err(|error| control_plane_problem(request_id, error))?;
        let items = records
            .into_iter()
            .map(|record| {
                let runner = record.runner;
                Ok(json!({
                    "id": runner.id,
                    "poolId": runner.pool_id,
                    "pool": pool_names.get(&runner.pool_id).cloned().unwrap_or_else(|| runner.pool_id.clone()),
                    "ephemeral": runner.ephemeral,
                    "status": runner.status,
                    "os": runner.os,
                    "arch": runner.arch,
                    "isolation": runner.isolation_backends,
                    "logicalCpus": runner.logical_cpus,
                    "memoryBytes": runner.memory_bytes,
                    "activeJobs": runner.active_jobs,
                    "region": runner.region,
                    "lastHeartbeatAt": timestamp(runner.last_heartbeat_unix_ms).map_err(|()| internal_problem(request_id))?,
                    "createdAt": timestamp(record.created_unix_ms).map_err(|()| internal_problem(request_id))?,
                    "updatedAt": timestamp(record.updated_unix_ms).map_err(|()| internal_problem(request_id))?,
                }))
            })
            .collect::<Result<Vec<_>, Response>>()?;
        Some(json!({"items": items, "pools": pools}))
    } else {
        None
    };

    let api_tokens = if can_view_tokens {
        let records = state
            .store
            .tokens_page(&context.tenant_id, None, 100)
            .await
            .map_err(|error| control_plane_problem(request_id, error))?;
        Some(
            records
                .into_iter()
                .map(|record| {
                    Ok(json!({
                        "id": record.id,
                        "principalId": record.principal_id,
                        "name": record.name,
                        "scopes": record.scopes,
                        "createdAt": timestamp(record.created_unix_ms).map_err(|()| internal_problem(request_id))?,
                        "expiresAt": timestamp(record.expires_unix_ms).map_err(|()| internal_problem(request_id))?,
                        "lastUsedAt": record.last_used_unix_ms.map(timestamp).transpose().map_err(|()| internal_problem(request_id))?,
                        "revokedAt": record.revoked_unix_ms.map(timestamp).transpose().map_err(|()| internal_problem(request_id))?,
                    }))
                })
                .collect::<Result<Vec<_>, Response>>()?,
        )
    } else {
        None
    };

    let audit = if can_view_audit {
        let records = state
            .store
            .events_page_for_tenant(&context.tenant_id, None, None, 100)
            .await
            .map_err(|error| control_plane_problem(request_id, error))?;
        Some(
            records
                .into_iter()
                .map(|event| {
                    Ok(json!({
                        "sequence": event.sequence,
                        "observedAt": timestamp(event.data.observed_unix_ms).map_err(|()| internal_problem(request_id))?,
                        "actor": event.data.actor,
                        "action": event.data.action,
                        "resource": event.data.resource,
                        "result": event.data.result,
                        "requestId": event.data.request_id,
                        "decisionId": event.data.decision_id,
                        "metadata": event.data.metadata,
                        "eventHash": event.event_hash.to_string(),
                    }))
                })
                .collect::<Result<Vec<_>, Response>>()?,
        )
    } else {
        None
    };

    Ok(json!({
        "capabilities": {
            "runs": can_view_runs,
            "approvals": can_view_approvals,
            "runners": can_view_runners,
            "apiTokens": can_view_tokens,
            "audit": can_view_audit,
            "identity": can_manage_identity,
        },
        "runs": runs,
        "approvals": approvals,
        "runners": runners,
        "apiTokens": api_tokens,
        "audit": audit,
    }))
}

async fn browser_approval_view(
    state: &AppState,
    request_id: &RequestId,
    context: &AuthContext,
    repository_names: &BTreeMap<String, String>,
    record: ApprovalRequest,
) -> Result<Option<Value>, Response> {
    let Some(action) = browser_approval_action(record.kind) else {
        return Ok(None);
    };
    let (repository_id, capsule_id) = state
        .store
        .approval_request_binding(&record.id)
        .await
        .map_err(|error| control_plane_problem(request_id, error))?;
    let resource = browser_approval_resource(&record, &context.tenant_id, &repository_id);
    if authorize_browser_resource(state, request_id, context, action, resource)
        .await
        .is_err()
    {
        return Ok(None);
    }
    let signed_capsule = state
        .store
        .signed_capsule(&capsule_id)
        .await
        .map_err(|error| control_plane_problem(request_id, error))?;
    if signed_capsule.repository_id != repository_id {
        return Err(internal_problem(request_id));
    }
    let capsule: ExecutionCapsule = serde_json::from_slice(&signed_capsule.canonical_capsule)
        .map_err(|_| internal_problem(request_id))?;
    let event = capsule
        .context
        .normalized_event_json
        .as_deref()
        .and_then(|encoded| serde_json::from_str::<Value>(encoded).ok())
        .unwrap_or(Value::Null);
    let event_string = |pointer: &str| {
        event
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let event_number = |pointer: &str| event.pointer(pointer).and_then(Value::as_u64);
    let approved_decisions = record
        .decisions
        .values()
        .filter(|decision| decision.decision == Decision::Approve)
        .count();
    let remaining_approvals =
        usize::from(record.rule.required_approvals).saturating_sub(approved_decisions);
    let decisions = record
        .decisions
        .values()
        .map(|decision| {
            Ok(json!({
                "actor": decision.actor_id,
                "decision": decision.decision,
                "reason": decision.reason,
                "decidedAt": timestamp(decision.decided_unix_ms)
                    .map_err(|()| internal_problem(request_id))?,
            }))
        })
        .collect::<Result<Vec<_>, Response>>()?;
    let repository = match repository_names.get(&repository_id) {
        Some(repository) => repository.clone(),
        None => {
            let repository = state
                .store
                .repository(&repository_id)
                .await
                .map_err(|error| control_plane_problem(request_id, error))?;
            if repository.tenant_id != context.tenant_id {
                return Err(internal_problem(request_id));
            }
            format!("{}/{}", repository.owner, repository.name)
        }
    };
    let waiting_events = state
        .store
        .approval_pending_execution_events(&record.id)
        .await
        .map_err(|error| control_plane_problem(request_id, error))?;
    let waiting_pull_requests = waiting_events
        .iter()
        .filter_map(|event| {
            event
                .pointer("/pull_request/number")
                .and_then(Value::as_u64)
                .or_else(|| {
                    event
                        .pointer("/issue_comment/issue_number")
                        .and_then(Value::as_u64)
                })
        })
        .collect::<BTreeSet<_>>();
    Ok(Some(json!({
        "id": record.id,
        "kind": record.kind,
        "repositoryId": repository_id,
        "repository": repository,
        "capsuleId": capsule_id,
        "subjectDigest": record.subject_digest.to_string(),
        "status": record.status,
        "riskScore": record.risk_score,
        "ruleId": record.rule.id,
        "oneShot": record.rule.one_shot,
        "requiredApprovals": record.rule.required_approvals,
        "decisionCount": record.decisions.len(),
        "remainingApprovals": remaining_approvals,
        "waitingExecutions": state.store.approval_pending_execution_count(&record.id).await
            .map_err(|error| control_plane_problem(request_id, error))?,
        "waitingPullRequests": waiting_pull_requests,
        "decisions": decisions,
        "createdAt": timestamp(record.created_unix_ms).map_err(|()| internal_problem(request_id))?,
        "expiresAt": timestamp(record.expires_unix_ms).map_err(|()| internal_problem(request_id))?,
        "workflow": {
            "name": capsule.workflow.name,
            "path": capsule.workflow.source_path,
        },
        "source": {
            "commit": capsule.context.source_commit,
            "baseCommit": capsule.context.base_commit,
            "ref": event_string("/source/ref_name"),
            "event": event_string("/event_type/kind"),
            "action": event_string("/event_type/action"),
            "pullRequest": event_number("/pull_request/number")
                .or_else(|| event_number("/issue_comment/issue_number")),
        },
        "reasons": capsule.approval.reasons,
        "permissions": capsule.permissions,
        "jobs": capsule.jobs.into_iter().map(|job| json!({
            "id": job.id,
            "name": job.name,
        })).collect::<Vec<_>>(),
        "canDecide": true,
    })))
}

fn browser_run_source(capsule: &ExecutionCapsule, repository_url: Option<&str>) -> Value {
    let event = capsule
        .context
        .normalized_event_json
        .as_deref()
        .and_then(|value| serde_json::from_str::<Value>(value).ok());
    let event_kind = event
        .as_ref()
        .and_then(|value| value.pointer("/event_type/kind"))
        .or_else(|| event.as_ref().and_then(|value| value.get("trigger_kind")))
        .and_then(Value::as_str)
        .unwrap_or("manual");
    let event_action = event
        .as_ref()
        .and_then(|value| value.pointer("/event_type/action"))
        .and_then(Value::as_str);
    let actor = event
        .as_ref()
        .and_then(|value| value.pointer("/actor/login"))
        .or_else(|| event.as_ref().and_then(|value| value.get("actor_id")))
        .and_then(Value::as_str);
    let ref_name = event
        .as_ref()
        .and_then(|value| value.get("ref_name"))
        .or_else(|| {
            event
                .as_ref()
                .and_then(|value| value.pointer("/source/ref_name"))
        })
        .and_then(Value::as_str);
    let pull_request_number = event
        .as_ref()
        .and_then(|value| value.pointer("/pull_request/number"))
        .and_then(Value::as_u64);
    let source_url = repository_url.map(|url| {
        if let Some(number) = pull_request_number {
            format!("{}/pull/{number}", url.trim_end_matches('/'))
        } else if capsule.context.source_commit.len() >= 7
            && capsule
                .context
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            format!(
                "{}/commit/{}",
                url.trim_end_matches('/'),
                capsule.context.source_commit
            )
        } else {
            url.to_owned()
        }
    });

    json!({
        "workflowName": capsule.workflow.name,
        "workflowPath": capsule.workflow.source_path,
        "eventKind": event_kind,
        "eventAction": event_action,
        "actor": actor,
        "refName": ref_name,
        "commitSha": capsule.context.source_commit,
        "pullRequestNumber": pull_request_number,
        "url": source_url,
        "jobCount": capsule.jobs.len(),
    })
}

fn browser_scm_event(capsule: &ExecutionCapsule) -> Option<EventEnvelope> {
    let event =
        serde_json::from_str::<EventEnvelope>(capsule.context.normalized_event_json.as_deref()?)
            .ok()?;
    if event.provider != ProviderKind::GitHub {
        return None;
    }
    event.verify(Default::default()).ok()?;
    if event.normalized_digest != capsule.context.normalized_event_digest {
        return None;
    }
    Some(event)
}

fn durable_scm_event_id(provider_event_id: &str) -> String {
    let digest = ContentDigest::sha256(provider_event_id.as_bytes());
    format!(
        "event-scm-github-{}",
        digest.as_str().trim_start_matches("sha256:")
    )
}

fn browser_event_resource(
    context: &AuthContext,
    event_id: &str,
    repository_id: &str,
) -> CedarResource {
    CedarResource {
        kind: CedarResourceKind::Event,
        id: event_id.to_owned(),
        tenant_id: context.tenant_id.clone(),
        repository_id: Some(repository_id.to_owned()),
        author_id: None,
        risk_score: 0,
        privileged: false,
        untrusted: false,
    }
}

fn equivalent_browser_retry(
    existing: &DurableEventRecord,
    requested: &DurableEventRecord,
    requested_envelope: &EventEnvelope,
) -> bool {
    if existing.id != requested.id
        || existing.tenant_id != requested.tenant_id
        || existing.source != requested.source
        || existing.kind != requested.kind
        || existing.handler_kind != requested.handler_kind
        || existing.idempotency_identity != requested.idempotency_identity
        || existing.actor_identity != requested.actor_identity
        || existing.task_id != requested.task_id
    {
        return false;
    }
    let Ok(existing_envelope) = serde_json::from_value::<EventEnvelope>(existing.payload.clone())
    else {
        return false;
    };
    if existing_envelope.verify(Default::default()).is_err() {
        return false;
    }
    let mut expected = requested_envelope.clone();
    expected.received_unix_ms = existing_envelope.received_unix_ms;
    let Ok(normalized) = expected.canonical_normalized_bytes() else {
        return false;
    };
    expected.normalized_digest = ContentDigest::sha256(normalized);
    if existing_envelope != expected {
        return false;
    }
    serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(
        existing.payload.clone(),
    ))
    .is_ok_and(|payload| ContentDigest::sha256(payload) == existing.payload_digest)
}

pub(in crate::app) async fn start_github_installation_from_ui(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "invalid GitHub setup form"),
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(token) => token,
        Err(response) => return *response,
    };
    let idempotency_key = match form_value(&body, "idempotency_key") {
        Ok(Some(value)) if !value.is_empty() => value,
        _ => return invalid_object_problem(&request_id, "invalid GitHub setup idempotency key"),
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let (context, session, _) = match authenticated_browser_session(
        &state,
        &request_id,
        &headers,
        SCM_WRITE_SCOPE,
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = authorize_browser_tenant(
        &state,
        &request_id,
        &context,
        CedarAction::EditWorkflowSettings,
    )
    .await
    {
        return *response;
    }
    let repository_ids = match form_value(&body, "repository_ids") {
        Ok(Some(value)) => {
            let parsed = value
                .split(',')
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>();
            match parsed {
                Ok(repository_ids)
                    if !repository_ids.is_empty()
                        && repository_ids.len() <= 100
                        && repository_ids
                            .iter()
                            .all(|repository_id| *repository_id != 0)
                        && repository_ids
                            .iter()
                            .copied()
                            .collect::<std::collections::BTreeSet<_>>()
                            .len()
                            == repository_ids.len() =>
                {
                    repository_ids
                }
                _ => {
                    return invalid_object_problem(
                        &request_id,
                        "invalid GitHub repository selection",
                    )
                }
            }
        }
        Ok(None) => Vec::new(),
        Err(()) => {
            return invalid_object_problem(&request_id, "invalid GitHub repository selection")
        }
    };
    let repository_preselection = if repository_ids.is_empty() {
        None
    } else {
        let catalog = match github_catalog_for_browser_session(&state, &headers, &session).await {
            GitHubCatalogLoad::Ready { catalog, .. } => catalog,
            GitHubCatalogLoad::ReauthenticationRequired | GitHubCatalogLoad::Unavailable => {
                return problem_response(
                    &request_id,
                    StatusCode::CONFLICT,
                    "GitHub access must be refreshed",
                    "refresh GitHub access before installing the App on selected repositories",
                )
            }
        };
        let repositories = catalog
            .repositories
            .iter()
            .map(|repository| (repository.repository_id, repository))
            .collect::<BTreeMap<_, _>>();
        let selected = repository_ids
            .iter()
            .filter_map(|repository_id| repositories.get(repository_id).copied())
            .collect::<Vec<_>>();
        let target_ids = selected
            .iter()
            .map(|repository| repository.owner_id)
            .collect::<std::collections::BTreeSet<_>>();
        if selected.len() != repository_ids.len() || target_ids.len() != 1 {
            return invalid_object_problem(
                &request_id,
                "selected repositories must be visible and belong to one GitHub account",
            );
        }
        let owner = selected[0].owner.clone();
        let existing_installations = match state
            .store
            .github_installations_for_tenant(&context.tenant_id, None, 100)
            .await
        {
            Ok(installations) => installations,
            Err(error) => return control_plane_problem(&request_id, error),
        };
        if let Some(existing) = existing_installations.into_iter().find(|installation| {
            installation.installation.status == "active"
                && installation.account_login.eq_ignore_ascii_case(&owner)
        }) {
            let external_installation_id = match existing.installation.external_id.parse::<u64>() {
                Ok(id) if id != 0 => id,
                _ => return internal_problem(&request_id),
            };
            let snapshot = match inspect_github_installation(
                &state,
                &request_id,
                external_installation_id,
                now,
            )
            .await
            {
                Ok(snapshot) => snapshot,
                Err(response) => return response,
            };
            let granted = snapshot
                .repositories
                .iter()
                .filter(|repository| !repository.disabled)
                .map(|repository| repository.id)
                .collect::<std::collections::BTreeSet<_>>();
            if snapshot.repository_catalog_complete
                && repository_ids
                    .iter()
                    .all(|repository_id| granted.contains(repository_id))
            {
                let reconciliation = match github_reconciliation_from_snapshot(
                    &state,
                    &context.tenant_id,
                    snapshot,
                    now,
                )
                .await
                {
                    Ok(reconciliation) => reconciliation,
                    Err(error) => return control_plane_problem(&request_id, error),
                };
                if let Err(error) = state
                    .store
                    .reconcile_github_installation(&reconciliation)
                    .await
                {
                    return control_plane_problem(&request_id, error);
                }
                for selected in reconciliation
                    .selected_repositories
                    .iter()
                    .filter(|repository| {
                        repository
                            .external_repository_id
                            .parse::<u64>()
                            .ok()
                            .is_some_and(|id| repository_ids.contains(&id))
                    })
                {
                    let external_repository_id = selected.external_repository_id.clone();
                    let repository = RepositoryRecord {
                        id: github_repository_internal_id(
                            external_repository_id.parse().unwrap_or_default(),
                        ),
                        tenant_id: context.tenant_id.clone(),
                        owner: selected.owner.clone(),
                        name: selected.name.clone(),
                        default_branch: selected.default_branch.clone(),
                        visibility: selected.visibility.clone(),
                        created_unix_ms: now,
                    };
                    if let Err(error) = state
                        .store
                        .link_selected_github_repository(&LinkSelectedGitHubRepository {
                            tenant_id: context.tenant_id.clone(),
                            installation_id: reconciliation.installation.installation.id.clone(),
                            external_repository_id,
                            repository,
                            now_unix_ms: now,
                        })
                        .await
                    {
                        return control_plane_problem(&request_id, error);
                    }
                }
                let mut response = StatusCode::SEE_OTHER.into_response();
                response
                    .headers_mut()
                    .insert(LOCATION, HeaderValue::from_static("/?github=linked"));
                protect_sensitive_response(&mut response);
                return response;
            }
        }
        Some((
            *target_ids.iter().next().unwrap_or(&0),
            repository_ids.as_slice(),
        ))
    };
    let setup = match start_github_setup_service(
        &state,
        &request_id,
        GitHubSetupRequest {
            tenant_id: &context.tenant_id,
            principal_id: &context.principal_id,
            idempotency_key: &idempotency_key,
            return_path: "/?github=installed",
            now_unix_ms: now,
            repository_preselection,
        },
    )
    .await
    {
        Ok(setup) => setup,
        Err(response) => return response,
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    let location = match HeaderValue::from_str(&setup.install_url) {
        Ok(location) => location,
        Err(_) => return internal_problem(&request_id),
    };
    response.headers_mut().insert(LOCATION, location);
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    protect_sensitive_response(&mut response);
    response
}

pub(in crate::app) async fn link_github_repository_from_ui(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "invalid repository form"),
    };
    let csrf = match browser_csrf_input(&request_id, &headers, Ok(body.clone())) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let installation_id = match form_value(&body, "installation_id") {
        Ok(Some(value)) if !value.is_empty() => value,
        _ => return invalid_object_problem(&request_id, "invalid installation"),
    };
    let external_repository_id = match form_value(&body, "external_repository_id") {
        Ok(Some(value)) if value.parse::<u64>().ok().is_some_and(|id| id > 0) => value,
        _ => return invalid_object_problem(&request_id, "invalid repository"),
    };
    let now = match now_unix_ms(&request_id) {
        Ok(value) => value,
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
        Ok(value) => value,
        Err(response) => return *response,
    };
    if let Err(response) = authorize_browser_tenant(
        &state,
        &request_id,
        &context,
        CedarAction::EditWorkflowSettings,
    )
    .await
    {
        return *response;
    }
    let _installation = match state
        .store
        .github_installation_for_tenant(&context.tenant_id, &installation_id)
        .await
    {
        Ok(value) if value.installation.status == "active" => value,
        _ => {
            return problem_response(
                &request_id,
                StatusCode::CONFLICT,
                "Installation unavailable",
                "the selected installation is not active",
            )
        }
    };
    let mut catalog = Vec::new();
    let mut cursor = None;
    for _ in 0..10 {
        let page = match state
            .store
            .github_repository_catalog_for_tenant(
                &context.tenant_id,
                &installation_id,
                false,
                cursor.as_deref(),
                100,
            )
            .await
        {
            Ok(value) => value,
            Err(error) => return control_plane_problem(&request_id, error),
        };
        if page.is_empty() {
            break;
        }
        cursor = page
            .last()
            .map(|repository| repository.external_repository_id.clone());
        let full = page.len() == 100;
        catalog.extend(page);
        if !full {
            break;
        }
    }
    let Some(selected) = catalog.into_iter().find(|repository| {
        repository.external_repository_id == external_repository_id
            && repository.status == "selected"
    }) else {
        return problem_response(
            &request_id,
            StatusCode::NOT_FOUND,
            "Repository unavailable",
            "the selected repository was not found in this installation",
        );
    };
    let repository = RepositoryRecord {
        id: github_repository_internal_id(external_repository_id.parse().unwrap_or_default()),
        tenant_id: context.tenant_id.clone(),
        owner: selected.owner,
        name: selected.name,
        default_branch: selected.default_branch,
        visibility: selected.visibility,
        created_unix_ms: now,
    };
    match state
        .store
        .link_selected_github_repository(&LinkSelectedGitHubRepository {
            tenant_id: context.tenant_id,
            installation_id: installation_id.clone(),
            external_repository_id,
            repository,
            now_unix_ms: now,
        })
        .await
    {
        Ok(_) => {
            let mut response = StatusCode::SEE_OTHER.into_response();
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_static("/?github=linked"));
            protect_sensitive_response(&mut response);
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

use super::installations::{
    github_reconciliation_from_snapshot, github_repository_internal_id, github_status_service,
    inspect_github_installation,
};
use axum::response::IntoResponse as _;

#[cfg(test)]
mod user_catalog_tests {
    use super::*;
    use crate::human_oidc::GitHubUserRepository;
    use runtrue_model::ContentDigest;
    use runtrue_workflow_ir::{
        ApprovalRequirements, CapsuleContext, ParityGrade, PermissionSet, SourceTrust,
        WorkflowIdentity, CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
    };

    #[test]
    fn run_source_links_to_the_originating_pull_request() {
        let capsule = ExecutionCapsule {
            schema_version: CAPSULE_SCHEMA_VERSION,
            engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
            compiler_version: "test".to_owned(),
            workflow: WorkflowIdentity {
                name: "CI".to_owned(),
                digest: ContentDigest::sha256(b"workflow"),
                source_path: ".runtrue/workflows/ci.yaml".to_owned(),
            },
            context: CapsuleContext {
                source_commit: "a".repeat(40),
                source_tree_digest: None,
                base_commit: Some("b".repeat(40)),
                source_trust: SourceTrust::Trusted,
                normalized_event_digest: ContentDigest::sha256(b"event"),
                normalized_event_json: Some(
                    json!({
                        "event_type": {"kind": "pull_request", "action": "synchronize"},
                        "actor": {"login": "ada"},
                        "ref_name": "refs/heads/feature",
                        "pull_request": {"number": 42}
                    })
                    .to_string(),
                ),
                scm: None,
                event_context: BTreeMap::new(),
                lockfile_digest: None,
                workflow_frontend: None,
                policy_version_ids: Vec::new(),
            },
            variables: BTreeMap::new(),
            permissions: PermissionSet::default(),
            jobs: Vec::new(),
            dynamic_jobs: Vec::new(),
            approval: ApprovalRequirements {
                workflow_definition: false,
                privileged_execution: false,
                reasons: Vec::new(),
            },
            expected_parity: ParityGrade::AExact,
        };

        let source = browser_run_source(&capsule, Some("https://github.example/octo/repo"));
        assert_eq!(source["workflowName"], "CI");
        assert_eq!(source["eventKind"], "pull_request");
        assert_eq!(source["actor"], "ada");
        assert_eq!(source["pullRequestNumber"], 42);
        assert_eq!(source["url"], "https://github.example/octo/repo/pull/42");
    }

    #[test]
    fn recognizes_only_well_formed_unlinked_github_placeholders() {
        assert!(is_unlinked_github_repository_id("github:2078151"));
        assert!(!is_unlinked_github_repository_id("github:"));
        assert!(!is_unlinked_github_repository_id("github:0"));
        assert!(!is_unlinked_github_repository_id("github:repo-1"));
        assert!(!is_unlinked_github_repository_id(
            "github-repository-2078151"
        ));
    }

    #[test]
    fn signed_in_user_catalog_marks_installation_and_link_state() {
        let page = GitHubInstallationsPage {
            tenant_name: "Forge".to_owned(),
            principal_name: "Ada".to_owned(),
            session_csrf_token: "session-csrf".to_owned(),
            app: GitHubAppHealth {
                app_id: Some(42),
                app_slug: Some("runtrue-ci".to_owned()),
                provider_host: "github.example".to_owned(),
                app: ComponentHealth::Ready,
                signer: ComponentHealth::Ready,
                webhook: ComponentHealth::Ready,
                callback: ComponentHealth::Ready,
            },
            installations: Vec::new(),
            repositories: vec![GitHubRepositoryLinkView {
                repository_id: 3,
                control_plane_id: Some("repo-3".to_owned()),
                owner: "octo".to_owned(),
                name: "linked".to_owned(),
                web_origin: "https://github.example".to_owned(),
                visibility: RepositoryVisibility::Private,
                installation_account: "octo".to_owned(),
                default_branch: "main".to_owned(),
                state: RepositoryLinkState::Ready,
            }],
            repository_candidates: vec![GitHubRepositoryCandidateAction {
                installation_id: "installation-7".to_owned(),
                external_repository_id: "2".to_owned(),
                owner: "octo".to_owned(),
                name: "available".to_owned(),
                visibility: RepositoryVisibility::Private,
                default_branch: "main".to_owned(),
                csrf_token: "candidate-csrf".to_owned(),
            }],
            events: Vec::new(),
            alert: None,
            install_action: None,
        };
        let catalog = GitHubUserCatalog {
            organizations: vec!["octo".to_owned()],
            repositories: [(1, "needs-app"), (2, "available"), (3, "linked")]
                .into_iter()
                .map(|(repository_id, name)| GitHubUserRepository {
                    repository_id,
                    owner_id: 10,
                    owner: "octo".to_owned(),
                    name: name.to_owned(),
                    visibility: "private".to_owned(),
                    default_branch: "main".to_owned(),
                })
                .collect(),
        };

        let organizations = github_user_organization_catalog("ada", &catalog, &page);
        let octo = organizations
            .as_array()
            .unwrap()
            .iter()
            .find(|organization| organization["name"] == "octo")
            .unwrap();
        let states = octo["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|repository| {
                (
                    repository["name"].as_str().unwrap(),
                    repository["state"].as_str().unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(states["needs-app"], "needs_installation");
        assert_eq!(states["available"], "available");
        assert_eq!(states["linked"], "added");
        assert!(organizations
            .as_array()
            .unwrap()
            .iter()
            .any(|organization| organization["name"] == "ada"));
    }

    #[test]
    fn installed_repository_candidates_survive_an_oauth_catalog_omission() {
        let page = GitHubInstallationsPage {
            tenant_name: "Forge".to_owned(),
            principal_name: "Ada".to_owned(),
            session_csrf_token: "session-csrf".to_owned(),
            app: GitHubAppHealth {
                app_id: Some(42),
                app_slug: Some("runtrue-ci".to_owned()),
                provider_host: "github.example".to_owned(),
                app: ComponentHealth::Ready,
                signer: ComponentHealth::Ready,
                webhook: ComponentHealth::Ready,
                callback: ComponentHealth::Ready,
            },
            installations: vec![GitHubInstallationView {
                installation_id: 42_417,
                account_login: "AgentOps".to_owned(),
                account_kind: UiGitHubAccountKind::Organization,
                state: UiGitHubInstallationState::Active,
                repository_selection: RepositorySelection::All,
                permissions: vec![UiGitHubPermission::MetadataRead],
            }],
            repositories: Vec::new(),
            repository_candidates: vec![GitHubRepositoryCandidateAction {
                installation_id: "github-installation-42417".to_owned(),
                external_repository_id: "2042673".to_owned(),
                owner: "AgentOps".to_owned(),
                name: "agentops-service".to_owned(),
                visibility: RepositoryVisibility::Private,
                default_branch: "main".to_owned(),
                csrf_token: "candidate-csrf".to_owned(),
            }],
            events: Vec::new(),
            alert: None,
            install_action: None,
        };
        let oauth_catalog = GitHubUserCatalog {
            organizations: vec!["agentops".to_owned()],
            repositories: Vec::new(),
        };

        let organizations = github_user_organization_catalog("ada", &oauth_catalog, &page);
        let organizations = organizations.as_array().unwrap();
        let agentops = organizations
            .iter()
            .filter(|organization| {
                organization["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("AgentOps"))
            })
            .collect::<Vec<_>>();

        assert_eq!(agentops.len(), 1);
        assert_eq!(agentops[0]["name"], "AgentOps");
        assert_eq!(agentops[0]["repositories"].as_array().unwrap().len(), 1);
        assert_eq!(agentops[0]["repositories"][0]["name"], "agentops-service");
        assert_eq!(agentops[0]["repositories"][0]["state"], "available");
        assert_eq!(
            agentops[0]["repositories"][0]["installationId"],
            "github-installation-42417"
        );
    }
}
