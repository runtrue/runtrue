use crate::app::{
    authenticated_browser_session, authorize_browser_tenant, authorize_resource,
    authorize_tenant_collection, browser_csrf_input, control_plane_problem, form_value,
    internal_problem, invalid_object_problem, now_unix_ms, problem_response, random_id,
    randomness_problem, required_json, timestamp, AppState, RequestId, RequestPrincipal,
    ServerResource, POLICY_READ_SCOPE,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use runtrue_control_plane::{
    HumanUserRecord, RepositoryAccessGrantRecord, RepositoryAccessSubject, TeamMembershipRecord,
    TeamRecord,
};
use runtrue_policy::{CedarAction, CedarResourceKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize)]
struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateUserBody {
    #[serde(default)]
    id: Option<String>,
    display_name: String,
    primary_email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateUserBody {
    expected_version: u64,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    primary_email: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTeamBody {
    #[serde(default)]
    id: Option<String>,
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateTeamBody {
    expected_version: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddTeamMemberBody {
    user_id: String,
    #[serde(default = "default_member_role")]
    role: String,
}

fn default_member_role() -> String {
    "member".to_owned()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutRepositoryGrantBody {
    #[serde(default)]
    id: Option<String>,
    subject_kind: String,
    subject_id: String,
    permission: String,
    #[serde(default)]
    expected_version: Option<u64>,
}

async fn authorize_tenant(
    state: &AppState,
    request_id: &RequestId,
    principal: &RequestPrincipal,
    action: CedarAction,
    tenant_id: &str,
) -> Result<(), Response> {
    authorize_tenant_collection(state, request_id, principal, action, tenant_id).await
}

async fn authorize_item(
    state: &AppState,
    request_id: &RequestId,
    principal: &RequestPrincipal,
    action: CedarAction,
    kind: CedarResourceKind,
    id: &str,
    tenant_id: &str,
) -> Result<(), Response> {
    authorize_resource(
        state,
        request_id,
        principal,
        action,
        ServerResource::new(kind, id, tenant_id),
    )
    .await
}

pub(in crate::app) async fn list_users(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(tenant_id): Path<String>,
) -> Response {
    if let Err(response) = authorize_tenant(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageUser,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    match state.store.users_for_tenant(&tenant_id).await {
        Ok(items) => Json(Page {
            items,
            next_cursor: None,
        })
        .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn create_user(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(tenant_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: CreateUserBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let id = match body.id {
        Some(id) => id,
        None => match random_id("user") {
            Ok(id) => id,
            Err(()) => return randomness_problem(&request_id),
        },
    };
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageUser,
        CedarResourceKind::User,
        &id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let record = HumanUserRecord {
        id,
        display_name: body.display_name,
        primary_email: body.primary_email,
        status: "active".to_owned(),
        created_unix_ms: now,
        updated_unix_ms: now,
        last_seen_unix_ms: None,
        version: 1,
    };
    match state.store.put_human_user(&tenant_id, &record, None).await {
        Ok(_) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn get_user(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((tenant_id, user_id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageUser,
        CedarResourceKind::User,
        &user_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    match state.store.human_user(&tenant_id, &user_id).await {
        Ok(record) => Json(record).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn update_user(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((tenant_id, user_id)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: UpdateUserBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageUser,
        CedarResourceKind::User,
        &user_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    let mut record = match state.store.human_user(&tenant_id, &user_id).await {
        Ok(record) => record,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if record.version != body.expected_version {
        return invalid_object_problem(&request_id, "expected_version is stale");
    }
    if let Some(value) = body.display_name {
        record.display_name = value;
    }
    if let Some(value) = body.primary_email {
        record.primary_email = value;
    }
    if let Some(value) = body.status {
        record.status = value;
    }
    record.version = match record.version.checked_add(1) {
        Some(version) => version,
        None => return invalid_object_problem(&request_id, "user version overflows"),
    };
    record.updated_unix_ms = match now_unix_ms(&request_id) {
        Ok(now) => now.max(record.updated_unix_ms),
        Err(response) => return response,
    };
    match state
        .store
        .put_human_user(&tenant_id, &record, Some(body.expected_version))
        .await
    {
        Ok(_) => Json(record).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn effective_user_repository_access(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((tenant_id, user_id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageUser,
        CedarResourceKind::User,
        &user_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    match state
        .store
        .effective_repository_access_for_user(&tenant_id, &user_id)
        .await
    {
        Ok(items) => Json(Page {
            items,
            next_cursor: None,
        })
        .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn list_teams(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(tenant_id): Path<String>,
) -> Response {
    if let Err(response) = authorize_tenant(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageTeam,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    match state.store.teams_for_tenant(&tenant_id).await {
        Ok(items) => Json(Page {
            items,
            next_cursor: None,
        })
        .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn create_team(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(tenant_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: CreateTeamBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let id = match body.id {
        Some(id) => id,
        None => match random_id("team") {
            Ok(id) => id,
            Err(()) => return randomness_problem(&request_id),
        },
    };
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageTeam,
        CedarResourceKind::Team,
        &id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let record = TeamRecord {
        id,
        tenant_id,
        name: body.name,
        description: body.description,
        status: "active".to_owned(),
        created_unix_ms: now,
        updated_unix_ms: now,
        version: 1,
    };
    match state.store.put_team(&record, None).await {
        Ok(_) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn get_team(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((tenant_id, team_id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageTeam,
        CedarResourceKind::Team,
        &team_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    match state.store.team(&tenant_id, &team_id).await {
        Ok(record) => Json(record).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn update_team(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((tenant_id, team_id)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: UpdateTeamBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageTeam,
        CedarResourceKind::Team,
        &team_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    let mut record = match state.store.team(&tenant_id, &team_id).await {
        Ok(record) => record,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if record.version != body.expected_version {
        return invalid_object_problem(&request_id, "expected_version is stale");
    }
    if let Some(value) = body.name {
        record.name = value;
    }
    if let Some(value) = body.description {
        record.description = value;
    }
    if let Some(value) = body.status {
        record.status = value;
    }
    record.version = match record.version.checked_add(1) {
        Some(version) => version,
        None => return invalid_object_problem(&request_id, "team version overflows"),
    };
    record.updated_unix_ms = match now_unix_ms(&request_id) {
        Ok(now) => now.max(record.updated_unix_ms),
        Err(response) => return response,
    };
    match state
        .store
        .put_team(&record, Some(body.expected_version))
        .await
    {
        Ok(_) => Json(record).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn list_team_members(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((tenant_id, team_id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageTeam,
        CedarResourceKind::Team,
        &team_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    match state.store.team_memberships(&tenant_id, &team_id).await {
        Ok(items) => Json(Page {
            items,
            next_cursor: None,
        })
        .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn add_team_member(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((tenant_id, team_id)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: AddTeamMemberBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageTeam,
        CedarResourceKind::Team,
        &team_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    let existing_created_unix_ms = match state.store.team_memberships(&tenant_id, &team_id).await {
        Ok(memberships) => memberships
            .into_iter()
            .find(|membership| membership.user_id == body.user_id)
            .map(|membership| membership.created_unix_ms),
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let record = TeamMembershipRecord {
        tenant_id,
        team_id,
        user_id: body.user_id,
        role: body.role,
        created_unix_ms: match existing_created_unix_ms {
            Some(created_unix_ms) => created_unix_ms,
            None => match now_unix_ms(&request_id) {
                Ok(now) => now,
                Err(response) => return response,
            },
        },
    };
    match state.store.put_team_membership(&record).await {
        Ok(created) => (
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            Json(record),
        )
            .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn remove_team_member(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((tenant_id, team_id, user_id)): Path<(String, String, String)>,
) -> Response {
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageTeam,
        CedarResourceKind::Team,
        &team_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    match state
        .store
        .remove_team_membership(&tenant_id, &team_id, &user_id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Serialize)]
struct BrowserUserView {
    id: String,
    display_name: String,
    primary_email: String,
    status: String,
    created_at: String,
    updated_at: String,
    last_seen_at: Option<String>,
    version: u64,
    team_ids: Vec<String>,
}

#[derive(Serialize)]
struct BrowserTeamView {
    id: String,
    name: String,
    description: String,
    status: String,
    created_at: String,
    updated_at: String,
    version: u64,
    member_ids: Vec<String>,
}

#[derive(Serialize)]
struct BrowserIdentityView {
    users: Vec<BrowserUserView>,
    teams: Vec<BrowserTeamView>,
}

async fn browser_identity_view(
    state: &AppState,
    request_id: &RequestId,
    tenant_id: &str,
) -> Result<BrowserIdentityView, Response> {
    let records = state
        .store
        .users_for_tenant(tenant_id)
        .await
        .map_err(|error| control_plane_problem(request_id, error))?;
    let team_records = state
        .store
        .teams_for_tenant(tenant_id)
        .await
        .map_err(|error| control_plane_problem(request_id, error))?;
    let mut user_teams = records
        .iter()
        .map(|record| (record.id.clone(), Vec::new()))
        .collect::<BTreeMap<_, _>>();
    let mut teams = Vec::with_capacity(team_records.len());
    for record in team_records {
        let memberships = state
            .store
            .team_memberships(tenant_id, &record.id)
            .await
            .map_err(|error| control_plane_problem(request_id, error))?;
        let mut member_ids = Vec::with_capacity(memberships.len());
        for membership in memberships {
            if let Some(team_ids) = user_teams.get_mut(&membership.user_id) {
                team_ids.push(record.id.clone());
            }
            member_ids.push(membership.user_id);
        }
        teams.push(BrowserTeamView {
            id: record.id,
            name: record.name,
            description: record.description,
            status: record.status,
            created_at: timestamp(record.created_unix_ms)
                .map_err(|()| internal_problem(request_id))?,
            updated_at: timestamp(record.updated_unix_ms)
                .map_err(|()| internal_problem(request_id))?,
            version: record.version,
            member_ids,
        });
    }
    let users = records
        .into_iter()
        .map(|record| {
            Ok(BrowserUserView {
                team_ids: user_teams.remove(&record.id).unwrap_or_default(),
                id: record.id,
                display_name: record.display_name,
                primary_email: record.primary_email,
                status: record.status,
                created_at: timestamp(record.created_unix_ms)
                    .map_err(|()| internal_problem(request_id))?,
                updated_at: timestamp(record.updated_unix_ms)
                    .map_err(|()| internal_problem(request_id))?,
                last_seen_at: record
                    .last_seen_unix_ms
                    .map(timestamp)
                    .transpose()
                    .map_err(|()| internal_problem(request_id))?,
                version: record.version,
            })
        })
        .collect::<Result<Vec<_>, Response>>()?;
    Ok(BrowserIdentityView { users, teams })
}

async fn browser_identity_session(
    state: &AppState,
    request_id: &RequestId,
    headers: &HeaderMap,
    csrf: Option<&str>,
) -> Result<runtrue_auth::AuthContext, Response> {
    let now = now_unix_ms(request_id)?;
    let (context, _, _) =
        authenticated_browser_session(state, request_id, headers, POLICY_READ_SCOPE, csrf, now)
            .await
            .map_err(|response| *response)?;
    authorize_browser_tenant(state, request_id, &context, CedarAction::ManageUser)
        .await
        .map_err(|response| *response)?;
    authorize_browser_tenant(state, request_id, &context, CedarAction::ManageTeam)
        .await
        .map_err(|response| *response)?;
    Ok(context)
}

fn browser_form_value(request_id: &RequestId, body: &[u8], name: &str) -> Result<String, Response> {
    match form_value(body, name) {
        Ok(Some(value)) if !value.trim().is_empty() => Ok(value),
        _ => Err(problem_response(
            request_id,
            StatusCode::BAD_REQUEST,
            "Invalid object",
            format!("{name} is required"),
        )),
    }
}

fn browser_form_version(request_id: &RequestId, body: &[u8]) -> Result<u64, Response> {
    browser_form_value(request_id, body, "expected_version")?
        .parse()
        .map_err(|_| invalid_object_problem(request_id, "expected_version is invalid"))
}

async fn browser_mutation_session(
    state: &AppState,
    request_id: &RequestId,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<runtrue_auth::AuthContext, Response> {
    let csrf =
        browser_csrf_input(request_id, headers, Ok(body.clone())).map_err(|response| *response)?;
    browser_identity_session(state, request_id, headers, Some(&csrf)).await
}

async fn browser_identity_response(
    state: &AppState,
    request_id: &RequestId,
    tenant_id: &str,
) -> Response {
    match browser_identity_view(state, request_id, tenant_id).await {
        Ok(view) => Json(view).into_response(),
        Err(response) => response,
    }
}

pub(in crate::app) async fn browser_identity(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    let context = match browser_identity_session(&state, &request_id, &headers, None).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    browser_identity_response(&state, &request_id, &context.tenant_id).await
}

pub(in crate::app) async fn browser_create_user(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "invalid user form"),
    };
    let context = match browser_mutation_session(&state, &request_id, &headers, &body).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let id = match random_id("user") {
        Ok(id) => id,
        Err(()) => return randomness_problem(&request_id),
    };
    let record = HumanUserRecord {
        id,
        display_name: match browser_form_value(&request_id, &body, "display_name") {
            Ok(value) => value,
            Err(response) => return response,
        },
        primary_email: match browser_form_value(&request_id, &body, "primary_email") {
            Ok(value) => value,
            Err(response) => return response,
        },
        status: "active".to_owned(),
        created_unix_ms: now,
        updated_unix_ms: now,
        last_seen_unix_ms: None,
        version: 1,
    };
    match state
        .store
        .put_human_user(&context.tenant_id, &record, None)
        .await
    {
        Ok(_) => browser_identity_response(&state, &request_id, &context.tenant_id).await,
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn browser_create_team(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "invalid team form"),
    };
    let context = match browser_mutation_session(&state, &request_id, &headers, &body).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let id = match form_value(&body, "id") {
        Ok(Some(id)) if !id.trim().is_empty() => id,
        Ok(_) => match random_id("team") {
            Ok(id) => id,
            Err(()) => return randomness_problem(&request_id),
        },
        Err(()) => return invalid_object_problem(&request_id, "invalid team id"),
    };
    let record = TeamRecord {
        id,
        tenant_id: context.tenant_id.clone(),
        name: match browser_form_value(&request_id, &body, "name") {
            Ok(value) => value,
            Err(response) => return response,
        },
        description: match form_value(&body, "description") {
            Ok(value) => value.unwrap_or_default(),
            Err(()) => return invalid_object_problem(&request_id, "invalid description"),
        },
        status: "active".to_owned(),
        created_unix_ms: now,
        updated_unix_ms: now,
        version: 1,
    };
    match state.store.put_team(&record, None).await {
        Ok(_) => browser_identity_response(&state, &request_id, &context.tenant_id).await,
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn browser_update_team(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(team_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "invalid team form"),
    };
    let context = match browser_mutation_session(&state, &request_id, &headers, &body).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let expected_version = match browser_form_version(&request_id, &body) {
        Ok(version) => version,
        Err(response) => return response,
    };
    let mut record = match state.store.team(&context.tenant_id, &team_id).await {
        Ok(record) => record,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if record.version != expected_version {
        return problem_response(
            &request_id,
            StatusCode::CONFLICT,
            "Conflict",
            "the team was updated by another request",
        );
    }
    record.name = match browser_form_value(&request_id, &body, "name") {
        Ok(value) => value,
        Err(response) => return response,
    };
    record.description = match form_value(&body, "description") {
        Ok(value) => value.unwrap_or_default(),
        Err(()) => return invalid_object_problem(&request_id, "invalid description"),
    };
    record.status = match browser_form_value(&request_id, &body, "status") {
        Ok(value) => value,
        Err(response) => return response,
    };
    record.updated_unix_ms = match now_unix_ms(&request_id) {
        Ok(now) => now.max(record.updated_unix_ms),
        Err(response) => return response,
    };
    record.version = match record.version.checked_add(1) {
        Some(version) => version,
        None => return invalid_object_problem(&request_id, "team version overflows"),
    };
    match state.store.put_team(&record, Some(expected_version)).await {
        Ok(_) => browser_identity_response(&state, &request_id, &context.tenant_id).await,
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn browser_update_user(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "invalid user form"),
    };
    let context = match browser_mutation_session(&state, &request_id, &headers, &body).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let expected_version = match browser_form_version(&request_id, &body) {
        Ok(version) => version,
        Err(response) => return response,
    };
    let mut record = match state.store.human_user(&context.tenant_id, &user_id).await {
        Ok(record) => record,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if record.version != expected_version {
        return problem_response(
            &request_id,
            StatusCode::CONFLICT,
            "Conflict",
            "the user was updated by another request",
        );
    }
    record.display_name = match browser_form_value(&request_id, &body, "display_name") {
        Ok(value) => value,
        Err(response) => return response,
    };
    record.primary_email = match browser_form_value(&request_id, &body, "primary_email") {
        Ok(value) => value,
        Err(response) => return response,
    };
    record.status = match browser_form_value(&request_id, &body, "status") {
        Ok(value) => value,
        Err(response) => return response,
    };
    record.updated_unix_ms = match now_unix_ms(&request_id) {
        Ok(now) => now.max(record.updated_unix_ms),
        Err(response) => return response,
    };
    record.version = match record.version.checked_add(1) {
        Some(version) => version,
        None => return invalid_object_problem(&request_id, "user version overflows"),
    };
    match state
        .store
        .put_human_user(&context.tenant_id, &record, Some(expected_version))
        .await
    {
        Ok(_) => browser_identity_response(&state, &request_id, &context.tenant_id).await,
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn browser_change_team_member(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(team_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return invalid_object_problem(&request_id, "invalid membership form"),
    };
    let context = match browser_mutation_session(&state, &request_id, &headers, &body).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let user_id = match browser_form_value(&request_id, &body, "user_id") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let action = match browser_form_value(&request_id, &body, "action") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result = match action.as_str() {
        "add" => {
            let existing = match state
                .store
                .team_memberships(&context.tenant_id, &team_id)
                .await
            {
                Ok(memberships) => memberships
                    .into_iter()
                    .find(|membership| membership.user_id == user_id),
                Err(error) => return control_plane_problem(&request_id, error),
            };
            let membership = TeamMembershipRecord {
                tenant_id: context.tenant_id.clone(),
                team_id,
                user_id,
                role: existing
                    .as_ref()
                    .map(|membership| membership.role.clone())
                    .unwrap_or_else(|| "member".to_owned()),
                created_unix_ms: match existing {
                    Some(membership) => membership.created_unix_ms,
                    None => match now_unix_ms(&request_id) {
                        Ok(now) => now,
                        Err(response) => return response,
                    },
                },
            };
            state.store.put_team_membership(&membership).await
        }
        "remove" => {
            state
                .store
                .remove_team_membership(&context.tenant_id, &team_id, &user_id)
                .await
        }
        _ => return invalid_object_problem(&request_id, "membership action must be add or remove"),
    };
    match result {
        Ok(_) => browser_identity_response(&state, &request_id, &context.tenant_id).await,
        Err(error) => control_plane_problem(&request_id, error),
    }
}

async fn repository_tenant(
    state: &AppState,
    request_id: &RequestId,
    repository_id: &str,
) -> Result<String, Response> {
    state
        .store
        .repository(repository_id)
        .await
        .map(|repository| repository.tenant_id)
        .map_err(|error| control_plane_problem(request_id, error))
}

pub(in crate::app) async fn list_repository_access(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(repository_id): Path<String>,
) -> Response {
    let tenant_id = match repository_tenant(&state, &request_id, &repository_id).await {
        Ok(tenant_id) => tenant_id,
        Err(response) => return response,
    };
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageRepositoryAccess,
        CedarResourceKind::Repository,
        &repository_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    match state
        .store
        .repository_access_grants(&tenant_id, &repository_id)
        .await
    {
        Ok(items) => Json(Page {
            items,
            next_cursor: None,
        })
        .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn put_repository_access(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(repository_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: PutRepositoryGrantBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let tenant_id = match repository_tenant(&state, &request_id, &repository_id).await {
        Ok(tenant_id) => tenant_id,
        Err(response) => return response,
    };
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageRepositoryAccess,
        CedarResourceKind::Repository,
        &repository_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    let subject = match body.subject_kind.as_str() {
        "user" => RepositoryAccessSubject::User(body.subject_id),
        "team" | "group" => RepositoryAccessSubject::Team(body.subject_id),
        _ => return invalid_object_problem(&request_id, "subject_kind must be user or team"),
    };
    let id = match body.id {
        Some(id) => id,
        None if body.expected_version.is_some() => {
            return invalid_object_problem(&request_id, "id is required when updating a grant")
        }
        None => match random_id("repository-grant") {
            Ok(id) => id,
            Err(()) => return randomness_problem(&request_id),
        },
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let version = match body.expected_version {
        Some(version) => match version.checked_add(1) {
            Some(version) => version,
            None => return invalid_object_problem(&request_id, "grant version overflows"),
        },
        None => 1,
    };
    let created_unix_ms = if body.expected_version.is_some() {
        match state
            .store
            .repository_access_grants(&tenant_id, &repository_id)
            .await
        {
            Ok(grants) => match grants.into_iter().find(|grant| grant.id == id) {
                Some(grant) => grant.created_unix_ms,
                None => return StatusCode::NOT_FOUND.into_response(),
            },
            Err(error) => return control_plane_problem(&request_id, error),
        }
    } else {
        now
    };
    let record = RepositoryAccessGrantRecord {
        id,
        tenant_id,
        repository_id,
        subject,
        permission: body.permission,
        created_unix_ms,
        updated_unix_ms: now,
        version,
    };
    match state
        .store
        .put_repository_access_grant(&record, body.expected_version)
        .await
    {
        Ok(_) => (
            if body.expected_version.is_some() {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            Json(record),
        )
            .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn revoke_repository_access(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((repository_id, grant_id)): Path<(String, String)>,
) -> Response {
    let tenant_id = match repository_tenant(&state, &request_id, &repository_id).await {
        Ok(tenant_id) => tenant_id,
        Err(response) => return response,
    };
    if let Err(response) = authorize_item(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageRepositoryAccess,
        CedarResourceKind::Repository,
        &repository_id,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    match state
        .store
        .revoke_repository_access_grant(&tenant_id, &repository_id, &grant_id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}
