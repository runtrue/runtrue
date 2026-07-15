use crate::app::{
    api_token_tenant, authorize_resource, authorize_tenant_collection, control_plane_problem,
    now_unix_ms, random_id, randomness_problem, required_json, AppState, RequestId,
    RequestPrincipal, ServerResource,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use runtrue_control_plane::RepositoryRecord;
use runtrue_policy::{CedarAction, CedarResourceKind};
use serde::{Deserialize, Serialize};
#[derive(Serialize)]
struct RepositoryPage {
    items: Vec<RepositoryView>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct RepositoryView {
    id: String,
    owner: String,
    name: String,
    default_branch: String,
    visibility: String,
}

impl From<RepositoryRecord> for RepositoryView {
    fn from(value: RepositoryRecord) -> Self {
        Self {
            id: value.id,
            owner: value.owner,
            name: value.name,
            default_branch: value.default_branch,
            visibility: value.visibility,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRepositoryBody {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    owner: String,
    name: String,
    #[serde(default)]
    default_branch: Option<String>,
    #[serde(default)]
    visibility: Option<String>,
}

pub(in crate::app) async fn list_repositories(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
) -> Response {
    let repositories = if let Some(tenant_id) = api_token_tenant(&principal) {
        if let Err(response) = authorize_tenant_collection(
            &state,
            &request_id,
            &principal,
            CedarAction::ViewRepository,
            tenant_id,
        ) {
            return response;
        }
        state.control_plane.list_repositories_for_tenant(tenant_id)
    } else {
        state.control_plane.list_repositories()
    };
    match repositories {
        Ok(repositories) => Json(RepositoryPage {
            items: repositories.into_iter().map(RepositoryView::from).collect(),
            next_cursor: None,
        })
        .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn create_repository(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: CreateRepositoryBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let id = match body.id {
        Some(id) => id,
        None => match random_id("repo") {
            Ok(id) => id,
            Err(()) => return randomness_problem(&request_id),
        },
    };
    let tenant_id = body.tenant_id.unwrap_or_else(|| match &principal {
        RequestPrincipal::Bootstrap => "default".to_owned(),
        RequestPrincipal::ApiToken(context) => context.tenant_id.clone(),
    });
    let record = RepositoryRecord {
        id,
        tenant_id,
        owner: body.owner,
        name: body.name,
        default_branch: body.default_branch.unwrap_or_else(|| "main".to_owned()),
        visibility: body.visibility.unwrap_or_else(|| "private".to_owned()),
        created_unix_ms: now,
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::EditWorkflowSettings,
        ServerResource::new(CedarResourceKind::Repository, &record.id, &record.tenant_id),
    ) {
        return response;
    }
    match state.control_plane.create_repository(&record) {
        Ok(()) => (StatusCode::CREATED, Json(RepositoryView::from(record))).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn get_repository(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(repository_id): Path<String>,
) -> Response {
    match state.control_plane.repository(&repository_id) {
        Ok(repository) => {
            if let Err(response) = authorize_resource(
                &state,
                &request_id,
                &principal,
                CedarAction::ViewRepository,
                ServerResource::new(
                    CedarResourceKind::Repository,
                    &repository.id,
                    &repository.tenant_id,
                ),
            ) {
                return response;
            }
            Json(RepositoryView::from(repository)).into_response()
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}
use axum::response::IntoResponse as _;
