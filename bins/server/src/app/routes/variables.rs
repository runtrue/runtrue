use crate::app::{
    authorize_resource, control_plane_problem, idempotency_key, now_unix_ms, required_json,
    scope_tenant, scoped_resource, AppState, RequestId, RequestPrincipal, IDEMPOTENCY_REPLAYED,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_policy::{CedarAction, CedarResourceKind};
use serde::Deserialize;
use serde_json::Value;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutVariableBody {
    value: Value,
}

pub(in crate::app) async fn put_variable(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((scope, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: PutVariableBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let idempotency_key = match idempotency_key(&request_id, &headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let tenant = match scope_tenant(&state, &scope).await {
        Ok(tenant) => tenant,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let resource_id = format!("{scope}/{name}");
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::WriteVariable,
        scoped_resource(CedarResourceKind::Variable, &resource_id, &tenant, &scope),
    )
    .await
    {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    match state
        .store
        .put_variable(&idempotency_key, &tenant, &scope, &name, body.value, now)
        .await
    {
        Ok(result) => {
            let mut response = Json(result.value).into_response();
            response.headers_mut().insert(
                IDEMPOTENCY_REPLAYED.clone(),
                HeaderValue::from_static(if result.replayed { "true" } else { "false" }),
            );
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn get_variable(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((scope, name)): Path<(String, String)>,
) -> Response {
    let tenant = match scope_tenant(&state, &scope).await {
        Ok(tenant) => tenant,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let resource_id = format!("{scope}/{name}");
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ReadVariable,
        scoped_resource(CedarResourceKind::Variable, &resource_id, &tenant, &scope),
    )
    .await
    {
        return response;
    }
    match state.store.variable_record(&tenant, &scope, &name).await {
        Ok(variable) => Json(variable).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn delete_variable(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((scope, name)): Path<(String, String)>,
) -> Response {
    let tenant = match scope_tenant(&state, &scope).await {
        Ok(tenant) => tenant,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let resource_id = format!("{scope}/{name}");
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::WriteVariable,
        scoped_resource(CedarResourceKind::Variable, &resource_id, &tenant, &scope),
    )
    .await
    {
        return response;
    }
    match state
        .store
        .delete_variable_record(&tenant, &scope, &name)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}
use axum::response::IntoResponse as _;
