use crate::app::{
    authorize_resource, control_plane_problem, idempotency_key, now_unix_ms, random_id,
    randomness_problem, required_json, scope_tenant, AppState, Items, RequestId, RequestPrincipal,
    ServerResource, IDEMPOTENCY_REPLAYED,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_control_plane::SecretMetadataReference;
use runtrue_policy::{CedarAction, CedarResourceKind};
use runtrue_secrets::SecretPlaintext;
use serde::Deserialize;
pub(in crate::app) fn scoped_resource<'a>(
    kind: CedarResourceKind,
    id: &'a str,
    tenant_id: &'a str,
    scope: &'a str,
) -> ServerResource<'a> {
    let resource = ServerResource::new(kind, id, tenant_id);
    scope
        .strip_prefix("repository:")
        .map_or(resource, |repository_id| {
            resource.in_repository(repository_id)
        })
}

pub(in crate::app) async fn list_secret_metadata(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(scope): Path<String>,
) -> Response {
    let tenant = match scope_tenant(&state, &scope).await {
        Ok(tenant) => tenant,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ReadSecretMetadata,
        scoped_resource(CedarResourceKind::Secret, &scope, &tenant, &scope),
    )
    .await
    {
        return response;
    }
    match state.store.secrets(&tenant, &scope).await {
        Ok(items) => Json(Items { items }).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSecretBody {
    name: String,
    secret_type: String,
    #[serde(default = "default_secret_provider")]
    provider: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    provider_reference: Option<String>,
}

fn default_secret_provider() -> String {
    "built-in".to_owned()
}

pub(in crate::app) async fn create_secret(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(scope): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: CreateSecretBody = match required_json(&request_id, body) {
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
    let resource_id = format!("{scope}/{}", body.name);
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::WriteSecret,
        scoped_resource(CedarResourceKind::Secret, &resource_id, &tenant, &scope),
    )
    .await
    {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let id = match random_id("secret") {
        Ok(id) => id,
        Err(()) => return randomness_problem(&request_id),
    };
    let built_in = body.provider == "built-in";
    let plaintext = body
        .value
        .map(|value| SecretPlaintext::new(value.into_bytes()));
    let metadata = SecretMetadataReference {
        id,
        tenant_id: tenant,
        scope,
        name: body.name,
        provider: body.provider,
        provider_reference: body.provider_reference,
        secret_type: body.secret_type,
        status: "active".to_owned(),
        current_version: built_in.then_some(1),
        created_unix_ms: now,
        updated_unix_ms: now,
    };
    match state
        .store
        .create_secret(
            &idempotency_key,
            &metadata,
            plaintext.as_ref(),
            &state.secret_master_key,
        )
        .await
    {
        Ok(result) => {
            let mut response = (StatusCode::CREATED, Json(result.value)).into_response();
            response.headers_mut().insert(
                IDEMPOTENCY_REPLAYED.clone(),
                HeaderValue::from_static(if result.replayed { "true" } else { "false" }),
            );
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn get_secret_metadata(
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
        CedarAction::ReadSecretMetadata,
        scoped_resource(CedarResourceKind::Secret, &resource_id, &tenant, &scope),
    )
    .await
    {
        return response;
    }
    match state.store.secret_by_name(&tenant, &scope, &name).await {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateSecretBody {
    value: String,
}

pub(in crate::app) async fn rotate_secret(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((scope, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: RotateSecretBody = match required_json(&request_id, body) {
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
        CedarAction::WriteSecret,
        scoped_resource(CedarResourceKind::Secret, &resource_id, &tenant, &scope),
    )
    .await
    {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let plaintext = SecretPlaintext::new(body.value.into_bytes());
    match state
        .store
        .rotate_secret(
            &idempotency_key,
            &tenant,
            &scope,
            &name,
            &plaintext,
            &state.secret_master_key,
            now,
        )
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

pub(in crate::app) async fn delete_secret(
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
        CedarAction::WriteSecret,
        scoped_resource(CedarResourceKind::Secret, &resource_id, &tenant, &scope),
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
        .delete_secret_configuration(&tenant, &scope, &name, &state.secret_master_key, now)
        .await
    {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}
use axum::response::IntoResponse as _;
