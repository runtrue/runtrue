use crate::app::{
    api_token_tenant, authorize_resource, authorize_tenant_collection, control_plane_problem,
    idempotency_key, internal_problem, now_unix_ms, optional_json, problem_response,
    protect_sensitive_response, timestamp, AppState, RequestId, RequestPrincipal, ServerResource,
    IDEMPOTENCY_REPLAYED,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_control_plane::{
    ControlPlaneError, EnrollmentTokenIssueResult, RunnerPoolRecord, RunnerPoolStatus,
};
use runtrue_policy::{CedarAction, CedarResourceKind};
use runtrue_scheduler::RunnerRecord;
use serde::{Deserialize, Serialize};
#[derive(Serialize)]
pub(in crate::app) struct Items<T> {
    pub(in crate::app) items: Vec<T>,
}

pub(in crate::app) async fn list_runner_pools(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
) -> Response {
    let pools = if let Some(tenant_id) = api_token_tenant(&principal) {
        if let Err(response) = authorize_tenant_collection(
            &state,
            &request_id,
            &principal,
            CedarAction::ManageRunnerPool,
            tenant_id,
        ) {
            return response;
        }
        state.control_plane.list_runner_pools_for_tenant(tenant_id)
    } else {
        state.control_plane.list_runner_pools()
    };
    match pools {
        Ok(items) => Json(Items { items }).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct CreateRunnerPoolBody {
    id: String,
    tenant_id: String,
    name: String,
    #[serde(default)]
    region: Option<String>,
}

pub(in crate::app) async fn create_runner_pool(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    body: Result<Json<CreateRunnerPoolBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid runner pool",
                "request body must contain only id, tenant_id, name, and optional region",
            )
        }
    };
    if let Some(tenant_id) = api_token_tenant(&principal) {
        if tenant_id != body.tenant_id {
            return problem_response(
                &request_id,
                StatusCode::FORBIDDEN,
                "Forbidden",
                "runner pool tenant does not match the API token tenant",
            );
        }
    }
    if let Err(response) = authorize_tenant_collection(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageRunnerPool,
        &body.tenant_id,
    ) {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let pool = RunnerPoolRecord {
        id: body.id,
        tenant_id: body.tenant_id,
        name: body.name,
        region: body.region,
        status: RunnerPoolStatus::Active,
        created_unix_ms: now,
    };
    match state.control_plane.create_runner_pool(&pool) {
        Ok(()) => (StatusCode::CREATED, Json(pool)).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn get_runner_pool(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
) -> Response {
    match state.control_plane.runner_pool(&pool_id) {
        Ok(pool) => {
            if let Err(response) = authorize_resource(
                &state,
                &request_id,
                &principal,
                CedarAction::ManageRunnerPool,
                ServerResource::new(CedarResourceKind::RunnerPool, &pool.id, &pool.tenant_id),
            ) {
                return response;
            }
            Json(pool).into_response()
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Serialize)]
struct CapsuleTrustKeyView {
    key_id: String,
    algorithm: &'static str,
    public_key_hex: String,
}

pub(in crate::app) async fn get_runner_capsule_trust_key(
    State(state): State<AppState>,
) -> Response {
    let key = state.capsule_signing_key.verifying_key();
    Json(CapsuleTrustKeyView {
        key_id: key.key_id().to_string(),
        algorithm: "ed25519",
        public_key_hex: hex::encode(key.to_bytes()),
    })
    .into_response()
}

#[derive(Serialize)]
struct RunnerView {
    #[serde(flatten)]
    runner: RunnerRecord,
    created_at: String,
    updated_at: String,
}

fn runner_view(record: runtrue_control_plane::PersistedRunner) -> Result<RunnerView, ()> {
    Ok(RunnerView {
        runner: record.runner,
        created_at: timestamp(record.created_unix_ms)?,
        updated_at: timestamp(record.updated_unix_ms)?,
    })
}

pub(in crate::app) async fn list_runners(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
) -> Response {
    let records = if let Some(tenant_id) = api_token_tenant(&principal) {
        if let Err(response) = authorize_tenant_collection(
            &state,
            &request_id,
            &principal,
            CedarAction::ManageRunnerPool,
            tenant_id,
        ) {
            return response;
        }
        state.control_plane.list_runners_for_tenant(tenant_id)
    } else {
        state.control_plane.list_runners()
    };
    match records {
        Ok(records) => {
            let items = match records
                .into_iter()
                .map(runner_view)
                .collect::<Result<_, _>>()
            {
                Ok(items) => items,
                Err(()) => return internal_problem(&request_id),
            };
            Json(Items { items }).into_response()
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn get_runner(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(runner_id): Path<String>,
) -> Response {
    match state.control_plane.runner(&runner_id) {
        Ok(record) => {
            let pool = match state.control_plane.runner_pool(&record.runner.pool_id) {
                Ok(pool) => pool,
                Err(_) => return internal_problem(&request_id),
            };
            if let Err(response) = authorize_resource(
                &state,
                &request_id,
                &principal,
                CedarAction::ManageRunnerPool,
                ServerResource::new(
                    CedarResourceKind::Runner,
                    &record.runner.id,
                    &pool.tenant_id,
                ),
            ) {
                return response;
            }
            match runner_view(record) {
                Ok(runner) => Json(runner).into_response(),
                Err(()) => internal_problem(&request_id),
            }
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentTokenBody {
    #[serde(default = "default_enrollment_lifetime")]
    expires_in_seconds: u64,
}

const fn default_enrollment_lifetime() -> u64 {
    600
}

#[derive(Serialize)]
struct EnrollmentTokenView<'a> {
    token: &'a str,
    expires_at: String,
}

pub(in crate::app) async fn create_enrollment_token(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let pool = match state.control_plane.runner_pool(&pool_id) {
        Ok(pool) => pool,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageRunnerPool,
        ServerResource::new(CedarResourceKind::RunnerPool, &pool.id, &pool.tenant_id),
    ) {
        return response;
    }
    let idempotency_key = match idempotency_key(&request_id, &headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let body: EnrollmentTokenBody = match optional_json(&request_id, body) {
        Ok(body) => body.unwrap_or(EnrollmentTokenBody {
            expires_in_seconds: default_enrollment_lifetime(),
        }),
        Err(response) => return response,
    };
    if !(60..=3600).contains(&body.expires_in_seconds) {
        return problem_response(
            &request_id,
            StatusCode::BAD_REQUEST,
            "Invalid enrollment expiry",
            "expires_in_seconds must be between 60 and 3600",
        );
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let expires = match body
        .expires_in_seconds
        .checked_mul(1000)
        .and_then(|delta| now.checked_add(delta))
    {
        Some(expires) => expires,
        None => return internal_problem(&request_id),
    };
    match state.control_plane.create_enrollment_token_idempotent(
        &idempotency_key,
        &pool_id,
        body.expires_in_seconds,
        now,
        expires,
    ) {
        Ok(EnrollmentTokenIssueResult::Issued(issued)) => {
            match timestamp(issued.metadata.expires_unix_ms) {
                Ok(expires_at) => {
                    let mut response = (
                        StatusCode::CREATED,
                        Json(EnrollmentTokenView {
                            token: issued.token.expose(),
                            expires_at,
                        }),
                    )
                        .into_response();
                    response.headers_mut().insert(
                        IDEMPOTENCY_REPLAYED.clone(),
                        HeaderValue::from_static("false"),
                    );
                    protect_sensitive_response(&mut response);
                    response
                }
                Err(()) => internal_problem(&request_id),
            }
        }
        Ok(EnrollmentTokenIssueResult::Replayed(_)) => {
            let mut response = problem_response(
                &request_id,
                StatusCode::CONFLICT,
                "Enrollment token already issued",
                "this idempotent request already issued a one-time token; its bearer value cannot be replayed",
            );
            response.headers_mut().insert(
                IDEMPOTENCY_REPLAYED.clone(),
                HeaderValue::from_static("true"),
            );
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn drain_runner(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(runner_id): Path<String>,
) -> Response {
    let existing = match state.control_plane.runner(&runner_id) {
        Ok(runner) => runner,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let pool = match state.control_plane.runner_pool(&existing.runner.pool_id) {
        Ok(pool) => pool,
        Err(_) => return internal_problem(&request_id),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageRunnerPool,
        ServerResource::new(
            CedarResourceKind::Runner,
            &existing.runner.id,
            &pool.tenant_id,
        ),
    ) {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    match state.control_plane.drain_runner(&runner_id, now) {
        Ok(record) => match runner_view(record) {
            Ok(view) => (StatusCode::ACCEPTED, Json(view)).into_response(),
            Err(()) => internal_problem(&request_id),
        },
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) fn scope_tenant(
    state: &AppState,
    scope: &str,
) -> Result<String, ControlPlaneError> {
    if let Some(repository_id) = scope.strip_prefix("repository:") {
        return state
            .control_plane
            .repository(repository_id)
            .map(|repository| repository.tenant_id);
    }
    if let Some(tenant_id) = scope.strip_prefix("tenant:") {
        if tenant_id.is_empty() {
            return Err(ControlPlaneError::InvalidInput("tenant scope is empty"));
        }
        return Ok(tenant_id.to_owned());
    }
    Ok("default".to_owned())
}
use axum::response::IntoResponse as _;
