use crate::app::{
    control_plane_problem, idempotency_key, now_unix_ms, random_id, randomness_problem,
    require_bootstrap, required_json, AppState, RequestId, RequestPrincipal, IDEMPOTENCY_REPLAYED,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_control_plane::PolicyVersionRecord;
use runtrue_model::ContentDigest;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyVersionBody {
    source: String,
    mode: String,
}

pub(in crate::app) async fn create_policy_version(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(policy_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Err(response) = require_bootstrap(&request_id, &principal) {
        return response;
    }
    let body: PolicyVersionBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let idempotency_key = match idempotency_key(&request_id, &headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let version = match state.control_plane.next_policy_version(&policy_id) {
        Ok(version) => version,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let id = match random_id("policy-version") {
        Ok(id) => id,
        Err(()) => return randomness_problem(&request_id),
    };
    let record = PolicyVersionRecord {
        id,
        policy_id,
        version,
        digest: ContentDigest::sha256(body.source.as_bytes()),
        source: body.source,
        mode: body.mode,
        created_unix_ms: now,
    };
    match state
        .control_plane
        .create_policy_version_idempotent(&idempotency_key, &record)
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
use axum::response::IntoResponse as _;
