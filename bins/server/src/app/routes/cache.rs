use crate::app::{
    create_promotion_response, invalid_object_problem, require_bootstrap, required_json, AppState,
    RequestId, RequestPrincipal,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use serde_json::Value;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CachePromotionBody {
    target_trust_domain: String,
    evidence: Value,
}

pub(in crate::app) async fn promote_cache(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(entry_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Err(response) = require_bootstrap(&request_id, &principal) {
        return response;
    }
    let body: CachePromotionBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if !body.evidence.is_object() {
        return invalid_object_problem(&request_id, "promotion evidence must be an object");
    }
    create_promotion_response(
        &state,
        &request_id,
        &headers,
        "cache",
        entry_id,
        serde_json::json!({"trust_domain": body.target_trust_domain}),
        body.evidence,
    )
    .await
}
