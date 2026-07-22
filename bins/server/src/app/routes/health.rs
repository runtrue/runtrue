use crate::app::{problem_response, AppState, Health, Readiness, RequestId};
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
pub(in crate::app) async fn health() -> impl IntoResponse {
    Json(Health { status: "ok" })
}

pub(in crate::app) async fn readiness(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
) -> Response {
    match state.store.load_database_readiness().await {
        Ok(readiness) if !readiness.recovery.safe_mode => Json(Readiness {
            status: "ready",
            backend: readiness.backend,
            schema_version: readiness.schema_version,
            installation_id: readiness.installation_id,
            fencing_epoch: readiness.recovery.fencing_epoch,
        })
        .into_response(),
        Ok(_) => problem_response(
            &request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "Restore safe mode",
            "restore verification must complete before the control plane becomes ready",
        ),
        Err(_) => problem_response(
            &request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "Service unavailable",
            "the durable control plane is not ready",
        ),
    }
}

pub(in crate::app) async fn route_not_found(
    Extension(request_id): Extension<RequestId>,
) -> Response {
    problem_response(
        &request_id,
        StatusCode::NOT_FOUND,
        "Route not found",
        "the requested endpoint does not exist",
    )
}
