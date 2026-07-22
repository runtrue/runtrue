use crate::app::{
    approval_actor_id, authorize_resource, control_plane_problem, idempotency_key,
    internal_problem, now_unix_ms, timestamp, AppState, RequestId, RequestPrincipal,
    ServerResource, IDEMPOTENCY_REPLAYED,
};
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use runtrue_control_plane::{DurableEventRecord, DurableTaskStatus, ReplayEventRequest};
use runtrue_model::ContentDigest;
use runtrue_policy::{CedarAction, CedarResourceKind};
use serde::Serialize;

#[derive(Serialize)]
struct EventView {
    id: String,
    source: runtrue_control_plane::DurableEventSource,
    kind: String,
    payload_digest: ContentDigest,
    status: DurableTaskStatus,
    attempts: u32,
    created_at: String,
}

#[derive(Serialize)]
struct EventReplayView {
    id: String,
    event_id: String,
    task_id: String,
    status: DurableTaskStatus,
    queued_at: String,
}

async fn authorized_event(
    state: &AppState,
    request_id: &RequestId,
    principal: &RequestPrincipal,
    event_id: &str,
) -> Result<DurableEventRecord, Response> {
    let event = state
        .store
        .event(event_id)
        .await
        .map_err(|error| control_plane_problem(request_id, error))?;
    authorize_resource(
        state,
        request_id,
        principal,
        CedarAction::ReplayEvent,
        ServerResource::new(CedarResourceKind::Event, &event.id, &event.tenant_id),
    )
    .await?;
    Ok(event)
}

pub(in crate::app) async fn get_event(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(event_id): Path<String>,
) -> Response {
    let event = match authorized_event(&state, &request_id, &principal, &event_id).await {
        Ok(event) => event,
        Err(response) => return response,
    };
    let task = match state.store.task(&event.task_id).await {
        Ok(task) => task,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let created_at = match timestamp(event.created_unix_ms) {
        Ok(value) => value,
        Err(()) => return internal_problem(&request_id),
    };
    Json(EventView {
        id: event.id,
        source: event.source,
        kind: event.kind,
        payload_digest: event.payload_digest,
        status: task.status,
        attempts: task.attempts,
        created_at,
    })
    .into_response()
}

pub(in crate::app) async fn replay_event(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(event_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let event = match authorized_event(&state, &request_id, &principal, &event_id).await {
        Ok(event) => event,
        Err(response) => return response,
    };
    let key = match idempotency_key(&request_id, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let requested_by = approval_actor_id(&principal);
    let identity = ContentDigest::sha256(
        format!(
            "runtrue.event.replay.v1\0{}\0{}\0{}\0{}",
            event.tenant_id, event.id, requested_by, key
        )
        .as_bytes(),
    );
    let suffix = identity.as_str().trim_start_matches("sha256:");
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let request = ReplayEventRequest {
        id: format!("replay-{suffix}"),
        event_id: event.id,
        requested_by,
        requested_unix_ms: now,
    };
    let result = match state.store.replay_event(&event.tenant_id, &request).await {
        Ok(result) => result,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let queued_at = match timestamp(result.value.requested_unix_ms) {
        Ok(value) => value,
        Err(()) => return internal_problem(&request_id),
    };
    let mut response = (
        StatusCode::ACCEPTED,
        Json(EventReplayView {
            id: result.value.id,
            event_id: result.value.event_id,
            task_id: result.value.task_id,
            status: DurableTaskStatus::Pending,
            queued_at,
        }),
    )
        .into_response();
    response.headers_mut().insert(
        IDEMPOTENCY_REPLAYED.clone(),
        HeaderValue::from_static(if result.replayed { "true" } else { "false" }),
    );
    response
}
