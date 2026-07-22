use crate::app::{
    api_token_tenant, authorize_tenant_collection, control_plane_problem, problem_response,
    AppState, RequestId, RequestPrincipal,
};
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use runtrue_audit::AuditEvent;
use runtrue_policy::CedarAction;
use serde::{Deserialize, Serialize};
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct AuditListQuery {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Serialize)]
pub(in crate::app) struct AuditPage {
    items: Vec<AuditEvent>,
    next_cursor: Option<String>,
}

pub(in crate::app) async fn list_audit_events(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Query(query): Query<AuditListQuery>,
) -> Response {
    let cursor = match query.cursor.as_deref().map(str::parse::<u64>).transpose() {
        Ok(cursor) => cursor,
        Err(_) => return invalid_object_problem(&request_id, "audit cursor must be an integer"),
    };
    let limit = query.limit.unwrap_or(50);
    let events = if let Some(tenant_id) = api_token_tenant(&principal) {
        if let Err(response) = authorize_tenant_collection(
            &state,
            &request_id,
            &principal,
            CedarAction::ReadAudit,
            tenant_id,
        )
        .await
        {
            return response;
        }
        state
            .store
            .events_page_for_tenant(tenant_id, query.action.as_deref(), cursor, limit)
            .await
    } else {
        state
            .store
            .events_page(query.action.as_deref(), cursor, limit)
            .await
    };
    match events {
        Ok(items) => {
            let next_cursor = (items.len() == limit)
                .then(|| items.last().map(|event| event.sequence.to_string()))
                .flatten();
            Json(AuditPage { items, next_cursor }).into_response()
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) fn invalid_object_problem(
    request_id: &RequestId,
    detail: &'static str,
) -> Response {
    problem_response(
        request_id,
        StatusCode::BAD_REQUEST,
        "Invalid request",
        detail,
    )
}
use axum::response::IntoResponse as _;
