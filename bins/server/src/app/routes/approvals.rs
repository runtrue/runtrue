use crate::app::{
    api_token_tenant, approval_actor_id, authorize_resource, authorize_tenant_collection,
    control_plane_problem, idempotency_key, internal_problem, now_unix_ms, problem_response,
    required_json, timestamp, AppState, RequestId, RequestPrincipal, ServerResource,
    IDEMPOTENCY_REPLAYED,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_model::ContentDigest;
use runtrue_policy::{
    ApprovalDecision, ApprovalKind, ApprovalRequest, CedarAction, CedarResourceKind, Decision,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Serialize)]
struct ApprovalView {
    id: String,
    subject_digest: String,
    approval_kind: Value,
    status: Value,
    risk_score: u32,
    expires_at: Option<String>,
}

impl ApprovalView {
    fn from_record(record: ApprovalRequest) -> Result<Self, ()> {
        Ok(Self {
            id: record.id,
            subject_digest: record.subject_digest.to_string(),
            approval_kind: serde_json::to_value(record.kind).map_err(|_| ())?,
            status: serde_json::to_value(record.status).map_err(|_| ())?,
            risk_score: record.risk_score,
            expires_at: Some(timestamp(record.expires_unix_ms)?),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct ApprovalListQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ApprovalPage {
    items: Vec<ApprovalView>,
    next_cursor: Option<String>,
}

pub(in crate::app) async fn list_approvals(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Query(query): Query<ApprovalListQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(50);
    let records = if let Some(tenant_id) = api_token_tenant(&principal) {
        if let Err(response) = authorize_tenant_collection(
            &state,
            &request_id,
            &principal,
            CedarAction::ApproveWorkflow,
            tenant_id,
        ) {
            return response;
        }
        state.control_plane.list_approval_requests_page_for_tenant(
            tenant_id,
            query.status.as_deref(),
            query.cursor.as_deref(),
            limit,
        )
    } else {
        state.control_plane.list_approval_requests_page(
            query.status.as_deref(),
            query.cursor.as_deref(),
            limit,
        )
    };
    let records = match records {
        Ok(records) => records,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let next_cursor = (records.len() == limit)
        .then(|| records.last().map(|record| record.id.clone()))
        .flatten();
    let items = match records
        .into_iter()
        .map(ApprovalView::from_record)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(items) => items,
        Err(()) => return internal_problem(&request_id),
    };
    Json(ApprovalPage { items, next_cursor }).into_response()
}

pub(in crate::app) async fn get_approval(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(approval_id): Path<String>,
) -> Response {
    match state.control_plane.approval_request(&approval_id) {
        Ok(record) => {
            let tenant = match state.control_plane.approval_request_tenant(&approval_id) {
                Ok(tenant) => tenant,
                Err(_) => return internal_problem(&request_id),
            };
            if let Err(response) = authorize_resource(
                &state,
                &request_id,
                &principal,
                approval_action(record.kind),
                ServerResource::new(CedarResourceKind::ApprovalRequest, &record.id, &tenant)
                    .with_risk(
                        record.risk_score,
                        record.kind != ApprovalKind::WorkflowDefinition,
                        false,
                    ),
            ) {
                return response;
            }
            match ApprovalView::from_record(record) {
                Ok(approval) => Json(approval).into_response(),
                Err(()) => internal_problem(&request_id),
            }
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDecisionBody {
    decision: Decision,
    subject_digest: String,
    reason: String,
    rule_id: String,
}

pub(in crate::app) async fn decide_approval(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(approval_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let approval = match state.control_plane.approval_request(&approval_id) {
        Ok(approval) => approval,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let tenant = match state.control_plane.approval_request_tenant(&approval_id) {
        Ok(tenant) => tenant,
        Err(_) => return internal_problem(&request_id),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        approval_action(approval.kind),
        ServerResource::new(CedarResourceKind::ApprovalRequest, &approval.id, &tenant).with_risk(
            approval.risk_score,
            approval.kind != ApprovalKind::WorkflowDefinition,
            false,
        ),
    ) {
        return response;
    }
    let body: ApprovalDecisionBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let idempotency_key = match idempotency_key(&request_id, &headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let subject_digest = match ContentDigest::parse(body.subject_digest) {
        Ok(digest) => digest,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "subject_digest must be a qualified SHA-256 digest",
            )
        }
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let decision = ApprovalDecision {
        actor_id: approval_actor_id(&principal),
        decision: body.decision,
        reason: body.reason,
        rule_id: body.rule_id,
        subject_digest,
        decided_unix_ms: now,
    };
    match state.control_plane.decide_approval_idempotent(
        &idempotency_key,
        &approval_id,
        decision,
        now,
    ) {
        Ok(result) => match ApprovalView::from_record(result.value) {
            Ok(approval) => {
                let mut response = (StatusCode::CREATED, Json(approval)).into_response();
                response.headers_mut().insert(
                    IDEMPOTENCY_REPLAYED.clone(),
                    HeaderValue::from_static(if result.replayed { "true" } else { "false" }),
                );
                response
            }
            Err(()) => internal_problem(&request_id),
        },
        Err(error) => control_plane_problem(&request_id, error),
    }
}

const fn approval_action(kind: ApprovalKind) -> CedarAction {
    match kind {
        ApprovalKind::WorkflowDefinition => CedarAction::ApproveWorkflow,
        ApprovalKind::PrivilegedExecution
        | ApprovalKind::EnvironmentDeployment
        | ApprovalKind::ArtifactPromotion
        | ApprovalKind::BreakGlass => CedarAction::ApprovePrivilegedRun,
    }
}
use axum::response::IntoResponse as _;
