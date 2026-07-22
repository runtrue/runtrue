use crate::app::{
    auth_input_problem, authorize_resource, authorize_tenant_collection, control_plane_problem,
    internal_problem, invalid_object_problem, now_unix_ms, principal_can_delegate,
    principal_matches_tenant, problem_response, random_id, randomness_problem,
    request_audit_principal, request_credential_id, required_json, timestamp, AppState, RequestId,
    RequestPrincipal, ServerResource, MAX_API_TOKEN_TTL_MS,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_auth::{ApiTokenRecord, IssueApiToken};
use runtrue_policy::{CedarAction, CedarResourceKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateApiTokenBody {
    #[serde(default)]
    id: Option<String>,
    principal_id: String,
    #[serde(default)]
    tenant_id: Option<String>,
    name: String,
    scopes: BTreeSet<String>,
    ttl_seconds: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct ApiTokenListQuery {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ApiTokenView {
    id: String,
    principal_id: String,
    tenant_id: String,
    name: String,
    scopes: BTreeSet<String>,
    created_at: String,
    expires_at: String,
    last_used_at: Option<String>,
    revoked_at: Option<String>,
}

impl ApiTokenView {
    fn from_record(record: ApiTokenRecord) -> Result<Self, ()> {
        Ok(Self {
            id: record.id,
            principal_id: record.principal_id,
            tenant_id: record.tenant_id,
            name: record.name,
            scopes: record.scopes,
            created_at: timestamp(record.created_unix_ms)?,
            expires_at: timestamp(record.expires_unix_ms)?,
            last_used_at: record.last_used_unix_ms.map(timestamp).transpose()?,
            revoked_at: record.revoked_unix_ms.map(timestamp).transpose()?,
        })
    }
}

#[derive(Serialize)]
struct IssuedApiTokenView<'a> {
    token: &'a str,
    token_type: &'static str,
    #[serde(flatten)]
    metadata: ApiTokenView,
}

#[derive(Serialize)]
struct ApiTokenPage {
    items: Vec<ApiTokenView>,
    next_cursor: Option<String>,
}

pub(in crate::app) async fn create_api_token(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: CreateApiTokenBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let tenant_id = body.tenant_id.unwrap_or_else(|| match &principal {
        RequestPrincipal::Bootstrap => "default".to_owned(),
        RequestPrincipal::ApiToken(context) => context.tenant_id.clone(),
    });
    if !principal_can_delegate(&principal, &tenant_id, &body.scopes) {
        return problem_response(
            &request_id,
            StatusCode::FORBIDDEN,
            "Forbidden",
            "an API token cannot delegate another tenant or scopes it does not hold",
        );
    }
    let (principal_id, parent_token) = match &principal {
        RequestPrincipal::Bootstrap => (body.principal_id, None),
        RequestPrincipal::ApiToken(context) => {
            if body.principal_id != context.principal_id {
                return problem_response(
                    &request_id,
                    StatusCode::FORBIDDEN,
                    "Forbidden",
                    "an API token cannot delegate a different durable principal identity",
                );
            }
            let (Some(credential_id), Some(credential_expires_unix_ms)) = (
                context.credential_id.clone(),
                context.credential_expires_unix_ms,
            ) else {
                return internal_problem(&request_id);
            };
            (
                context.principal_id.clone(),
                Some((credential_id, credential_expires_unix_ms)),
            )
        }
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let ttl_ms = match body.ttl_seconds.checked_mul(1000) {
        Some(ttl) if ttl > 0 && ttl <= MAX_API_TOKEN_TTL_MS => ttl,
        _ => {
            return invalid_object_problem(
                &request_id,
                "ttl_seconds must be between one second and 365 days",
            )
        }
    };
    let expires_unix_ms = match now.checked_add(ttl_ms) {
        Some(expires) => expires,
        None => return invalid_object_problem(&request_id, "API token lifetime overflows"),
    };
    if parent_token
        .as_ref()
        .is_some_and(|(_, parent_expiry)| expires_unix_ms > *parent_expiry)
    {
        return problem_response(
            &request_id,
            StatusCode::FORBIDDEN,
            "Forbidden",
            "a delegated API token cannot outlive its authenticated parent",
        );
    }
    let id = match body.id {
        Some(id) => id,
        None => match random_id("api-token") {
            Ok(id) => id,
            Err(()) => return randomness_problem(&request_id),
        },
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageApiToken,
        ServerResource::new(CedarResourceKind::ApiToken, &id, &tenant_id),
    )
    .await
    {
        return response;
    }
    let issued = match ApiTokenRecord::issue(
        &state.token_hasher,
        IssueApiToken {
            id,
            principal_id,
            tenant_id,
            name: body.name,
            scopes: body.scopes,
            created_unix_ms: now,
            expires_unix_ms,
        },
    ) {
        Ok(issued) => issued,
        Err(error) => return auth_input_problem(&request_id, error),
    };
    let metadata = match ApiTokenView::from_record(issued.record.clone()) {
        Ok(metadata) => metadata,
        Err(()) => return internal_problem(&request_id),
    };
    let actor = request_audit_principal(&principal);
    let persisted = state
        .store
        .create_token(
            &issued.record,
            parent_token.as_ref().map(|(id, _)| id.as_str()),
            actor,
            &request_id.0,
        )
        .await;
    if let Err(error) = persisted {
        return control_plane_problem(&request_id, error);
    }
    let mut response = (
        StatusCode::CREATED,
        Json(IssuedApiTokenView {
            token: issued.token.expose(),
            token_type: "Bearer",
            metadata,
        }),
    )
        .into_response();
    protect_sensitive_response(&mut response);
    response
}

pub(in crate::app) fn protect_sensitive_response(response: &mut Response) {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
}

pub(in crate::app) async fn list_api_tokens(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Query(query): Query<ApiTokenListQuery>,
) -> Response {
    let tenant_id = query.tenant_id.unwrap_or_else(|| match &principal {
        RequestPrincipal::Bootstrap => "default".to_owned(),
        RequestPrincipal::ApiToken(context) => context.tenant_id.clone(),
    });
    if !principal_matches_tenant(&principal, &tenant_id) {
        return problem_response(
            &request_id,
            StatusCode::FORBIDDEN,
            "Forbidden",
            "an API token cannot enumerate another tenant",
        );
    }
    if let Err(response) = authorize_tenant_collection(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageApiToken,
        &tenant_id,
    )
    .await
    {
        return response;
    }
    let limit = query.limit.unwrap_or(50);
    match state
        .store
        .tokens_page(&tenant_id, query.cursor.as_deref(), limit)
        .await
    {
        Ok(records) => {
            let next_cursor = (records.len() == limit)
                .then(|| records.last().map(|record| record.id.clone()))
                .flatten();
            match records
                .into_iter()
                .map(ApiTokenView::from_record)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(items) => Json(ApiTokenPage { items, next_cursor }).into_response(),
                Err(()) => internal_problem(&request_id),
            }
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn revoke_api_token(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(token_id): Path<String>,
) -> Response {
    let existing = match state.store.token(&token_id).await {
        Ok(record) => record,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageApiToken,
        ServerResource::new(
            CedarResourceKind::ApiToken,
            &existing.id,
            &existing.tenant_id,
        ),
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
        .revoke_token(
            &token_id,
            request_audit_principal(&principal),
            request_credential_id(&principal),
            &request_id.0,
            now,
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}
use axum::response::IntoResponse as _;
