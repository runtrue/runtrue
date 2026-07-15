use crate::app::{
    internal_problem, now_unix_ms, problem_response, AppState, RequestId, RequestPrincipal,
    FALLBACK_REQUEST_ID, MAX_BOOTSTRAP_TOKEN_BYTES, MAX_REQUEST_ID_BYTES, MAX_REQUEST_TARGET_BYTES,
    PROBLEM_MEDIA_TYPE, SCM_READ_SCOPE, SCM_WRITE_SCOPE, X_REQUEST_ID,
};
use axum::extract::State;
use axum::http::header::{ALLOW, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use rand_core::OsRng;
use runtrue_auth::AuthError;
use runtrue_control_plane::ControlPlaneError;
use std::sync::atomic::Ordering;
use std::time::Duration;
pub(in crate::app) async fn request_context<B>(
    mut request: Request<B>,
    next: Next<B>,
    request_timeout: Duration,
) -> Response {
    let request_id = request_id(request.headers());
    request.extensions_mut().insert(request_id.clone());
    if request
        .uri()
        .path_and_query()
        .map_or(0, |value| value.as_str().len())
        > MAX_REQUEST_TARGET_BYTES
    {
        let mut response = problem_response(
            &request_id,
            StatusCode::URI_TOO_LONG,
            "Request target too long",
            "the path and query exceed the server request-target bound",
        );
        if let Ok(value) = HeaderValue::from_str(&request_id.0) {
            response.headers_mut().insert(X_REQUEST_ID.clone(), value);
        }
        return response;
    }
    let mut response = match tokio::time::timeout(request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => problem_response(
            &request_id,
            StatusCode::REQUEST_TIMEOUT,
            "Request timed out",
            "the request exceeded the server processing deadline",
        ),
    };
    response = normalize_framework_error(&request_id, response);
    if let Ok(value) = HeaderValue::from_str(&request_id.0) {
        response.headers_mut().insert(X_REQUEST_ID.clone(), value);
    }
    response
}

pub(in crate::app) async fn require_bearer<B>(
    State(state): State<AppState>,
    mut request: Request<B>,
    next: Next<B>,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(generated_request_id);
    let Some(candidate) = bearer_token(request.headers()) else {
        return authentication_problem(&request_id);
    };
    if state.auth.verify(&candidate) {
        request.extensions_mut().insert(RequestPrincipal::Bootstrap);
        return next.run(request).await;
    }

    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let required_scope = required_api_scope(request.method(), request.uri().path());
    match state.control_plane.authenticate_api_token(
        &state.token_hasher,
        &candidate,
        required_scope,
        now,
    ) {
        Ok(context) => {
            request
                .extensions_mut()
                .insert(RequestPrincipal::ApiToken(context));
            next.run(request).await
        }
        Err(ControlPlaneError::Auth(AuthError::InsufficientScope(_))) => problem_response(
            &request_id,
            StatusCode::FORBIDDEN,
            "Forbidden",
            "the bearer token does not grant the required API scope",
        ),
        Err(ControlPlaneError::Auth(
            AuthError::InvalidCredential | AuthError::Expired | AuthError::Revoked,
        )) => authentication_problem(&request_id),
        Err(_) => internal_problem(&request_id),
    }
}

pub(in crate::app) fn required_api_scope(method: &Method, path: &str) -> &'static str {
    let read = method == Method::GET || method == Method::HEAD;
    if path.starts_with("/api/v1/api-tokens") {
        if read {
            "tokens:read"
        } else {
            "tokens:write"
        }
    } else if path.contains("/secrets") {
        if read {
            "secrets:read"
        } else {
            "secrets:write"
        }
    } else if path.starts_with("/api/v1/approval-requests") {
        if read {
            "approvals:read"
        } else {
            "approvals:write"
        }
    } else if path.starts_with("/api/v1/runners") || path.starts_with("/api/v1/runner-pools") {
        if read {
            "runners:read"
        } else {
            "runners:write"
        }
    } else if path.starts_with("/api/v1/audit-events") {
        "audit:read"
    } else if path.starts_with("/api/v1/policies") {
        if read {
            "policies:read"
        } else {
            "policies:write"
        }
    } else if path.starts_with("/api/v1/scm/") {
        if read {
            SCM_READ_SCOPE
        } else {
            SCM_WRITE_SCOPE
        }
    } else if path.contains("/promote") {
        "promotions:write"
    } else if read {
        "api:read"
    } else {
        "api:write"
    }
}

pub(in crate::app) fn authentication_problem(request_id: &RequestId) -> Response {
    let mut response = problem_response(
        request_id,
        StatusCode::UNAUTHORIZED,
        "Unauthorized",
        "a valid bearer token is required",
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

pub(in crate::app) async fn require_writable_control_plane<B>(
    State(state): State<AppState>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    if !matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return next.run(request).await;
    }
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(generated_request_id);
    match state.control_plane.recovery_state() {
        Ok(state) if !state.safe_mode => next.run(request).await,
        Ok(_) => problem_response(
            &request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "Restore safe mode",
            "state mutation is disabled until restore verification is acknowledged",
        ),
        Err(_) => problem_response(
            &request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "Service unavailable",
            "the durable recovery state could not be verified",
        ),
    }
}

pub(in crate::app) async fn require_writable_human_auth<B>(
    State(state): State<AppState>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(generated_request_id);
    match state.control_plane.recovery_state() {
        Ok(state) if !state.safe_mode => next.run(request).await,
        Ok(_) => problem_response(
            &request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "Restore safe mode",
            "authentication state mutation is disabled until restore verification is acknowledged",
        ),
        Err(_) => problem_response(
            &request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "Service unavailable",
            "the durable recovery state could not be verified",
        ),
    }
}

pub(in crate::app) fn normalize_framework_error(
    request_id: &RequestId,
    response: Response,
) -> Response {
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error())
        || response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with(PROBLEM_MEDIA_TYPE))
    {
        return response;
    }
    let allow = response.headers().get(ALLOW).cloned();
    let (title, detail) = match status {
        StatusCode::BAD_REQUEST => ("Invalid request", "the request could not be decoded"),
        StatusCode::UNAUTHORIZED => ("Unauthorized", "authentication is required"),
        StatusCode::FORBIDDEN => ("Forbidden", "the operation is not permitted"),
        StatusCode::NOT_FOUND => ("Route not found", "the requested endpoint does not exist"),
        StatusCode::METHOD_NOT_ALLOWED => (
            "Method not allowed",
            "the endpoint does not support this HTTP method",
        ),
        StatusCode::PAYLOAD_TOO_LARGE => {
            ("Payload too large", "the request body exceeds its limit")
        }
        StatusCode::UNSUPPORTED_MEDIA_TYPE => (
            "Unsupported media type",
            "the request media type is not supported",
        ),
        StatusCode::REQUEST_TIMEOUT => (
            "Request timed out",
            "the request exceeded the processing deadline",
        ),
        _ if status.is_server_error() => (
            "Internal server error",
            "the server could not complete the operation",
        ),
        _ => ("Request rejected", "the server rejected the request"),
    };
    let mut normalized = problem_response(request_id, status, title, detail);
    if let Some(allow) = allow {
        normalized.headers_mut().insert(ALLOW, allow);
    }
    normalized
}

pub(in crate::app) fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > MAX_BOOTSTRAP_TOKEN_BYTES
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(token.to_owned())
}

pub(in crate::app) fn request_id(headers: &HeaderMap) -> RequestId {
    let mut values = headers.get_all(&X_REQUEST_ID).iter();
    if let Some(value) = values.next() {
        if values.next().is_none() {
            if let Ok(value) = value.to_str() {
                if !value.is_empty()
                    && value.len() <= MAX_REQUEST_ID_BYTES
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return RequestId(value.to_owned());
                }
            }
        }
    }
    generated_request_id()
}

pub(in crate::app) fn generated_request_id() -> RequestId {
    let mut bytes = [0_u8; 16];
    if OsRng.try_fill_bytes(&mut bytes).is_ok() {
        RequestId(hex::encode(bytes))
    } else {
        RequestId(format!(
            "fallback-{}",
            FALLBACK_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }
}
use rand_core::RngCore as _;
