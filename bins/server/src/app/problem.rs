use crate::app::{GitHubLifecycleWorkerError, Problem, RequestId, PROBLEM_MEDIA_TYPE};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use rand_core::OsRng;
use runtrue_auth::AuthError;
use runtrue_control_plane::ControlPlaneError;
use runtrue_oidc::OidcError;
use runtrue_policy::PolicyError;
use runtrue_scm::ScmError;
use serde::de::DeserializeOwned;
use std::time::{SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
#[allow(clippy::result_large_err)]
pub(in crate::app) fn required_json<T: DeserializeOwned>(
    request_id: &RequestId,
    body: Result<Bytes, BytesRejection>,
) -> Result<T, Response> {
    let Some(body) = optional_json(request_id, body)? else {
        return Err(problem_response(
            request_id,
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "a JSON request body is required",
        ));
    };
    Ok(body)
}

#[allow(clippy::result_large_err)]
pub(in crate::app) fn optional_json<T: DeserializeOwned>(
    request_id: &RequestId,
    body: Result<Bytes, BytesRejection>,
) -> Result<Option<T>, Response> {
    let body = body.map_err(|_| payload_too_large_problem(request_id))?;
    if body.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(&body).map(Some).map_err(|_| {
        problem_response(
            request_id,
            StatusCode::BAD_REQUEST,
            "Invalid JSON",
            "the request body is not valid for this endpoint",
        )
    })
}

#[allow(clippy::result_large_err)]
pub(in crate::app) fn idempotency_key(
    request_id: &RequestId,
    headers: &HeaderMap,
) -> Result<String, Response> {
    let name = HeaderName::from_static("idempotency-key");
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return random_id("idem").map_err(|()| randomness_problem(request_id));
    };
    if values.next().is_some() {
        return Err(invalid_idempotency_problem(request_id));
    }
    let value = value
        .to_str()
        .map_err(|_| invalid_idempotency_problem(request_id))?;
    if value.is_empty() || value.len() > 200 || value.contains('\0') {
        return Err(invalid_idempotency_problem(request_id));
    }
    Ok(value.to_owned())
}

pub(in crate::app) fn invalid_idempotency_problem(request_id: &RequestId) -> Response {
    problem_response(
        request_id,
        StatusCode::BAD_REQUEST,
        "Invalid idempotency key",
        "Idempotency-Key must contain 1 to 200 safe bytes",
    )
}

pub(in crate::app) fn random_id(prefix: &str) -> Result<String, ()> {
    let mut bytes = [0_u8; 16];
    OsRng.try_fill_bytes(&mut bytes).map_err(|_| ())?;
    Ok(format!("{prefix}_{}", hex::encode(bytes)))
}

#[allow(clippy::result_large_err)]
pub(in crate::app) fn now_unix_ms(request_id: &RequestId) -> Result<u64, Response> {
    wall_clock_unix_ms().map_err(|_| internal_problem(request_id))
}

pub(in crate::app) fn wall_clock_unix_ms() -> Result<u64, GitHubLifecycleWorkerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(GitHubLifecycleWorkerError::Clock)
}

pub(in crate::app) fn timestamp(unix_ms: u64) -> Result<String, ()> {
    let nanos = i128::from(unix_ms) * 1_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| ())?
        .format(&Rfc3339)
        .map_err(|_| ())
}

pub(in crate::app) fn control_plane_problem(
    request_id: &RequestId,
    error: ControlPlaneError,
) -> Response {
    match error {
        ControlPlaneError::NotFound { .. } => problem_response(
            request_id,
            StatusCode::NOT_FOUND,
            "Resource not found",
            error.to_string(),
        ),
        ControlPlaneError::IdempotencyConflict
        | ControlPlaneError::ApprovalRequired
        | ControlPlaneError::StaleOidcGrant
        | ControlPlaneError::InvalidTransition { .. }
        | ControlPlaneError::ConflictingCompletion
        | ControlPlaneError::InvalidLeaseState { .. }
        | ControlPlaneError::LeaseOfferExpired
        | ControlPlaneError::LeaseExpired
        | ControlPlaneError::EnrollmentTokenConsumed
        | ControlPlaneError::TaskNotOwned
        | ControlPlaneError::TaskLeaseExpired => problem_response(
            request_id,
            StatusCode::CONFLICT,
            "Conflict",
            error.to_string(),
        ),
        ControlPlaneError::Policy(
            PolicyError::IneligibleApprover(_)
            | PolicyError::SeparationOfDuties(_)
            | PolicyError::EmergencyDenied(_),
        ) => problem_response(
            request_id,
            StatusCode::FORBIDDEN,
            "Forbidden",
            error.to_string(),
        ),
        ControlPlaneError::Policy(
            PolicyError::RequestNotPending(_)
            | PolicyError::SubjectConflict { .. }
            | PolicyError::RuleConflict
            | PolicyError::DuplicateDecision(_)
            | PolicyError::NotAuthorized(_),
        ) => problem_response(
            request_id,
            StatusCode::CONFLICT,
            "Conflict",
            error.to_string(),
        ),
        ControlPlaneError::Oidc(OidcError::AudienceNotGranted) => problem_response(
            request_id,
            StatusCode::FORBIDDEN,
            "Forbidden",
            "the requested OIDC audience is not authorized for this step",
        ),
        ControlPlaneError::Oidc(
            OidcError::InvalidIdentifier(_)
            | OidcError::InvalidFencingGeneration
            | OidcError::InvalidAudiences
            | OidcError::InvalidTtl,
        ) => problem_response(
            request_id,
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "the OIDC request is invalid",
        ),
        ControlPlaneError::Secrets(
            runtrue_secrets::SecretsError::InvalidComponent { .. }
            | runtrue_secrets::SecretsError::SecretTooLarge { .. },
        ) => problem_response(
            request_id,
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "the secret metadata or value is invalid",
        ),
        ControlPlaneError::Secrets(
            runtrue_secrets::SecretsError::SecretAlreadyExists(_)
            | runtrue_secrets::SecretsError::SecretTombstoned(_)
            | runtrue_secrets::SecretsError::ImmutableVersionConflict(_),
        ) => problem_response(
            request_id,
            StatusCode::CONFLICT,
            "Conflict",
            "the secret conflicts with existing durable state",
        ),
        ControlPlaneError::Secrets(runtrue_secrets::SecretsError::SecretNotFound(_)) => {
            problem_response(
                request_id,
                StatusCode::NOT_FOUND,
                "Resource not found",
                "the requested secret was not found",
            )
        }
        ControlPlaneError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
            if code.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            problem_response(
                request_id,
                StatusCode::CONFLICT,
                "Conflict",
                "the request conflicts with existing durable state",
            )
        }
        ControlPlaneError::InvalidInput(_)
        | ControlPlaneError::IntegerRange { .. }
        | ControlPlaneError::Model(_)
        | ControlPlaneError::Auth(
            AuthError::InvalidIdentifier(_)
            | AuthError::InvalidScopes
            | AuthError::InvalidLifetime
            | AuthError::InvalidSessionPolicy
            | AuthError::FutureAuthenticationAssertion,
        )
        | ControlPlaneError::Policy(
            PolicyError::InvalidRule(_)
            | PolicyError::InvalidRequest(_)
            | PolicyError::InvalidDecisionTime
            | PolicyError::InvalidReason,
        ) => problem_response(
            request_id,
            StatusCode::BAD_REQUEST,
            "Invalid request",
            error.to_string(),
        ),
        _ => internal_problem(request_id),
    }
}

pub(in crate::app) fn scm_problem(request_id: &RequestId, error: ScmError) -> Response {
    match error {
        ScmError::LimitExceeded(_) => payload_too_large_problem(request_id),
        ScmError::MissingHeader(_) | ScmError::MalformedSignature | ScmError::SignatureMismatch => {
            problem_response(
                request_id,
                StatusCode::UNAUTHORIZED,
                "Invalid webhook authentication",
                "the webhook signature or required authentication headers are invalid",
            )
        }
        ScmError::InvalidConfiguration(_) => internal_problem(request_id),
        _ => problem_response(
            request_id,
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid webhook",
            "the authenticated webhook payload is unsupported or malformed",
        ),
    }
}

pub(in crate::app) fn randomness_problem(request_id: &RequestId) -> Response {
    problem_response(
        request_id,
        StatusCode::SERVICE_UNAVAILABLE,
        "Randomness unavailable",
        "the server cannot safely allocate a resource identifier",
    )
}

pub(in crate::app) fn payload_too_large_problem(request_id: &RequestId) -> Response {
    problem_response(
        request_id,
        StatusCode::PAYLOAD_TOO_LARGE,
        "Payload too large",
        "the request body exceeds the configured limit",
    )
}

pub(in crate::app) fn internal_problem(request_id: &RequestId) -> Response {
    problem_response(
        request_id,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal server error",
        "the server could not complete the operation",
    )
}

pub(in crate::app) fn problem_response(
    request_id: &RequestId,
    status: StatusCode,
    title: &'static str,
    detail: impl Into<String>,
) -> Response {
    let slug = title.to_ascii_lowercase().replace(' ', "-");
    let problem = Problem {
        r#type: format!("https://runtrue.invalid/problems/{slug}"),
        title,
        status: status.as_u16(),
        detail: detail.into(),
        request_id: request_id.0.clone(),
    };
    let mut response = (status, Json(problem)).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(PROBLEM_MEDIA_TYPE));
    response
}
use axum::response::IntoResponse as _;
use rand_core::RngCore as _;
