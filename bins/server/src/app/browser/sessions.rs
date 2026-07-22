use super::{
    cookies::{
        append_session_cookies, clear_all_browser_cookies, clear_browser_authentication,
        sealed_cookie,
    },
    csrf::{browser_csrf_input, constant_time_text_equal},
};
use crate::app::{
    authentication_problem, internal_problem, now_unix_ms, protect_sensitive_response, AppState,
    RequestId, ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE, SESSION_WRITE_SCOPE,
};
use axum::{
    body::Bytes,
    extract::{rejection::BytesRejection, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use runtrue_auth::{AuthContext, AuthError, RotateSessionRequest, SessionPolicy, SessionRecord};
use runtrue_control_plane::{ControlPlaneError, R9AuditMetadata};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct SessionCookiePayload {
    pub(in crate::app) session_id: String,
    pub(in crate::app) tenant_id: String,
    pub(in crate::app) token: String,
}

impl Drop for SessionCookiePayload {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.session_id.zeroize();
        self.tenant_id.zeroize();
        self.token.zeroize();
    }
}

pub(in crate::app) async fn refresh_browser_session(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(human) = state.human_oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, body) {
        Ok(token) => token,
        Err(response) => return *response,
    };
    let refresh = match sealed_cookie::<SessionCookiePayload>(&headers, human, REFRESH_COOKIE) {
        Ok(payload) => payload,
        Err(_) => return clear_browser_authentication(authentication_problem(&request_id)),
    };
    let csrf = match sealed_cookie::<SessionCookiePayload>(&headers, human, CSRF_COOKIE) {
        Ok(payload) => payload,
        Err(_) => return clear_browser_authentication(authentication_problem(&request_id)),
    };
    if refresh.session_id != csrf.session_id
        || refresh.tenant_id != csrf.tenant_id
        || !constant_time_text_equal(&csrf.token, &presented_csrf)
    {
        return clear_browser_authentication(authentication_problem(&request_id));
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let mut record = match state
        .store
        .session(&refresh.tenant_id, &refresh.session_id)
        .await
    {
        Ok(record) => record,
        Err(_) => return clear_browser_authentication(authentication_problem(&request_id)),
    };
    let generation = record.access_generation;
    let rotated = record.rotate(
        &state.token_hasher,
        human.session_policy,
        RotateSessionRequest {
            refresh_token: &refresh.token,
            csrf_token: &presented_csrf,
            require_mfa_within_ms: None,
            now_unix_ms: now,
        },
    );
    let audit = R9AuditMetadata {
        actor_id: record.principal_id.clone(),
        correlation_id: request_id.0.clone(),
        occurred_unix_ms: now,
    };
    let rotated = match rotated {
        Ok(rotated) => rotated,
        Err(error) => {
            if record.revoked_unix_ms.is_some() {
                match state
                    .store
                    .persist_session(&record, Some(generation), &audit)
                    .await
                {
                    Ok(_) => {}
                    Err(ControlPlaneError::IdempotencyConflict) => {
                        if revoke_refresh_family_after_conflict(
                            &state,
                            &refresh,
                            &presented_csrf,
                            now,
                            &audit,
                        )
                        .await
                        .is_err()
                        {
                            return clear_browser_authentication(internal_problem(&request_id));
                        }
                    }
                    Err(_) => return clear_browser_authentication(internal_problem(&request_id)),
                }
            }
            if error == AuthError::RefreshReplay {
                human.metrics.refresh_replay_revoked();
            }
            return clear_browser_authentication(authentication_problem(&request_id));
        }
    };
    match state
        .store
        .persist_session(&record, Some(generation), &audit)
        .await
    {
        Ok(_) => {}
        Err(ControlPlaneError::IdempotencyConflict) => {
            if revoke_refresh_family_after_conflict(&state, &refresh, &presented_csrf, now, &audit)
                .await
                .is_err()
            {
                return clear_browser_authentication(internal_problem(&request_id));
            }
            human.metrics.refresh_replay_revoked();
            return clear_browser_authentication(authentication_problem(&request_id));
        }
        Err(_) => return clear_browser_authentication(internal_problem(&request_id)),
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    if append_session_cookies(
        &mut response,
        human,
        &record,
        rotated.access_token.expose(),
        rotated.refresh_token.expose(),
        rotated.csrf_token.expose(),
        now,
    )
    .is_err()
    {
        return internal_problem(&request_id);
    }
    protect_sensitive_response(&mut response);
    human.metrics.session_rotated();
    response
}

pub(in crate::app) async fn logout_browser_session(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(human) = state.human_oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let presented_csrf = match browser_csrf_input(&request_id, &headers, body) {
        Ok(token) => token,
        Err(response) => return *response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let (_, mut record, _) = match authenticated_browser_session(
        &state,
        &request_id,
        &headers,
        SESSION_WRITE_SCOPE,
        Some(&presented_csrf),
        now,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return clear_browser_authentication(*response),
    };
    let generation = record.access_generation;
    record.revoke(now);
    let audit = R9AuditMetadata {
        actor_id: record.principal_id.clone(),
        correlation_id: request_id.0.clone(),
        occurred_unix_ms: now,
    };
    if state
        .store
        .persist_session(&record, Some(generation), &audit)
        .await
        .is_err()
    {
        return internal_problem(&request_id);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_all_browser_cookies(&mut response);
    protect_sensitive_response(&mut response);
    human.metrics.session_logged_out();
    response
}
pub(in crate::app) async fn authenticated_browser_session(
    state: &AppState,
    request_id: &RequestId,
    headers: &HeaderMap,
    required_scope: &str,
    presented_csrf: Option<&str>,
    now_unix_ms: u64,
) -> Result<(AuthContext, SessionRecord, String), Box<Response>> {
    let human = state
        .human_oidc
        .as_ref()
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;
    let access = sealed_cookie::<SessionCookiePayload>(headers, human, ACCESS_COOKIE)
        .map_err(|_| authentication_problem(request_id))?;
    let csrf = sealed_cookie::<SessionCookiePayload>(headers, human, CSRF_COOKIE)
        .map_err(|_| authentication_problem(request_id))?;
    if access.session_id != csrf.session_id || access.tenant_id != csrf.tenant_id {
        return Err(authentication_problem(request_id).into());
    }
    let record = state
        .store
        .session(&access.tenant_id, &access.session_id)
        .await
        .map_err(|_| authentication_problem(request_id))?;
    let context = record
        .authenticate_browser_request(
            &state.token_hasher,
            &access.token,
            Some(&csrf.token),
            required_scope,
            true,
            now_unix_ms,
        )
        .map_err(|_| authentication_problem(request_id))?;
    if let Some(presented) = presented_csrf {
        record
            .authenticate_browser_request(
                &state.token_hasher,
                &access.token,
                Some(presented),
                required_scope,
                true,
                now_unix_ms,
            )
            .map_err(|_| authentication_problem(request_id))?;
    }
    Ok((context, record, csrf.token.clone()))
}

pub(in crate::app) async fn revoke_refresh_family_after_conflict(
    state: &AppState,
    presented: &SessionCookiePayload,
    csrf_token: &str,
    now: u64,
    audit: &R9AuditMetadata,
) -> Result<(), ControlPlaneError> {
    for _ in 0..3 {
        let mut latest = state
            .store
            .session(&presented.tenant_id, &presented.session_id)
            .await?;
        let generation = latest.access_generation;
        let mut replay_probe = latest.clone();
        let replay = replay_probe.rotate(
            &state.token_hasher,
            state
                .human_oidc
                .as_ref()
                .map_or_else(SessionPolicy::default, |human| human.session_policy),
            RotateSessionRequest {
                refresh_token: &presented.token,
                csrf_token,
                require_mfa_within_ms: None,
                now_unix_ms: now,
            },
        );
        if replay.is_err() && replay_probe.revoked_unix_ms.is_some() {
            latest = replay_probe;
        } else {
            latest.revoke(now);
        }
        match state
            .store
            .persist_session(&latest, Some(generation), audit)
            .await
        {
            Ok(_) => return Ok(()),
            Err(ControlPlaneError::IdempotencyConflict) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(ControlPlaneError::IdempotencyConflict)
}
