use super::{
    cookies::{
        append_cookie, append_github_credential_cookie, append_session_cookies, clear_cookie,
        sealed_cookie,
    },
    csrf::{constant_time_text_equal, valid_return_to},
    status::{callback_failure, hidden_login_resource, human_oidc_unavailable},
};
use crate::app::{
    internal_problem, invalid_object_problem, now_unix_ms, protect_sensitive_response, random_id,
    randomness_problem, AppState, RequestId, GITHUB_CREDENTIAL_COOKIE, LOGIN_COOKIE,
    OIDC_LOGIN_TTL_MS, POLICY_READ_SCOPE, SCM_READ_SCOPE, SCM_WRITE_SCOPE, SESSION_READ_SCOPE,
    SESSION_WRITE_SCOPE,
};
use crate::human_oidc::encode_query_component;
use axum::{
    extract::{Extension, Query, State},
    http::{header::LOCATION, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use runtrue_auth::{
    AuthError, BeginOidcExchange, IssueOidcAuthorization, IssueSession,
    OidcAuthorizationTransaction, OidcTransactionStatus, SessionRecord,
};
use runtrue_control_plane::{
    ControlPlaneError, HumanIdentityRecord, HumanUserRecord, R9AuditMetadata,
    TenantMembershipRecord,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct HumanLoginQuery {
    tenant_id: String,
    provider_id: String,
    #[serde(default)]
    return_to: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct GitHubOauthLoginQuery {
    #[serde(default)]
    return_to: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct HumanOidcCallbackQuery {
    code: String,
    state: String,
}

impl Drop for HumanOidcCallbackQuery {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.code.zeroize();
        self.state.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct LoginCookiePayload {
    transaction_id: String,
    tenant_id: String,
    provider_id: String,
    state: String,
    nonce: String,
    pkce_verifier: String,
    return_to: String,
    expires_unix_ms: u64,
}

impl Drop for LoginCookiePayload {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.transaction_id.zeroize();
        self.tenant_id.zeroize();
        self.provider_id.zeroize();
        self.state.zeroize();
        self.nonce.zeroize();
        self.pkce_verifier.zeroize();
        self.return_to.zeroize();
    }
}

pub(in crate::app) async fn begin_human_oidc_login(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Query(query): Query<HumanLoginQuery>,
) -> Response {
    let Some(human) = state.human_oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let return_to = query.return_to.as_deref().unwrap_or("/ui/session");
    if !valid_return_to(return_to) {
        return invalid_object_problem(&request_id, "return_to must be a bounded local path");
    }
    let provider = match state
        .store
        .oidc_provider(&query.tenant_id, &query.provider_id)
        .await
    {
        Ok(provider) if provider.status == "active" => provider,
        _ => return hidden_login_resource(&request_id),
    };
    let expected_redirect = format!("{}/auth/oidc/callback", human.public_origin);
    if provider.redirect_uri != expected_redirect || provider.authorization_endpoint.contains('?') {
        return hidden_login_resource(&request_id);
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let expires = match now.checked_add(OIDC_LOGIN_TTL_MS) {
        Some(expires) => expires,
        None => return internal_problem(&request_id),
    };
    let transaction_id = match random_id("login") {
        Ok(id) => id,
        Err(()) => return randomness_problem(&request_id),
    };
    let issued = match OidcAuthorizationTransaction::issue(
        &state.token_hasher,
        IssueOidcAuthorization {
            id: transaction_id,
            tenant_id: provider.tenant_id.clone(),
            provider_configuration_id: provider.id.clone(),
            issuer: provider.issuer.clone(),
            client_id: provider.client_id.clone(),
            redirect_uri: provider.redirect_uri.clone(),
            created_unix_ms: now,
            expires_unix_ms: expires,
        },
    ) {
        Ok(issued) => issued,
        Err(_) => return hidden_login_resource(&request_id),
    };
    let audit = R9AuditMetadata {
        actor_id: "anonymous-browser".to_owned(),
        correlation_id: request_id.0.clone(),
        occurred_unix_ms: now,
    };
    if state
        .store
        .persist_oidc_transaction(&issued.record, &audit)
        .await
        .is_err()
    {
        return hidden_login_resource(&request_id);
    }
    let payload = LoginCookiePayload {
        transaction_id: issued.record.id.clone(),
        tenant_id: issued.record.tenant_id.clone(),
        provider_id: issued.record.provider_configuration_id.clone(),
        state: issued.state.expose().to_owned(),
        nonce: issued.nonce.expose().to_owned(),
        pkce_verifier: issued.pkce_verifier.expose().to_owned(),
        return_to: return_to.to_owned(),
        expires_unix_ms: expires,
    };
    let sealed = match human.cookie_sealer.seal(LOGIN_COOKIE, &payload) {
        Ok(sealed) => sealed,
        Err(_) => return internal_problem(&request_id),
    };
    let scopes = provider.scopes.join(" ");
    let location = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        provider.authorization_endpoint,
        encode_query_component(&provider.client_id),
        encode_query_component(&provider.redirect_uri),
        encode_query_component(&scopes),
        encode_query_component(issued.state.expose()),
        encode_query_component(issued.nonce.expose()),
        encode_query_component(&issued.pkce_challenge),
    );
    let mut response = StatusCode::FOUND.into_response();
    let Ok(location) = HeaderValue::from_str(&location) else {
        return internal_problem(&request_id);
    };
    response.headers_mut().insert(LOCATION, location);
    if append_cookie(
        &mut response,
        LOGIN_COOKIE,
        &sealed,
        "/auth/oidc/callback",
        "Lax",
        OIDC_LOGIN_TTL_MS / 1000,
    )
    .is_err()
    {
        return internal_problem(&request_id);
    }
    protect_sensitive_response(&mut response);
    human.metrics.login_started();
    response
}

pub(in crate::app) async fn begin_github_oauth_login(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Query(query): Query<GitHubOauthLoginQuery>,
) -> Response {
    let Some(human) = state.human_oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(github) = human.github_oauth.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let return_to = query.return_to.as_deref().unwrap_or("/");
    if !valid_return_to(return_to) {
        return invalid_object_problem(&request_id, "return_to must be a bounded local path");
    }
    let now = match now_unix_ms(&request_id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let expires = match now.checked_add(OIDC_LOGIN_TTL_MS) {
        Some(v) => v,
        None => return internal_problem(&request_id),
    };
    let provider = match state
        .store
        .oidc_provider(&github.tenant_id, &github.provider_id)
        .await
    {
        Ok(v) if v.status == "active" => v,
        _ => return hidden_login_resource(&request_id),
    };
    let issued = match OidcAuthorizationTransaction::issue(
        &state.token_hasher,
        IssueOidcAuthorization {
            id: match random_id("github-login") {
                Ok(v) => v,
                Err(()) => return randomness_problem(&request_id),
            },
            tenant_id: github.tenant_id.clone(),
            provider_configuration_id: github.provider_id.clone(),
            issuer: github.issuer.clone(),
            client_id: github.client_id.clone(),
            redirect_uri: provider.redirect_uri.clone(),
            created_unix_ms: now,
            expires_unix_ms: expires,
        },
    ) {
        Ok(v) => v,
        Err(_) => return hidden_login_resource(&request_id),
    };
    let audit = R9AuditMetadata {
        actor_id: "anonymous-browser".to_owned(),
        correlation_id: request_id.0.clone(),
        occurred_unix_ms: now,
    };
    if state
        .store
        .persist_oidc_transaction(&issued.record, &audit)
        .await
        .is_err()
    {
        return hidden_login_resource(&request_id);
    }
    let payload = LoginCookiePayload {
        transaction_id: issued.record.id.clone(),
        tenant_id: github.tenant_id.clone(),
        provider_id: github.provider_id.clone(),
        state: issued.state.expose().to_owned(),
        nonce: issued.nonce.expose().to_owned(),
        pkce_verifier: issued.pkce_verifier.expose().to_owned(),
        return_to: return_to.to_owned(),
        expires_unix_ms: expires,
    };
    let sealed = match human.cookie_sealer.seal(LOGIN_COOKIE, &payload) {
        Ok(v) => v,
        Err(_) => return internal_problem(&request_id),
    };
    let location = format!(
        "{}?client_id={}&redirect_uri={}&scope={}&state={}",
        github.authorization_endpoint,
        encode_query_component(&github.client_id),
        encode_query_component(&provider.redirect_uri),
        encode_query_component("read:user read:org repo"),
        encode_query_component(issued.state.expose())
    );
    let mut response = StatusCode::FOUND.into_response();
    let Ok(location) = HeaderValue::from_str(&location) else {
        return internal_problem(&request_id);
    };
    response.headers_mut().insert(LOCATION, location);
    if append_cookie(
        &mut response,
        LOGIN_COOKIE,
        &sealed,
        "/auth/callback",
        "Lax",
        OIDC_LOGIN_TTL_MS / 1000,
    )
    .is_err()
    {
        return internal_problem(&request_id);
    }
    protect_sensitive_response(&mut response);
    human.metrics.login_started();
    response
}

pub(in crate::app) async fn finish_github_oauth_login(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<HumanOidcCallbackQuery>,
) -> Response {
    let Some(human) = state.human_oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(github) = human.github_oauth.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let payload = match sealed_cookie::<LoginCookiePayload>(&headers, human, LOGIN_COOKIE) {
        Ok(v) => v,
        Err(_) => return callback_failure(human, &request_id),
    };
    if payload.tenant_id != github.tenant_id || payload.provider_id != github.provider_id {
        return callback_failure(human, &request_id);
    }
    let now = match now_unix_ms(&request_id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let audit = R9AuditMetadata {
        actor_id: "anonymous-browser".to_owned(),
        correlation_id: request_id.0.clone(),
        occurred_unix_ms: now,
    };
    let provider = match state
        .store
        .oidc_provider(&github.tenant_id, &github.provider_id)
        .await
    {
        Ok(v) => v,
        Err(_) => return callback_failure(human, &request_id),
    };
    let mut transaction = match state
        .store
        .oidc_transaction(&github.tenant_id, &payload.transaction_id)
        .await
    {
        Ok(v) => v,
        Err(_) => return callback_failure(human, &request_id),
    };
    let begin_failed = now >= payload.expires_unix_ms
        || !constant_time_text_equal(&payload.state, &query.state)
        || transaction
            .begin_exchange(
                &state.token_hasher,
                BeginOidcExchange {
                    tenant_id: &github.tenant_id,
                    provider_configuration_id: &github.provider_id,
                    issuer: &github.issuer,
                    client_id: &github.client_id,
                    redirect_uri: &provider.redirect_uri,
                    state: &query.state,
                    pkce_verifier: &payload.pkce_verifier,
                    now_unix_ms: now,
                },
            )
            .is_err();
    if begin_failed {
        if transaction.status == OidcTransactionStatus::Pending {
            let _ = reject_oidc_transaction(&state, &mut transaction, now, &audit).await;
        } else if transaction.status == OidcTransactionStatus::Expired {
            let _ = state
                .store
                .persist_oidc_transaction(&transaction, &audit)
                .await;
        }
        return callback_failure(human, &request_id);
    }
    if state
        .store
        .persist_oidc_transaction(&transaction, &audit)
        .await
        .is_err()
    {
        return callback_failure(human, &request_id);
    }
    let permit = match Arc::clone(&human.exchange_admission).try_acquire_owned() {
        Ok(v) => v,
        Err(_) => return human_oidc_unavailable(&request_id),
    };
    let adapter = Arc::clone(&github.adapter);
    let code = Zeroizing::new(query.code.clone());
    let redirect = provider.redirect_uri.clone();
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        adapter.exchange_authorization_code(&code, &redirect)
    })
    .await;
    let verified = match verified {
        Ok(Ok(v)) => v,
        _ => {
            let _ = reject_oidc_transaction(&state, &mut transaction, now, &audit).await;
            return callback_failure(human, &request_id);
        }
    };
    let Some(role) = github.allowed_roles.get(&verified.user_id).cloned() else {
        let _ = reject_oidc_transaction(&state, &mut transaction, now, &audit).await;
        return callback_failure(human, &request_id);
    };
    let completed = now_unix_ms(&request_id).unwrap_or(now);
    if transaction
        .finish_identity(&state.token_hasher, &payload.nonce, completed)
        .is_err()
    {
        return callback_failure(human, &request_id);
    }
    let user_id = format!("github-{}", verified.user_id);
    let existing_user = state
        .store
        .human_user(&github.tenant_id, &user_id)
        .await
        .ok();
    if existing_user.is_none() {
        let email = verified
            .email
            .clone()
            .filter(|v| {
                v.len() <= 320 && v.contains('@') && !v.bytes().any(|b| b.is_ascii_control())
            })
            .unwrap_or_else(|| format!("{}@github.invalid", verified.user_id));
        let user = HumanUserRecord {
            id: user_id.clone(),
            display_name: verified.login.clone(),
            primary_email: email,
            status: "active".to_owned(),
            created_unix_ms: completed,
            updated_unix_ms: completed,
            last_seen_unix_ms: Some(completed),
            version: 1,
        };
        if state
            .store
            .put_human_user(&github.tenant_id, &user, None)
            .await
            .is_err()
        {
            return callback_failure(human, &request_id);
        }
        let mut membership = TenantMembershipRecord {
            id: format!("github-membership-{}", verified.user_id),
            tenant_id: github.tenant_id.clone(),
            user_id: user_id.clone(),
            role_template: role,
            attributes: serde_json::json!({"github_user_id": verified.user_id, "github_login": verified.login}),
            attributes_digest: ContentDigest::sha256([]),
            status: "active".to_owned(),
            created_unix_ms: completed,
            updated_unix_ms: completed,
            version: 1,
        };
        membership.attributes_digest = match membership.expected_attributes_digest() {
            Ok(v) => v,
            Err(_) => return callback_failure(human, &request_id),
        };
        if state.store.put_membership(&membership, None).await.is_err() {
            return callback_failure(human, &request_id);
        }
    }
    let subject = verified.user_id.to_string();
    let identity_id = format!("github-identity-{}", verified.user_id);
    let existing_identity = state
        .store
        .human_identity_for_subject(
            &github.tenant_id,
            &github.provider_id,
            &github.issuer,
            &subject,
        )
        .await
        .ok();
    let identity = HumanIdentityRecord {
        id: identity_id,
        tenant_id: github.tenant_id.clone(),
        user_id: user_id.clone(),
        provider_configuration_id: github.provider_id.clone(),
        issuer: github.issuer.clone(),
        subject,
        provider_kind: "github".to_owned(),
        claims_digest: verified.claims_digest.clone(),
        created_unix_ms: existing_identity
            .as_ref()
            .map_or(completed, |v| v.created_unix_ms),
        last_authenticated_unix_ms: completed,
    };
    if state
        .store
        .put_human_identity(&github.tenant_id, &identity)
        .await
        .is_err()
    {
        return callback_failure(human, &request_id);
    }
    let completed_audit = R9AuditMetadata {
        actor_id: user_id.clone(),
        correlation_id: request_id.0.clone(),
        occurred_unix_ms: completed,
    };
    if state
        .store
        .persist_oidc_transaction(&transaction, &completed_audit)
        .await
        .is_err()
    {
        return callback_failure(human, &request_id);
    }
    let issued = match SessionRecord::issue(
        &state.token_hasher,
        human.session_policy,
        IssueSession {
            id: match random_id("session") {
                Ok(v) => v,
                Err(()) => return randomness_problem(&request_id),
            },
            principal_id: user_id,
            tenant_id: github.tenant_id.clone(),
            device_id: match random_id("browser-device") {
                Ok(v) => v,
                Err(()) => return randomness_problem(&request_id),
            },
            scopes: BTreeSet::from([
                SESSION_READ_SCOPE.to_owned(),
                SESSION_WRITE_SCOPE.to_owned(),
                POLICY_READ_SCOPE.to_owned(),
                SCM_READ_SCOPE.to_owned(),
                SCM_WRITE_SCOPE.to_owned(),
            ]),
            now_unix_ms: completed,
            mfa_authenticated_unix_ms: None,
        },
    ) {
        Ok(v) => v,
        Err(_) => return callback_failure(human, &request_id),
    };
    if state
        .store
        .persist_session(&issued.record, None, &completed_audit)
        .await
        .is_err()
    {
        return callback_failure(human, &request_id);
    }
    let mut response = StatusCode::SEE_OTHER.into_response();
    let Ok(location) = HeaderValue::from_str(&payload.return_to) else {
        return callback_failure(human, &request_id);
    };
    response.headers_mut().insert(LOCATION, location);
    if append_session_cookies(
        &mut response,
        human,
        &issued.record,
        issued.access_token.expose(),
        issued.refresh_token.expose(),
        issued.csrf_token.expose(),
        completed,
    )
    .is_err()
    {
        return callback_failure(human, &request_id);
    }
    if append_github_credential_cookie(
        &mut response,
        human,
        &issued.record,
        &verified.login,
        verified.access_token.expose(),
        completed,
    )
    .is_err()
    {
        return callback_failure(human, &request_id);
    }
    clear_cookie(&mut response, LOGIN_COOKIE, "/auth/callback");
    protect_sensitive_response(&mut response);
    human.metrics.callback_succeeded();
    response
}

pub(in crate::app) async fn finish_human_oidc_login(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(query): Query<HumanOidcCallbackQuery>,
) -> Response {
    let Some(human) = state.human_oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let payload = match sealed_cookie::<LoginCookiePayload>(&headers, human, LOGIN_COOKIE) {
        Ok(payload) => payload,
        Err(_) => return callback_failure(human, &request_id),
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let audit = R9AuditMetadata {
        actor_id: "anonymous-browser".to_owned(),
        correlation_id: request_id.0.clone(),
        occurred_unix_ms: now,
    };
    let mut transaction = match state
        .store
        .oidc_transaction(&payload.tenant_id, &payload.transaction_id)
        .await
    {
        Ok(transaction) => transaction,
        Err(_) => return callback_failure(human, &request_id),
    };
    if now >= payload.expires_unix_ms {
        if terminalize_oidc_callback_before_exchange(&state, &mut transaction, now, &audit)
            .await
            .is_err()
        {
            return internal_problem(&request_id);
        }
        return callback_failure(human, &request_id);
    }
    let provider = match state
        .store
        .oidc_provider(&payload.tenant_id, &payload.provider_id)
        .await
    {
        Ok(provider) if provider.status == "active" => provider,
        _ => {
            if terminalize_oidc_callback_before_exchange(&state, &mut transaction, now, &audit)
                .await
                .is_err()
            {
                return internal_problem(&request_id);
            }
            return callback_failure(human, &request_id);
        }
    };
    if provider.redirect_uri != format!("{}/auth/oidc/callback", human.public_origin) {
        if terminalize_oidc_callback_before_exchange(&state, &mut transaction, now, &audit)
            .await
            .is_err()
        {
            return internal_problem(&request_id);
        }
        return callback_failure(human, &request_id);
    }
    let begin = if constant_time_text_equal(&payload.state, &query.state) {
        transaction.begin_exchange(
            &state.token_hasher,
            BeginOidcExchange {
                tenant_id: &payload.tenant_id,
                provider_configuration_id: &payload.provider_id,
                issuer: &provider.issuer,
                client_id: &provider.client_id,
                redirect_uri: &provider.redirect_uri,
                state: &query.state,
                pkce_verifier: &payload.pkce_verifier,
                now_unix_ms: now,
            },
        )
    } else {
        Err(AuthError::InvalidCredential)
    };
    if begin.is_err() {
        let persisted = if transaction.status == OidcTransactionStatus::Pending {
            reject_oidc_transaction(&state, &mut transaction, now, &audit).await
        } else if transaction.status == OidcTransactionStatus::Expired {
            state
                .store
                .persist_oidc_transaction(&transaction, &audit)
                .await
                .map(drop)
        } else {
            Ok(())
        };
        if persisted.is_err() {
            return internal_problem(&request_id);
        }
        return callback_failure(human, &request_id);
    }
    if state
        .store
        .persist_oidc_transaction(&transaction, &audit)
        .await
        .is_err()
    {
        return callback_failure(human, &request_id);
    }

    let permit = match Arc::clone(&human.exchange_admission).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            if reject_oidc_transaction(&state, &mut transaction, now, &audit)
                .await
                .is_err()
            {
                return internal_problem(&request_id);
            }
            return human_oidc_unavailable(&request_id);
        }
    };
    let adapter = Arc::clone(&human.adapter);
    let provider_for_exchange = provider.clone();
    let code = Zeroizing::new(query.code.clone());
    let verifier = Zeroizing::new(payload.pkce_verifier.clone());
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        adapter.exchange_authorization_code(
            &provider_for_exchange,
            code.as_str(),
            verifier.as_str(),
            now / 1000,
        )
    })
    .await;
    let verified = match verified {
        Ok(Ok(verified)) => verified,
        _ => {
            let completed = now_unix_ms(&request_id).unwrap_or(now);
            if reject_oidc_transaction(&state, &mut transaction, completed, &audit)
                .await
                .is_err()
            {
                return internal_problem(&request_id);
            }
            return callback_failure(human, &request_id);
        }
    };
    let completed = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    if transaction
        .finish_identity(&state.token_hasher, &verified.nonce, completed)
        .is_err()
    {
        let completed_audit = R9AuditMetadata {
            occurred_unix_ms: completed,
            ..audit
        };
        if state
            .store
            .persist_oidc_transaction(&transaction, &completed_audit)
            .await
            .is_err()
        {
            return internal_problem(&request_id);
        }
        return callback_failure(human, &request_id);
    }
    let mut identity = match state
        .store
        .human_identity_for_subject(
            &payload.tenant_id,
            &payload.provider_id,
            &verified.issuer,
            &verified.subject,
        )
        .await
    {
        Ok(identity) => identity,
        Err(_) => {
            if reject_oidc_transaction(&state, &mut transaction, completed, &audit)
                .await
                .is_err()
            {
                return internal_problem(&request_id);
            }
            return callback_failure(human, &request_id);
        }
    };
    identity.claims_digest = verified.claims_digest.clone();
    identity.last_authenticated_unix_ms = completed;
    let user = match state
        .store
        .human_user(&payload.tenant_id, &identity.user_id)
        .await
    {
        Ok(user) if user.status == "active" => user,
        _ => {
            if reject_oidc_transaction(&state, &mut transaction, completed, &audit)
                .await
                .is_err()
            {
                return internal_problem(&request_id);
            }
            return callback_failure(human, &request_id);
        }
    };
    if state
        .store
        .put_human_identity(&payload.tenant_id, &identity)
        .await
        .is_err()
    {
        if reject_oidc_transaction(&state, &mut transaction, completed, &audit)
            .await
            .is_err()
        {
            return internal_problem(&request_id);
        }
        return callback_failure(human, &request_id);
    }
    let completed_audit = R9AuditMetadata {
        actor_id: user.id.clone(),
        correlation_id: request_id.0.clone(),
        occurred_unix_ms: completed,
    };
    if state
        .store
        .persist_oidc_transaction(&transaction, &completed_audit)
        .await
        .is_err()
    {
        return callback_failure(human, &request_id);
    }
    let session_id = match random_id("session") {
        Ok(id) => id,
        Err(()) => return randomness_problem(&request_id),
    };
    let device_id = match random_id("browser-device") {
        Ok(id) => id,
        Err(()) => return randomness_problem(&request_id),
    };
    let issued_session = match SessionRecord::issue(
        &state.token_hasher,
        human.session_policy,
        IssueSession {
            id: session_id,
            principal_id: user.id,
            tenant_id: payload.tenant_id.clone(),
            device_id,
            scopes: BTreeSet::from([
                SESSION_READ_SCOPE.to_owned(),
                SESSION_WRITE_SCOPE.to_owned(),
                POLICY_READ_SCOPE.to_owned(),
                SCM_READ_SCOPE.to_owned(),
                SCM_WRITE_SCOPE.to_owned(),
            ]),
            now_unix_ms: completed,
            mfa_authenticated_unix_ms: verified.mfa_authenticated.then_some(completed),
        },
    ) {
        Ok(session) => session,
        Err(_) => return callback_failure(human, &request_id),
    };
    if state
        .store
        .persist_session(&issued_session.record, None, &completed_audit)
        .await
        .is_err()
    {
        return callback_failure(human, &request_id);
    }
    let mut response = StatusCode::SEE_OTHER.into_response();
    let Ok(location) = HeaderValue::from_str(&payload.return_to) else {
        return callback_failure(human, &request_id);
    };
    response.headers_mut().insert(LOCATION, location);
    if append_session_cookies(
        &mut response,
        human,
        &issued_session.record,
        issued_session.access_token.expose(),
        issued_session.refresh_token.expose(),
        issued_session.csrf_token.expose(),
        completed,
    )
    .is_err()
    {
        return callback_failure(human, &request_id);
    }
    clear_cookie(&mut response, GITHUB_CREDENTIAL_COOKIE, "/");
    clear_cookie(&mut response, LOGIN_COOKIE, "/auth/oidc/callback");
    protect_sensitive_response(&mut response);
    human.metrics.callback_succeeded();
    response
}

pub(in crate::app) async fn terminalize_oidc_callback_before_exchange(
    state: &AppState,
    transaction: &mut OidcAuthorizationTransaction,
    now: u64,
    audit: &R9AuditMetadata,
) -> Result<(), ControlPlaneError> {
    if transaction.status != OidcTransactionStatus::Pending {
        return Ok(());
    }
    if now >= transaction.expires_unix_ms {
        transaction.status = OidcTransactionStatus::Expired;
        transaction.finished_unix_ms = Some(now);
        state
            .store
            .persist_oidc_transaction(transaction, audit)
            .await
            .map(drop)
    } else {
        reject_oidc_transaction(state, transaction, now, audit).await
    }
}

pub(in crate::app) async fn reject_oidc_transaction(
    state: &AppState,
    transaction: &mut OidcAuthorizationTransaction,
    now: u64,
    audit: &R9AuditMetadata,
) -> Result<(), ControlPlaneError> {
    if transaction.status == OidcTransactionStatus::Pending {
        transaction.reject_callback(now)?;
    } else {
        transaction.status = if now >= transaction.expires_unix_ms {
            OidcTransactionStatus::Expired
        } else {
            OidcTransactionStatus::Rejected
        };
        transaction.finished_unix_ms = Some(now);
    }
    let audit = R9AuditMetadata {
        occurred_unix_ms: now,
        ..audit.clone()
    };
    state
        .store
        .persist_oidc_transaction(transaction, &audit)
        .await
        .map(drop)
}
