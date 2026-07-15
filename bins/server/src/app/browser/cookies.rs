use super::sessions::SessionCookiePayload;
use crate::app::{
    protect_sensitive_response, HumanOidcState, ACCESS_COOKIE, CSRF_COOKIE,
    GITHUB_CREDENTIAL_COOKIE, LOGIN_COOKIE, MAX_COOKIE_HEADER_BYTES, REFRESH_COOKIE,
};
use crate::human_oidc::HumanOidcError;
use axum::http::header::COOKIE;
use axum::{
    http::{header::SET_COOKIE, HeaderMap, HeaderValue},
    response::Response,
};
use runtrue_auth::SessionRecord;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct GitHubCredentialCookiePayload {
    pub(in crate::app) session_id: String,
    pub(in crate::app) tenant_id: String,
    pub(in crate::app) principal_id: String,
    pub(in crate::app) login: String,
    pub(in crate::app) access_token: String,
}

impl Drop for GitHubCredentialCookiePayload {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.session_id.zeroize();
        self.tenant_id.zeroize();
        self.principal_id.zeroize();
        self.login.zeroize();
        self.access_token.zeroize();
    }
}

pub(in crate::app) fn append_github_credential_cookie(
    response: &mut Response,
    human: &HumanOidcState,
    record: &SessionRecord,
    login: &str,
    access_token: &str,
    now: u64,
) -> Result<(), HumanOidcError> {
    let payload = GitHubCredentialCookiePayload {
        session_id: record.id.clone(),
        tenant_id: record.tenant_id.clone(),
        principal_id: record.principal_id.clone(),
        login: login.to_owned(),
        access_token: access_token.to_owned(),
    };
    let sealed = human
        .cookie_sealer
        .seal(GITHUB_CREDENTIAL_COOKIE, &payload)?;
    append_cookie(
        response,
        GITHUB_CREDENTIAL_COOKIE,
        &sealed,
        "/",
        "Lax",
        record.absolute_expires_unix_ms.saturating_sub(now) / 1000,
    )
}

pub(in crate::app) fn github_credential_cookie(
    headers: &HeaderMap,
    human: &HumanOidcState,
    record: &SessionRecord,
) -> Result<GitHubCredentialCookiePayload, HumanOidcError> {
    let payload =
        sealed_cookie::<GitHubCredentialCookiePayload>(headers, human, GITHUB_CREDENTIAL_COOKIE)?;
    if payload.session_id != record.id
        || payload.tenant_id != record.tenant_id
        || payload.principal_id != record.principal_id
        || payload.login.is_empty()
        || payload.login.len() > 255
        || payload.access_token.is_empty()
        || payload.access_token.len() > 2048
    {
        return Err(HumanOidcError::InvalidCookie);
    }
    Ok(payload)
}

pub(in crate::app) fn append_session_cookies(
    response: &mut Response,
    human: &HumanOidcState,
    record: &SessionRecord,
    access_token: &str,
    refresh_token: &str,
    csrf_token: &str,
    now: u64,
) -> Result<(), HumanOidcError> {
    for (name, token, path, same_site, expires) in [
        (
            ACCESS_COOKIE,
            access_token,
            "/",
            "Lax",
            record.access_expires_unix_ms,
        ),
        (
            REFRESH_COOKIE,
            refresh_token,
            "/auth/session",
            "Strict",
            record.refresh_expires_unix_ms,
        ),
        (
            CSRF_COOKIE,
            csrf_token,
            "/",
            // The first authenticated GET remains part of the cross-site
            // OAuth navigation. Mutations still require the separately
            // presented token, so Lax does not authorize a write by itself.
            "Lax",
            record.refresh_expires_unix_ms,
        ),
    ] {
        let payload = SessionCookiePayload {
            session_id: record.id.clone(),
            tenant_id: record.tenant_id.clone(),
            token: token.to_owned(),
        };
        let sealed = human.cookie_sealer.seal(name, &payload)?;
        append_cookie(
            response,
            name,
            &sealed,
            path,
            same_site,
            expires.saturating_sub(now) / 1000,
        )?;
    }
    Ok(())
}

pub(in crate::app) fn append_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    path: &str,
    same_site: &str,
    maximum_age_seconds: u64,
) -> Result<(), HumanOidcError> {
    let value = HeaderValue::from_str(&format!(
        "{name}={value}; Path={path}; Max-Age={maximum_age_seconds}; Secure; HttpOnly; SameSite={same_site}"
    ))
    .map_err(|_| HumanOidcError::InvalidCookie)?;
    response.headers_mut().append(SET_COOKIE, value);
    Ok(())
}

pub(in crate::app) fn clear_cookie(response: &mut Response, name: &str, path: &str) {
    if let Ok(value) = HeaderValue::from_str(&format!(
        "{name}=; Path={path}; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
    )) {
        response.headers_mut().append(SET_COOKIE, value);
    }
}

pub(in crate::app) fn clear_all_browser_cookies(response: &mut Response) {
    clear_cookie(response, LOGIN_COOKIE, "/auth/oidc/callback");
    clear_cookie(response, LOGIN_COOKIE, "/auth/callback");
    clear_cookie(response, GITHUB_CREDENTIAL_COOKIE, "/");
    clear_cookie(response, ACCESS_COOKIE, "/");
    clear_cookie(response, REFRESH_COOKIE, "/auth/session");
    clear_cookie(response, CSRF_COOKIE, "/");
}

pub(in crate::app) fn clear_browser_authentication(mut response: Response) -> Response {
    clear_all_browser_cookies(&mut response);
    protect_sensitive_response(&mut response);
    response
}

pub(in crate::app) fn sealed_cookie<T: DeserializeOwned>(
    headers: &HeaderMap,
    human: &HumanOidcState,
    name: &str,
) -> Result<T, HumanOidcError> {
    let value = cookie_value(headers, name)?.ok_or(HumanOidcError::InvalidCookie)?;
    human.cookie_sealer.open(name, value)
}

pub(in crate::app) fn cookie_value<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, HumanOidcError> {
    let mut found = None;
    let mut total = 0_usize;
    for header in headers.get_all(COOKIE) {
        let header = header.to_str().map_err(|_| HumanOidcError::InvalidCookie)?;
        total = total
            .checked_add(header.len())
            .ok_or(HumanOidcError::InvalidCookie)?;
        if total > MAX_COOKIE_HEADER_BYTES {
            return Err(HumanOidcError::InvalidCookie);
        }
        for pair in header.split(';') {
            let Some((candidate, value)) = pair.trim().split_once('=') else {
                return Err(HumanOidcError::InvalidCookie);
            };
            if candidate == name && found.replace(value).is_some() {
                return Err(HumanOidcError::InvalidCookie);
            }
        }
    }
    Ok(found)
}
