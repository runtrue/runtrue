use super::{
    super::parse_strict_json, SubmitError, CONNECT_TIMEOUT, MAX_RESPONSE_HEADER_BYTES,
    MAX_SUBMIT_RESPONSE_BYTES, SUBMIT_TIMEOUT,
};
use serde::de::DeserializeOwned;
use std::{fmt, net::IpAddr, str::FromStr as _};
use ureq::{http::Uri, Agent};
use zeroize::Zeroizing;

pub(super) struct ServerOrigin {
    base: String,
    https_only: bool,
}

impl ServerOrigin {
    pub(super) fn parse(value: &str, allow_loopback_http: bool) -> Result<Self, SubmitError> {
        let uri = Uri::from_str(value).map_err(|_| SubmitError::InvalidServerOrigin)?;
        let scheme = uri.scheme_str().ok_or(SubmitError::InvalidServerOrigin)?;
        let authority = uri.authority().ok_or(SubmitError::InvalidServerOrigin)?;
        if authority.as_str().contains('@')
            || uri
                .path_and_query()
                .is_some_and(|value| value.path() != "/" || value.query().is_some())
        {
            return Err(SubmitError::InvalidServerOrigin);
        }
        let https_only = match scheme {
            "https" => true,
            "http" => {
                if !allow_loopback_http {
                    return Err(SubmitError::PlaintextHttpDenied);
                }
                let host = authority
                    .host()
                    .trim_start_matches('[')
                    .trim_end_matches(']');
                let address = host
                    .parse::<IpAddr>()
                    .map_err(|_| SubmitError::LoopbackHttpRequired)?;
                if !address.is_loopback() {
                    return Err(SubmitError::LoopbackHttpRequired);
                }
                false
            }
            _ => return Err(SubmitError::InvalidServerOrigin),
        };
        Ok(Self {
            base: format!("{scheme}://{authority}"),
            https_only,
        })
    }
}

pub(super) struct RemoteClient {
    origin: ServerOrigin,
    agent: Agent,
    token: Zeroizing<String>,
}

impl RemoteClient {
    pub(super) fn new(origin: ServerOrigin, token: Zeroizing<String>) -> Self {
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .https_only(origin.https_only)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .timeout_global(Some(SUBMIT_TIMEOUT))
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_send_request(Some(CONNECT_TIMEOUT))
            .timeout_send_body(Some(SUBMIT_TIMEOUT))
            .timeout_recv_response(Some(SUBMIT_TIMEOUT))
            .timeout_recv_body(Some(SUBMIT_TIMEOUT))
            .build()
            .into();
        Self {
            origin,
            agent,
            token,
        }
    }

    pub(super) fn post_json<T: DeserializeOwned>(
        &self,
        operation: &'static str,
        path: &str,
        idempotency_key: &str,
        body: &[u8],
    ) -> Result<(T, bool), SubmitError> {
        let url = format!("{}{path}", self.origin.base);
        let authorization = Zeroizing::new(format!("Bearer {}", self.token.as_str()));
        let mut response = self
            .agent
            .post(&url)
            .header("authorization", authorization.as_str())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("idempotency-key", idempotency_key)
            .send(body)
            .map_err(|_| SubmitError::Transport { operation })?;
        let status = response.status().as_u16();
        if status != 201 {
            return Err(SubmitError::RemoteStatus { operation, status });
        }
        let replayed = match response.headers().get("idempotency-replayed") {
            Some(value) if value == "true" => true,
            Some(value) if value == "false" => false,
            _ => return Err(SubmitError::MalformedResponse),
        };
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(SubmitError::MalformedResponse);
        }
        if response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > MAX_SUBMIT_RESPONSE_BYTES)
        {
            return Err(SubmitError::ResponseTooLarge);
        }
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_SUBMIT_RESPONSE_BYTES + 1)
            .read_to_vec()
            .map_err(|_| SubmitError::ResponseRead)?;
        if bytes.len() as u64 > MAX_SUBMIT_RESPONSE_BYTES {
            return Err(SubmitError::ResponseTooLarge);
        }
        let value = parse_strict_json(&bytes).map_err(|_| SubmitError::MalformedResponse)?;
        serde_json::from_value(value)
            .map(|value| (value, replayed))
            .map_err(|_| SubmitError::MalformedResponse)
    }
}

impl fmt::Debug for RemoteClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteClient")
            .field("origin", &self.origin.base)
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
