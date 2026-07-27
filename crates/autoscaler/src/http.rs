use crate::{
    AutoscalerError, ControlPlaneClient, FleetRequest, FleetView, LaunchClaim, OwnershipLease,
    PlannedReplacement, PoolTemplate, ProviderIdentity,
};
use async_trait::async_trait;
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::{str::FromStr as _, sync::Arc, time::Duration};
use ureq::{http::Uri, Agent};
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub struct HttpControlPlane {
    base: String,
    token: Arc<Zeroizing<String>>,
    agent: Agent,
}

impl std::fmt::Debug for HttpControlPlane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpControlPlane")
            .field("base", &self.base)
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl HttpControlPlane {
    pub fn new(base: &str, token: Zeroizing<String>) -> Result<Self, AutoscalerError> {
        let base = parse_origin(base)?;
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(64 * 1024)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_send_request(Some(Duration::from_secs(5)))
            .timeout_send_body(Some(REQUEST_TIMEOUT))
            .timeout_recv_response(Some(REQUEST_TIMEOUT))
            .timeout_recv_body(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Ok(Self {
            base,
            token: Arc::new(token),
            agent,
        })
    }

    async fn request<T: DeserializeOwned + Send + 'static>(
        &self,
        operation: &'static str,
        method: Method,
        path: String,
        input: Option<Value>,
        idempotency_key: Option<String>,
        absent_statuses: &'static [u16],
    ) -> Result<Option<T>, AutoscalerError> {
        let client = self.clone();
        tokio::task::spawn_blocking(move || {
            client.request_blocking(
                operation,
                method,
                &path,
                input.as_ref(),
                idempotency_key.as_deref(),
                absent_statuses,
            )
        })
        .await?
    }

    fn request_blocking<T: DeserializeOwned>(
        &self,
        operation: &'static str,
        method: Method,
        path: &str,
        input: Option<&Value>,
        supplied_key: Option<&str>,
        absent_statuses: &[u16],
    ) -> Result<Option<T>, AutoscalerError> {
        let generated_key = random_id("autoscaler-")?;
        let key = supplied_key.unwrap_or(&generated_key);
        let body = input.map(serde_json::to_vec).transpose()?;
        let authorization = Zeroizing::new(format!("Bearer {}", self.token.as_str()));
        let url = format!("{}{path}", self.base);
        for attempt in 0..3 {
            let response = match method {
                Method::Get => self
                    .agent
                    .get(&url)
                    .header("authorization", authorization.as_str())
                    .header("accept", "application/json")
                    .header("idempotency-key", key)
                    .call(),
                Method::Post => self
                    .agent
                    .post(&url)
                    .header("authorization", authorization.as_str())
                    .header("content-type", "application/json")
                    .header("accept", "application/json")
                    .header("idempotency-key", key)
                    .send(body.as_deref().unwrap_or_default()),
            };
            let mut response = match response {
                Ok(response) => response,
                Err(error) if attempt < 2 => {
                    let _ = error;
                    continue;
                }
                Err(error) => {
                    return Err(AutoscalerError::ControlPlaneTransport {
                        operation,
                        detail: error.to_string(),
                    })
                }
            };
            let status = response.status().as_u16();
            let bytes = response
                .body_mut()
                .with_config()
                .limit(MAX_RESPONSE_BYTES + 1)
                .read_to_vec()
                .map_err(|error| AutoscalerError::ControlPlaneTransport {
                    operation,
                    detail: error.to_string(),
                })?;
            if bytes.len() as u64 > MAX_RESPONSE_BYTES {
                return Err(AutoscalerError::MalformedControlPlaneResponse(operation));
            }
            if absent_statuses.contains(&status) {
                return Ok(None);
            }
            if !(200..300).contains(&status) {
                return Err(AutoscalerError::ControlPlaneStatus {
                    operation,
                    status,
                    detail: bounded_detail(&bytes),
                });
            }
            if bytes.is_empty() {
                return serde_json::from_slice(b"null")
                    .map(Some)
                    .map_err(|_| AutoscalerError::MalformedControlPlaneResponse(operation));
            }
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| AutoscalerError::MalformedControlPlaneResponse(operation));
        }
        Err(AutoscalerError::ControlPlaneTransport {
            operation,
            detail: "request exhausted retries".into(),
        })
    }
}

#[async_trait]
impl ControlPlaneClient for HttpControlPlane {
    async fn acquire_lease(
        &self,
        pool: &str,
        _owner: &str,
        expires_in_ms: u64,
    ) -> Result<OwnershipLease, AutoscalerError> {
        self.request(
            "acquire fleet lease",
            Method::Post,
            format!("/api/v1/runner-pools/{}/fleet/lease", encode_segment(pool)),
            Some(json!({"expires_in_ms": expires_in_ms})),
            None,
            &[],
        )
        .await?
        .ok_or(AutoscalerError::MalformedControlPlaneResponse(
            "acquire fleet lease",
        ))
    }

    async fn fleet(&self, pool: &str) -> Result<FleetView, AutoscalerError> {
        self.request(
            "read fleet",
            Method::Get,
            format!("/api/v1/runner-pools/{}/fleet", encode_segment(pool)),
            None,
            None,
            &[],
        )
        .await?
        .ok_or(AutoscalerError::MalformedControlPlaneResponse("read fleet"))
    }

    async fn create_request(
        &self,
        pool: &str,
        generation: u64,
        template: &PoolTemplate,
    ) -> Result<FleetRequest, AutoscalerError> {
        let request_id = random_id("fleet-")?;
        self.request(
            "create fleet request",
            Method::Post,
            format!(
                "/api/v1/runner-pools/{}/fleet/requests",
                encode_segment(pool)
            ),
            Some(json!({
                "request_id": request_id,
                "fencing_generation": generation,
                "template": template,
            })),
            Some(request_id),
            &[],
        )
        .await?
        .ok_or(AutoscalerError::MalformedControlPlaneResponse(
            "create fleet request",
        ))
    }

    async fn transition(
        &self,
        request: &FleetRequest,
        next: &str,
        generation: u64,
        detail: &str,
    ) -> Result<FleetRequest, AutoscalerError> {
        self.request(
            "transition fleet request",
            Method::Post,
            format!(
                "/api/v1/runner-pools/{}/fleet/requests/{}/transition",
                encode_segment(&request.pool_id),
                encode_segment(&request.id)
            ),
            Some(json!({
                "expected_state": request.state,
                "next_state": next,
                "fencing_generation": generation,
                "detail": detail,
            })),
            None,
            &[],
        )
        .await?
        .ok_or(AutoscalerError::MalformedControlPlaneResponse(
            "transition fleet request",
        ))
    }

    async fn create_launch_claim(
        &self,
        request: &FleetRequest,
        generation: u64,
        identity: &ProviderIdentity,
    ) -> Result<LaunchClaim, AutoscalerError> {
        #[derive(serde::Deserialize)]
        struct IssuedToken {
            token: String,
            #[serde(rename = "expires_unix_ms")]
            _expires_unix_ms: u64,
        }
        let digest = launch_identity_proof_digest(identity)?;
        let issued: IssuedToken = self
            .request(
                "create launch claim",
                Method::Post,
                format!(
                    "/api/v1/runner-pools/{}/fleet/requests/{}/launch-claim",
                    encode_segment(&request.pool_id),
                    encode_segment(&request.id)
                ),
                Some(json!({
                    "fencing_generation": generation,
                    "provider_instance_id": identity.provider_instance_id,
                    "identity_proof_digest": digest,
                })),
                None,
                &[],
            )
            .await?
            .ok_or(AutoscalerError::MalformedControlPlaneResponse(
                "create launch claim",
            ))?;
        Ok(LaunchClaim {
            version: 1,
            enrollment_token: issued.token,
            provider: identity.provider.clone(),
            provider_instance_id: identity.provider_instance_id.clone(),
            evidence_hex: hex::encode(&identity.evidence),
            endorsement_hex: hex::encode(&identity.endorsement),
            nonce_digest: identity.nonce_digest.clone(),
        })
    }

    async fn plan_replacement(
        &self,
        pool: &str,
        generation: u64,
    ) -> Result<Option<PlannedReplacement>, AutoscalerError> {
        self.request(
            "plan immutable replacement",
            Method::Post,
            format!(
                "/api/v1/runner-pools/{}/fleet/replacements",
                encode_segment(pool)
            ),
            Some(json!({"fencing_generation": generation})),
            None,
            &[204, 400, 404, 409],
        )
        .await
    }

    async fn activate_replacement(
        &self,
        pool: &str,
        replacement: &str,
        generation: u64,
    ) -> Result<(), AutoscalerError> {
        let _: Option<Value> = self
            .request(
                "activate immutable replacement",
                Method::Post,
                format!(
                    "/api/v1/runner-pools/{}/fleet/replacements/{}/activate",
                    encode_segment(pool),
                    encode_segment(replacement)
                ),
                Some(json!({"fencing_generation": generation})),
                None,
                &[],
            )
            .await?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
}

fn parse_origin(value: &str) -> Result<String, AutoscalerError> {
    let uri = Uri::from_str(value)
        .map_err(|_| AutoscalerError::InvalidConfiguration("invalid control-plane origin"))?;
    let scheme = uri
        .scheme_str()
        .filter(|value| matches!(*value, "http" | "https"))
        .ok_or(AutoscalerError::InvalidConfiguration(
            "control-plane origin must use HTTP or HTTPS",
        ))?;
    let authority = uri
        .authority()
        .filter(|value| !value.as_str().contains('@'))
        .ok_or(AutoscalerError::InvalidConfiguration(
            "control-plane origin must have an authority",
        ))?;
    if uri
        .path_and_query()
        .is_some_and(|value| value.path() != "/" || value.query().is_some())
    {
        return Err(AutoscalerError::InvalidConfiguration(
            "control-plane origin cannot include a path or query",
        ));
    }
    Ok(format!("{scheme}://{authority}"))
}

fn random_id(prefix: &str) -> Result<String, AutoscalerError> {
    let mut value = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut value)
        .map_err(|_| AutoscalerError::RandomnessUnavailable)?;
    Ok(format!("{prefix}{}", hex::encode(value)))
}

fn encode_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn launch_identity_proof_digest(
    identity: &ProviderIdentity,
) -> Result<ContentDigest, AutoscalerError> {
    fn field(encoded: &mut Vec<u8>, value: &[u8]) {
        encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
        encoded.extend_from_slice(value);
    }
    let nonce = ContentDigest::parse(identity.nonce_digest.clone()).map_err(|_| {
        AutoscalerError::Provider("provider identity nonce digest is malformed".into())
    })?;
    let nonce_bytes = hex::decode(
        nonce
            .as_str()
            .strip_prefix("sha256:")
            .ok_or_else(|| AutoscalerError::Provider("unsupported nonce digest".into()))?,
    )
    .map_err(|_| AutoscalerError::Provider("provider nonce digest is malformed".into()))?;
    let mut encoded = b"runtrue.runner.launch-identity-proof.v1\0".to_vec();
    field(
        &mut encoded,
        format!("runtrue.launch.{}", identity.provider).as_bytes(),
    );
    field(&mut encoded, &identity.evidence);
    field(&mut encoded, &identity.endorsement);
    field(&mut encoded, b"sha256");
    field(&mut encoded, &nonce_bytes);
    Ok(ContentDigest::sha256(encoded))
}

fn bounded_detail(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(4096)])
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_proof_digest_is_stable_and_field_bound() {
        let identity = ProviderIdentity {
            provider: "docker".into(),
            provider_instance_id: "one".into(),
            evidence: b"instance-a".to_vec(),
            nonce_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            ..ProviderIdentity::default()
        };
        let first = launch_identity_proof_digest(&identity).unwrap();
        let mut changed = identity;
        changed.evidence = b"instance-b".to_vec();
        assert_ne!(first, launch_identity_proof_digest(&changed).unwrap());
    }

    #[test]
    fn origin_and_segments_are_closed() {
        assert_eq!(
            parse_origin("https://runtrue.example").unwrap(),
            "https://runtrue.example"
        );
        assert!(parse_origin("https://user@runtrue.example").is_err());
        assert!(parse_origin("https://runtrue.example/path").is_err());
        assert_eq!(encode_segment("pool/a"), "pool%2Fa");
    }
}
