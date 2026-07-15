use super::{broker::TonicRunnerBroker, tonic::TonicRunnerTransport, TransportError};
use crate::state::read_bounded_private_file;
use ::tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
use runtrue_protocol::{v1, v2};
use std::{
    net::IpAddr,
    path::PathBuf,
    str::FromStr as _,
    sync::{
        atomic::{AtomicBool, AtomicU32},
        Arc,
    },
    time::Duration,
};
use tokio::runtime::Handle;
use zeroize::Zeroizing;

const MAX_PEM_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct EnrollmentEndpointSecurity {
    pub endpoint: String,
    pub ca_certificate: PathBuf,
}

impl EnrollmentEndpointSecurity {
    pub fn validate_configuration(&self) -> Result<(), TransportError> {
        self.configured_endpoint().map(drop)
    }

    pub async fn enroll(
        &self,
        request: v1::EnrollRequest,
    ) -> Result<v1::EnrollResponse, TransportError> {
        let channel = self.configured_endpoint()?.connect().await?;
        Ok(v1::runner_control_client::RunnerControlClient::new(channel)
            .enroll(request)
            .await?
            .into_inner())
    }

    fn configured_endpoint(&self) -> Result<Endpoint, TransportError> {
        let mut endpoint = base_endpoint(&self.endpoint)?;
        if endpoint.uri().scheme_str() != Some("https") {
            return Err(TransportError::EnrollmentRequiresTls);
        }
        endpoint.uri().host().ok_or(TransportError::EndpointHost)?;
        let ca = read_bounded_private_file(&self.ca_certificate, MAX_PEM_BYTES)?;
        require_pem(&ca, &["CERTIFICATE"])?;
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca)))?;
        Ok(endpoint)
    }
}

#[derive(Debug, Clone)]
pub struct EndpointSecurity {
    pub endpoint: String,
    pub ca_certificate: Option<PathBuf>,
    pub client_certificate: Option<PathBuf>,
    pub client_private_key: Option<PathBuf>,
    pub insecure_loopback: bool,
}

impl EndpointSecurity {
    pub fn validate_configuration(&self) -> Result<(), TransportError> {
        self.configured_endpoint().map(drop)
    }

    pub async fn connect(&self) -> Result<TonicRunnerTransport, TransportError> {
        let endpoint = self.configured_endpoint()?;
        let channel = endpoint.connect().await?;
        let client = v1::runner_control_client::RunnerControlClient::new(channel.clone());
        let session_open = Arc::new(AtomicBool::new(false));
        let protocol_version = Arc::new(AtomicU32::new(0));
        let broker = Arc::new(TonicRunnerBroker {
            client: client.clone(),
            object_client: v2::runner_object_transfer_client::RunnerObjectTransferClient::new(
                channel.clone(),
            ),
            runtime: Handle::current(),
            session_open: session_open.clone(),
            protocol_version: protocol_version.clone(),
        });
        Ok(TonicRunnerTransport {
            client,
            outbound: None,
            inbound: None,
            broker,
            session_open,
            protocol_version,
        })
    }

    fn configured_endpoint(&self) -> Result<Endpoint, TransportError> {
        let mut endpoint = base_endpoint(&self.endpoint)?;
        let scheme = endpoint
            .uri()
            .scheme_str()
            .ok_or(TransportError::EndpointScheme)?;
        let host = endpoint.uri().host().ok_or(TransportError::EndpointHost)?;

        match scheme {
            "https" => {
                if self.insecure_loopback {
                    return Err(TransportError::InsecureFlagWithTls);
                }
                let ca_path = self
                    .ca_certificate
                    .as_ref()
                    .ok_or(TransportError::MissingMutualTls)?;
                let certificate_path = self
                    .client_certificate
                    .as_ref()
                    .ok_or(TransportError::MissingMutualTls)?;
                let private_key_path = self
                    .client_private_key
                    .as_ref()
                    .ok_or(TransportError::MissingMutualTls)?;
                let ca = read_bounded_private_file(ca_path, MAX_PEM_BYTES)?;
                let certificate = read_bounded_private_file(certificate_path, MAX_PEM_BYTES)?;
                let private_key =
                    Zeroizing::new(read_bounded_private_file(private_key_path, MAX_PEM_BYTES)?);
                require_pem(&ca, &["CERTIFICATE"])?;
                require_pem(&certificate, &["CERTIFICATE"])?;
                require_pem(
                    private_key.as_slice(),
                    &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"],
                )?;
                let tls = ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(ca))
                    .identity(Identity::from_pem(certificate, private_key.as_slice()));
                endpoint = endpoint.tls_config(tls)?;
            }
            "http" => {
                let loopback = IpAddr::from_str(host)
                    .map(|address| address.is_loopback())
                    .unwrap_or(false);
                if !self.insecure_loopback || !loopback {
                    return Err(TransportError::InsecureEndpoint);
                }
                if self.ca_certificate.is_some()
                    || self.client_certificate.is_some()
                    || self.client_private_key.is_some()
                {
                    return Err(TransportError::TlsMaterialWithInsecureEndpoint);
                }
            }
            _ => return Err(TransportError::EndpointScheme),
        }

        Ok(endpoint)
    }
}

fn base_endpoint(value: &str) -> Result<Endpoint, TransportError> {
    Ok(Endpoint::from_shared(value.to_owned())?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keep_alive_interval(Duration::from_secs(20))
        .keep_alive_while_idle(true))
}

fn require_pem(bytes: &[u8], labels: &[&str]) -> Result<(), TransportError> {
    let text = std::str::from_utf8(bytes).map_err(|_| TransportError::InvalidPem)?;
    if labels.iter().any(|label| {
        text.contains(&format!("-----BEGIN {label}-----"))
            && text.contains(&format!("-----END {label}-----"))
    }) {
        Ok(())
    } else {
        Err(TransportError::InvalidPem)
    }
}
