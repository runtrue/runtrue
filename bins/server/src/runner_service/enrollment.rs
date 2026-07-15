use super::{
    certificate_status, control_plane_status, duration_millis, enrolled_runner_record,
    enrollment_status, now_unix_ms, proto_timestamp, rotation_response, validate_identifier_status,
    validate_inventory, AuthenticatedIdentity, RunnerControlService, MAX_CONTROL_MESSAGE_BYTES,
    MAX_STREAM_MESSAGE_BYTES,
};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use runtrue_protocol::{
    advertised_protocol_range, negotiate_protocol_version_with_supported, v1, ProtocolVersionError,
    PROTOCOL_MAX,
};
use std::sync::atomic::Ordering;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
impl RunnerControlService {
    pub(super) async fn enroll_unauthenticated(
        &self,
        request: v1::EnrollRequest,
    ) -> Result<v1::EnrollResponse, Status> {
        let authority =
            self.inner.certificate_authority.as_ref().ok_or_else(|| {
                Status::failed_precondition("runner enrollment is not configured")
            })?;
        if request.attestation.is_some() {
            return Err(Status::invalid_argument(
                "runner attestation is not supported by this installation",
            ));
        }
        let mut inventory = request
            .inventory
            .clone()
            .ok_or_else(|| Status::invalid_argument("runner inventory is required"))?;
        let selected_protocol = self.select_enrollment_protocol(
            request.protocol_min,
            request.protocol_max,
            inventory.protocol_version,
        )?;
        // The service boundary translates the legacy enrollment envelope into
        // the durable selected-generation inventory. Domain validation and the
        // posture binding therefore never depend on scattered version checks.
        inventory.protocol_version = selected_protocol;
        let token = zeroize::Zeroizing::new(request.enrollment_token);
        let now = now_unix_ms()?;
        let token_record = self
            .inner
            .control_plane
            .inspect_enrollment_token(&token, now)
            .map_err(enrollment_status)?;
        let pool = self
            .inner
            .control_plane
            .runner_pool(&token_record.pool_id)
            .map_err(enrollment_status)?;
        let runner_id = random_runner_id()?;
        let runner = enrolled_runner_record(
            &runner_id,
            &pool.tenant_id,
            &token_record.pool_id,
            &inventory,
            request.ephemeral,
            now,
        )?;
        let inventory_digest = validate_inventory(&runner, &inventory, selected_protocol)?;
        let issued = authority
            .issue(
                &request.certificate_signing_request,
                &runner_id,
                &token_record.pool_id,
                now,
            )
            .map_err(certificate_status)?;
        self.inner
            .control_plane
            .complete_runner_enrollment(&token, &runner, &issued.record, &inventory_digest, now)
            .map_err(enrollment_status)?;
        let authoritative_posture = self
            .inner
            .control_plane
            .validate_runner_inventory_binding(&runner_id, &inventory_digest)
            .map_err(enrollment_status)?;
        self.inner
            .protocol_metrics
            .record_selection(selected_protocol);
        Ok(v1::EnrollResponse {
            runner_id,
            certificate_chain_pem: issued.certificate_chain_pem,
            certificate_expires_at: Some(proto_timestamp(issued.record.not_after_unix_ms)),
            runner_pool_id: token_record.pool_id,
            protocol_min: self.inner.config.protocol_minimum,
            protocol_max: PROTOCOL_MAX,
            authoritative_posture_digest: Some(
                v1::Digest::try_from(&authoritative_posture)
                    .map_err(|_| Status::internal("authoritative runner posture is invalid"))?,
            ),
            selected_protocol_version: selected_protocol,
        })
    }

    pub(super) fn select_enrollment_protocol(
        &self,
        advertised_min: u32,
        advertised_max: u32,
        inventory_version: u32,
    ) -> Result<u32, Status> {
        let reject = || {
            self.inner
                .protocol_metrics
                .enrollment_rejected
                .fetch_add(1, Ordering::Relaxed);
        };
        let (peer_min, peer_max) =
            match advertised_protocol_range(advertised_min, advertised_max, inventory_version) {
                Ok(range) => range,
                Err(_) => {
                    reject();
                    return Err(Status::invalid_argument(
                        "runner protocol range is malformed",
                    ));
                }
            };
        if inventory_version < peer_min || inventory_version > peer_max {
            reject();
            return Err(Status::invalid_argument(
                "runner inventory protocol is outside its advertised range",
            ));
        }
        match negotiate_protocol_version_with_supported(
            peer_min,
            peer_max,
            self.inner.config.protocol_minimum,
            PROTOCOL_MAX,
        ) {
            Ok(selected) => Ok(selected),
            Err(ProtocolVersionError::NoCompatibleVersion { .. }) => {
                reject();
                Err(Status::failed_precondition(
                    "runner protocol range is below the installation security minimum or unsupported",
                ))
            }
            Err(ProtocolVersionError::InvalidPeerRange { .. }) => {
                reject();
                Err(Status::invalid_argument(
                    "runner protocol range is malformed",
                ))
            }
            Err(ProtocolVersionError::InvalidSupportedRange { .. }) => {
                Err(Status::internal("runner protocol policy is invalid"))
            }
            Err(ProtocolVersionError::UnexpectedSelection { .. }) => {
                Err(Status::internal("runner protocol selection is invalid"))
            }
        }
    }

    pub(super) async fn rotate_authenticated(
        &self,
        authenticated: &AuthenticatedIdentity,
        request: v1::RotateCertificateRequest,
    ) -> Result<v1::RotateCertificateResponse, Status> {
        let authority = self
            .inner
            .certificate_authority
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("runner rotation is not configured"))?;
        let fingerprint = authenticated
            .certificate_fingerprint
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("a verified client certificate is required"))?;
        validate_identifier_status("runner id", &request.runner_id)?;
        if !authenticated.runner_id.is_empty() && request.runner_id != authenticated.runner_id {
            return Err(Status::permission_denied(
                "rotation runner id does not match the client certificate",
            ));
        }
        if request.attestation.is_some() {
            return Err(Status::invalid_argument(
                "runner attestation is not supported by this installation",
            ));
        }
        let now = now_unix_ms()?;
        let csr_digest = ContentDigest::sha256(&request.certificate_signing_request);
        let durable_certificate = self
            .inner
            .control_plane
            .runner_certificate(fingerprint)
            .map_err(control_plane_status)?;
        if durable_certificate.runner_id != request.runner_id {
            return Err(Status::permission_denied(
                "certificate identity changed during rotation",
            ));
        }
        if let Some(existing) = self
            .inner
            .control_plane
            .runner_certificate_rotation(fingerprint)
            .map_err(control_plane_status)?
        {
            if existing.runner_id != request.runner_id || existing.csr_digest != csr_digest {
                return Err(Status::already_exists(
                    "certificate fingerprint is bound to a different rotation CSR",
                ));
            }
            return rotation_response(&existing);
        }
        let durable = self
            .inner
            .control_plane
            .authenticate_runner_certificate(fingerprint, now)
            .map_err(control_plane_status)?;
        if durable.runner.runner.id != request.runner_id {
            return Err(Status::permission_denied(
                "certificate identity changed during rotation",
            ));
        }
        let issued = authority
            .issue(
                &request.certificate_signing_request,
                &request.runner_id,
                &durable.runner.runner.pool_id,
                now,
            )
            .map_err(certificate_status)?;
        let persisted = self
            .inner
            .control_plane
            .rotate_runner_certificate_idempotent(
                fingerprint,
                &request.runner_id,
                &csr_digest,
                &issued.record,
                &issued.certificate_chain_pem,
                now,
                duration_millis(self.inner.config.certificate_overlap)?,
            )
            .map_err(control_plane_status)?;
        rotation_response(&persisted.value)
    }
}

/// Enrollment-only façade for the TLS-server-auth listener. Every method
/// except `Enroll` is rejected without attempting application authentication.
#[derive(Clone)]
pub struct RunnerEnrollmentService {
    pub(super) control: RunnerControlService,
}

impl RunnerEnrollmentService {
    #[must_use]
    pub fn into_server(self) -> v1::runner_control_server::RunnerControlServer<Self> {
        v1::runner_control_server::RunnerControlServer::new(self)
            .max_decoding_message_size(MAX_STREAM_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_CONTROL_MESSAGE_BYTES)
    }
}

pub(super) fn enrollment_listener_denied<T>() -> Result<Response<T>, Status> {
    Err(Status::permission_denied(
        "this listener accepts only runner enrollment",
    ))
}

#[tonic::async_trait]
impl v1::runner_control_server::RunnerControl for RunnerEnrollmentService {
    async fn enroll(
        &self,
        request: Request<v1::EnrollRequest>,
    ) -> Result<Response<v1::EnrollResponse>, Status> {
        self.control
            .enroll_unauthenticated(request.into_inner())
            .await
            .map(Response::new)
    }

    async fn rotate_certificate(
        &self,
        _request: Request<v1::RotateCertificateRequest>,
    ) -> Result<Response<v1::RotateCertificateResponse>, Status> {
        enrollment_listener_denied()
    }

    async fn upload_blob(
        &self,
        _request: Request<tonic::Streaming<v1::UploadBlobChunk>>,
    ) -> Result<Response<v1::UploadBlobResponse>, Status> {
        enrollment_listener_denied()
    }

    type DownloadBlobStream = ReceiverStream<Result<v1::BlobChunk, Status>>;

    async fn download_blob(
        &self,
        _request: Request<v1::DownloadBlobRequest>,
    ) -> Result<Response<Self::DownloadBlobStream>, Status> {
        enrollment_listener_denied()
    }

    type OpenStream = ReceiverStream<Result<v1::ControlMessage, Status>>;

    async fn open(
        &self,
        _request: Request<tonic::Streaming<v1::RunnerMessage>>,
    ) -> Result<Response<Self::OpenStream>, Status> {
        enrollment_listener_denied()
    }

    async fn fetch_execution_capsule(
        &self,
        _request: Request<v1::FetchExecutionCapsuleRequest>,
    ) -> Result<Response<v1::FetchExecutionCapsuleResponse>, Status> {
        enrollment_listener_denied()
    }

    async fn request_secret_lease(
        &self,
        _request: Request<v1::SecretLeaseRequest>,
    ) -> Result<Response<v1::SecretLeaseResponse>, Status> {
        enrollment_listener_denied()
    }

    async fn revoke_secret_lease(
        &self,
        _request: Request<v1::RevokeSecretLeaseRequest>,
    ) -> Result<Response<()>, Status> {
        enrollment_listener_denied()
    }

    async fn mint_oidc_token(
        &self,
        _request: Request<v1::OidcTokenRequest>,
    ) -> Result<Response<v1::OidcTokenResponse>, Status> {
        enrollment_listener_denied()
    }

    async fn request_cache_ticket(
        &self,
        _request: Request<v1::CacheTicketRequest>,
    ) -> Result<Response<v1::CacheTicketResponse>, Status> {
        enrollment_listener_denied()
    }

    async fn commit_cache_entry(
        &self,
        _request: Request<v1::CommitCacheEntryRequest>,
    ) -> Result<Response<v1::CommitCacheEntryResponse>, Status> {
        enrollment_listener_denied()
    }

    async fn request_artifact_ticket(
        &self,
        _request: Request<v1::ArtifactTicketRequest>,
    ) -> Result<Response<v1::ArtifactTicketResponse>, Status> {
        enrollment_listener_denied()
    }

    async fn commit_artifact(
        &self,
        _request: Request<v1::CommitArtifactRequest>,
    ) -> Result<Response<v1::CommitArtifactResponse>, Status> {
        enrollment_listener_denied()
    }

    async fn complete_lease(
        &self,
        _request: Request<v1::CompleteLeaseRequest>,
    ) -> Result<Response<v1::CompleteLeaseResponse>, Status> {
        enrollment_listener_denied()
    }
}

pub(super) fn random_runner_id() -> Result<String, Status> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Status::internal("operating system randomness is unavailable"))?;
    Ok(format!("runner-{}", hex::encode(bytes)))
}

pub(super) fn source_ticket_id(
    lease_id: &str,
    fencing_generation: u64,
    job_attempt: u32,
) -> String {
    let mut material = Vec::with_capacity(lease_id.len() + 32);
    material.extend_from_slice(b"runtrue.runner.source-ticket.v2\0");
    material.extend_from_slice(lease_id.as_bytes());
    material.extend_from_slice(&fencing_generation.to_be_bytes());
    material.extend_from_slice(&job_attempt.to_be_bytes());
    format!(
        "source-{}",
        ContentDigest::sha256(material)
            .as_str()
            .trim_start_matches("sha256:")
    )
}
