#[cfg(test)]
use super::TestRunnerIdentity;
use super::{
    control_plane_status, data_status, now_unix_ms, parse_guest_session_key, proto_duration,
    proto_timestamp, require_session_lease, validate_bounded_text, validate_capsule_binding,
    validate_health, validate_identifier_status, validate_inventory, validate_locality,
    validate_runner_message_identity, AuthenticatedIdentity, RunnerControlConfig,
    RunnerControlInner, RunnerDataPlane, RunnerEnrollmentService, RunnerProtocolMetrics,
    RunnerProtocolMetricsSnapshot, RunnerServiceError, RunnerSession, RunnerUploadBinding,
    SessionState, MAX_BLOB_CHUNK_BYTES, MAX_CONNECTIONS, MAX_CONTROL_MESSAGE_BYTES,
    MAX_CONTROL_QUEUE, MAX_SECRET_LEASE_TTL_MS, MAX_STREAM_MESSAGE_BYTES,
    OBJECT_TRANSFER_IDLE_TIMEOUT,
};
use crate::runner_broker::{SecretEnvelopeBinding, SecretEnvelopeSealer, ENVELOPE_DELIVERY_KIND};
use crate::runner_certificates::RunnerCertificateAuthority;
use runtrue_cache::CacheRestoreRequest;
use runtrue_control_plane::{
    AuthorizeRunnerOidcRequest, ControlPlane, IssueRunnerSecretRequest, RecordRunnerBlobUpload,
    RecordRunnerOidcIssuance,
};
use runtrue_model::ContentDigest;
use runtrue_oidc::{MintTokenRequest, OidcIssuer, DEFAULT_TOKEN_TTL_SECONDS};
use runtrue_protocol::{v1, v2, PROTOCOL_MAX};
use runtrue_scheduler::{Lease, LeaseState, RunnerStatus};
use runtrue_scm::{EventEnvelope, GitHubPermission, GitHubPermissionLevel};
use runtrue_secrets::MasterKey;
use runtrue_secrets::SecretPlaintext;
use runtrue_storage::TreeEntryKind;
use runtrue_workflow_ir::{Access, ExecutionCapsule};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{atomic::Ordering, Arc, Mutex, MutexGuard},
};
use tokio::{sync::mpsc, time::Instant};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt as _};
use tonic::{Request, Response, Status};
#[derive(Clone)]
pub struct RunnerControlService {
    pub(super) inner: Arc<RunnerControlInner>,
}

impl RunnerControlService {
    pub fn new(
        control_plane: Arc<ControlPlane>,
        certificate_authority: Arc<RunnerCertificateAuthority>,
    ) -> Result<Self, RunnerServiceError> {
        Self::with_config(
            control_plane,
            certificate_authority,
            RunnerControlConfig::default(),
        )
    }

    pub fn new_with_brokers(
        control_plane: Arc<ControlPlane>,
        certificate_authority: Arc<RunnerCertificateAuthority>,
        secret_master_key: Arc<MasterKey>,
        oidc_issuer: Arc<OidcIssuer>,
    ) -> Result<Self, RunnerServiceError> {
        Self::new_with_brokers_and_config(
            control_plane,
            certificate_authority,
            secret_master_key,
            oidc_issuer,
            RunnerControlConfig::default(),
        )
    }

    pub fn new_with_brokers_and_config(
        control_plane: Arc<ControlPlane>,
        certificate_authority: Arc<RunnerCertificateAuthority>,
        secret_master_key: Arc<MasterKey>,
        oidc_issuer: Arc<OidcIssuer>,
        config: RunnerControlConfig,
    ) -> Result<Self, RunnerServiceError> {
        Self::with_optional_security(
            control_plane,
            Some(certificate_authority),
            Some(secret_master_key),
            Some(oidc_issuer),
            None,
            config,
        )
    }

    pub fn new_with_data_plane(
        control_plane: Arc<ControlPlane>,
        certificate_authority: Arc<RunnerCertificateAuthority>,
        secret_master_key: Arc<MasterKey>,
        oidc_issuer: Arc<OidcIssuer>,
        data_plane: Arc<RunnerDataPlane>,
    ) -> Result<Self, RunnerServiceError> {
        Self::new_with_data_plane_and_config(
            control_plane,
            certificate_authority,
            secret_master_key,
            oidc_issuer,
            data_plane,
            RunnerControlConfig::default(),
        )
    }

    pub fn new_with_data_plane_and_config(
        control_plane: Arc<ControlPlane>,
        certificate_authority: Arc<RunnerCertificateAuthority>,
        secret_master_key: Arc<MasterKey>,
        oidc_issuer: Arc<OidcIssuer>,
        data_plane: Arc<RunnerDataPlane>,
        config: RunnerControlConfig,
    ) -> Result<Self, RunnerServiceError> {
        Self::with_optional_security(
            control_plane,
            Some(certificate_authority),
            Some(secret_master_key),
            Some(oidc_issuer),
            Some(data_plane),
            config,
        )
    }

    pub fn with_config(
        control_plane: Arc<ControlPlane>,
        certificate_authority: Arc<RunnerCertificateAuthority>,
        config: RunnerControlConfig,
    ) -> Result<Self, RunnerServiceError> {
        Self::with_optional_security(
            control_plane,
            Some(certificate_authority),
            None,
            None,
            None,
            config,
        )
    }

    pub(super) fn with_optional_security(
        control_plane: Arc<ControlPlane>,
        certificate_authority: Option<Arc<RunnerCertificateAuthority>>,
        secret_master_key: Option<Arc<MasterKey>>,
        oidc_issuer: Option<Arc<OidcIssuer>>,
        data_plane: Option<Arc<RunnerDataPlane>>,
        config: RunnerControlConfig,
    ) -> Result<Self, RunnerServiceError> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(RunnerControlInner {
                control_plane,
                certificate_authority,
                secret_master_key,
                oidc_issuer,
                data_plane,
                scm_credential_provider: None,
                config,
                protocol_metrics: RunnerProtocolMetrics::default(),
                connections: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    pub fn with_scm_credential_provider(
        mut self,
        provider: Arc<dyn crate::scm_worker::GitHubInstallationTokenProvider>,
    ) -> Result<Self, RunnerServiceError> {
        let inner =
            Arc::get_mut(&mut self.inner).ok_or(RunnerServiceError::InvalidConfiguration)?;
        inner.scm_credential_provider = Some(provider);
        Ok(self)
    }

    #[cfg(test)]
    pub(super) fn with_test_config(
        control_plane: Arc<ControlPlane>,
        config: RunnerControlConfig,
    ) -> Result<Self, RunnerServiceError> {
        Self::with_optional_security(control_plane, None, None, None, None, config)
    }

    #[must_use]
    pub fn into_server(self) -> v1::runner_control_server::RunnerControlServer<Self> {
        v1::runner_control_server::RunnerControlServer::new(self)
            .max_decoding_message_size(MAX_STREAM_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_CONTROL_MESSAGE_BYTES)
    }

    #[must_use]
    pub fn into_v2_server(
        self,
    ) -> v2::runner_object_transfer_server::RunnerObjectTransferServer<Self> {
        v2::runner_object_transfer_server::RunnerObjectTransferServer::new(self)
            .max_decoding_message_size(MAX_STREAM_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_STREAM_MESSAGE_BYTES)
    }

    #[must_use]
    pub fn enrollment_service(&self) -> RunnerEnrollmentService {
        RunnerEnrollmentService {
            control: self.clone(),
        }
    }

    #[must_use]
    pub fn protocol_metrics(&self) -> RunnerProtocolMetricsSnapshot {
        self.inner.protocol_metrics.snapshot()
    }

    pub(super) fn authenticate<T>(
        &self,
        request: &Request<T>,
    ) -> Result<AuthenticatedIdentity, Status> {
        #[cfg(test)]
        if let Some(identity) = request.extensions().get::<TestRunnerIdentity>() {
            return Ok(AuthenticatedIdentity {
                runner_id: identity.0.clone(),
                certificate_fingerprint: None,
                certificate_expires_unix_ms: None,
            });
        }

        let certificates = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("a verified client certificate is required"))?;
        let leaf = certificates
            .first()
            .ok_or_else(|| Status::unauthenticated("a verified client certificate is required"))?;
        let fingerprint = ContentDigest::sha256(leaf.as_ref());
        let authenticated = self
            .inner
            .control_plane
            .authenticate_runner_certificate(&fingerprint, now_unix_ms()?)
            .map_err(control_plane_status)?;
        Ok(AuthenticatedIdentity {
            runner_id: authenticated.runner.runner.id,
            certificate_fingerprint: Some(fingerprint),
            certificate_expires_unix_ms: Some(authenticated.certificate.not_after_unix_ms),
        })
    }

    /// Extract only the identity asserted by the already-verified TLS peer.
    /// This deliberately bypasses application-level certificate status solely
    /// for RotateCertificate, whose durable journal decides whether the call
    /// is an exact replay. Every ordinary RPC continues through `authenticate`.
    pub(super) fn authenticate_rotation_peer<T>(
        &self,
        request: &Request<T>,
    ) -> Result<AuthenticatedIdentity, Status> {
        #[cfg(test)]
        if let Some(identity) = request.extensions().get::<TestRunnerIdentity>() {
            return Ok(AuthenticatedIdentity {
                runner_id: identity.0.clone(),
                certificate_fingerprint: None,
                certificate_expires_unix_ms: None,
            });
        }
        let certificates = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("a verified client certificate is required"))?;
        let leaf = certificates
            .first()
            .ok_or_else(|| Status::unauthenticated("a verified client certificate is required"))?;
        Ok(AuthenticatedIdentity {
            // The exact runner binding is checked against durable certificate
            // and rotation records after the request body is decoded.
            runner_id: String::new(),
            certificate_fingerprint: Some(ContentDigest::sha256(leaf.as_ref())),
            certificate_expires_unix_ms: None,
        })
    }

    pub(super) fn connections(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<String, Arc<RunnerSession>>>, Status> {
        self.inner
            .connections
            .lock()
            .map_err(|_| Status::internal("runner connection registry is unavailable"))
    }

    pub(super) fn session(&self, runner_id: &str) -> Result<Arc<RunnerSession>, Status> {
        self.connections()?
            .get(runner_id)
            .cloned()
            .ok_or_else(|| Status::failed_precondition("runner has no active Open session"))
    }

    pub(super) fn authenticated_session(
        &self,
        authenticated: &AuthenticatedIdentity,
    ) -> Result<Arc<RunnerSession>, Status> {
        let session = self.session(&authenticated.runner_id)?;
        if session.certificate_fingerprint != authenticated.certificate_fingerprint {
            return Err(Status::permission_denied(
                "unary client certificate does not own the live Open session",
            ));
        }
        Ok(session)
    }

    pub(super) fn register_session(&self, session: Arc<RunnerSession>) -> Result<(), Status> {
        let mut connections = self.connections()?;
        if connections.len() >= MAX_CONNECTIONS {
            return Err(Status::resource_exhausted(
                "runner connection limit reached",
            ));
        }
        if connections.contains_key(&session.runner_id)
            || connections
                .values()
                .any(|existing| existing.connection_id == session.connection_id)
        {
            return Err(Status::already_exists(
                "runner or connection already has an active Open session",
            ));
        }
        connections.insert(session.runner_id.clone(), session);
        Ok(())
    }

    pub(super) fn remove_session(&self, runner_id: &str, connection_id: &str) {
        let Ok(mut connections) = self.connections() else {
            return;
        };
        if connections
            .get(runner_id)
            .is_some_and(|session| session.connection_id == connection_id)
        {
            connections.remove(runner_id);
        }
    }

    pub(super) fn cleanup_session(&self, session: &RunnerSession) {
        if let Ok(now) = now_unix_ms() {
            let _ = self
                .inner
                .control_plane
                .mark_runner_disconnected(&session.runner_id, now);
        }
        self.remove_session(&session.runner_id, &session.connection_id);
    }

    pub(super) async fn send_control(
        &self,
        session: &RunnerSession,
        message: v1::ControlMessage,
    ) -> Result<(), Status> {
        tokio::time::timeout(
            self.inner.config.stream_send_timeout,
            session.outbound.send(Ok(message)),
        )
        .await
        .map_err(|_| Status::resource_exhausted("runner control stream is backpressured"))?
        .map_err(|_| Status::unavailable("runner control stream is closed"))
    }

    pub(super) async fn send_stream_error(&self, session: &RunnerSession, status: Status) {
        let _ = tokio::time::timeout(
            self.inner.config.stream_send_timeout,
            session.outbound.send(Err(status)),
        )
        .await;
    }

    pub(super) async fn open_authenticated<S>(
        &self,
        authenticated: AuthenticatedIdentity,
        mut inbound: S,
    ) -> Result<ReceiverStream<Result<v1::ControlMessage, Status>>, Status>
    where
        S: Stream<Item = Result<v1::RunnerMessage, Status>> + Send + Unpin + 'static,
    {
        let first = tokio::time::timeout(self.inner.config.heartbeat_timeout, inbound.next())
            .await
            .map_err(|_| Status::deadline_exceeded("RunnerHello was not received in time"))?
            .ok_or_else(|| Status::invalid_argument("RunnerHello is required"))??;
        let hello = match first.body {
            Some(v1::runner_message::Body::Hello(hello)) => hello,
            _ => {
                return Err(Status::invalid_argument(
                    "RunnerHello must be the first message",
                ));
            }
        };
        validate_identifier_status("runner id", &hello.runner_id)?;
        validate_identifier_status("connection id", &hello.connection_id)?;
        if hello.runner_id != authenticated.runner_id {
            return Err(Status::permission_denied(
                "RunnerHello does not match the client certificate identity",
            ));
        }
        if hello.protocol_version < self.inner.config.protocol_minimum
            || hello.protocol_version > PROTOCOL_MAX
        {
            self.inner
                .protocol_metrics
                .stream_version_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(Status::failed_precondition(
                "runner protocol version is below the installation security minimum or unsupported",
            ));
        }
        let recovery = self
            .inner
            .control_plane
            .recovery_state()
            .map_err(control_plane_status)?;
        if recovery.safe_mode {
            return Err(Status::unavailable(
                "runner connections are disabled during restore safe mode",
            ));
        }
        let persisted = self
            .inner
            .control_plane
            .runner(&authenticated.runner_id)
            .map_err(control_plane_status)?;
        if matches!(
            persisted.runner.status,
            RunnerStatus::Revoked | RunnerStatus::Quarantined
        ) {
            return Err(Status::permission_denied(
                "runner is revoked or quarantined",
            ));
        }
        let inventory = hello
            .inventory
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("RunnerHello inventory is required"))?;
        let inventory_digest =
            validate_inventory(&persisted.runner, inventory, hello.protocol_version)?;
        let posture_digest = self
            .inner
            .control_plane
            .validate_runner_inventory_binding(&persisted.runner.id, &inventory_digest)
            .map_err(control_plane_status)?;
        let runner_image_digest = inventory
            .runner_image_digest
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("runner image digest is required"))?;
        let runner_image_digest = ContentDigest::try_from(runner_image_digest)
            .map_err(|_| Status::invalid_argument("runner image digest is invalid"))?;

        let (outbound, receiver) = mpsc::channel(MAX_CONTROL_QUEUE);
        let session = Arc::new(RunnerSession {
            runner_id: authenticated.runner_id,
            connection_id: hello.connection_id,
            protocol_version: hello.protocol_version,
            posture_digest,
            runner_image_digest,
            certificate_fingerprint: authenticated.certificate_fingerprint,
            certificate_expires_unix_ms: authenticated.certificate_expires_unix_ms,
            outbound,
            state: Mutex::new(SessionState {
                offered: BTreeMap::new(),
                accepted: BTreeMap::new(),
                cancellation_acks: BTreeSet::new(),
                log_sequences: BTreeMap::new(),
                running_steps: BTreeMap::new(),
                terminal_steps: BTreeSet::new(),
                scm_credential_leases: BTreeSet::new(),
                current_attempts: BTreeMap::new(),
                rotation_notice_sent: false,
            }),
            offer_lock: tokio::sync::Mutex::new(()),
        });
        self.register_session(Arc::clone(&session))?;
        if let Err(error) = self
            .inner
            .control_plane
            .mark_runner_connected(&session.runner_id, now_unix_ms()?)
        {
            self.remove_session(&session.runner_id, &session.connection_id);
            return Err(control_plane_status(error));
        }

        let control_hello = v1::ControlMessage {
            body: Some(v1::control_message::Body::Hello(v1::ControlHello {
                connection_id: session.connection_id.clone(),
                heartbeat_interval: Some(proto_duration(self.inner.config.heartbeat_interval)?),
                server_time: Some(proto_timestamp(now_unix_ms()?)),
                installation_fencing_epoch: recovery.fencing_epoch,
            })),
        };
        if let Err(error) = self.send_control(&session, control_hello).await {
            self.cleanup_session(&session);
            return Err(error);
        }
        if let Err(error) = self.synchronize_session(&session, now_unix_ms()?).await {
            self.cleanup_session(&session);
            return Err(error);
        }

        let service = self.clone();
        tokio::spawn(async move {
            let result = service.consume_stream(Arc::clone(&session), inbound).await;
            if let Err(status) = result {
                service.send_stream_error(&session, status).await;
            }
            service.cleanup_session(&session);
        });
        Ok(ReceiverStream::new(receiver))
    }

    pub(super) async fn consume_stream<S>(
        &self,
        session: Arc<RunnerSession>,
        mut inbound: S,
    ) -> Result<(), Status>
    where
        S: Stream<Item = Result<v1::RunnerMessage, Status>> + Send + Unpin + 'static,
    {
        let mut heartbeat_deadline = Instant::now() + self.inner.config.heartbeat_timeout;
        loop {
            let message = tokio::select! {
                () = tokio::time::sleep_until(heartbeat_deadline) => {
                    return Err(Status::deadline_exceeded("runner heartbeat timed out"));
                }
                message = inbound.next() => message,
            };
            let Some(message) = message else {
                return Ok(());
            };
            let message = message?;
            if self.handle_runner_message(&session, message).await? {
                heartbeat_deadline = Instant::now() + self.inner.config.heartbeat_timeout;
            }
        }
    }

    pub(super) async fn handle_runner_message(
        &self,
        session: &Arc<RunnerSession>,
        message: v1::RunnerMessage,
    ) -> Result<bool, Status> {
        match message.body {
            Some(v1::runner_message::Body::Heartbeat(heartbeat)) => {
                self.handle_heartbeat(session, &heartbeat).await?;
                Ok(true)
            }
            Some(v1::runner_message::Body::LeaseDecision(decision)) => {
                self.handle_lease_decision(session, &decision).await?;
                Ok(false)
            }
            Some(v1::runner_message::Body::JobState(update)) => {
                self.handle_job_state(session, &update)?;
                Ok(false)
            }
            Some(v1::runner_message::Body::StepState(update)) => {
                self.validate_step_state(session, &update)?;
                Ok(false)
            }
            Some(v1::runner_message::Body::LogBatch(batch)) => {
                self.validate_log_batch(session, &batch)?;
                Ok(false)
            }
            Some(v1::runner_message::Body::CancellationAck(ack)) => {
                self.handle_cancellation_ack(session, &ack)?;
                Ok(false)
            }
            Some(v1::runner_message::Body::Locality(locality)) => {
                validate_runner_message_identity(session, &locality.runner_id)?;
                let digests = validate_locality(&locality)?;
                self.inner
                    .control_plane
                    .update_runner_locality(&session.runner_id, &digests, now_unix_ms()?)
                    .map_err(control_plane_status)?;
                Ok(false)
            }
            Some(v1::runner_message::Body::Health(health)) => {
                validate_runner_message_identity(session, &health.runner_id)?;
                validate_health(&health)?;
                Ok(false)
            }
            Some(v1::runner_message::Body::Hello(_)) | None => Err(Status::invalid_argument(
                "RunnerHello is allowed only as the first stream message",
            )),
        }
    }
}
impl RunnerControlService {
    fn issue_scm_provider_credential(
        &self,
        session: &Arc<RunnerSession>,
        lease: &Lease,
        request: &v1::SecretLeaseRequest,
        guest_key: [u8; 32],
        maximum_expires_unix_ms: u64,
    ) -> Result<Option<v1::SecretLeaseResponse>, Status> {
        let (job_key, signed) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&lease.id)
            .map_err(control_plane_status)?;
        validate_capsule_binding(lease, &signed)?;
        let capsule: ExecutionCapsule = serde_json::from_slice(&signed.canonical_capsule)
            .map_err(|_| Status::data_loss("durable execution capsule is invalid"))?;
        if capsule.canonical_bytes().ok().as_deref() != Some(signed.canonical_capsule.as_slice())
            || capsule.digest().ok() != Some(lease.capsule_digest.clone())
        {
            return Err(Status::data_loss(
                "durable signed execution capsule is not canonical",
            ));
        }
        let job = capsule
            .jobs
            .iter()
            .find(|job| job.id == job_key)
            .ok_or_else(|| Status::data_loss("signed lease job is absent from its capsule"))?;
        let step = job
            .steps
            .iter()
            .find(|step| step.id == request.step_id)
            .ok_or_else(|| Status::permission_denied("SCM credential step is not declared"))?;
        let provider_grant = step.capabilities.secrets.iter().find(|grant| {
            grant.name == "runtrue-scm-provider-token"
                && grant.metadata_id == request.secret_metadata_id
                && grant.purpose.as_deref().unwrap_or_default() == request.purpose
        });
        if provider_grant.is_none() {
            return Ok(None);
        }
        if job.permissions.scm.is_denied() {
            return Err(Status::permission_denied(
                "SCM credential has no signed provider permissions",
            ));
        }
        let scm = capsule
            .context
            .scm
            .as_ref()
            .filter(|context| context.provider == "git_hub")
            .ok_or_else(|| {
                Status::permission_denied("signed SCM provider context is unavailable")
            })?;
        let encoded_event = capsule
            .context
            .normalized_event_json
            .as_ref()
            .ok_or_else(|| Status::data_loss("signed SCM event is unavailable"))?;
        let event: EventEnvelope = serde_json::from_str(encoded_event)
            .map_err(|_| Status::data_loss("signed SCM event is invalid"))?;
        event
            .verify(Default::default())
            .map_err(|_| Status::data_loss("signed SCM event digest is invalid"))?;
        if event.repository.full_name != scm.repository {
            return Err(Status::permission_denied(
                "SCM runtime repository does not match its signed event",
            ));
        }
        let (repository, installation, link) = self
            .inner
            .control_plane
            .github_repository_for_event(
                &event.installation_id,
                &event.repository.external_id,
                &event.repository.owner,
                &event.repository.name,
            )
            .map_err(control_plane_status)?;
        if repository.id != signed.repository_id {
            return Err(Status::permission_denied(
                "SCM credential repository does not match the signed capsule",
            ));
        }
        let permissions = github_provider_permissions(&job.permissions.scm);
        let provider = self.inner.scm_credential_provider.as_ref().ok_or_else(|| {
            Status::failed_precondition("SCM credential broker is not configured")
        })?;
        let credential = provider
            .mint_provider_token(
                &installation,
                &link,
                &repository.owner,
                &repository.name,
                &permissions,
            )
            .map_err(|error| {
                eprintln!("SCM provider credential mint failed: {error}");
                Status::unavailable("SCM provider credential is unavailable")
            })?;
        let provider_expires_unix_ms = credential
            .expires_at_unix_seconds
            .checked_mul(1_000)
            .ok_or_else(|| Status::out_of_range("SCM credential expiry is invalid"))?;
        let expires_unix_ms = provider_expires_unix_ms.min(maximum_expires_unix_ms);
        if expires_unix_ms <= now_unix_ms()? {
            return Err(Status::failed_precondition(
                "SCM provider credential is already expiring",
            ));
        }
        let suffix = credential
            .scope_digest
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or_else(|| credential.scope_digest.as_str());
        let secret_lease_id = format!("scm-{suffix}");
        let sealer = SecretEnvelopeSealer::new(guest_key)
            .map_err(|_| Status::invalid_argument("guest session X25519 public key is invalid"))?;
        let plaintext = SecretPlaintext::new(credential.bearer_token().as_bytes().to_vec());
        let envelope = sealer
            .seal(
                &SecretEnvelopeBinding {
                    execution_lease_id: &lease.id,
                    fencing_generation: lease.fencing_generation,
                    installation_fencing_epoch: lease.installation_fencing_epoch,
                    job_id: &request.job_id,
                    job_attempt: request.job_attempt,
                    step_id: &request.step_id,
                    secret_lease_id: &secret_lease_id,
                    secret_metadata_id: &request.secret_metadata_id,
                    purpose: &request.purpose,
                    expires_unix_ms,
                },
                &plaintext,
            )
            .map_err(|_| Status::internal("SCM credential envelope encryption failed"))?;
        session
            .state()?
            .scm_credential_leases
            .insert(secret_lease_id.clone());
        Ok(Some(v1::SecretLeaseResponse {
            secret_lease_id,
            encrypted_envelope: envelope,
            delivery_kind: ENVELOPE_DELIVERY_KIND.to_owned(),
            expires_at: Some(proto_timestamp(expires_unix_ms)),
        }))
    }

    pub(super) fn request_secret_authenticated(
        &self,
        authenticated: &AuthenticatedIdentity,
        request: v1::SecretLeaseRequest,
    ) -> Result<v1::SecretLeaseResponse, Status> {
        validate_identifier_status("secret metadata id", &request.secret_metadata_id)?;
        validate_bounded_text("secret purpose", &request.purpose, true)?;
        let (session, lease) = self.active_broker_binding(
            authenticated,
            &request.execution_lease_id,
            request.fencing_generation,
            &request.job_id,
            request.job_attempt,
            &request.step_id,
        )?;
        let guest_key = parse_guest_session_key(request.guest_session_key.as_ref())?;
        let now = now_unix_ms()?;
        let expires_unix_ms = now
            .checked_add(MAX_SECRET_LEASE_TTL_MS)
            .map(|deadline| deadline.min(lease.expires_unix_ms))
            .filter(|deadline| *deadline > now)
            .ok_or_else(|| Status::failed_precondition("execution lease is expiring"))?;
        if let Some(response) = self.issue_scm_provider_credential(
            &session,
            &lease,
            &request,
            guest_key,
            expires_unix_ms,
        )? {
            return Ok(response);
        }
        let mut guest_key_binding = Vec::with_capacity(64);
        guest_key_binding.extend_from_slice(b"runtrue.runner.guest-x25519-key.v1\0");
        guest_key_binding.extend_from_slice(&guest_key);
        let sealer = SecretEnvelopeSealer::new(guest_key)
            .map_err(|_| Status::invalid_argument("guest session X25519 public key is invalid"))?;
        let master_key =
            self.inner.secret_master_key.as_ref().ok_or_else(|| {
                Status::failed_precondition("runner secret broker is not configured")
            })?;
        let running_state = session.state()?;
        if running_state
            .running_steps
            .get(&(lease.id.clone(), request.job_attempt))
            .map(String::as_str)
            != Some(request.step_id.as_str())
        {
            return Err(Status::failed_precondition(
                "secret release raced with the running step transition",
            ));
        }
        let delivered = self
            .inner
            .control_plane
            .issue_runner_secret(
                &IssueRunnerSecretRequest {
                    execution_lease_id: lease.id.clone(),
                    fencing_generation: lease.fencing_generation,
                    runner_id: authenticated.runner_id.clone(),
                    job_id: lease.job_id.clone(),
                    job_attempt: request.job_attempt,
                    step_id: request.step_id.clone(),
                    secret_metadata_id: request.secret_metadata_id.clone(),
                    purpose: request.purpose.clone(),
                    guest_key_fingerprint: ContentDigest::sha256(guest_key_binding),
                    runner_posture_digest: session.posture_digest.clone(),
                    issued_unix_ms: now,
                    expires_unix_ms,
                },
                master_key,
            )
            .map_err(control_plane_status)?;
        drop(running_state);
        let envelope = sealer
            .seal(
                &SecretEnvelopeBinding {
                    execution_lease_id: &lease.id,
                    fencing_generation: lease.fencing_generation,
                    installation_fencing_epoch: lease.installation_fencing_epoch,
                    job_id: &request.job_id,
                    job_attempt: request.job_attempt,
                    step_id: &request.step_id,
                    secret_lease_id: &delivered.lease.id,
                    secret_metadata_id: &request.secret_metadata_id,
                    purpose: &request.purpose,
                    expires_unix_ms,
                },
                &delivered.plaintext,
            )
            .map_err(|_| Status::internal("secret envelope encryption failed"))?;
        Ok(v1::SecretLeaseResponse {
            secret_lease_id: delivered.lease.id,
            encrypted_envelope: envelope,
            delivery_kind: ENVELOPE_DELIVERY_KIND.to_owned(),
            expires_at: Some(proto_timestamp(expires_unix_ms)),
        })
    }

    pub(super) fn revoke_secret_authenticated(
        &self,
        authenticated: &AuthenticatedIdentity,
        request: v1::RevokeSecretLeaseRequest,
    ) -> Result<(), Status> {
        validate_identifier_status("secret lease id", &request.secret_lease_id)?;
        validate_identifier_status("execution lease id", &request.execution_lease_id)?;
        let session = self.authenticated_session(authenticated)?;
        require_session_lease(
            &session,
            &request.execution_lease_id,
            request.fencing_generation,
            true,
        )?;
        let lease = self.bound_lease(
            &authenticated.runner_id,
            &request.execution_lease_id,
            request.fencing_generation,
        )?;
        if lease.state != LeaseState::Active {
            return Err(Status::failed_precondition(
                "secret revocation requires an active accepted lease",
            ));
        }
        {
            let mut state = session.state()?;
            if state.scm_credential_leases.remove(&request.secret_lease_id) {
                if !state
                    .running_steps
                    .contains_key(&(request.execution_lease_id.clone(), request.job_attempt))
                {
                    return Err(Status::failed_precondition(
                        "SCM credential revocation requires its running step",
                    ));
                }
                return Ok(());
            }
        }
        let record = self
            .inner
            .control_plane
            .runner_secret_lease(&request.secret_lease_id)
            .map_err(control_plane_status)?;
        let state = session.state()?;
        if state
            .running_steps
            .get(&(request.execution_lease_id.clone(), request.job_attempt))
            .map(String::as_str)
            != Some(record.step_id.as_str())
        {
            return Err(Status::failed_precondition(
                "secret revocation must come from its currently running step",
            ));
        }
        self.inner
            .control_plane
            .revoke_runner_secret(
                &request.secret_lease_id,
                &request.execution_lease_id,
                request.fencing_generation,
                &authenticated.runner_id,
                now_unix_ms()?,
            )
            .map_err(control_plane_status)?;
        drop(state);
        Ok(())
    }

    pub(super) fn mint_oidc_authenticated(
        &self,
        authenticated: &AuthenticatedIdentity,
        request: v1::OidcTokenRequest,
    ) -> Result<v1::OidcTokenResponse, Status> {
        validate_bounded_text("OIDC audience", &request.audience, false)?;
        let (session, lease) = self.active_broker_binding(
            authenticated,
            &request.execution_lease_id,
            request.fencing_generation,
            &request.job_id,
            request.job_attempt,
            &request.step_id,
        )?;
        let now = now_unix_ms()?;
        let running_state = session.state()?;
        if running_state
            .running_steps
            .get(&(lease.id.clone(), request.job_attempt))
            .map(String::as_str)
            != Some(request.step_id.as_str())
        {
            return Err(Status::failed_precondition(
                "OIDC mint raced with the running step transition",
            ));
        }
        let grant = self
            .inner
            .control_plane
            .authorize_runner_oidc(&AuthorizeRunnerOidcRequest {
                execution_lease_id: lease.id.clone(),
                fencing_generation: lease.fencing_generation,
                runner_id: authenticated.runner_id.clone(),
                job_id: lease.job_id.clone(),
                job_attempt: request.job_attempt,
                step_id: request.step_id.clone(),
                audience: request.audience.clone(),
                runner_posture_digest: session.posture_digest.clone(),
                now_unix_ms: now,
            })
            .map_err(control_plane_status)?;
        let issuer =
            self.inner.oidc_issuer.as_ref().ok_or_else(|| {
                Status::failed_precondition("runner OIDC broker is not configured")
            })?;
        let minted = issuer
            .mint(
                &grant,
                &MintTokenRequest {
                    audience: request.audience.clone(),
                    ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
                },
                now / 1000,
            )
            .map_err(|_| Status::failed_precondition("OIDC grant cannot mint this token"))?;
        let expires_unix_ms = minted
            .expires_unix_seconds
            .checked_mul(1000)
            .ok_or_else(|| Status::out_of_range("OIDC expiry is outside the supported range"))?;
        self.inner
            .control_plane
            .record_runner_oidc_issuance(&RecordRunnerOidcIssuance {
                grant_id: grant.grant_id,
                audience: request.audience,
                jti: minted.jti.clone(),
                runner_id: authenticated.runner_id.clone(),
                runner_posture_digest: session.posture_digest.clone(),
                job_attempt: request.job_attempt,
                issued_unix_ms: now,
                expires_unix_ms,
            })
            .map_err(control_plane_status)?;
        drop(running_state);
        Ok(v1::OidcTokenResponse {
            token: minted.token,
            expires_at: Some(proto_timestamp(expires_unix_ms)),
            jti: minted.jti,
        })
    }
}
#[tonic::async_trait]
impl v1::runner_control_server::RunnerControl for RunnerControlService {
    async fn enroll(
        &self,
        _request: Request<v1::EnrollRequest>,
    ) -> Result<Response<v1::EnrollResponse>, Status> {
        Err(Status::permission_denied(
            "runner enrollment is available only on the enrollment listener",
        ))
    }

    async fn rotate_certificate(
        &self,
        request: Request<v1::RotateCertificateRequest>,
    ) -> Result<Response<v1::RotateCertificateResponse>, Status> {
        let authenticated = self.authenticate_rotation_peer(&request)?;
        self.rotate_authenticated(&authenticated, request.into_inner())
            .await
            .map(Response::new)
    }

    type OpenStream = ReceiverStream<Result<v1::ControlMessage, Status>>;

    async fn open(
        &self,
        request: Request<tonic::Streaming<v1::RunnerMessage>>,
    ) -> Result<Response<Self::OpenStream>, Status> {
        let authenticated = self.authenticate(&request)?;
        self.open_authenticated(authenticated, request.into_inner())
            .await
            .map(Response::new)
    }

    async fn fetch_execution_capsule(
        &self,
        request: Request<v1::FetchExecutionCapsuleRequest>,
    ) -> Result<Response<v1::FetchExecutionCapsuleResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        self.fetch_authenticated(&authenticated, request.into_inner())
            .await
            .map(Response::new)
    }

    async fn request_secret_lease(
        &self,
        request: Request<v1::SecretLeaseRequest>,
    ) -> Result<Response<v1::SecretLeaseResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        self.request_secret_authenticated(&authenticated, request.into_inner())
            .map(Response::new)
    }

    async fn revoke_secret_lease(
        &self,
        request: Request<v1::RevokeSecretLeaseRequest>,
    ) -> Result<Response<()>, Status> {
        let authenticated = self.authenticate(&request)?;
        self.revoke_secret_authenticated(&authenticated, request.into_inner())?;
        Ok(Response::new(()))
    }

    async fn mint_oidc_token(
        &self,
        request: Request<v1::OidcTokenRequest>,
    ) -> Result<Response<v1::OidcTokenResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        self.mint_oidc_authenticated(&authenticated, request.into_inner())
            .map(Response::new)
    }

    async fn request_cache_ticket(
        &self,
        request: Request<v1::CacheTicketRequest>,
    ) -> Result<Response<v1::CacheTicketResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        self.request_cache_ticket_authenticated(&authenticated, request.into_inner())
            .map(Response::new)
    }

    async fn commit_cache_entry(
        &self,
        request: Request<v1::CommitCacheEntryRequest>,
    ) -> Result<Response<v1::CommitCacheEntryResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        self.commit_cache_authenticated(&authenticated, request.into_inner())
            .map(Response::new)
    }

    async fn request_artifact_ticket(
        &self,
        request: Request<v1::ArtifactTicketRequest>,
    ) -> Result<Response<v1::ArtifactTicketResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        self.request_artifact_ticket_authenticated(&authenticated, request.into_inner())
            .map(Response::new)
    }

    async fn commit_artifact(
        &self,
        request: Request<v1::CommitArtifactRequest>,
    ) -> Result<Response<v1::CommitArtifactResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        self.commit_artifact_authenticated(&authenticated, request.into_inner())
            .map(Response::new)
    }

    async fn upload_blob(
        &self,
        request: Request<tonic::Streaming<v1::UploadBlobChunk>>,
    ) -> Result<Response<v1::UploadBlobResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        let _transfer_slot = self
            .data_plane()?
            .transfer_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted("runner object transfer concurrency exhausted")
            })?;
        let mut stream = request.into_inner();
        let first = tokio::time::timeout(OBJECT_TRANSFER_IDLE_TIMEOUT, stream.message())
            .await
            .map_err(|_| Status::deadline_exceeded("blob upload idle timeout"))??
            .ok_or_else(|| Status::invalid_argument("blob upload stream is empty"))?;
        let declared = first
            .declared_digest
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("blob digest is required"))?;
        let declared = ContentDigest::try_from(declared)
            .map_err(|_| Status::invalid_argument("blob digest is invalid"))?;
        let binding = RunnerUploadBinding {
            execution_lease_id: first.execution_lease_id.clone(),
            fencing_generation: first.fencing_generation,
            job_id: first.job_id.clone(),
            job_attempt: first.job_attempt,
            step_id: first.step_id.clone(),
            ticket_id: first.ticket_id.clone(),
            ticket_kind: first.ticket_kind.clone(),
            declared_digest: declared,
            declared_size: None,
        };
        let authorized = self.authorize_runner_upload(&authenticated, &binding)?;
        let mut pending = self.begin_runner_upload(&authorized)?;
        let mut next = Some(first);
        while let Some(chunk) = next.take() {
            Self::require_runner_upload_active(&authorized)?;
            let chunk_digest = chunk
                .declared_digest
                .as_ref()
                .map(ContentDigest::try_from)
                .transpose()
                .map_err(|_| Status::invalid_argument("blob digest is invalid"))?;
            if chunk.execution_lease_id != binding.execution_lease_id
                || chunk.fencing_generation != binding.fencing_generation
                || chunk.job_id != binding.job_id
                || chunk.job_attempt != binding.job_attempt
                || chunk.step_id != binding.step_id
                || chunk.ticket_id != binding.ticket_id
                || chunk.ticket_kind != binding.ticket_kind
                || chunk_digest.as_ref() != Some(&binding.declared_digest)
            {
                return Err(Status::invalid_argument(
                    "blob upload chunk metadata mismatch",
                ));
            }
            Self::append_runner_upload_chunk(
                &mut pending,
                &v2::ObjectChunk {
                    offset: chunk.offset,
                    payload: chunk.payload,
                },
                None,
                authorized.maximum_blob_bytes,
            )
            .await?;
            next = tokio::time::timeout(Self::runner_upload_wait(&authorized)?, stream.message())
                .await
                .map_err(|_| Status::deadline_exceeded("blob upload idle timeout"))??;
        }
        self.finish_runner_upload(&authenticated, &binding, authorized, pending)
            .await
            .map(Response::new)
    }

    type DownloadBlobStream = ReceiverStream<Result<v1::BlobChunk, Status>>;

    async fn download_blob(
        &self,
        request: Request<v1::DownloadBlobRequest>,
    ) -> Result<Response<Self::DownloadBlobStream>, Status> {
        let authenticated = self.authenticate(&request)?;
        let transfer_slot = self
            .data_plane()?
            .transfer_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted("runner object transfer concurrency exhausted")
            })?;
        let request = request.into_inner();
        let subject = self.active_data_subject(
            &authenticated,
            &request.execution_lease_id,
            request.fencing_generation,
            &request.job_id,
            request.job_attempt,
            &request.step_id,
        )?;
        let data = self.data_plane()?;
        let ticket_id = ContentDigest::parse(request.ticket_id)
            .map_err(|_| Status::invalid_argument("cache restore ticket id is invalid"))?;
        let ticket = data.cache.write_ticket(&ticket_id).map_err(data_status)?;
        let entry = data
            .cache
            .ticketed_restore_entry(&CacheRestoreRequest {
                ticket: &ticket,
                active_tenant_id: &subject.repository.tenant_id,
                active_repository_id: &subject.repository.id,
                active_job_id: &subject.lease.job_id,
                active_job_attempt: request.job_attempt,
                active_step_id: &request.step_id,
                active_lease_id: &subject.lease.id,
                active_fencing_generation: subject.lease.fencing_generation,
                now_unix_seconds: now_unix_ms()? / 1000,
            })
            .map_err(data_status)?
            .ok_or_else(|| Status::not_found("cache restore ticket is a miss"))?;
        let digest = request
            .digest
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("download digest is required"))?;
        let digest = ContentDigest::try_from(digest)
            .map_err(|_| Status::invalid_argument("download digest is invalid"))?;
        let manifest = data
            .cas
            .load_tree_manifest(&entry.manifest.tree.manifest_digest)
            .map_err(data_status)?;
        let allowed = digest == entry.manifest.tree.manifest_digest
            || manifest.entries.iter().any(|entry| {
                matches!(&entry.kind, TreeEntryKind::File { digest: file, .. } if *file == digest)
            });
        if !allowed {
            return Err(Status::permission_denied(
                "blob is not part of the ticketed cache snapshot",
            ));
        }
        let read_limit = if digest == entry.manifest.tree.manifest_digest {
            data.cas.limits().max_manifest_bytes
        } else {
            ticket.max_total_bytes
        };
        let mut reader = data
            .cas
            .verified_reader(&digest, read_limit)
            .map_err(data_status)?;
        let transfer_size = reader.size_bytes();
        self.inner
            .control_plane
            .record_runner_blob_download(
                &RecordRunnerBlobUpload {
                    ticket_id: ticket_id.to_string(),
                    blob_digest: digest.clone(),
                    ticket_kind: "cache".to_owned(),
                    execution_lease_id: subject.lease.id.clone(),
                    fencing_generation: subject.lease.fencing_generation,
                    job_attempt: request.job_attempt,
                    size_bytes: transfer_size,
                    maximum_ticket_bytes: ticket
                        .max_total_bytes
                        .max(data.cas.limits().max_manifest_bytes),
                    recorded_unix_ms: now_unix_ms()?,
                },
                &subject.session.runner_id,
            )
            .map_err(control_plane_status)?;
        let wire_digest = v1::Digest::try_from(&digest)
            .map_err(|_| Status::internal("download digest cannot be encoded"))?;
        let (sender, receiver) = mpsc::channel(8);
        tokio::task::spawn_blocking(move || {
            let _transfer_slot = transfer_slot;
            let mut offset = 0_u64;
            let mut payload = vec![0_u8; MAX_BLOB_CHUNK_BYTES];
            loop {
                let read = match std::io::Read::read(&mut reader, &mut payload) {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(_) => {
                        let _ = sender
                            .blocking_send(Err(Status::data_loss("verified blob read failed")));
                        break;
                    }
                };
                if sender
                    .blocking_send(Ok(v1::BlobChunk {
                        digest: Some(wire_digest.clone()),
                        offset,
                        payload: payload[..read].to_vec(),
                    }))
                    .is_err()
                {
                    break;
                }
                offset = match offset.checked_add(read as u64) {
                    Some(offset) => offset,
                    None => break,
                };
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }

    async fn complete_lease(
        &self,
        request: Request<v1::CompleteLeaseRequest>,
    ) -> Result<Response<v1::CompleteLeaseResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        self.complete_authenticated(&authenticated, request.into_inner())
            .await
            .map(Response::new)
    }
}

pub(super) fn github_provider_permissions(
    scm: &runtrue_workflow_ir::ScmPermissions,
) -> BTreeMap<GitHubPermission, GitHubPermissionLevel> {
    let mut permissions =
        BTreeMap::from([(GitHubPermission::Metadata, GitHubPermissionLevel::Read)]);
    let mut add = |permission, access: Access| {
        let level = match access {
            Access::Deny => None,
            Access::Read => Some(GitHubPermissionLevel::Read),
            Access::Write => Some(GitHubPermissionLevel::Write),
        };
        if let Some(level) = level {
            permissions.insert(permission, level);
        }
    };
    add(GitHubPermission::Contents, scm.contents);
    add(GitHubPermission::Issues, scm.issues);
    add(GitHubPermission::PullRequests, scm.pull_requests);
    add(GitHubPermission::Checks, scm.checks);
    add(GitHubPermission::Statuses, scm.statuses);
    permissions
}
