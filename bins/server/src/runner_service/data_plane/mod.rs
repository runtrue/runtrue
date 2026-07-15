pub(super) mod artifacts;
pub(super) mod authorization;
pub(super) mod cache;
pub(super) mod storage;
pub(super) mod uploads;
pub(super) mod wire;

use super::{
    authorize_source_object, cache_generation_id, control_plane_status, data_status,
    duration_millis, now_unix_ms, parse_v2_digest, proto_timestamp, require_session_lease,
    require_session_protocol, source_ticket_id, validate_identifier_status, wire_v2_digest,
    RunnerControlService, RunnerServiceError, RunnerUploadBinding, MAX_BLOB_CHUNK_BYTES,
    MAX_CONCURRENT_OBJECT_TRANSFERS, MAX_SOURCE_TICKET_BYTES, OBJECT_TRANSFER_IDLE_TIMEOUT,
    SOURCE_TICKET_TTL,
};
use runtrue_artifacts::{ArtifactHandle, ArtifactLimits, ArtifactStore};
use runtrue_attest::CapsuleSigningKey;
use runtrue_cache::{CacheKeyMaterial, CacheLimits, CacheStore, PromotionEvidence, TrustDomain};
use runtrue_control_plane::{
    CacheTrustGenerationRecord, ControlPlane, IssueRunnerSourceTicket, RunnerSourceDownload,
};
use runtrue_model::ContentDigest;
use runtrue_output_lifecycle::{
    execute_artifact_promotion, ArtifactScannerClient, GcSummary, LifecycleLimits,
    OutputLifecycleWorker,
};
use runtrue_protocol::v2;
use runtrue_scheduler::LeaseState;
use runtrue_storage::{CasLimits, FsCas, PathSnapshot, VerifiedBlobReader};
use std::{
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, Semaphore},
    time::Instant,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
#[derive(Debug)]
pub struct RunnerDataPlane {
    pub(in crate::runner_service) root: PathBuf,
    pub(in crate::runner_service) cas: FsCas,
    pub(in crate::runner_service) cache: CacheStore,
    pub(in crate::runner_service) artifacts: ArtifactStore,
    pub(in crate::runner_service) signing_key: Arc<CapsuleSigningKey>,
    pub(in crate::runner_service) transfer_slots: Arc<Semaphore>,
}

impl RunnerDataPlane {
    pub fn open(
        root: impl AsRef<Path>,
        signing_key: Arc<CapsuleSigningKey>,
    ) -> Result<Self, RunnerServiceError> {
        let root = root.as_ref();
        let mut checked = if root.is_absolute() {
            PathBuf::from("/")
        } else {
            PathBuf::new()
        };
        for component in root.components() {
            match component {
                std::path::Component::RootDir | std::path::Component::CurDir => continue,
                std::path::Component::Normal(value) => checked.push(value),
                std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                    return Err(RunnerServiceError::DataPlane(
                        "runner data root must be normalized".to_owned(),
                    ));
                }
            }
            match std::fs::symlink_metadata(&checked) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(RunnerServiceError::DataPlane(
                        "runner data root cannot contain symlink ancestors".to_owned(),
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(RunnerServiceError::DataPlane(error.to_string())),
            }
        }
        match std::fs::symlink_metadata(root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(RunnerServiceError::DataPlane(
                    "runner data root must be a real directory".to_owned(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(root)
                    .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
            }
            Err(error) => return Err(RunnerServiceError::DataPlane(error.to_string())),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        }
        let root = root
            .canonicalize()
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let cas = FsCas::open(root.join("cas"), CasLimits::default())
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let cache = CacheStore::open(root.join("cache"), cas.clone(), CacheLimits::default())
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let artifacts = ArtifactStore::open(
            root.join("artifacts"),
            cas.clone(),
            ArtifactLimits::default(),
        )
        .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        Ok(Self {
            root,
            cas,
            cache,
            artifacts,
            signing_key,
            transfer_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_OBJECT_TRANSFERS)),
        })
    }

    /// Execute one already-durable cache promotion intent. This is suitable
    /// for a bounded durable-task worker: it revalidates filesystem metadata,
    /// immutable bytes, source/target identities, evidence, and target CAS
    /// before atomically completing the SQLite journal.
    pub fn execute_cache_promotion(
        &self,
        control_plane: &ControlPlane,
        tenant_id: &str,
        promotion_id: &str,
        now_unix_ms: u64,
    ) -> Result<ContentDigest, RunnerServiceError> {
        let journal = control_plane
            .cache_promotion(tenant_id, promotion_id)
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let completed_result =
            if journal.state == runtrue_control_plane::CachePromotionState::Completed {
                Some(
                    journal
                        .promoted_cache_entry_id
                        .as_deref()
                        .ok_or_else(|| {
                            RunnerServiceError::DataPlane(
                                "completed cache promotion has no result".to_owned(),
                            )
                        })
                        .and_then(|value| {
                            ContentDigest::parse(value)
                                .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))
                        })?,
                )
            } else {
                None
            };
        if completed_result.is_none()
            && journal.state != runtrue_control_plane::CachePromotionState::Pending
        {
            return Err(RunnerServiceError::DataPlane(
                "cache promotion is not pending".to_owned(),
            ));
        }
        let source_record = control_plane
            .cache_trust_generation(tenant_id, &journal.source_cache_entry_id)
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let material: CacheKeyMaterial = serde_json::from_value(source_record.key_material.clone())
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        if material
            .digest(self.cache.limits())
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?
            != source_record.key_material_digest
        {
            return Err(RunnerServiceError::DataPlane(
                "cache promotion key material digest mismatch".to_owned(),
            ));
        }
        let source_trust: TrustDomain = serde_json::from_value(source_record.trust_domain.clone())
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let source_identity = material.with_trust_domain(source_trust);
        let source = self
            .cache
            .inspect(&source_identity)
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?
            .ok_or_else(|| {
                RunnerServiceError::DataPlane("cache promotion source is unavailable".to_owned())
            })?;
        let source_id = cache_generation_id(&source)
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        if source_id.to_string() != source_record.cache_entry_id
            || source.head.manifest_digest != source_record.manifest_digest
            || source.manifest.tree.manifest_digest != source_record.tree_manifest_digest
        {
            return Err(RunnerServiceError::DataPlane(
                "cache promotion source metadata mismatch".to_owned(),
            ));
        }
        let target_trust: TrustDomain = serde_json::from_value(journal.target_trust_domain.clone())
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let target_identity = material.with_trust_domain(target_trust);
        if target_identity
            .digest(self.cache.limits())
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?
            != journal.target_identity_digest
        {
            return Err(RunnerServiceError::DataPlane(
                "cache promotion target identity mismatch".to_owned(),
            ));
        }
        let evidence: PromotionEvidence = serde_json::from_value(journal.evidence.clone())
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let evidence_bytes = serde_json::to_vec(&evidence)
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let evidence_digest = ContentDigest::sha256(&evidence_bytes);
        if evidence_digest != journal.evidence_digest {
            return Err(RunnerServiceError::DataPlane(
                "cache promotion evidence digest mismatch".to_owned(),
            ));
        }
        let evidence_object = self
            .cas
            .put_bytes(&evidence_bytes)
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        if evidence_object.digest != journal.evidence_digest {
            return Err(RunnerServiceError::DataPlane(
                "cache promotion evidence object mismatch".to_owned(),
            ));
        }
        self.cas
            .verify_blob(&evidence.evidence_digest)
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let current_target = self
            .cache
            .inspect(&target_identity)
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        let exact_effect = current_target.as_ref().filter(|entry| {
            entry.manifest.tree == source.manifest.tree
                && entry.manifest.promotion.as_ref().is_some_and(|promotion| {
                    promotion.source_manifest_digest == source.head.manifest_digest
                        && promotion.evidence == evidence
                })
        });
        if let Some(completed_result) = completed_result {
            let recovered = exact_effect.ok_or_else(|| {
                RunnerServiceError::DataPlane(
                    "completed cache promotion result is unavailable or changed".to_owned(),
                )
            })?;
            let recovered_id = recovered
                .immutable_id()
                .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
            if recovered_id != completed_result {
                return Err(RunnerServiceError::DataPlane(
                    "completed cache promotion result identity changed".to_owned(),
                ));
            }
            return Ok(completed_result);
        }
        let promoted = if let Some(recovered) = exact_effect {
            recovered.clone()
        } else {
            if let Some(expected_id) = &journal.expected_target_cache_entry_id {
                let actual = current_target
                    .as_ref()
                    .map(cache_generation_id)
                    .transpose()
                    .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
                if actual.as_ref().map(ToString::to_string).as_deref() != Some(expected_id) {
                    return Err(RunnerServiceError::DataPlane(
                        "cache promotion target head changed".to_owned(),
                    ));
                }
            } else if current_target.is_some() {
                return Err(RunnerServiceError::DataPlane(
                    "cache promotion target head changed".to_owned(),
                ));
            }
            let fencing_generation = current_target
                .as_ref()
                .map_or(1, |entry| entry.head.fencing_generation.saturating_add(1));
            self.cache
                .promote(
                    &source_identity,
                    target_identity,
                    evidence,
                    current_target.as_ref().map(|entry| &entry.head),
                    fencing_generation,
                )
                .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?
        };
        let promoted_id = promoted
            .immutable_id()
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        control_plane
            .complete_cache_promotion(
                tenant_id,
                promotion_id,
                &CacheTrustGenerationRecord {
                    cache_entry_id: promoted_id.to_string(),
                    tenant_id: source_record.tenant_id,
                    repository_id: source_record.repository_id,
                    identity_digest: promoted.head.identity_digest.clone(),
                    key_material_digest: source_record.key_material_digest,
                    key_material: source_record.key_material,
                    trust_domain: serde_json::to_value(&promoted.manifest.identity.trust_domain)
                        .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?,
                    generation: promoted.head.generation,
                    manifest_digest: promoted.head.manifest_digest,
                    tree_manifest_digest: promoted.manifest.tree.manifest_digest,
                    fencing_generation: promoted.head.fencing_generation,
                    source_cache_entry_id: Some(source_record.cache_entry_id),
                    promotion_evidence_digest: Some(journal.evidence_digest),
                    created_unix_ms: journal.created_unix_ms,
                },
                now_unix_ms,
            )
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        Ok(promoted_id)
    }

    /// Production adapter for one bounded scanner claim. The concrete scanner
    /// remains an isolated service client and receives no data-plane or runner
    /// credentials.
    pub fn scan_artifact_once(
        &self,
        control_plane: &ControlPlane,
        worker_id: &str,
        scanner: &dyn ArtifactScannerClient,
        limits: LifecycleLimits,
        now_unix_ms: u64,
    ) -> Result<bool, RunnerServiceError> {
        OutputLifecycleWorker::new(control_plane, &self.artifacts, limits)
            .and_then(|worker| worker.scan_once(worker_id, scanner, now_unix_ms))
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))
    }

    /// Production adapter for one restart-safe, installation-fenced GC cycle.
    pub fn collect_outputs_once(
        &self,
        control_plane: &ControlPlane,
        worker_id: &str,
        lease_token: &str,
        limits: LifecycleLimits,
        now_unix_ms: u64,
    ) -> Result<GcSummary, RunnerServiceError> {
        OutputLifecycleWorker::new(control_plane, &self.artifacts, limits)
            .and_then(|worker| worker.gc_once(worker_id, lease_token, now_unix_ms))
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))
    }

    /// Execute or reconcile one evidence-bound immutable artifact promotion.
    pub fn promote_artifact_once(
        &self,
        control_plane: &ControlPlane,
        tenant_id: &str,
        promotion_id: &str,
        now_unix_ms: u64,
    ) -> Result<ContentDigest, RunnerServiceError> {
        execute_artifact_promotion(
            control_plane,
            &self.artifacts,
            tenant_id,
            promotion_id,
            now_unix_ms,
        )
        .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))
    }

    pub(crate) fn load_artifact(
        &self,
        artifact_id: &ContentDigest,
    ) -> Result<ArtifactHandle, RunnerServiceError> {
        self.artifacts
            .load(artifact_id)
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))
    }

    pub(crate) fn artifact_file_reader(
        &self,
        artifact_id: &ContentDigest,
    ) -> Result<(ArtifactHandle, VerifiedBlobReader), RunnerServiceError> {
        let artifact = self.load_artifact(artifact_id)?;
        let digest = match &artifact.record.content {
            PathSnapshot::File { digest, .. } => digest,
            PathSnapshot::Directory { .. } => {
                return Err(RunnerServiceError::DataPlane(
                    "directory artifact download requires an archive adapter".to_owned(),
                ));
            }
        };
        let reader = self
            .artifacts
            .cas()
            .verified_reader(digest, self.artifacts.cas().limits().max_blob_bytes)
            .map_err(|error| RunnerServiceError::DataPlane(error.to_string()))?;
        Ok((artifact, reader))
    }

    pub(crate) fn cas(&self) -> FsCas {
        self.cas.clone()
    }
}
#[tonic::async_trait]
impl v2::runner_object_transfer_server::RunnerObjectTransfer for RunnerControlService {
    async fn request_source_ticket(
        &self,
        request: Request<v2::SourceTicketRequest>,
    ) -> Result<Response<v2::SourceTicketResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        let request = request.into_inner();
        validate_identifier_status("execution lease id", &request.execution_lease_id)?;
        validate_identifier_status("job id", &request.job_id)?;
        if request.job_attempt == 0 {
            return Err(Status::invalid_argument("job attempt must be positive"));
        }
        let session = self.authenticated_session(&authenticated)?;
        require_session_protocol(&session, 2)?;
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
                "source ticket requires an active lease",
            ));
        }
        let (job_key, _) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&lease.id)
            .map_err(control_plane_status)?;
        let job = self
            .inner
            .control_plane
            .job(&lease.job_id)
            .map_err(control_plane_status)?;
        if job_key != request.job_id || job.attempt != request.job_attempt {
            return Err(Status::permission_denied(
                "source ticket execution binding mismatch",
            ));
        }
        let data = self.inner.data_plane.as_ref().ok_or_else(|| {
            Status::failed_precondition("runner object data plane is not configured")
        })?;
        let now = now_unix_ms()?;
        let ttl_ms = duration_millis(SOURCE_TICKET_TTL)?;
        let expires = now.saturating_add(ttl_ms).min(lease.expires_unix_ms);
        if expires <= now {
            return Err(Status::failed_precondition("execution lease is expiring"));
        }
        let ticket_id = source_ticket_id(&lease.id, lease.fencing_generation, job.attempt);
        let issued = self
            .inner
            .control_plane
            .issue_runner_source_ticket(&IssueRunnerSourceTicket {
                id: ticket_id,
                tenant_id: lease.tenant_id.clone(),
                runner_id: authenticated.runner_id,
                execution_lease_id: lease.id,
                fencing_generation: lease.fencing_generation,
                job_id: job.id,
                job_attempt: job.attempt,
                maximum_bytes: MAX_SOURCE_TICKET_BYTES.min(data.cas.limits().max_tree_total_bytes),
                issued_unix_ms: now,
                expires_unix_ms: expires,
            })
            .map_err(control_plane_status)?;
        let digest = wire_v2_digest(&issued.value.tree_manifest_digest)?;
        Ok(Response::new(v2::SourceTicketResponse {
            ticket_id: issued.value.id,
            digest_algorithm: digest.0,
            tree_manifest_digest: digest.1,
            maximum_bytes: issued.value.maximum_bytes,
            expires_at: Some(proto_timestamp(issued.value.expires_unix_ms)),
        }))
    }

    async fn upload_object(
        &self,
        request: Request<tonic::Streaming<v2::ObjectUploadFrame>>,
    ) -> Result<Response<v2::ObjectUploadResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        let session = self.authenticated_session(&authenticated)?;
        require_session_protocol(&session, 2)?;
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
            .map_err(|_| Status::deadline_exceeded("object upload idle timeout"))??
            .ok_or_else(|| Status::invalid_argument("object upload stream is empty"))?;
        let header = match first.body {
            Some(v2::object_upload_frame::Body::Header(header)) => header,
            _ => {
                return Err(Status::invalid_argument(
                    "object upload must begin with exactly one header",
                ))
            }
        };
        let binding = RunnerUploadBinding {
            execution_lease_id: header.execution_lease_id,
            fencing_generation: header.fencing_generation,
            job_id: header.job_id,
            job_attempt: header.job_attempt,
            step_id: header.step_id,
            ticket_id: header.ticket_id,
            ticket_kind: header.ticket_kind,
            declared_digest: parse_v2_digest(&header.digest_algorithm, &header.digest)?,
            declared_size: Some(header.size_bytes),
        };
        let authorized = self.authorize_runner_upload(&authenticated, &binding)?;
        let mut pending = self.begin_runner_upload(&authorized)?;
        loop {
            let frame =
                tokio::time::timeout(Self::runner_upload_wait(&authorized)?, stream.message())
                    .await
                    .map_err(|_| Status::deadline_exceeded("object upload idle timeout"))??;
            let Some(frame) = frame else {
                break;
            };
            let chunk = match frame.body {
                Some(v2::object_upload_frame::Body::Chunk(chunk)) if !chunk.payload.is_empty() => {
                    chunk
                }
                Some(v2::object_upload_frame::Body::Header(_)) => {
                    return Err(Status::invalid_argument(
                        "object upload contains more than one header",
                    ))
                }
                _ => {
                    return Err(Status::invalid_argument(
                        "object upload chunk is empty or malformed",
                    ))
                }
            };
            Self::require_runner_upload_active(&authorized)?;
            Self::append_runner_upload_chunk(
                &mut pending,
                &chunk,
                binding.declared_size,
                authorized.maximum_blob_bytes,
            )
            .await?;
        }
        let response = self
            .finish_runner_upload(&authenticated, &binding, authorized, pending)
            .await?;
        let digest = response
            .digest
            .ok_or_else(|| Status::internal("uploaded object response omitted its digest"))?;
        Ok(Response::new(v2::ObjectUploadResponse {
            digest_algorithm: digest.algorithm,
            digest: digest.value,
            size_bytes: response.size_bytes,
            already_present: response.already_present,
        }))
    }

    type DownloadObjectStream = ReceiverStream<Result<v2::ObjectDownloadFrame, Status>>;

    async fn download_object(
        &self,
        request: Request<v2::ObjectDownloadRequest>,
    ) -> Result<Response<Self::DownloadObjectStream>, Status> {
        let authenticated = self.authenticate(&request)?;
        let request = request.into_inner();
        validate_identifier_status("source ticket id", &request.ticket_id)?;
        validate_identifier_status("execution lease id", &request.execution_lease_id)?;
        validate_identifier_status("job id", &request.job_id)?;
        let requested_digest = parse_v2_digest(&request.digest_algorithm, &request.digest)?;
        let session = self.authenticated_session(&authenticated)?;
        require_session_protocol(&session, 2)?;
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
        let (job_key, _) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&lease.id)
            .map_err(control_plane_status)?;
        let job = self
            .inner
            .control_plane
            .job(&lease.job_id)
            .map_err(control_plane_status)?;
        if lease.state != LeaseState::Active
            || job_key != request.job_id
            || job.attempt != request.job_attempt
        {
            return Err(Status::permission_denied(
                "source download execution binding mismatch",
            ));
        }
        let ticket = self
            .inner
            .control_plane
            .runner_source_ticket(&request.ticket_id)
            .map_err(|_| Status::permission_denied("source download is not authorized"))?;
        let now = now_unix_ms()?;
        if ticket.runner_id != authenticated.runner_id
            || ticket.tenant_id != lease.tenant_id
            || ticket.execution_lease_id != lease.id
            || ticket.fencing_generation != lease.fencing_generation
            || ticket.job_id != job.id
            || ticket.job_attempt != job.attempt
            || ticket.expires_unix_ms <= now
        {
            return Err(Status::permission_denied(
                "source download is not authorized",
            ));
        }
        let data = Arc::clone(self.inner.data_plane.as_ref().ok_or_else(|| {
            Status::failed_precondition("runner object data plane is not configured")
        })?);
        let expected_size = authorize_source_object(
            &data.cas,
            &ticket.tree_manifest_digest,
            &requested_digest,
            ticket.maximum_bytes,
        )?;
        let mut reader = data
            .cas
            .verified_reader(&requested_digest, expected_size)
            .map_err(data_status)?;
        if reader.size_bytes() != expected_size {
            return Err(Status::data_loss(
                "source object size does not match its manifest",
            ));
        }
        let transfer = RunnerSourceDownload {
            ticket_id: ticket.id,
            object_digest: requested_digest.clone(),
            runner_id: authenticated.runner_id,
            execution_lease_id: lease.id,
            fencing_generation: lease.fencing_generation,
            job_id: job.id,
            job_attempt: job.attempt,
            size_bytes: expected_size,
            recorded_unix_ms: now,
        };
        let transfer_lifetime = Duration::from_millis(ticket.expires_unix_ms.saturating_sub(now));
        self.inner
            .control_plane
            .begin_runner_source_download(&transfer)
            .map_err(control_plane_status)?;
        let permit = data
            .transfer_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted("runner object transfer concurrency limit reached")
            })?;
        let (sender, receiver) = mpsc::channel(4);
        let control = Arc::clone(&self.inner.control_plane);
        tokio::spawn(async move {
            let _permit = permit;
            let deadline = Instant::now() + transfer_lifetime;
            let wire = match wire_v2_digest(&requested_digest) {
                Ok(value) => value,
                Err(error) => {
                    let _ = sender.send(Err(error)).await;
                    return;
                }
            };
            let first_wait = OBJECT_TRANSFER_IDLE_TIMEOUT
                .min(deadline.saturating_duration_since(Instant::now()));
            if first_wait.is_zero()
                || !matches!(
                    tokio::time::timeout(
                        first_wait,
                        sender.send(Ok(v2::ObjectDownloadFrame {
                            body: Some(v2::object_download_frame::Body::Header(
                                v2::ObjectDownloadHeader {
                                    digest_algorithm: wire.0,
                                    digest: wire.1,
                                    size_bytes: expected_size,
                                },
                            )),
                        })),
                    )
                    .await,
                    Ok(Ok(()))
                )
            {
                return;
            }
            let mut offset = 0_u64;
            loop {
                if Instant::now() >= deadline {
                    let _ = sender
                        .send(Err(Status::deadline_exceeded(
                            "source transfer deadline expired",
                        )))
                        .await;
                    return;
                }
                let read = tokio::task::spawn_blocking(move || {
                    let mut bytes = vec![0_u8; MAX_BLOB_CHUNK_BYTES];
                    let result = reader.read(&mut bytes);
                    (reader, bytes, result)
                })
                .await;
                let Ok((next_reader, mut bytes, Ok(count))) = read else {
                    let _ = sender
                        .send(Err(Status::internal("source object read failed")))
                        .await;
                    return;
                };
                reader = next_reader;
                if count == 0 {
                    break;
                }
                bytes.truncate(count);
                let frame = v2::ObjectDownloadFrame {
                    body: Some(v2::object_download_frame::Body::Chunk(v2::ObjectChunk {
                        offset,
                        payload: bytes,
                    })),
                };
                let wait = OBJECT_TRANSFER_IDLE_TIMEOUT
                    .min(deadline.saturating_duration_since(Instant::now()));
                if wait.is_zero()
                    || !matches!(
                        tokio::time::timeout(wait, sender.send(Ok(frame))).await,
                        Ok(Ok(()))
                    )
                {
                    return;
                }
                offset = offset.saturating_add(count as u64);
            }
            if offset != expected_size {
                let _ = sender
                    .send(Err(Status::data_loss(
                        "source object changed length during transfer",
                    )))
                    .await;
                return;
            }
            let mut completed = transfer;
            completed.recorded_unix_ms = now_unix_ms().unwrap_or(completed.recorded_unix_ms);
            if let Err(error) = control.finish_runner_source_download(&completed) {
                let _ = sender.send(Err(control_plane_status(error))).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }

    async fn complete_lease(
        &self,
        request: Request<v2::CompleteLeaseRequest>,
    ) -> Result<Response<v2::CompleteLeaseResponse>, Status> {
        let authenticated = self.authenticate(&request)?;
        let session = self.authenticated_session(&authenticated)?;
        require_session_protocol(&session, 2)?;
        let (request, artifact_claims, credential_taint) =
            self.adapt_v2_completion(request.into_inner())?;
        let lease = self.bound_lease(
            &authenticated.runner_id,
            &request.lease_id,
            request.fencing_generation,
        )?;
        if lease.state != LeaseState::Completed {
            require_session_lease(
                &session,
                &request.lease_id,
                request.fencing_generation,
                true,
            )?;
        }
        self.inner
            .control_plane
            .validate_runner_completion_artifact_claims(
                &request.lease_id,
                &authenticated.runner_id,
                request.fencing_generation,
                request.installation_fencing_epoch,
                request.final_job_attempt,
                &artifact_claims,
            )
            .map_err(control_plane_status)?;
        let response = self
            .complete_authenticated(&authenticated, request, credential_taint)
            .await?;
        let resulting_job_state = match response.resulting_job_state.as_str() {
            "succeeded" => v2::LeaseFinalState::Succeeded,
            "failed" => v2::LeaseFinalState::Failed,
            "canceled" => v2::LeaseFinalState::Canceled,
            "timed_out" => v2::LeaseFinalState::TimedOut,
            _ => return Err(Status::internal("completion returned an invalid job state")),
        };
        Ok(Response::new(v2::CompleteLeaseResponse {
            accepted: response.accepted,
            resulting_job_state: resulting_job_state as i32,
        }))
    }
}
