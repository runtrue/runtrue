use super::super::{
    control_plane_status, data_status, now_unix_ms, runner_upload_wait_until,
    AuthenticatedIdentity, RunnerControlService, RunnerDataPlane, RunnerDataSubject,
    MAX_BLOB_CHUNK_BYTES, OBJECT_TRANSFER_TOTAL_TIMEOUT,
};
use rand_core::{OsRng, RngCore as _};
use runtrue_cache::CacheTicketOperation;
use runtrue_control_plane::RecordRunnerBlobUpload;
use runtrue_model::ContentDigest;
use runtrue_protocol::{v1, v2};
use std::{
    fs::{File, OpenOptions},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, time::Instant};
use tonic::Status;
pub(in crate::runner_service) struct RunnerUploadStaging(pub(in crate::runner_service) PathBuf);

impl Drop for RunnerUploadStaging {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub(in crate::runner_service) struct RunnerUploadBinding {
    pub(in crate::runner_service) execution_lease_id: String,
    pub(in crate::runner_service) fencing_generation: u64,
    pub(in crate::runner_service) job_id: String,
    pub(in crate::runner_service) job_attempt: u32,
    pub(in crate::runner_service) step_id: String,
    pub(in crate::runner_service) ticket_id: String,
    pub(in crate::runner_service) ticket_kind: String,
    pub(in crate::runner_service) declared_digest: ContentDigest,
    pub(in crate::runner_service) declared_size: Option<u64>,
}

pub(in crate::runner_service) struct AuthorizedRunnerUpload {
    pub(in crate::runner_service) data: Arc<RunnerDataPlane>,
    pub(in crate::runner_service) subject: RunnerDataSubject,
    pub(in crate::runner_service) ticket_id: ContentDigest,
    pub(in crate::runner_service) ticket_kind: &'static str,
    pub(in crate::runner_service) maximum_blob_bytes: u64,
    pub(in crate::runner_service) maximum_ticket_bytes: u64,
    pub(in crate::runner_service) deadline: Instant,
}

pub(in crate::runner_service) struct PendingRunnerUpload {
    pub(in crate::runner_service) temporary: RunnerUploadStaging,
    pub(in crate::runner_service) file: tokio::fs::File,
    pub(in crate::runner_service) expected_offset: u64,
}

impl RunnerControlService {
    pub(in crate::runner_service) fn authorize_runner_upload(
        &self,
        authenticated: &AuthenticatedIdentity,
        binding: &RunnerUploadBinding,
    ) -> Result<AuthorizedRunnerUpload, Status> {
        let subject = if binding.ticket_kind == "artifact" {
            self.active_artifact_subject(
                authenticated,
                &binding.execution_lease_id,
                binding.fencing_generation,
                &binding.job_id,
                binding.job_attempt,
                &binding.step_id,
            )?
        } else {
            self.active_data_subject(
                authenticated,
                &binding.execution_lease_id,
                binding.fencing_generation,
                &binding.job_id,
                binding.job_attempt,
                &binding.step_id,
            )?
        };
        let data = Arc::clone(self.inner.data_plane.as_ref().ok_or_else(|| {
            Status::failed_precondition("runner object data plane is not configured")
        })?);
        let ticket_id = ContentDigest::parse(binding.ticket_id.clone())
            .map_err(|_| Status::invalid_argument("blob ticket id is invalid"))?;
        let now = now_unix_ms()?;
        let (maximum_content_bytes, ticket_kind, ticket_expires_unix_ms) =
            match binding.ticket_kind.as_str() {
                "cache" => {
                    let ticket = data.cache.write_ticket(&ticket_id).map_err(data_status)?;
                    if ticket.operation != CacheTicketOperation::Commit
                        || ticket.tenant_id != subject.repository.tenant_id
                        || ticket.repository_id != subject.repository.id
                        || ticket.job_id != subject.lease.job_id
                        || ticket.lease_id != subject.lease.id
                        || ticket.fencing_generation != subject.lease.fencing_generation
                        || ticket.job_attempt != binding.job_attempt
                        || ticket.step_id != binding.step_id
                        || ticket.producer_capsule_digest != subject.lease.capsule_digest
                        || now / 1000 >= ticket.expires_at_unix_seconds
                    {
                        return Err(Status::permission_denied(
                            "cache upload ticket scope mismatch",
                        ));
                    }
                    (
                        ticket.max_total_bytes,
                        "cache",
                        ticket.expires_at_unix_seconds.saturating_mul(1_000),
                    )
                }
                "artifact" => {
                    let ticket = data.artifacts.ticket(&ticket_id).map_err(data_status)?;
                    if ticket.tenant_id != subject.repository.tenant_id
                        || ticket.repository_id != subject.repository.id
                        || ticket.run_id != subject.run_id
                        || ticket.job_id != subject.lease.job_id
                        || ticket.lease_id != subject.lease.id
                        || ticket.fencing_generation != subject.lease.fencing_generation
                        || ticket.job_attempt != binding.job_attempt
                        || ticket.step_id != binding.step_id
                        || now / 1000 >= ticket.expires_at_unix_seconds
                    {
                        return Err(Status::permission_denied(
                            "artifact upload ticket scope mismatch",
                        ));
                    }
                    (
                        ticket.max_bytes,
                        "artifact",
                        ticket.expires_at_unix_seconds.saturating_mul(1_000),
                    )
                }
                _ => return Err(Status::invalid_argument("invalid blob ticket kind")),
            };
        let maximum_blob_bytes = maximum_content_bytes.max(data.cas.limits().max_manifest_bytes);
        let maximum_ticket_bytes =
            maximum_content_bytes.saturating_add(data.cas.limits().max_manifest_bytes);
        if binding
            .declared_size
            .is_some_and(|size| size > maximum_blob_bytes || size > maximum_ticket_bytes)
        {
            return Err(Status::resource_exhausted(
                "blob upload exceeds ticket bound",
            ));
        }
        let expires_unix_ms = ticket_expires_unix_ms.min(subject.lease.expires_unix_ms);
        let lifetime = Duration::from_millis(expires_unix_ms.saturating_sub(now))
            .min(OBJECT_TRANSFER_TOTAL_TIMEOUT);
        if lifetime.is_zero() {
            return Err(Status::deadline_exceeded("blob upload ticket expired"));
        }
        Ok(AuthorizedRunnerUpload {
            data,
            subject,
            ticket_id,
            ticket_kind,
            maximum_blob_bytes,
            maximum_ticket_bytes,
            deadline: Instant::now() + lifetime,
        })
    }

    pub(in crate::runner_service) fn runner_upload_wait(
        authorized: &AuthorizedRunnerUpload,
    ) -> Result<Duration, Status> {
        runner_upload_wait_until(authorized.deadline)
    }

    pub(in crate::runner_service) fn require_runner_upload_active(
        authorized: &AuthorizedRunnerUpload,
    ) -> Result<(), Status> {
        Self::runner_upload_wait(authorized).map(drop)
    }

    pub(in crate::runner_service) fn begin_runner_upload(
        &self,
        authorized: &AuthorizedRunnerUpload,
    ) -> Result<PendingRunnerUpload, Status> {
        let mut nonce = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Status::internal("blob upload randomness unavailable"))?;
        let temporary = RunnerUploadStaging(authorized.data.root.join(format!(
            ".upload-{}-{}",
            std::process::id(),
            hex::encode(nonce)
        )));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&temporary.0)
            .map_err(|_| Status::internal("blob upload staging is unavailable"))?;
        Ok(PendingRunnerUpload {
            temporary,
            file: tokio::fs::File::from_std(file),
            expected_offset: 0,
        })
    }

    pub(in crate::runner_service) async fn append_runner_upload_chunk(
        pending: &mut PendingRunnerUpload,
        chunk: &v2::ObjectChunk,
        declared_size: Option<u64>,
        maximum_blob_bytes: u64,
    ) -> Result<(), Status> {
        if chunk.offset != pending.expected_offset || chunk.payload.len() > MAX_BLOB_CHUNK_BYTES {
            return Err(Status::invalid_argument(
                "blob upload chunk offset or size mismatch",
            ));
        }
        let next = pending
            .expected_offset
            .checked_add(chunk.payload.len() as u64)
            .ok_or_else(|| Status::out_of_range("blob upload size overflow"))?;
        if next > maximum_blob_bytes || declared_size.is_some_and(|size| next > size) {
            return Err(Status::resource_exhausted(
                "blob upload exceeds ticket or declared-size bound",
            ));
        }
        pending
            .file
            .write_all(&chunk.payload)
            .await
            .map_err(|_| Status::internal("blob upload staging write failed"))?;
        pending.expected_offset = next;
        Ok(())
    }

    pub(in crate::runner_service) async fn finish_runner_upload(
        &self,
        authenticated: &AuthenticatedIdentity,
        binding: &RunnerUploadBinding,
        authorized: AuthorizedRunnerUpload,
        pending: PendingRunnerUpload,
    ) -> Result<v1::UploadBlobResponse, Status> {
        Self::require_runner_upload_active(&authorized)?;
        if binding
            .declared_size
            .is_some_and(|size| size != pending.expected_offset)
        {
            return Err(Status::invalid_argument(
                "blob upload does not match declared size",
            ));
        }
        pending
            .file
            .sync_all()
            .await
            .map_err(|_| Status::internal("blob upload staging sync failed"))?;
        drop(pending.file);
        Self::require_runner_upload_active(&authorized)?;
        let source = File::open(&pending.temporary.0)
            .map_err(|_| Status::internal("blob upload staging disappeared"))?;
        let record = authorized
            .data
            .cas
            .put_verified_reader(
                source,
                &binding.declared_digest,
                pending.expected_offset,
                authorized.maximum_blob_bytes,
            )
            .map_err(data_status)?;
        Self::require_runner_upload_active(&authorized)?;
        let replayed = self
            .inner
            .control_plane
            .record_runner_blob_upload(
                &RecordRunnerBlobUpload {
                    ticket_id: authorized.ticket_id.to_string(),
                    blob_digest: binding.declared_digest.clone(),
                    ticket_kind: authorized.ticket_kind.to_owned(),
                    execution_lease_id: authorized.subject.lease.id.clone(),
                    fencing_generation: authorized.subject.lease.fencing_generation,
                    job_attempt: binding.job_attempt,
                    size_bytes: pending.expected_offset,
                    maximum_ticket_bytes: authorized.maximum_ticket_bytes,
                    recorded_unix_ms: now_unix_ms()?,
                },
                &authenticated.runner_id,
            )
            .map_err(control_plane_status)?;
        Self::require_runner_upload_active(&authorized)?;
        Ok(v1::UploadBlobResponse {
            digest: Some(
                v1::Digest::try_from(&record.digest)
                    .map_err(|_| Status::internal("uploaded blob digest cannot be encoded"))?,
            ),
            size_bytes: record.size_bytes,
            already_present: record.already_present || replayed,
        })
    }
}
