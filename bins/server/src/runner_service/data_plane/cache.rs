use super::super::{architecture_name, isolation_name};
use super::super::{
    cache_read_policy, cache_source_trust, cache_write_policy, canonical_json,
    control_plane_status, data_status, issue_or_recover_cache_ticket, now_unix_ms,
    operating_system_name, proto_timestamp, reserve_or_recover_storage, AuthenticatedIdentity,
    RunnerControlService, RunnerDataPlane,
};
use runtrue_cache::{
    cache_definition_digest, derive_cache_access, CacheAccessContext, CacheKeyMaterial,
    CachePlatform, CacheProducer, CacheRestoreRequest, CacheSnapshotCommitRequest,
    CacheTicketOperation, CacheWriteTicketRequest,
};
use runtrue_control_plane::{
    CacheAccessObservation, CacheTrustGenerationRecord, RunnerDataCommit, RunnerDataCommitKind,
    StorageReservationState, TenantStorageReservation,
};
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_storage::TreeSnapshot;
use runtrue_workflow_ir::{CacheRead, CacheWrite};
use serde::Serialize;
use tonic::Status;
impl RunnerControlService {
    pub(in crate::runner_service) fn data_plane(&self) -> Result<&RunnerDataPlane, Status> {
        self.inner
            .data_plane
            .as_deref()
            .ok_or_else(|| Status::failed_precondition("runner data plane is not configured"))
    }

    pub(in crate::runner_service) fn request_cache_ticket_authenticated(
        &self,
        authenticated: &AuthenticatedIdentity,
        request: v1::CacheTicketRequest,
    ) -> Result<v1::CacheTicketResponse, Status> {
        let subject = self.active_data_subject(
            authenticated,
            &request.execution_lease_id,
            request.fencing_generation,
            &request.job_id,
            request.job_attempt,
            &request.step_id,
        )?;
        let data = self.data_plane()?;
        let job = subject
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == subject.job_key)
            .ok_or_else(|| Status::data_loss("signed lease job is missing"))?;
        let step = job
            .steps
            .iter()
            .find(|step| step.id == request.step_id)
            .ok_or_else(|| Status::permission_denied("cache step is not declared"))?;
        let declaration = step
            .cache
            .as_ref()
            .ok_or_else(|| Status::permission_denied("step has no cache declaration"))?;
        let operation = match request.operation.as_str() {
            "commit"
                if !matches!(declaration.mode, runtrue_workflow_ir::CacheMode::ReadOnly)
                    && step.capabilities.cache_write != CacheWrite::Deny
                    && job.permissions.cache_write != CacheWrite::Deny =>
            {
                CacheTicketOperation::Commit
            }
            "restore"
                if !matches!(declaration.mode, runtrue_workflow_ir::CacheMode::WriteOnly)
                    && step.capabilities.cache_read != CacheRead::Deny
                    && job.permissions.cache_read != CacheRead::Deny =>
            {
                CacheTicketOperation::Restore
            }
            "commit" | "restore" => {
                return Err(Status::permission_denied(
                    "cache operation is denied by the signed declaration",
                ))
            }
            _ => return Err(Status::invalid_argument("unsupported cache operation")),
        };
        #[derive(Serialize)]
        struct DefinitionMaterial<'a> {
            version: u32,
            job_id: &'a str,
            step_id: &'a str,
            declaration: &'a runtrue_workflow_ir::CacheDeclaration,
            action: &'a runtrue_workflow_ir::StepAction,
            runner_image: &'a Option<String>,
            isolation: &'static str,
        }
        let definition = cache_definition_digest(&DefinitionMaterial {
            version: 1,
            job_id: &subject.job_key,
            step_id: &request.step_id,
            declaration,
            action: &step.action,
            runner_image: &job.runner.image,
            isolation: isolation_name(job.runner.isolation),
        })
        .map_err(|_| Status::internal("cache definition could not be encoded"))?;
        let declared_inputs = request
            .declared_inputs_digest
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("declared input digest is required"))?;
        let declared_inputs = ContentDigest::try_from(declared_inputs)
            .map_err(|_| Status::invalid_argument("declared input digest is invalid"))?;
        if !request.cache_identity_json.is_empty() || request.cache_identity.is_some() {
            return Err(Status::invalid_argument(
                "cache identity is derived by the server",
            ));
        }
        let material = CacheKeyMaterial {
            tenant_id: subject.repository.tenant_id.clone(),
            repository_id: subject.repository.id.clone(),
            purpose: format!("{}.{}", subject.job_key, request.step_id),
            platform: CachePlatform {
                os: operating_system_name(job.runner.os).to_owned(),
                architecture: architecture_name(job.runner.arch).to_owned(),
            },
            toolchain: subject.capsule.context.lockfile_digest.clone(),
            definition: definition.clone(),
            declared_inputs,
            policy_epoch: subject.lease.installation_fencing_epoch,
            user_suffix: request.user_suffix.clone(),
        };
        material.digest(data.cache.limits()).map_err(data_status)?;
        let access = CacheAccessContext {
            installation_id: self.inner.control_plane.installation_id().to_owned(),
            tenant_id: subject.repository.tenant_id.clone(),
            repository_id: subject.repository.id.clone(),
            run_id: subject.run_id.clone(),
            default_branch: subject.repository.default_branch.clone(),
            source: cache_source_trust(&subject.capsule, &subject.repository),
            read: cache_read_policy(step.capabilities.cache_read),
            write: cache_write_policy(step.capabilities.cache_write),
            // An active lease proves that the exact signed capsule passed its
            // approval/policy gates. Protected source remains an independent
            // requirement inside derive_cache_access.
            verified_write_authorized: true,
        };
        let scopes =
            derive_cache_access(&material, &access, data.cache.limits()).map_err(data_status)?;
        let candidate_scopes = scopes
            .read_candidates
            .iter()
            .map(|identity| serde_json::to_value(&identity.trust_domain))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Status::internal("cache read scopes could not be encoded"))?;
        let identity = match operation {
            CacheTicketOperation::Commit => scopes.write_identity.ok_or_else(|| {
                Status::permission_denied(
                    "cache write trust scope is denied by source trust and policy",
                )
            })?,
            CacheTicketOperation::Restore => {
                let fallback = scopes.read_candidates.first().cloned().ok_or_else(|| {
                    Status::permission_denied("cache read trust scope is denied by policy")
                })?;
                // Cache metadata/CAS failure is deliberately a bounded miss.
                // Artifact and source integrity paths do not use this logic.
                scopes
                    .read_candidates
                    .into_iter()
                    .find(|candidate| matches!(data.cache.inspect(candidate), Ok(Some(_))))
                    .unwrap_or(fallback)
            }
            _ => return Err(Status::invalid_argument("unsupported cache operation")),
        };
        let maximum = request.maximum_bytes.min(
            declaration
                .max_size_bytes
                .unwrap_or(data.cas.limits().max_tree_total_bytes),
        );
        if maximum == 0 {
            return Err(Status::invalid_argument("cache byte bound is required"));
        }
        let expected_head = if operation == CacheTicketOperation::Commit {
            data.cache
                .inspect(&identity)
                .map_err(data_status)?
                .map(|entry| entry.head)
        } else {
            None
        };
        let expected_tree_manifest_digest = request
            .expected_tree_manifest_digest
            .as_ref()
            .map(ContentDigest::try_from)
            .transpose()
            .map_err(|_| Status::invalid_argument("expected cache tree digest is invalid"))?;
        if operation == CacheTicketOperation::Restore && expected_tree_manifest_digest.is_some() {
            return Err(Status::invalid_argument(
                "restore callers cannot select cache content",
            ));
        }
        let now = now_unix_ms()? / 1000;
        let now_ms = now.saturating_mul(1_000);
        let reservation = if operation == CacheTicketOperation::Commit {
            let cache_identity_digest =
                identity.digest(data.cache.limits()).map_err(data_status)?;
            let reservation_identity = ContentDigest::sha256(
                serde_json::to_vec(&(
                    "runtrue.cache-ticket-storage-reservation.v2",
                    &subject.repository.tenant_id,
                    &subject.repository.id,
                    &subject.lease.id,
                    subject.lease.fencing_generation,
                    &subject.lease.capsule_digest,
                    request.job_attempt,
                    &request.step_id,
                    operation,
                    &cache_identity_digest,
                    &identity.trust_domain,
                    &expected_head,
                    &expected_tree_manifest_digest,
                    maximum,
                ))
                .map_err(|_| Status::internal("cache reservation could not be encoded"))?,
            );
            let proposed = TenantStorageReservation {
                id: format!("cache-ticket-{reservation_identity}"),
                tenant_id: subject.repository.tenant_id.clone(),
                ticket_kind: "cache".to_owned(),
                object_digest: expected_tree_manifest_digest.clone(),
                reserved_bytes: maximum,
                reserved_objects: 1,
                state: StorageReservationState::Reserved,
                created_unix_ms: now_ms,
                expires_unix_ms: now_ms.saturating_add(300_000),
                completed_unix_ms: None,
            };
            Some(reserve_or_recover_storage(
                &self.inner.control_plane,
                proposed,
                now_ms,
            )?)
        } else {
            None
        };
        let (issued_at_unix_seconds, expires_at_unix_seconds) =
            reservation
                .as_ref()
                .map_or((now, now.saturating_add(300)), |reservation| {
                    (
                        reservation.created_unix_ms / 1_000,
                        reservation.expires_unix_ms / 1_000,
                    )
                });
        let ticket_request = CacheWriteTicketRequest {
            operation,
            tenant_id: subject.repository.tenant_id.clone(),
            repository_id: subject.repository.id.clone(),
            job_id: subject.lease.job_id.clone(),
            job_attempt: request.job_attempt,
            step_id: request.step_id,
            lease_id: subject.lease.id.clone(),
            producer_capsule_digest: subject.lease.capsule_digest.clone(),
            fencing_generation: subject.lease.fencing_generation,
            writer_trust_domain: identity.trust_domain.clone(),
            identity,
            expected_head,
            expected_tree_manifest_digest,
            max_total_bytes: maximum,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        };
        let ticket = if let Some(reservation) = &reservation {
            issue_or_recover_cache_ticket(
                &self.inner.control_plane,
                &data.cache,
                reservation,
                &ticket_request,
                now_ms,
            )?
        } else {
            data.cache
                .issue_write_ticket(ticket_request)
                .map_err(data_status)?
        };
        let restore_entry = if operation == CacheTicketOperation::Restore {
            data.cache
                .ticketed_restore_entry(&CacheRestoreRequest {
                    ticket: &ticket,
                    active_tenant_id: &subject.repository.tenant_id,
                    active_repository_id: &subject.repository.id,
                    active_job_id: &subject.lease.job_id,
                    active_job_attempt: request.job_attempt,
                    active_step_id: &ticket.step_id,
                    active_lease_id: &subject.lease.id,
                    active_fencing_generation: subject.lease.fencing_generation,
                    now_unix_seconds: now,
                })
                .map_err(data_status)?
        } else {
            None
        };
        if operation == CacheTicketOperation::Restore {
            self.inner
                .control_plane
                .record_cache_access_observation(&CacheAccessObservation {
                    id: format!("cache-restore-{}", ticket.ticket_id),
                    tenant_id: subject.repository.tenant_id.clone(),
                    repository_id: subject.repository.id.clone(),
                    run_id: subject.run_id.clone(),
                    job_id: subject.lease.job_id.clone(),
                    job_attempt: request.job_attempt,
                    step_id: ticket.step_id.clone(),
                    operation: "restore".to_owned(),
                    key_material_digest: material
                        .digest(data.cache.limits())
                        .map_err(data_status)?,
                    candidates: candidate_scopes,
                    outcome: if restore_entry.is_some() {
                        "hit"
                    } else {
                        "miss"
                    }
                    .to_owned(),
                    selected_trust_domain: restore_entry
                        .as_ref()
                        .map(|entry| serde_json::to_value(&entry.manifest.identity.trust_domain))
                        .transpose()
                        .map_err(|_| {
                            Status::internal("cache selected scope could not be encoded")
                        })?,
                    selected_generation: restore_entry.as_ref().map(|entry| entry.head.generation),
                    transferred_bytes: 0,
                    latency_ms: 0,
                    breaker_state: "closed".to_owned(),
                    created_unix_ms: ticket.issued_at_unix_seconds.saturating_mul(1000),
                })
                .map_err(control_plane_status)?;
        }
        let cache_entry_json = restore_entry
            .map(|entry| serde_json::to_vec(&entry))
            .transpose()
            .map_err(|_| Status::internal("cache entry could not be encoded"))?
            .unwrap_or_default();
        Ok(v1::CacheTicketResponse {
            ticket_id: ticket.ticket_id.to_string(),
            endpoint: "runner-grpc://upload-blob".to_owned(),
            bearer_token: String::new(),
            expires_at: Some(proto_timestamp(
                ticket.expires_at_unix_seconds.saturating_mul(1000),
            )),
            maximum_bytes: ticket.max_total_bytes,
            cache_entry_json,
            cache_identity_json: serde_json::to_vec(&ticket.identity)
                .map_err(|_| Status::internal("cache identity could not be encoded"))?,
        })
    }

    pub(in crate::runner_service) fn commit_cache_authenticated(
        &self,
        authenticated: &AuthenticatedIdentity,
        request: v1::CommitCacheEntryRequest,
    ) -> Result<v1::CommitCacheEntryResponse, Status> {
        let data = self.data_plane()?;
        let ticket_id = ContentDigest::parse(request.ticket_id.clone())
            .map_err(|_| Status::invalid_argument("cache ticket id is invalid"))?;
        let ticket = data.cache.write_ticket(&ticket_id).map_err(data_status)?;
        let (job_key, _) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&request.execution_lease_id)
            .map_err(control_plane_status)?;
        let subject = self.active_data_subject(
            authenticated,
            &request.execution_lease_id,
            request.fencing_generation,
            &job_key,
            request.job_attempt,
            &ticket.step_id,
        )?;
        if ticket.job_attempt != request.job_attempt {
            return Err(Status::failed_precondition("cache ticket attempt is stale"));
        }
        let snapshot: TreeSnapshot = canonical_json(&request.tree_snapshot_json, "cache snapshot")?;
        let declared_manifest = request
            .manifest_digest
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("cache manifest digest is required"))?;
        let declared_manifest = ContentDigest::try_from(declared_manifest)
            .map_err(|_| Status::invalid_argument("cache manifest digest is invalid"))?;
        if declared_manifest != snapshot.manifest_digest
            || request.size_bytes != snapshot.total_file_bytes
        {
            return Err(Status::invalid_argument(
                "cache snapshot declaration mismatch",
            ));
        }
        let recovered = data
            .cache
            .claimed_cache_entry(&ticket)
            .map_err(data_status)?;
        let entry = if let Some(entry) = recovered {
            if entry.manifest.tree != snapshot {
                return Err(Status::already_exists(
                    "cache ticket was claimed by a different immutable snapshot",
                ));
            }
            entry
        } else {
            data.cache
                .commit_ticketed_snapshot(&CacheSnapshotCommitRequest {
                    ticket: &ticket,
                    active_tenant_id: &subject.repository.tenant_id,
                    active_repository_id: &subject.repository.id,
                    active_job_id: &subject.lease.job_id,
                    active_step_id: &ticket.step_id,
                    active_lease_id: &subject.lease.id,
                    active_fencing_generation: subject.lease.fencing_generation,
                    active_writer_trust_domain: &ticket.writer_trust_domain,
                    now_unix_seconds: now_unix_ms()? / 1000,
                    snapshot: &snapshot,
                    producer: CacheProducer {
                        capsule_digest: subject.lease.capsule_digest.clone(),
                        job_id: subject.lease.job_id.clone(),
                        step_id: ticket.step_id.clone(),
                        lease_id: subject.lease.id.clone(),
                    },
                })
                .map_err(data_status)?
        };
        let cache_entry_id = entry
            .completion_id(&ticket.ticket_id)
            .map_err(data_status)?;
        let committed_unix_ms = now_unix_ms()?;
        self.inner
            .control_plane
            .commit_tenant_storage_ticket(
                &subject.repository.tenant_id,
                ticket.ticket_id.as_str(),
                cache_entry_id.as_str(),
                snapshot.total_file_bytes,
                1,
                committed_unix_ms,
            )
            .map_err(control_plane_status)?;
        let key_material_digest = CacheKeyMaterial::from(&entry.manifest.identity)
            .digest(data.cache.limits())
            .map_err(data_status)?;
        self.inner
            .control_plane
            .record_cache_trust_generation(
                &CacheTrustGenerationRecord {
                    cache_entry_id: cache_entry_id.to_string(),
                    tenant_id: subject.repository.tenant_id.clone(),
                    repository_id: subject.repository.id.clone(),
                    identity_digest: entry.head.identity_digest.clone(),
                    key_material_digest: key_material_digest.clone(),
                    key_material: serde_json::to_value(CacheKeyMaterial::from(
                        &entry.manifest.identity,
                    ))
                    .map_err(|_| Status::internal("cache key material could not be encoded"))?,
                    trust_domain: serde_json::to_value(&entry.manifest.identity.trust_domain)
                        .map_err(|_| Status::internal("cache trust domain could not be encoded"))?,
                    generation: entry.head.generation,
                    manifest_digest: entry.head.manifest_digest.clone(),
                    tree_manifest_digest: entry.manifest.tree.manifest_digest.clone(),
                    fencing_generation: entry.head.fencing_generation,
                    source_cache_entry_id: None,
                    promotion_evidence_digest: None,
                    created_unix_ms: committed_unix_ms,
                },
                ticket.expected_head.as_ref().map(|head| head.generation),
            )
            .map_err(control_plane_status)?;
        self.inner
            .control_plane
            .record_runner_data_commit(
                &RunnerDataCommit {
                    kind: RunnerDataCommitKind::Cache,
                    object_id: cache_entry_id.to_string(),
                    tenant_id: subject.repository.tenant_id.clone(),
                    repository_id: subject.repository.id.clone(),
                    run_id: subject.run_id.clone(),
                    job_id: subject.lease.job_id.clone(),
                    job_attempt: request.job_attempt,
                    step_id: ticket.step_id.clone(),
                    output_name: None,
                    lease_id: subject.lease.id.clone(),
                    fencing_generation: subject.lease.fencing_generation,
                    ticket_id: ticket.ticket_id.to_string(),
                    committed_unix_ms,
                },
                &authenticated.runner_id,
            )
            .map_err(control_plane_status)?;
        self.inner
            .control_plane
            .account_tenant_storage_ticket(
                &subject.repository.tenant_id,
                ticket.ticket_id.as_str(),
                cache_entry_id.as_str(),
                committed_unix_ms,
            )
            .map_err(control_plane_status)?;
        self.inner
            .control_plane
            .record_cache_access_observation(&CacheAccessObservation {
                id: format!("cache-save-{}", ticket.ticket_id),
                tenant_id: subject.repository.tenant_id.clone(),
                repository_id: subject.repository.id.clone(),
                run_id: subject.run_id.clone(),
                job_id: subject.lease.job_id.clone(),
                job_attempt: request.job_attempt,
                step_id: ticket.step_id.clone(),
                operation: "save".to_owned(),
                key_material_digest,
                candidates: Vec::new(),
                outcome: "saved".to_owned(),
                selected_trust_domain: Some(
                    serde_json::to_value(&entry.manifest.identity.trust_domain)
                        .map_err(|_| Status::internal("cache save scope could not be encoded"))?,
                ),
                selected_generation: Some(entry.head.generation),
                transferred_bytes: snapshot.total_file_bytes,
                latency_ms: 0,
                breaker_state: "closed".to_owned(),
                created_unix_ms: ticket.issued_at_unix_seconds.saturating_mul(1000),
            })
            .map_err(control_plane_status)?;
        Ok(v1::CommitCacheEntryResponse {
            cache_entry_id: cache_entry_id.to_string(),
            generation: entry.head.generation,
            status: "committed".to_owned(),
        })
    }
}
