use super::super::control_plane_status;
use runtrue_artifacts::{ArtifactStore, ArtifactTicket, ArtifactTicketRequest};
use runtrue_cache::{CacheStore, CacheWriteTicket, CacheWriteTicketRequest};
use runtrue_control_plane::{
    ControlPlaneError, ControlPlaneStore, StorageReservationState, StorageTicketBinding,
    StorageTicketBindingState, TenantStorageReservation,
};
use runtrue_model::ContentDigest;
use tonic::Status;
pub(in crate::runner_service) async fn reserve_or_recover_storage(
    control: &dyn ControlPlaneStore,
    proposed: TenantStorageReservation,
    now_unix_ms: u64,
) -> Result<TenantStorageReservation, Status> {
    if let Some(existing) = control
        .tenant_storage_reservation(&proposed.tenant_id, &proposed.id)
        .await
        .map_err(control_plane_status)?
    {
        return validate_recovered_storage_reservation(existing, &proposed, now_unix_ms);
    }
    match control.reserve_tenant_storage(&proposed, now_unix_ms).await {
        Ok(_) => Ok(proposed),
        Err(ControlPlaneError::IdempotencyConflict) => {
            let existing = control
                .tenant_storage_reservation(&proposed.tenant_id, &proposed.id)
                .await
                .map_err(control_plane_status)?
                .ok_or_else(|| Status::aborted("storage reservation race was lost"))?;
            validate_recovered_storage_reservation(existing, &proposed, now_unix_ms)
        }
        Err(error) => Err(control_plane_status(error)),
    }
}

pub(in crate::runner_service) fn validate_recovered_storage_reservation(
    existing: TenantStorageReservation,
    proposed: &TenantStorageReservation,
    now_unix_ms: u64,
) -> Result<TenantStorageReservation, Status> {
    if existing.tenant_id != proposed.tenant_id
        || existing.ticket_kind != proposed.ticket_kind
        || existing.object_digest != proposed.object_digest
        || existing.reserved_bytes != proposed.reserved_bytes
        || existing.reserved_objects != proposed.reserved_objects
        || existing.state != StorageReservationState::Reserved
        || existing.completed_unix_ms.is_some()
        || now_unix_ms >= existing.expires_unix_ms
    {
        return Err(Status::already_exists(
            "storage reservation was already used by different ticket material",
        ));
    }
    Ok(existing)
}

pub(in crate::runner_service) async fn issue_or_recover_cache_ticket(
    control: &dyn ControlPlaneStore,
    cache: &CacheStore,
    reservation: &TenantStorageReservation,
    request: &CacheWriteTicketRequest,
    now_unix_ms: u64,
) -> Result<CacheWriteTicket, Status> {
    if let Some(binding) = control
        .storage_ticket_binding_for_reservation(&reservation.tenant_id, &reservation.id)
        .await
        .map_err(control_plane_status)?
    {
        return load_bound_cache_ticket(cache, reservation, request, &binding);
    }
    let issued = match cache.issue_write_ticket(request.clone()) {
        Ok(ticket) => ticket,
        Err(error) => {
            let _ = control
                .finish_tenant_storage_reservation(
                    &reservation.tenant_id,
                    &reservation.id,
                    StorageReservationState::Released,
                    now_unix_ms,
                )
                .await;
            return Err(data_status(error));
        }
    };
    let binding = StorageTicketBinding {
        reservation_id: reservation.id.clone(),
        tenant_id: reservation.tenant_id.clone(),
        ticket_kind: reservation.ticket_kind.clone(),
        ticket_id: issued.ticket_id.to_string(),
        object_id: None,
        actual_bytes: None,
        actual_objects: None,
        state: StorageTicketBindingState::Issued,
        created_unix_ms: now_unix_ms,
        updated_unix_ms: now_unix_ms,
        completed_unix_ms: None,
    };
    match control
        .bind_tenant_storage_ticket(&binding, now_unix_ms)
        .await
    {
        Ok(_) => Ok(issued),
        Err(ControlPlaneError::IdempotencyConflict) => {
            let winner = control
                .storage_ticket_binding_for_reservation(&reservation.tenant_id, &reservation.id)
                .await
                .map_err(control_plane_status)?
                .ok_or_else(|| Status::aborted("storage ticket binding race was lost"))?;
            load_bound_cache_ticket(cache, reservation, request, &winner)
        }
        Err(error) => Err(control_plane_status(error)),
    }
}

pub(in crate::runner_service) fn load_bound_cache_ticket(
    cache: &CacheStore,
    reservation: &TenantStorageReservation,
    request: &CacheWriteTicketRequest,
    binding: &StorageTicketBinding,
) -> Result<CacheWriteTicket, Status> {
    if binding.tenant_id != reservation.tenant_id
        || binding.ticket_kind != "cache"
        || binding.reservation_id != reservation.id
        || binding.state == StorageTicketBindingState::Released
    {
        return Err(Status::already_exists(
            "storage reservation is bound outside the cache ticket subject",
        ));
    }
    let digest = ContentDigest::parse(binding.ticket_id.as_str())
        .map_err(|_| Status::data_loss("bound cache ticket id is invalid"))?;
    let ticket = cache.write_ticket(&digest).map_err(data_status)?;
    if !cache_ticket_matches_request(&ticket, request) {
        return Err(Status::already_exists(
            "bound cache ticket differs from the requested immutable subject",
        ));
    }
    Ok(ticket)
}

pub(in crate::runner_service) fn cache_ticket_matches_request(
    ticket: &CacheWriteTicket,
    request: &CacheWriteTicketRequest,
) -> bool {
    ticket.operation == request.operation
        && ticket.tenant_id == request.tenant_id
        && ticket.repository_id == request.repository_id
        && ticket.job_id == request.job_id
        && ticket.job_attempt == request.job_attempt
        && ticket.step_id == request.step_id
        && ticket.lease_id == request.lease_id
        && ticket.producer_capsule_digest == request.producer_capsule_digest
        && ticket.fencing_generation == request.fencing_generation
        && ticket.writer_trust_domain == request.writer_trust_domain
        && ticket.identity == request.identity
        && ticket.expected_head == request.expected_head
        && ticket.expected_tree_manifest_digest == request.expected_tree_manifest_digest
        && ticket.max_total_bytes == request.max_total_bytes
        && ticket.issued_at_unix_seconds == request.issued_at_unix_seconds
        && ticket.expires_at_unix_seconds == request.expires_at_unix_seconds
}

pub(in crate::runner_service) async fn issue_or_recover_artifact_ticket(
    control: &dyn ControlPlaneStore,
    artifacts: &ArtifactStore,
    reservation: &TenantStorageReservation,
    request: &ArtifactTicketRequest,
    now_unix_ms: u64,
) -> Result<ArtifactTicket, Status> {
    if let Some(binding) = control
        .storage_ticket_binding_for_reservation(&reservation.tenant_id, &reservation.id)
        .await
        .map_err(control_plane_status)?
    {
        return load_bound_artifact_ticket(artifacts, reservation, request, &binding);
    }
    let issued = match artifacts.issue_ticket(request.clone()) {
        Ok(ticket) => ticket,
        Err(error) => {
            let _ = control
                .finish_tenant_storage_reservation(
                    &reservation.tenant_id,
                    &reservation.id,
                    StorageReservationState::Released,
                    now_unix_ms,
                )
                .await;
            return Err(data_status(error));
        }
    };
    let binding = StorageTicketBinding {
        reservation_id: reservation.id.clone(),
        tenant_id: reservation.tenant_id.clone(),
        ticket_kind: reservation.ticket_kind.clone(),
        ticket_id: issued.ticket_id.to_string(),
        object_id: None,
        actual_bytes: None,
        actual_objects: None,
        state: StorageTicketBindingState::Issued,
        created_unix_ms: now_unix_ms,
        updated_unix_ms: now_unix_ms,
        completed_unix_ms: None,
    };
    match control
        .bind_tenant_storage_ticket(&binding, now_unix_ms)
        .await
    {
        Ok(_) => Ok(issued),
        Err(ControlPlaneError::IdempotencyConflict) => {
            let winner = control
                .storage_ticket_binding_for_reservation(&reservation.tenant_id, &reservation.id)
                .await
                .map_err(control_plane_status)?
                .ok_or_else(|| Status::aborted("storage ticket binding race was lost"))?;
            load_bound_artifact_ticket(artifacts, reservation, request, &winner)
        }
        Err(error) => Err(control_plane_status(error)),
    }
}

pub(in crate::runner_service) fn load_bound_artifact_ticket(
    artifacts: &ArtifactStore,
    reservation: &TenantStorageReservation,
    request: &ArtifactTicketRequest,
    binding: &StorageTicketBinding,
) -> Result<ArtifactTicket, Status> {
    if binding.tenant_id != reservation.tenant_id
        || binding.ticket_kind != "artifact"
        || binding.reservation_id != reservation.id
        || binding.state == StorageTicketBindingState::Released
    {
        return Err(Status::already_exists(
            "storage reservation is bound outside the artifact ticket subject",
        ));
    }
    let digest = ContentDigest::parse(binding.ticket_id.as_str())
        .map_err(|_| Status::data_loss("bound artifact ticket id is invalid"))?;
    let ticket = artifacts.ticket(&digest).map_err(data_status)?;
    if !artifact_ticket_matches_request(&ticket, request) {
        return Err(Status::already_exists(
            "bound artifact ticket differs from the requested immutable subject",
        ));
    }
    Ok(ticket)
}

pub(in crate::runner_service) fn artifact_ticket_matches_request(
    ticket: &ArtifactTicket,
    request: &ArtifactTicketRequest,
) -> bool {
    ticket.tenant_id == request.tenant_id
        && ticket.repository_id == request.repository_id
        && ticket.run_id == request.run_id
        && ticket.job_id == request.job_id
        && ticket.job_attempt == request.job_attempt
        && ticket.step_id == request.step_id
        && ticket.lease_id == request.lease_id
        && ticket.fencing_generation == request.fencing_generation
        && ticket.name == request.name
        && ticket.classification == request.classification
        && ticket.max_bytes == request.max_bytes
        && ticket.expected_content_digest == request.expected_content_digest
        && ticket.issued_at_unix_seconds == request.issued_at_unix_seconds
        && ticket.expires_at_unix_seconds == request.expires_at_unix_seconds
}

pub(in crate::runner_service) fn data_status(error: impl std::fmt::Display) -> Status {
    Status::failed_precondition(error.to_string())
}

pub(in crate::runner_service) fn cache_generation_id(
    entry: &runtrue_cache::CacheEntry,
) -> Result<ContentDigest, runtrue_cache::CacheError> {
    match entry.head.claim_ticket_id.as_ref() {
        Some(ticket_id) => entry.completion_id(ticket_id),
        None => entry.immutable_id(),
    }
}
