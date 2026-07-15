use super::super::{
    control_plane_status, data_status, require_session_lease, validate_capsule_binding,
    validate_identifier_status, AuthenticatedIdentity, RunnerControlService, RunnerDataSubject,
    RunnerSession,
};
use runtrue_git::{GitTreeEntryKind, GitTreeManifest};
use runtrue_model::ContentDigest;
use runtrue_scheduler::{Lease, LeaseState};
use runtrue_storage::FsCas;
use runtrue_workflow_ir::ExecutionCapsule;
use std::{io::Read as _, sync::Arc};
use tonic::Status;
impl RunnerControlService {
    pub(in crate::runner_service) fn active_broker_binding(
        &self,
        authenticated: &AuthenticatedIdentity,
        execution_lease_id: &str,
        fencing_generation: u64,
        wire_job_id: &str,
        job_attempt: u32,
        step_id: &str,
    ) -> Result<(Arc<RunnerSession>, Lease), Status> {
        validate_identifier_status("execution lease id", execution_lease_id)?;
        validate_identifier_status("job id", wire_job_id)?;
        validate_identifier_status("step id", step_id)?;
        let session = self.authenticated_session(authenticated)?;
        require_session_lease(&session, execution_lease_id, fencing_generation, true)?;
        let lease = self.bound_lease(
            &authenticated.runner_id,
            execution_lease_id,
            fencing_generation,
        )?;
        if lease.state != LeaseState::Active {
            return Err(Status::failed_precondition(
                "runner brokers require an active accepted lease",
            ));
        }
        let (job_key, _) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&lease.id)
            .map_err(control_plane_status)?;
        if job_key != wire_job_id {
            return Err(Status::permission_denied(
                "broker job does not match the signed lease job",
            ));
        }
        self.require_declared_attempt_step(&lease, job_attempt, step_id)?;
        if session
            .state()?
            .running_steps
            .get(&(execution_lease_id.to_owned(), job_attempt))
            .map(String::as_str)
            != Some(step_id)
        {
            return Err(Status::failed_precondition(
                "broker request requires the declared step to be currently running",
            ));
        }
        Ok((session, lease))
    }

    pub(in crate::runner_service) fn active_data_subject(
        &self,
        authenticated: &AuthenticatedIdentity,
        execution_lease_id: &str,
        fencing_generation: u64,
        wire_job_id: &str,
        job_attempt: u32,
        step_id: &str,
    ) -> Result<RunnerDataSubject, Status> {
        let (session, lease) = self.active_broker_binding(
            authenticated,
            execution_lease_id,
            fencing_generation,
            wire_job_id,
            job_attempt,
            step_id,
        )?;
        let (job_key, signed) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&lease.id)
            .map_err(control_plane_status)?;
        validate_capsule_binding(&lease, &signed)?;
        let capsule: ExecutionCapsule = serde_json::from_slice(&signed.canonical_capsule)
            .map_err(|_| Status::data_loss("durable execution capsule is invalid"))?;
        let job = self
            .inner
            .control_plane
            .job(&lease.job_id)
            .map_err(control_plane_status)?;
        let run = self
            .inner
            .control_plane
            .run(&job.run_id)
            .map_err(control_plane_status)?;
        let repository = self
            .inner
            .control_plane
            .repository(&run.repository_id)
            .map_err(control_plane_status)?;
        Ok(RunnerDataSubject {
            session,
            lease,
            capsule,
            job_key,
            run_id: run.id,
            repository,
        })
    }

    pub(in crate::runner_service) fn active_artifact_subject(
        &self,
        authenticated: &AuthenticatedIdentity,
        execution_lease_id: &str,
        fencing_generation: u64,
        wire_job_id: &str,
        job_attempt: u32,
        step_id: &str,
    ) -> Result<RunnerDataSubject, Status> {
        if step_id != "job-finalize" || job_attempt == 0 {
            return Err(Status::permission_denied(
                "artifact uploads require the job-finalize scope",
            ));
        }
        let session = self.authenticated_session(authenticated)?;
        require_session_lease(&session, execution_lease_id, fencing_generation, true)?;
        let lease = self.bound_lease(
            &authenticated.runner_id,
            execution_lease_id,
            fencing_generation,
        )?;
        if lease.state != LeaseState::Active {
            return Err(Status::failed_precondition(
                "artifact finalization requires an active lease",
            ));
        }
        let state = session.state()?;
        if state.current_attempts.get(execution_lease_id).copied() != Some(job_attempt)
            || state
                .running_steps
                .keys()
                .any(|(lease_id, _)| lease_id == execution_lease_id)
        {
            return Err(Status::failed_precondition(
                "artifact finalization requires a completed current attempt",
            ));
        }
        drop(state);
        let (job_key, signed) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&lease.id)
            .map_err(control_plane_status)?;
        if job_key != wire_job_id {
            return Err(Status::permission_denied(
                "artifact job does not match the signed lease job",
            ));
        }
        validate_capsule_binding(&lease, &signed)?;
        let capsule: ExecutionCapsule = serde_json::from_slice(&signed.canonical_capsule)
            .map_err(|_| Status::data_loss("durable execution capsule is invalid"))?;
        let job = self
            .inner
            .control_plane
            .job(&lease.job_id)
            .map_err(control_plane_status)?;
        let run = self
            .inner
            .control_plane
            .run(&job.run_id)
            .map_err(control_plane_status)?;
        let repository = self
            .inner
            .control_plane
            .repository(&run.repository_id)
            .map_err(control_plane_status)?;
        Ok(RunnerDataSubject {
            session,
            lease,
            capsule,
            job_key,
            run_id: run.id,
            repository,
        })
    }
}
pub(in crate::runner_service) fn authorize_source_object(
    cas: &FsCas,
    manifest_digest: &ContentDigest,
    requested_digest: &ContentDigest,
    maximum_bytes: u64,
) -> Result<u64, Status> {
    let mut manifest_reader = cas
        .verified_reader(manifest_digest, cas.limits().max_manifest_bytes)
        .map_err(data_status)?;
    let manifest_size = manifest_reader.size_bytes();
    if requested_digest == manifest_digest {
        return Ok(manifest_size);
    }
    let capacity = usize::try_from(manifest_size)
        .map_err(|_| Status::resource_exhausted("source manifest is too large"))?;
    let mut bytes = Vec::with_capacity(capacity);
    manifest_reader
        .read_to_end(&mut bytes)
        .map_err(|_| Status::data_loss("source manifest cannot be read"))?;
    let manifest: GitTreeManifest = serde_json::from_slice(&bytes)
        .map_err(|_| Status::data_loss("source manifest is invalid"))?;
    manifest
        .entries
        .into_iter()
        .find_map(|entry| match entry.kind {
            GitTreeEntryKind::File {
                digest, size_bytes, ..
            } if digest == *requested_digest => Some(size_bytes),
            _ => None,
        })
        .filter(|size| *size <= maximum_bytes)
        .ok_or_else(|| Status::permission_denied("object is not authorized by the source manifest"))
}
