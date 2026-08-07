//! Runner authority persistence boundaries shared by SQLite and PostgreSQL.
//!
//! These contracts deliberately end at complete runner transactions: a lease
//! fence mutation, a broker mutation, one fleet reconciliation mutation, or
//! enrollment of a runner and certificate. The unported run boundary passes a
//! validated job binding into `put_copied_lease`; PostgreSQL never guesses at
//! run state or performs a partial cross-backend transaction.

use super::{ControlPlane, ControlPlaneError, StoreFuture};
use crate::{
    AppendRunnerLogsRequest, AuthenticatedRunnerCertificate, AuthorizeRunnerOidcRequest,
    CredentialTaintState, DeliveredRunnerSecret, EnrollmentTokenIssueResult, EnrollmentTokenRecord,
    IdempotentResult, IssueRunnerSecretRequest, IssuedEnrollmentToken, IssuedRunnerLaunchClaim,
    IssuedRunnerSoftwareUpdateClaim, PersistedRunner, PlannedRunnerReplacement,
    RecordRunnerBlobUpload, RecordRunnerOidcIssuance, RunnerAutoscalerLease,
    RunnerCertificateRecord, RunnerCertificateRotationRecord, RunnerDataCommit,
    RunnerEnrollmentReplay, RunnerFleetRequestRecord, RunnerFleetRequestState,
    RunnerLaunchClaimRecord, RunnerLogFrameRecord, RunnerPoolRecord, RunnerPoolScalingPolicy,
    RunnerPoolStatus, RunnerPoolTemplateRecord, RunnerPoolUpdatePolicy, RunnerReplacementRecord,
    RunnerSecretLeaseRecord, RunnerSlotRecord, RunnerSoftwareUpdateClaim,
    VerifiedRunnerUpdateReleaseRegistration,
};
#[cfg(feature = "postgres")]
use crate::{RunnerReplacementMode, RunnerReplacementState};
use runtrue_lifecycle::JobState;
use runtrue_model::ContentDigest;
use runtrue_oidc::OidcGrant;
use runtrue_scheduler::{Lease, RunnerRecord};
use runtrue_secrets::MasterKey;

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "postgres")]
use super::{postgres_i64, postgres_u64, PostgresInstallationStore};
#[cfg(feature = "postgres")]
use crate::{authoritative_runner_posture_digest, EnrollmentToken, RunnerLaunchClaimToken};
#[cfg(feature = "postgres")]
use rand_core::{OsRng, RngCore as _};
#[cfg(feature = "postgres")]
use runtrue_audit::{AuditEventData, AuditPrincipal, AuditResource, AuditValue};
#[cfg(feature = "postgres")]
use runtrue_secrets::SecretIdentity;
#[cfg(feature = "postgres")]
use sha2::{Digest as _, Sha256};
#[cfg(feature = "postgres")]
use sqlx::Row as _;
#[cfg(feature = "postgres")]
use zeroize::Zeroize as _;

#[cfg(feature = "postgres")]
pub(super) const POSTGRES_MIGRATION: &str =
    include_str!("../../migrations/postgres/0006_runner_authority.sql");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerPoolConfiguration {
    pub pool: RunnerPoolRecord,
    pub scaling_policy: Option<RunnerPoolScalingPolicy>,
    pub templates: Vec<RunnerPoolTemplateRecord>,
}

pub struct PoolEnrollmentCompletion<'a> {
    pub token: &'a str,
    pub request_digest: &'a ContentDigest,
    pub runner: &'a RunnerRecord,
    pub certificate: &'a RunnerCertificateRecord,
    pub certificate_chain_pem: &'a [u8],
    pub inventory_digest: &'a ContentDigest,
    pub selected_protocol_version: u32,
    pub now_unix_ms: u64,
}

pub struct AutoscaledReplacementPlan<'a> {
    pub pool_id: &'a str,
    pub source_runner_id: &'a str,
    pub replacement_id: &'a str,
    pub fleet_request_id: &'a str,
    pub owner_id: &'a str,
    pub fencing_generation: u64,
    pub now_unix_ms: u64,
}

/// Execution lease and broker operations whose fences must be observed and
/// mutated in one database transaction.
pub trait RunnerLeaseBrokerStore: Send + Sync {
    fn put_copied_lease<'a>(
        &'a self,
        lease: &'a Lease,
        hard_deadline_unix_ms: u64,
    ) -> StoreFuture<'a, bool>;

    fn runner_execution_lease<'a>(&'a self, lease_id: &'a str) -> StoreFuture<'a, Lease>;
    fn runner_execution_lease_hard_deadline<'a>(
        &'a self,
        lease_id: &'a str,
    ) -> StoreFuture<'a, u64>;
    fn open_runner_execution_leases<'a>(
        &'a self,
        runner_id: &'a str,
        limit: usize,
    ) -> StoreFuture<'a, Vec<Lease>>;
    fn runner_log_frame_count<'a>(&'a self, lease_id: &'a str) -> StoreFuture<'a, u64>;
    #[allow(clippy::too_many_arguments)]
    fn reject_runner_execution_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        generation: u64,
        epoch: u64,
        rejection_code: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, Lease>;

    fn accept_runner_execution_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, Lease>;

    fn heartbeat_runner_execution_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
        new_expires_unix_ms: u64,
    ) -> StoreFuture<'a, Lease>;

    fn issue_runner_secret<'a>(
        &'a self,
        request: &'a IssueRunnerSecretRequest,
        master_key: &'a MasterKey,
    ) -> StoreFuture<'a, DeliveredRunnerSecret>;

    fn put_copied_runner_secret_lease<'a>(
        &'a self,
        record: &'a RunnerSecretLeaseRecord,
    ) -> StoreFuture<'a, bool>;

    fn runner_secret_lease_record<'a>(
        &'a self,
        lease_id: &'a str,
    ) -> StoreFuture<'a, RunnerSecretLeaseRecord>;

    fn revoke_runner_secret_lease_record<'a>(
        &'a self,
        lease_id: &'a str,
        execution_lease_id: &'a str,
        fencing_generation: u64,
        runner_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerSecretLeaseRecord>;

    fn authorize_runner_oidc_grant<'a>(
        &'a self,
        request: &'a AuthorizeRunnerOidcRequest,
    ) -> StoreFuture<'a, OidcGrant>;

    fn record_runner_oidc_token<'a>(
        &'a self,
        request: &'a RecordRunnerOidcIssuance,
    ) -> StoreFuture<'a, ()>;

    fn append_runner_log_frames<'a>(
        &'a self,
        request: &'a AppendRunnerLogsRequest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()>;

    fn record_runner_blob_transfer<'a>(
        &'a self,
        request: &'a RecordRunnerBlobUpload,
        runner_id: &'a str,
        direction: &'a str,
    ) -> StoreFuture<'a, bool>;

    fn record_runner_data_commit_journal<'a>(
        &'a self,
        request: &'a RunnerDataCommit,
        runner_id: &'a str,
    ) -> StoreFuture<'a, bool>;

    fn set_runner_scheduler_quota<'a>(
        &'a self,
        tenant_id: &'a str,
        maximum_running_jobs: u32,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()>;

    fn maintain_runner_scheduler(&self, now_unix_ms: u64) -> StoreFuture<'_, ()>;

    fn offer_next_runner_lease<'a>(
        &'a self,
        runner_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, Option<Lease>>;

    #[allow(clippy::too_many_arguments)]
    fn complete_runner_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        generation: u64,
        epoch: u64,
        result_digest: &'a ContentDigest,
        final_job_state: JobState,
        credential_taint: CredentialTaintState,
        job_attempt: u32,
        artifact_ids: &'a [String],
        cache_entry_ids: &'a [String],
        required_artifact_names: &'a [String],
        completed_unix_ms: u64,
    ) -> StoreFuture<'a, Lease>;

    fn runner_run_credential_taint<'a>(
        &'a self,
        run_id: &'a str,
    ) -> StoreFuture<'a, CredentialTaintState>;

    #[allow(clippy::too_many_arguments)]
    fn validate_runner_completion_artifact_claims<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        job_attempt: u32,
        claims: &'a [(String, String)],
    ) -> StoreFuture<'a, ()>;

    fn runner_logs_for_run<'a>(
        &'a self,
        run_id: &'a str,
        maximum_frames: usize,
    ) -> StoreFuture<'a, Vec<RunnerLogFrameRecord>>;
}

/// Pool configuration, autoscaler fencing, fleet state, one-time launch
/// claims, and enrollment/certificate persistence.
pub trait RunnerFleetEnrollmentStore: Send + Sync {
    fn put_runner_pool_configuration<'a>(
        &'a self,
        configuration: &'a RunnerPoolConfiguration,
    ) -> StoreFuture<'a, ()>;

    fn runner_pool_configuration<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, RunnerPoolConfiguration>;

    fn inspect_pool_enrollment_token<'a>(
        &'a self,
        token: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, EnrollmentTokenRecord>;
    fn replay_pool_enrollment<'a>(
        &'a self,
        token: &'a str,
        request_digest: &'a ContentDigest,
    ) -> StoreFuture<'a, Option<RunnerEnrollmentReplay>>;
    fn launch_claim_for_enrollment_token<'a>(
        &'a self,
        enrollment_token_id: &'a str,
    ) -> StoreFuture<'a, Option<RunnerLaunchClaimRecord>>;
    fn software_update_claim_for_enrollment_token<'a>(
        &'a self,
        enrollment_token_id: &'a str,
    ) -> StoreFuture<'a, Option<RunnerSoftwareUpdateClaim>>;
    fn put_runner_release<'a>(
        &'a self,
        registration: &'a VerifiedRunnerUpdateReleaseRegistration,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()>;
    fn put_pool_update_policy<'a>(
        &'a self,
        policy: &'a RunnerPoolUpdatePolicy,
    ) -> StoreFuture<'a, ()>;
    fn replacements<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerReplacementRecord>>;
    fn plan_autoscaled_replacement<'a>(
        &'a self,
        plan: AutoscaledReplacementPlan<'a>,
    ) -> StoreFuture<'a, PlannedRunnerReplacement>;
    fn activate_replacement<'a>(
        &'a self,
        replacement_id: &'a str,
        owner_id: &'a str,
        fencing_generation: u64,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerReplacementRecord>;
    fn put_fixed_runner_slot<'a>(&'a self, slot: &'a RunnerSlotRecord) -> StoreFuture<'a, ()>;
    fn fixed_runner_slot<'a>(&'a self, slot_id: &'a str) -> StoreFuture<'a, RunnerSlotRecord>;
    fn create_fixed_update_claim<'a>(
        &'a self,
        slot_id: &'a str,
        identity_proof_digest: &'a ContentDigest,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, IssuedRunnerSoftwareUpdateClaim>;
    fn validate_pool_runner_inventory<'a>(
        &'a self,
        runner_id: &'a str,
        inventory_digest: &'a ContentDigest,
    ) -> StoreFuture<'a, ContentDigest>;
    fn update_pool_runner_locality<'a>(
        &'a self,
        runner_id: &'a str,
        locality: &'a BTreeSet<ContentDigest>,
        package_tiers: &'a BTreeMap<ContentDigest, runtrue_scheduler::PackagePreparationTier>,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, PersistedRunner>;

    fn runner_pools(&self) -> StoreFuture<'_, Vec<RunnerPoolRecord>>;
    fn runner_pools_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerPoolRecord>>;
    fn pool_runners(&self) -> StoreFuture<'_, Vec<PersistedRunner>>;
    fn pool_runners_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<PersistedRunner>>;
    fn pool_templates<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerPoolTemplateRecord>>;
    fn fleet_requests<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerFleetRequestRecord>>;
    fn fleet_request<'a>(
        &'a self,
        request_id: &'a str,
    ) -> StoreFuture<'a, RunnerFleetRequestRecord>;
    fn drain_pool_runner<'a>(
        &'a self,
        runner_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, PersistedRunner>;

    fn acquire_autoscaler_lease<'a>(
        &'a self,
        pool_id: &'a str,
        owner_id: &'a str,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerAutoscalerLease>;

    fn create_fleet_request<'a>(
        &'a self,
        request: &'a RunnerFleetRequestRecord,
        owner_id: &'a str,
        fencing_generation: u64,
    ) -> StoreFuture<'a, ()>;

    #[allow(clippy::too_many_arguments)]
    fn transition_fleet_request<'a>(
        &'a self,
        request_id: &'a str,
        expected: RunnerFleetRequestState,
        next: RunnerFleetRequestState,
        provider_request_id: Option<&'a str>,
        provider_instance_id: Option<&'a str>,
        runner_id: Option<&'a str>,
        failure_code: Option<&'a str>,
        owner_id: &'a str,
        fencing_generation: u64,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerFleetRequestRecord>;

    fn create_pool_enrollment_token<'a>(
        &'a self,
        pool_id: &'a str,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, IssuedEnrollmentToken>;

    fn create_pool_enrollment_token_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        pool_id: &'a str,
        lifetime_seconds: u64,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, EnrollmentTokenIssueResult>;

    fn consume_pool_enrollment_token<'a>(
        &'a self,
        token: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, EnrollmentTokenRecord>;

    #[allow(clippy::too_many_arguments)]
    fn create_launch_claim<'a>(
        &'a self,
        fleet_request_id: &'a str,
        provider_instance_id: &'a str,
        identity_proof_digest: &'a ContentDigest,
        owner_id: &'a str,
        fencing_generation: u64,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, IssuedRunnerLaunchClaim>;

    fn complete_pool_enrollment<'a>(
        &'a self,
        completion: PoolEnrollmentCompletion<'a>,
    ) -> StoreFuture<'a, RunnerEnrollmentReplay>;

    fn authenticate_pool_runner_certificate<'a>(
        &'a self,
        fingerprint: &'a ContentDigest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, AuthenticatedRunnerCertificate>;

    #[allow(clippy::too_many_arguments)]
    fn rotate_pool_runner_certificate<'a>(
        &'a self,
        authenticated_fingerprint: &'a ContentDigest,
        runner_id: &'a str,
        csr_digest: &'a ContentDigest,
        certificate: &'a RunnerCertificateRecord,
        certificate_chain_pem: &'a [u8],
        now_unix_ms: u64,
        overlap_millis: u64,
    ) -> StoreFuture<'a, IdempotentResult<RunnerCertificateRotationRecord>>;

    fn pool_runner_certificate<'a>(
        &'a self,
        fingerprint: &'a ContentDigest,
    ) -> StoreFuture<'a, RunnerCertificateRecord>;

    fn pool_runner_certificate_rotation<'a>(
        &'a self,
        old_fingerprint: &'a ContentDigest,
    ) -> StoreFuture<'a, Option<RunnerCertificateRotationRecord>>;

    fn register_pool_runner<'a>(
        &'a self,
        runner: &'a RunnerRecord,
        inventory_digest: &'a ContentDigest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ContentDigest>;

    fn pool_runner<'a>(&'a self, runner_id: &'a str) -> StoreFuture<'a, PersistedRunner>;

    fn set_pool_runner_connected<'a>(
        &'a self,
        runner_id: &'a str,
        connected: bool,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, PersistedRunner>;

    fn pool_fleet_snapshot<'a>(
        &'a self,
        pool_id: &'a str,
        observed_unix_ms: u64,
    ) -> StoreFuture<'a, crate::RunnerPoolFleetSnapshot>;
}

impl RunnerLeaseBrokerStore for ControlPlane {
    fn put_copied_lease<'a>(
        &'a self,
        lease: &'a Lease,
        hard_deadline_unix_ms: u64,
    ) -> StoreFuture<'a, bool> {
        let result = sqlite_put_copied_lease(self, lease, hard_deadline_unix_ms);
        Box::pin(async move { result })
    }

    fn issue_runner_secret<'a>(
        &'a self,
        request: &'a IssueRunnerSecretRequest,
        master_key: &'a MasterKey,
    ) -> StoreFuture<'a, DeliveredRunnerSecret> {
        let result = ControlPlane::issue_runner_secret(self, request, master_key);
        Box::pin(async move { result })
    }

    fn runner_execution_lease<'a>(&'a self, lease_id: &'a str) -> StoreFuture<'a, Lease> {
        let result = self.lease(lease_id);
        Box::pin(async move { result })
    }

    fn runner_execution_lease_hard_deadline<'a>(
        &'a self,
        lease_id: &'a str,
    ) -> StoreFuture<'a, u64> {
        let result = self.lease_hard_deadline_unix_ms(lease_id);
        Box::pin(async move { result })
    }

    fn open_runner_execution_leases<'a>(
        &'a self,
        runner_id: &'a str,
        limit: usize,
    ) -> StoreFuture<'a, Vec<Lease>> {
        let result = self.open_leases_for_runner(runner_id, limit);
        Box::pin(async move { result })
    }

    fn runner_log_frame_count<'a>(&'a self, lease_id: &'a str) -> StoreFuture<'a, u64> {
        let result = self.runner_log_frame_count_for_lease(lease_id);
        Box::pin(async move { result })
    }

    fn reject_runner_execution_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        generation: u64,
        epoch: u64,
        rejection_code: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, Lease> {
        let result = self.reject_lease_with_code(
            lease_id,
            runner_id,
            generation,
            epoch,
            rejection_code,
            now_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn accept_runner_execution_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, Lease> {
        let result = self.accept_lease(
            lease_id,
            runner_id,
            fencing_generation,
            installation_fencing_epoch,
            now_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn heartbeat_runner_execution_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
        new_expires_unix_ms: u64,
    ) -> StoreFuture<'a, Lease> {
        let result = self.heartbeat_lease(
            lease_id,
            runner_id,
            fencing_generation,
            installation_fencing_epoch,
            now_unix_ms,
            new_expires_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn put_copied_runner_secret_lease<'a>(
        &'a self,
        record: &'a RunnerSecretLeaseRecord,
    ) -> StoreFuture<'a, bool> {
        let result = sqlite_put_copied_secret_lease(self, record);
        Box::pin(async move { result })
    }

    fn runner_secret_lease_record<'a>(
        &'a self,
        lease_id: &'a str,
    ) -> StoreFuture<'a, RunnerSecretLeaseRecord> {
        let result = self.runner_secret_lease(lease_id);
        Box::pin(async move { result })
    }

    fn revoke_runner_secret_lease_record<'a>(
        &'a self,
        lease_id: &'a str,
        execution_lease_id: &'a str,
        fencing_generation: u64,
        runner_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerSecretLeaseRecord> {
        let result = self.revoke_runner_secret(
            lease_id,
            execution_lease_id,
            fencing_generation,
            runner_id,
            now_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn authorize_runner_oidc_grant<'a>(
        &'a self,
        request: &'a AuthorizeRunnerOidcRequest,
    ) -> StoreFuture<'a, OidcGrant> {
        let result = self.authorize_runner_oidc(request);
        Box::pin(async move { result })
    }

    fn record_runner_oidc_token<'a>(
        &'a self,
        request: &'a RecordRunnerOidcIssuance,
    ) -> StoreFuture<'a, ()> {
        let result = self.record_runner_oidc_issuance(request);
        Box::pin(async move { result })
    }

    fn append_runner_log_frames<'a>(
        &'a self,
        request: &'a AppendRunnerLogsRequest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()> {
        let result = self.append_runner_logs(request, now_unix_ms);
        Box::pin(async move { result })
    }

    fn record_runner_blob_transfer<'a>(
        &'a self,
        request: &'a RecordRunnerBlobUpload,
        runner_id: &'a str,
        direction: &'a str,
    ) -> StoreFuture<'a, bool> {
        let result = match direction {
            "upload" => self.record_runner_blob_upload(request, runner_id),
            "download" => self.record_runner_blob_download(request, runner_id),
            _ => Err(ControlPlaneError::InvalidInput(
                "invalid object transfer direction",
            )),
        };
        Box::pin(async move { result })
    }

    fn record_runner_data_commit_journal<'a>(
        &'a self,
        request: &'a RunnerDataCommit,
        runner_id: &'a str,
    ) -> StoreFuture<'a, bool> {
        let result = self.record_runner_data_commit(request, runner_id);
        Box::pin(async move { result })
    }

    fn set_runner_scheduler_quota<'a>(
        &'a self,
        tenant_id: &'a str,
        maximum_running_jobs: u32,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()> {
        let result = self.set_tenant_scheduler_quota(tenant_id, maximum_running_jobs, now_unix_ms);
        Box::pin(async move { result })
    }

    fn maintain_runner_scheduler(&self, now_unix_ms: u64) -> StoreFuture<'_, ()> {
        let result = self.perform_scheduler_maintenance(now_unix_ms);
        Box::pin(async move { result })
    }

    fn offer_next_runner_lease<'a>(
        &'a self,
        runner_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, Option<Lease>> {
        let result = self.offer_next_lease_for_runner(runner_id, now_unix_ms);
        Box::pin(async move { result })
    }

    fn complete_runner_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        generation: u64,
        epoch: u64,
        result_digest: &'a ContentDigest,
        final_job_state: JobState,
        credential_taint: CredentialTaintState,
        job_attempt: u32,
        artifact_ids: &'a [String],
        cache_entry_ids: &'a [String],
        required_artifact_names: &'a [String],
        completed_unix_ms: u64,
    ) -> StoreFuture<'a, Lease> {
        let result = self.complete_lease_with_objects(
            lease_id,
            runner_id,
            generation,
            epoch,
            result_digest,
            final_job_state,
            credential_taint,
            job_attempt,
            artifact_ids,
            cache_entry_ids,
            required_artifact_names,
            completed_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn runner_run_credential_taint<'a>(
        &'a self,
        run_id: &'a str,
    ) -> StoreFuture<'a, CredentialTaintState> {
        let result = self.run_credential_taint(run_id);
        Box::pin(async move { result })
    }

    fn validate_runner_completion_artifact_claims<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        job_attempt: u32,
        claims: &'a [(String, String)],
    ) -> StoreFuture<'a, ()> {
        let result = ControlPlane::validate_runner_completion_artifact_claims(
            self,
            lease_id,
            runner_id,
            fencing_generation,
            installation_fencing_epoch,
            job_attempt,
            claims,
        );
        Box::pin(async move { result })
    }

    fn runner_logs_for_run<'a>(
        &'a self,
        run_id: &'a str,
        maximum_frames: usize,
    ) -> StoreFuture<'a, Vec<RunnerLogFrameRecord>> {
        let result = ControlPlane::runner_logs_for_run(self, run_id, maximum_frames);
        Box::pin(async move { result })
    }
}

impl RunnerFleetEnrollmentStore for ControlPlane {
    fn put_runner_pool_configuration<'a>(
        &'a self,
        configuration: &'a RunnerPoolConfiguration,
    ) -> StoreFuture<'a, ()> {
        let result = sqlite_put_pool_configuration(self, configuration);
        Box::pin(async move { result })
    }

    fn runner_pool_configuration<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, RunnerPoolConfiguration> {
        let result = (|| {
            let pool = self.runner_pool(pool_id)?;
            let scaling_policy = self.runner_pool_scaling_policy(pool_id).ok();
            let templates = self.list_runner_pool_templates(pool_id)?;
            Ok(RunnerPoolConfiguration {
                pool,
                scaling_policy,
                templates,
            })
        })();
        Box::pin(async move { result })
    }

    fn inspect_pool_enrollment_token<'a>(
        &'a self,
        token: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, EnrollmentTokenRecord> {
        let result = self.inspect_enrollment_token(token, now_unix_ms);
        Box::pin(async move { result })
    }

    fn replay_pool_enrollment<'a>(
        &'a self,
        token: &'a str,
        request_digest: &'a ContentDigest,
    ) -> StoreFuture<'a, Option<RunnerEnrollmentReplay>> {
        let result = self.replay_runner_enrollment(token, request_digest);
        Box::pin(async move { result })
    }

    fn launch_claim_for_enrollment_token<'a>(
        &'a self,
        enrollment_token_id: &'a str,
    ) -> StoreFuture<'a, Option<RunnerLaunchClaimRecord>> {
        let result = self.runner_launch_claim_for_enrollment_token(enrollment_token_id);
        Box::pin(async move { result })
    }

    fn software_update_claim_for_enrollment_token<'a>(
        &'a self,
        enrollment_token_id: &'a str,
    ) -> StoreFuture<'a, Option<RunnerSoftwareUpdateClaim>> {
        let result = self.runner_software_update_claim_for_enrollment_token(enrollment_token_id);
        Box::pin(async move { result })
    }

    fn put_runner_release<'a>(
        &'a self,
        registration: &'a VerifiedRunnerUpdateReleaseRegistration,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()> {
        let result = self.put_verified_runner_update_release(registration, now_unix_ms);
        Box::pin(async move { result })
    }
    fn put_pool_update_policy<'a>(
        &'a self,
        policy: &'a RunnerPoolUpdatePolicy,
    ) -> StoreFuture<'a, ()> {
        let result = self.put_runner_pool_update_policy(policy);
        Box::pin(async move { result })
    }
    fn replacements<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerReplacementRecord>> {
        let result = self.runner_replacements(pool_id);
        Box::pin(async move { result })
    }
    fn plan_autoscaled_replacement<'a>(
        &'a self,
        plan: AutoscaledReplacementPlan<'a>,
    ) -> StoreFuture<'a, PlannedRunnerReplacement> {
        let result = self.plan_autoscaled_runner_replacement(
            plan.pool_id,
            plan.source_runner_id,
            plan.replacement_id,
            plan.fleet_request_id,
            plan.owner_id,
            plan.fencing_generation,
            plan.now_unix_ms,
        );
        Box::pin(async move { result })
    }
    fn activate_replacement<'a>(
        &'a self,
        replacement_id: &'a str,
        owner_id: &'a str,
        fencing_generation: u64,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerReplacementRecord> {
        let result = self.activate_runner_replacement(
            replacement_id,
            owner_id,
            fencing_generation,
            now_unix_ms,
        );
        Box::pin(async move { result })
    }
    fn put_fixed_runner_slot<'a>(&'a self, slot: &'a RunnerSlotRecord) -> StoreFuture<'a, ()> {
        let result = self.put_runner_slot(slot);
        Box::pin(async move { result })
    }

    fn fixed_runner_slot<'a>(&'a self, slot_id: &'a str) -> StoreFuture<'a, RunnerSlotRecord> {
        let result = self.runner_slot(slot_id);
        Box::pin(async move { result })
    }
    fn create_fixed_update_claim<'a>(
        &'a self,
        slot_id: &'a str,
        identity_proof_digest: &'a ContentDigest,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, IssuedRunnerSoftwareUpdateClaim> {
        let result = self.create_fixed_host_update_claim(
            slot_id,
            identity_proof_digest,
            now_unix_ms,
            expires_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn validate_pool_runner_inventory<'a>(
        &'a self,
        runner_id: &'a str,
        inventory_digest: &'a ContentDigest,
    ) -> StoreFuture<'a, ContentDigest> {
        let result = self.validate_runner_inventory_binding(runner_id, inventory_digest);
        Box::pin(async move { result })
    }

    fn update_pool_runner_locality<'a>(
        &'a self,
        runner_id: &'a str,
        locality: &'a BTreeSet<ContentDigest>,
        package_tiers: &'a BTreeMap<ContentDigest, runtrue_scheduler::PackagePreparationTier>,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, PersistedRunner> {
        let result = self.update_runner_locality(runner_id, locality, package_tiers, now_unix_ms);
        Box::pin(async move { result })
    }

    fn runner_pools(&self) -> StoreFuture<'_, Vec<RunnerPoolRecord>> {
        let result = self.list_runner_pools();
        Box::pin(async move { result })
    }

    fn runner_pools_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerPoolRecord>> {
        let result = self.list_runner_pools_for_tenant(tenant_id);
        Box::pin(async move { result })
    }

    fn pool_runners(&self) -> StoreFuture<'_, Vec<PersistedRunner>> {
        let result = self.list_runners();
        Box::pin(async move { result })
    }

    fn pool_runners_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<PersistedRunner>> {
        let result = self.list_runners_for_tenant(tenant_id);
        Box::pin(async move { result })
    }

    fn pool_templates<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerPoolTemplateRecord>> {
        let result = self.list_runner_pool_templates(pool_id);
        Box::pin(async move { result })
    }

    fn fleet_requests<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerFleetRequestRecord>> {
        let result = self.list_runner_fleet_requests(pool_id);
        Box::pin(async move { result })
    }

    fn fleet_request<'a>(
        &'a self,
        request_id: &'a str,
    ) -> StoreFuture<'a, RunnerFleetRequestRecord> {
        let result = self.runner_fleet_request(request_id);
        Box::pin(async move { result })
    }

    fn drain_pool_runner<'a>(
        &'a self,
        runner_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, PersistedRunner> {
        let result = self.drain_runner(runner_id, now_unix_ms);
        Box::pin(async move { result })
    }

    fn acquire_autoscaler_lease<'a>(
        &'a self,
        pool_id: &'a str,
        owner_id: &'a str,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerAutoscalerLease> {
        let result =
            self.acquire_runner_autoscaler_lease(pool_id, owner_id, now_unix_ms, expires_unix_ms);
        Box::pin(async move { result })
    }

    fn create_fleet_request<'a>(
        &'a self,
        request: &'a RunnerFleetRequestRecord,
        owner_id: &'a str,
        fencing_generation: u64,
    ) -> StoreFuture<'a, ()> {
        let result = self.create_runner_fleet_request(request, owner_id, fencing_generation);
        Box::pin(async move { result })
    }

    fn transition_fleet_request<'a>(
        &'a self,
        request_id: &'a str,
        expected: RunnerFleetRequestState,
        next: RunnerFleetRequestState,
        provider_request_id: Option<&'a str>,
        provider_instance_id: Option<&'a str>,
        runner_id: Option<&'a str>,
        failure_code: Option<&'a str>,
        owner_id: &'a str,
        fencing_generation: u64,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerFleetRequestRecord> {
        let result = self.transition_runner_fleet_request(
            request_id,
            expected,
            next,
            provider_request_id,
            provider_instance_id,
            runner_id,
            failure_code,
            owner_id,
            fencing_generation,
            now_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn create_pool_enrollment_token<'a>(
        &'a self,
        pool_id: &'a str,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, IssuedEnrollmentToken> {
        let result = self.create_enrollment_token(pool_id, now_unix_ms, expires_unix_ms);
        Box::pin(async move { result })
    }

    fn create_pool_enrollment_token_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        pool_id: &'a str,
        lifetime_seconds: u64,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, EnrollmentTokenIssueResult> {
        let result = self.create_enrollment_token_idempotent(
            idempotency_key,
            pool_id,
            lifetime_seconds,
            now_unix_ms,
            expires_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn consume_pool_enrollment_token<'a>(
        &'a self,
        token: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, EnrollmentTokenRecord> {
        let result = self.consume_enrollment_token(token, now_unix_ms);
        Box::pin(async move { result })
    }

    fn create_launch_claim<'a>(
        &'a self,
        fleet_request_id: &'a str,
        provider_instance_id: &'a str,
        identity_proof_digest: &'a ContentDigest,
        owner_id: &'a str,
        fencing_generation: u64,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, IssuedRunnerLaunchClaim> {
        let result = self.create_runner_launch_claim(
            fleet_request_id,
            provider_instance_id,
            identity_proof_digest,
            owner_id,
            fencing_generation,
            now_unix_ms,
            expires_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn complete_pool_enrollment<'a>(
        &'a self,
        completion: PoolEnrollmentCompletion<'a>,
    ) -> StoreFuture<'a, RunnerEnrollmentReplay> {
        let result = self.complete_runner_enrollment_idempotent(
            completion.token,
            completion.request_digest,
            completion.runner,
            completion.certificate,
            completion.certificate_chain_pem,
            completion.inventory_digest,
            completion.selected_protocol_version,
            completion.now_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn authenticate_pool_runner_certificate<'a>(
        &'a self,
        fingerprint: &'a ContentDigest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, AuthenticatedRunnerCertificate> {
        let result = self.authenticate_runner_certificate(fingerprint, now_unix_ms);
        Box::pin(async move { result })
    }

    fn rotate_pool_runner_certificate<'a>(
        &'a self,
        authenticated_fingerprint: &'a ContentDigest,
        runner_id: &'a str,
        csr_digest: &'a ContentDigest,
        certificate: &'a RunnerCertificateRecord,
        certificate_chain_pem: &'a [u8],
        now_unix_ms: u64,
        overlap_millis: u64,
    ) -> StoreFuture<'a, IdempotentResult<RunnerCertificateRotationRecord>> {
        let result = self.rotate_runner_certificate_idempotent(
            authenticated_fingerprint,
            runner_id,
            csr_digest,
            certificate,
            certificate_chain_pem,
            now_unix_ms,
            overlap_millis,
        );
        Box::pin(async move { result })
    }

    fn pool_runner_certificate<'a>(
        &'a self,
        fingerprint: &'a ContentDigest,
    ) -> StoreFuture<'a, RunnerCertificateRecord> {
        let result = self.runner_certificate(fingerprint);
        Box::pin(async move { result })
    }

    fn pool_runner_certificate_rotation<'a>(
        &'a self,
        old_fingerprint: &'a ContentDigest,
    ) -> StoreFuture<'a, Option<RunnerCertificateRotationRecord>> {
        let result = self.runner_certificate_rotation(old_fingerprint);
        Box::pin(async move { result })
    }

    fn register_pool_runner<'a>(
        &'a self,
        runner: &'a RunnerRecord,
        inventory_digest: &'a ContentDigest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ContentDigest> {
        let result = self.register_runner_with_inventory(runner, inventory_digest, now_unix_ms);
        Box::pin(async move { result })
    }

    fn pool_runner<'a>(&'a self, runner_id: &'a str) -> StoreFuture<'a, PersistedRunner> {
        let result = self.runner(runner_id);
        Box::pin(async move { result })
    }

    fn set_pool_runner_connected<'a>(
        &'a self,
        runner_id: &'a str,
        connected: bool,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, PersistedRunner> {
        let result = if connected {
            self.mark_runner_connected(runner_id, now_unix_ms)
        } else {
            self.mark_runner_disconnected(runner_id, now_unix_ms)
        };
        Box::pin(async move { result })
    }

    fn pool_fleet_snapshot<'a>(
        &'a self,
        pool_id: &'a str,
        observed_unix_ms: u64,
    ) -> StoreFuture<'a, crate::RunnerPoolFleetSnapshot> {
        let result = self.runner_pool_fleet_snapshot(pool_id, observed_unix_ms);
        Box::pin(async move { result })
    }
}

fn sqlite_put_copied_lease(
    store: &ControlPlane,
    lease: &Lease,
    hard_deadline_unix_ms: u64,
) -> Result<bool, ControlPlaneError> {
    if lease.fencing_generation == 0
        || lease.installation_fencing_epoch == 0
        || lease.accept_by_unix_ms <= lease.issued_unix_ms
        || lease.expires_unix_ms <= lease.issued_unix_ms
        || hard_deadline_unix_ms < lease.expires_unix_ms
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid copied runner lease",
        ));
    }
    let connection = store.connection()?;
    let state = lease_state_name(lease.state);
    let changed = connection.execute(
        "INSERT OR IGNORE INTO leases
         (id, job_id, tenant_id, runner_id, fencing_generation,
          installation_fencing_epoch, capsule_digest, state, issued_unix_ms,
          accept_by_unix_ms, expires_unix_ms, hard_deadline_unix_ms,
          terminal_result_digest)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        rusqlite::params![
            lease.id,
            lease.job_id,
            lease.tenant_id,
            lease.runner_id,
            to_i64(lease.fencing_generation, "lease generation")?,
            to_i64(lease.installation_fencing_epoch, "installation epoch")?,
            lease.capsule_digest.as_str(),
            state,
            to_i64(lease.issued_unix_ms, "lease issued")?,
            to_i64(lease.accept_by_unix_ms, "lease accept deadline")?,
            to_i64(lease.expires_unix_ms, "lease expiry")?,
            to_i64(hard_deadline_unix_ms, "lease hard deadline")?,
            lease
                .terminal_result_digest
                .as_ref()
                .map(ContentDigest::as_str),
        ],
    )?;
    if changed == 0 {
        drop(connection);
        let existing = store.lease(&lease.id)?;
        if existing != *lease {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        return Ok(false);
    }
    connection.execute(
        "INSERT INTO job_fencing(job_id,last_generation) VALUES(?1,?2)
         ON CONFLICT(job_id) DO UPDATE SET last_generation=MAX(last_generation,excluded.last_generation)",
        rusqlite::params![lease.job_id, to_i64(lease.fencing_generation, "lease generation")?],
    )?;
    Ok(changed == 1)
}

fn sqlite_put_pool_configuration(
    store: &ControlPlane,
    configuration: &RunnerPoolConfiguration,
) -> Result<(), ControlPlaneError> {
    validate_pool_configuration(configuration)?;
    let mut connection = store.connection()?;
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO runner_pools
         (id,tenant_id,name,region,status,created_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",
        rusqlite::params![
            configuration.pool.id,
            configuration.pool.tenant_id,
            configuration.pool.name,
            configuration.pool.region,
            pool_status_name(configuration.pool.status),
            to_i64(configuration.pool.created_unix_ms, "pool creation")?,
        ],
    )?;
    if inserted == 0 {
        let same: bool = tx.query_row(
            "SELECT tenant_id=?2 AND name=?3 AND region IS ?4 AND status=?5 AND created_unix_ms=?6
             FROM runner_pools WHERE id=?1",
            rusqlite::params![
                configuration.pool.id,
                configuration.pool.tenant_id,
                configuration.pool.name,
                configuration.pool.region,
                pool_status_name(configuration.pool.status),
                to_i64(configuration.pool.created_unix_ms, "pool creation")?,
            ],
            |row| row.get(0),
        )?;
        if !same {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
    }
    if let Some(policy) = &configuration.scaling_policy {
        tx.execute(
            "INSERT INTO runner_pool_scaling_policies
             (pool_id,baseline_runtime_compatibility_digest,minimum_workers,
              minimum_idle_workers,maximum_workers,scale_up_batch,idle_timeout_ms,
              offline_grace_ms,cooldown_ms,enabled,updated_unix_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(pool_id) DO UPDATE SET
              baseline_runtime_compatibility_digest=excluded.baseline_runtime_compatibility_digest,
              minimum_workers=excluded.minimum_workers,
              minimum_idle_workers=excluded.minimum_idle_workers,
              maximum_workers=excluded.maximum_workers,
              scale_up_batch=excluded.scale_up_batch,
              idle_timeout_ms=excluded.idle_timeout_ms,
              offline_grace_ms=excluded.offline_grace_ms,
              cooldown_ms=excluded.cooldown_ms,enabled=excluded.enabled,
              updated_unix_ms=excluded.updated_unix_ms",
            rusqlite::params![
                policy.pool_id,
                policy
                    .baseline_runtime_compatibility_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
                policy.minimum_workers,
                policy.minimum_idle_workers,
                policy.maximum_workers,
                policy.scale_up_batch,
                to_i64(policy.idle_timeout_ms, "idle timeout")?,
                to_i64(policy.offline_grace_ms, "offline grace")?,
                to_i64(policy.cooldown_ms, "autoscaler cooldown")?,
                policy.enabled,
                to_i64(policy.updated_unix_ms, "policy update")?,
            ],
        )?;
    }
    for template in &configuration.templates {
        tx.execute(
            "INSERT INTO runner_pool_templates
             (pool_id,runtime_compatibility_digest,provider,provider_template_id,
              runner_template_digest,created_unix_ms,updated_unix_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(pool_id,runtime_compatibility_digest) DO UPDATE SET
              provider=excluded.provider,provider_template_id=excluded.provider_template_id,
              runner_template_digest=excluded.runner_template_digest,
              updated_unix_ms=excluded.updated_unix_ms",
            rusqlite::params![
                template.pool_id,
                template.runtime_compatibility_digest.as_str(),
                template.provider,
                template.provider_template_id,
                template.runner_template_digest.as_str(),
                to_i64(template.created_unix_ms, "template creation")?,
                to_i64(template.updated_unix_ms, "template update")?,
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn sqlite_put_copied_secret_lease(
    store: &ControlPlane,
    record: &RunnerSecretLeaseRecord,
) -> Result<bool, ControlPlaneError> {
    validate_secret_record(record)?;
    let connection = store.connection()?;
    let changed = connection.execute(
        "INSERT OR IGNORE INTO runner_secret_leases
         (id,execution_lease_id,fencing_generation,installation_fencing_epoch,
          runner_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,
          secret_metadata_id,secret_version,purpose,guest_key_fingerprint,
          runner_posture_digest,issued_unix_ms,expires_unix_ms,state,revoked_unix_ms)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        rusqlite::params![
            record.id,
            record.execution_lease_id,
            to_i64(record.fencing_generation, "lease generation")?,
            to_i64(record.installation_fencing_epoch, "installation epoch")?,
            record.runner_id,
            record.tenant_id,
            record.repository_id,
            record.run_id,
            record.job_id,
            record.job_attempt,
            record.step_id,
            record.secret_metadata_id,
            to_i64(record.secret_version, "secret version")?,
            record.purpose,
            record.guest_key_fingerprint.as_str(),
            record.runner_posture_digest.as_str(),
            to_i64(record.issued_unix_ms, "secret lease issued")?,
            to_i64(record.expires_unix_ms, "secret lease expiry")?,
            record.state,
            record
                .revoked_unix_ms
                .map(|value| to_i64(value, "secret lease revoked"))
                .transpose()?,
        ],
    )?;
    if changed == 0 {
        drop(connection);
        if store.runner_secret_lease(&record.id)? != *record {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        return Ok(false);
    }
    Ok(changed == 1)
}

fn to_i64(value: u64, field: &'static str) -> Result<i64, ControlPlaneError> {
    i64::try_from(value).map_err(|_| ControlPlaneError::IntegerRange { field })
}

fn lease_state_name(state: runtrue_scheduler::LeaseState) -> &'static str {
    use runtrue_scheduler::LeaseState;
    match state {
        LeaseState::Offered => "offered",
        LeaseState::Active => "active",
        LeaseState::CancelRequested => "cancel_requested",
        LeaseState::Completed => "completed",
        LeaseState::Rejected => "rejected",
        LeaseState::Expired => "expired",
    }
}

#[cfg(feature = "postgres")]
fn fleet_state_name(state: RunnerFleetRequestState) -> &'static str {
    match state {
        RunnerFleetRequestState::Requested => "requested",
        RunnerFleetRequestState::Provisioning => "provisioning",
        RunnerFleetRequestState::Bootstrapping => "bootstrapping",
        RunnerFleetRequestState::Enrolled => "enrolled",
        RunnerFleetRequestState::Online => "online",
        RunnerFleetRequestState::Draining => "draining",
        RunnerFleetRequestState::Terminating => "terminating",
        RunnerFleetRequestState::Terminated => "terminated",
        RunnerFleetRequestState::Failed => "failed",
        RunnerFleetRequestState::Quarantined => "quarantined",
    }
}

#[cfg(feature = "postgres")]
fn parse_fleet_state(value: &str) -> Result<RunnerFleetRequestState, ControlPlaneError> {
    use RunnerFleetRequestState as State;
    match value {
        "requested" => Ok(State::Requested),
        "provisioning" => Ok(State::Provisioning),
        "bootstrapping" => Ok(State::Bootstrapping),
        "enrolled" => Ok(State::Enrolled),
        "online" => Ok(State::Online),
        "draining" => Ok(State::Draining),
        "terminating" => Ok(State::Terminating),
        "terminated" => Ok(State::Terminated),
        "failed" => Ok(State::Failed),
        "quarantined" => Ok(State::Quarantined),
        _ => Err(ControlPlaneError::CorruptState(
            "unknown PostgreSQL runner fleet state".to_owned(),
        )),
    }
}

fn validate_secret_record(record: &RunnerSecretLeaseRecord) -> Result<(), ControlPlaneError> {
    if record.id.is_empty()
        || record.execution_lease_id.is_empty()
        || record.runner_id.is_empty()
        || record.fencing_generation == 0
        || record.installation_fencing_epoch == 0
        || record.job_attempt == 0
        || record.secret_version == 0
        || record.expires_unix_ms <= record.issued_unix_ms
        || !matches!(record.state.as_str(), "delivered" | "revoked" | "expired")
        || (record.state == "delivered") != record.revoked_unix_ms.is_none()
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid copied runner secret lease",
        ));
    }
    Ok(())
}

/// Expire every copied bearer of runner authority in the same transaction as
/// the installation epoch advance. No old execution, broker credential,
/// enrollment token, launch claim, or autoscaler owner survives a restore.
#[cfg(feature = "postgres")]
pub(super) async fn fence_postgres_runner_authority(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    completed_unix_ms: i64,
) -> Result<(), ControlPlaneError> {
    // Preserve the lifecycle transition rule used by SQLite: only jobs that
    // can legally become Lost are concluded by restore fencing. The lease
    // rows are locked by the following update in this same transaction.
    sqlx::query(
        "UPDATE jobs AS j
         SET status='lost', completed_unix_ms=$1
         FROM leases AS l
         WHERE l.job_id=j.id
           AND l.state IN ('offered','active','cancel_requested')
           AND j.status IN ('queued','leased','preparing','running','finalizing')",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE leases SET state='expired', completed_unix_ms=COALESCE(completed_unix_ms,$1)
         WHERE state IN ('offered','active','cancel_requested')",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_secret_leases SET state='expired', revoked_unix_ms=$1
         WHERE state='delivered'",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_oidc_issuances SET state='expired', revoked_unix_ms=$1
         WHERE state='issued'",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_oidc_grants SET state='expired',revoked_unix_ms=$1
         WHERE state='authorized'",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE oidc_grants SET revoked_unix_ms=$1 WHERE revoked_unix_ms IS NULL
         AND id IN (SELECT grant_id FROM runner_oidc_grants WHERE state='expired')",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_object_transfers SET state='abandoned',updated_unix_ms=$1
         WHERE state IN ('reserved','transferring')",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE enrollment_tokens SET expires_unix_ms=LEAST(expires_unix_ms,$1)
         WHERE consumed_unix_ms IS NULL AND expires_unix_ms>$1",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_launch_claims SET expires_unix_ms=LEAST(expires_unix_ms,$1)
         WHERE consumed_unix_ms IS NULL AND expires_unix_ms>$1",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_autoscaler_leases SET expires_unix_ms=LEAST(expires_unix_ms,$1)
         WHERE expires_unix_ms>$1",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
impl RunnerLeaseBrokerStore for PostgresInstallationStore {
    fn put_copied_lease<'a>(
        &'a self,
        lease: &'a Lease,
        hard_deadline_unix_ms: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            if lease.fencing_generation == 0
                || lease.installation_fencing_epoch == 0
                || lease.accept_by_unix_ms <= lease.issued_unix_ms
                || lease.expires_unix_ms <= lease.issued_unix_ms
                || hard_deadline_unix_ms < lease.expires_unix_ms
            {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid copied runner lease",
                ));
            }
            let mut tx = self.pool.begin().await?;
            let epoch: i64 = sqlx::query_scalar(
                "SELECT fencing_epoch FROM installation_state WHERE singleton=TRUE FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await?;
            if postgres_u64(epoch, "fencing_epoch")? != lease.installation_fencing_epoch {
                return Err(ControlPlaneError::StaleInstallationEpoch {
                    expected: postgres_u64(epoch, "fencing_epoch")?,
                    actual: lease.installation_fencing_epoch,
                });
            }
            let changed = sqlx::query(
                "INSERT INTO leases
                 (id,job_id,tenant_id,runner_id,fencing_generation,
                  installation_fencing_epoch,capsule_digest,state,issued_unix_ms,
                  accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms,
                  terminal_result_digest)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(&lease.id)
            .bind(&lease.job_id)
            .bind(&lease.tenant_id)
            .bind(&lease.runner_id)
            .bind(postgres_i64(lease.fencing_generation, "lease generation")?)
            .bind(postgres_i64(
                lease.installation_fencing_epoch,
                "installation epoch",
            )?)
            .bind(lease.capsule_digest.as_str())
            .bind(lease_state_name(lease.state))
            .bind(postgres_i64(lease.issued_unix_ms, "lease issued")?)
            .bind(postgres_i64(
                lease.accept_by_unix_ms,
                "lease accept deadline",
            )?)
            .bind(postgres_i64(lease.expires_unix_ms, "lease expiry")?)
            .bind(postgres_i64(hard_deadline_unix_ms, "lease hard deadline")?)
            .bind(
                lease
                    .terminal_result_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();
            sqlx::query(
                "INSERT INTO job_fencing(job_id,last_generation) VALUES($1,$2)
                 ON CONFLICT(job_id) DO UPDATE SET
                 last_generation=GREATEST(job_fencing.last_generation,excluded.last_generation)",
            )
            .bind(&lease.job_id)
            .bind(postgres_i64(lease.fencing_generation, "lease generation")?)
            .execute(&mut *tx)
            .await?;
            if changed == 0 {
                let existing = postgres_lease_tx(&mut tx, &lease.id).await?;
                if existing != *lease {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            }
            tx.commit().await?;
            Ok(changed == 1)
        })
    }

    fn runner_execution_lease_hard_deadline<'a>(
        &'a self,
        lease_id: &'a str,
    ) -> StoreFuture<'a, u64> {
        Box::pin(async move {
            if lease_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput("lease id is empty"));
            }
            let value: i64 =
                sqlx::query_scalar("SELECT hard_deadline_unix_ms FROM leases WHERE id=$1")
                    .bind(lease_id)
                    .fetch_optional(&self.pool)
                    .await?
                    .ok_or_else(|| ControlPlaneError::NotFound {
                        kind: "lease",
                        id: lease_id.to_owned(),
                    })?;
            postgres_u64(value, "lease hard deadline")
        })
    }

    fn open_runner_execution_leases<'a>(
        &'a self,
        runner_id: &'a str,
        limit: usize,
    ) -> StoreFuture<'a, Vec<Lease>> {
        Box::pin(async move {
            if runner_id.is_empty() || limit == 0 || limit > 1024 {
                return Err(ControlPlaneError::InvalidInput(
                    "runner open-lease query limit is invalid",
                ));
            }
            let rows = sqlx::query(
                "SELECT id FROM leases WHERE runner_id=$1
                 AND state IN ('offered','active','cancel_requested')
                 ORDER BY issued_unix_ms,id LIMIT $2",
            )
            .bind(runner_id)
            .bind(
                i64::try_from(limit).map_err(|_| ControlPlaneError::IntegerRange {
                    field: "runner open-lease query limit",
                })?,
            )
            .fetch_all(&self.pool)
            .await?;
            let mut leases = Vec::with_capacity(rows.len());
            for row in rows {
                let id: String = row.try_get("id")?;
                let mut tx = self.pool.begin().await?;
                leases.push(postgres_lease_tx(&mut tx, &id).await?);
                tx.commit().await?;
            }
            Ok(leases)
        })
    }

    fn runner_log_frame_count<'a>(&'a self, lease_id: &'a str) -> StoreFuture<'a, u64> {
        Box::pin(async move {
            if lease_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput("lease id is empty"));
            }
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM runner_log_frames WHERE execution_lease_id=$1",
            )
            .bind(lease_id)
            .fetch_one(&self.pool)
            .await?;
            postgres_u64(count, "runner log frame count")
        })
    }

    fn reject_runner_execution_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        generation: u64,
        epoch: u64,
        rejection_code: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, Lease> {
        Box::pin(async move {
            if rejection_code.is_empty() {
                return Err(ControlPlaneError::InvalidInput(
                    "lease rejection code is empty",
                ));
            }
            let mut tx = self.pool.begin().await?;
            let lease =
                validate_postgres_lease_fence(&mut tx, lease_id, runner_id, generation, epoch)
                    .await?;
            if lease.state == runtrue_scheduler::LeaseState::Rejected {
                tx.commit().await?;
                return Ok(lease);
            }
            if lease.state != runtrue_scheduler::LeaseState::Offered {
                return Err(ControlPlaneError::InvalidLeaseState {
                    expected: "offered",
                    actual: lease_state_name(lease.state),
                });
            }
            if now_unix_ms >= lease.accept_by_unix_ms {
                sqlx::query("UPDATE leases SET state='expired',completed_unix_ms=$2 WHERE id=$1")
                    .bind(lease_id)
                    .bind(postgres_i64(now_unix_ms, "lease expiration")?)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE jobs SET status='queued' WHERE id=$1 AND status='leased'")
                    .bind(&lease.job_id)
                    .execute(&mut *tx)
                    .await?;
                revoke_postgres_brokers(&mut tx, &lease, now_unix_ms, "expired").await?;
                tx.commit().await?;
                return Err(ControlPlaneError::LeaseOfferExpired);
            }
            sqlx::query("UPDATE leases SET state='rejected' WHERE id=$1")
                .bind(lease_id)
                .execute(&mut *tx)
                .await?;
            if transient_postgres_rejection(rejection_code) {
                sqlx::query(
                    "INSERT INTO runner_job_rejections
                     (runner_id,job_id,rejection_count,last_code,updated_unix_ms)
                     VALUES($1,$2,1,$3,$4)
                     ON CONFLICT(runner_id,job_id) DO UPDATE SET
                       rejection_count=runner_job_rejections.rejection_count+1,
                       last_code=excluded.last_code,updated_unix_ms=excluded.updated_unix_ms",
                )
                .bind(runner_id)
                .bind(&lease.job_id)
                .bind(rejection_code)
                .bind(postgres_i64(now_unix_ms, "lease rejection")?)
                .execute(&mut *tx)
                .await?;
                sqlx::query("UPDATE jobs SET status='queued' WHERE id=$1 AND status='leased'")
                    .bind(&lease.job_id)
                    .execute(&mut *tx)
                    .await?;
            } else {
                sqlx::query(
                    "UPDATE jobs SET status='blocked_policy',completed_unix_ms=$2
                     WHERE id=$1 AND status='leased'",
                )
                .bind(&lease.job_id)
                .bind(postgres_i64(now_unix_ms, "lease rejection")?)
                .execute(&mut *tx)
                .await?;
                conclude_postgres_run_for_job(&mut tx, &lease.job_id, now_unix_ms).await?;
            }
            let rejected = postgres_lease_tx(&mut tx, lease_id).await?;
            tx.commit().await?;
            Ok(rejected)
        })
    }

    fn runner_execution_lease<'a>(&'a self, lease_id: &'a str) -> StoreFuture<'a, Lease> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let lease = postgres_lease_tx(&mut tx, lease_id).await?;
            tx.commit().await?;
            Ok(lease)
        })
    }

    fn accept_runner_execution_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, Lease> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let lease = validate_postgres_lease_fence(
                &mut tx,
                lease_id,
                runner_id,
                fencing_generation,
                installation_fencing_epoch,
            )
            .await?;
            if lease.state != runtrue_scheduler::LeaseState::Offered {
                return Err(ControlPlaneError::InvalidLeaseState {
                    expected: "offered",
                    actual: lease_state_name(lease.state),
                });
            }
            let hard_deadline: i64 =
                sqlx::query_scalar("SELECT hard_deadline_unix_ms FROM leases WHERE id=$1")
                    .bind(lease_id)
                    .fetch_one(&mut *tx)
                    .await?;
            let hard_deadline = postgres_u64(hard_deadline, "lease hard deadline")?;
            if now_unix_ms >= lease.accept_by_unix_ms
                || now_unix_ms >= lease.expires_unix_ms
                || now_unix_ms >= hard_deadline
            {
                sqlx::query("UPDATE leases SET state='expired',completed_unix_ms=$2 WHERE id=$1")
                    .bind(lease_id)
                    .bind(postgres_i64(now_unix_ms, "lease expiration")?)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE jobs SET status='queued' WHERE id=$1 AND status='leased'")
                    .bind(&lease.job_id)
                    .execute(&mut *tx)
                    .await?;
                revoke_postgres_brokers(&mut tx, &lease, now_unix_ms, "expired").await?;
                tx.commit().await?;
                return Err(ControlPlaneError::LeaseOfferExpired);
            }
            let changed =
                sqlx::query("UPDATE leases SET state='active' WHERE id=$1 AND state='offered'")
                    .bind(lease_id)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::InvalidLeaseState {
                    expected: "offered",
                    actual: lease_state_name(lease.state),
                });
            }
            let accepted = postgres_lease_tx(&mut tx, lease_id).await?;
            tx.commit().await?;
            Ok(accepted)
        })
    }

    fn heartbeat_runner_execution_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
        new_expires_unix_ms: u64,
    ) -> StoreFuture<'a, Lease> {
        Box::pin(async move {
            if new_expires_unix_ms <= now_unix_ms {
                return Err(ControlPlaneError::InvalidInput("invalid heartbeat expiry"));
            }
            let mut tx = self.pool.begin().await?;
            let lease = validate_postgres_lease_fence(
                &mut tx,
                lease_id,
                runner_id,
                fencing_generation,
                installation_fencing_epoch,
            )
            .await?;
            if !matches!(
                lease.state,
                runtrue_scheduler::LeaseState::Active
                    | runtrue_scheduler::LeaseState::CancelRequested
            ) {
                return Err(ControlPlaneError::InvalidLeaseState {
                    expected: "active or cancel_requested",
                    actual: lease_state_name(lease.state),
                });
            }
            let hard_deadline: i64 =
                sqlx::query_scalar("SELECT hard_deadline_unix_ms FROM leases WHERE id=$1")
                    .bind(lease_id)
                    .fetch_one(&mut *tx)
                    .await?;
            let hard_deadline = postgres_u64(hard_deadline, "lease hard deadline")?;
            if now_unix_ms >= lease.expires_unix_ms || now_unix_ms >= hard_deadline {
                let state = if lease.state == runtrue_scheduler::LeaseState::CancelRequested {
                    JobState::Canceled
                } else if now_unix_ms >= hard_deadline {
                    JobState::TimedOut
                } else {
                    JobState::Lost
                };
                expire_postgres_lease_with_job(&mut tx, &lease, state, now_unix_ms).await?;
                conclude_postgres_run_for_job(&mut tx, &lease.job_id, now_unix_ms).await?;
                tx.commit().await?;
                return Err(ControlPlaneError::LeaseExpired);
            }
            let expiry = new_expires_unix_ms.min(hard_deadline);
            sqlx::query("UPDATE leases SET expires_unix_ms=$2 WHERE id=$1")
                .bind(lease_id)
                .bind(postgres_i64(expiry, "lease expiry")?)
                .execute(&mut *tx)
                .await?;
            let lease = postgres_lease_tx(&mut tx, lease_id).await?;
            tx.commit().await?;
            Ok(lease)
        })
    }

    fn issue_runner_secret<'a>(
        &'a self,
        request: &'a IssueRunnerSecretRequest,
        master_key: &'a MasterKey,
    ) -> StoreFuture<'a, DeliveredRunnerSecret> {
        Box::pin(async move {
            validate_postgres_runner_secret_request(request)?;
            let mut tx = self.pool.begin().await?;
            let subject = postgres_runner_secret_subject(&mut tx, request).await?;
            if !subject.capsule.approval.privileged_execution {
                return Err(ControlPlaneError::ApprovalRequired);
            }
            let approval =
                postgres_runner_approval_subject(&mut tx, &subject.run_id, &subject.capsule)
                    .await?;
            let capsule_approval: Option<String> = sqlx::query_scalar(
                "SELECT approval_subject_digest FROM capsule_api_metadata WHERE capsule_id=$1",
            )
            .bind(&subject.capsule_id)
            .fetch_optional(&mut *tx)
            .await?;
            if capsule_approval.as_deref() != Some(approval.as_str()) {
                return Err(ControlPlaneError::ApprovalRequired);
            }
            let step = (request.job_attempt <= subject.planned_job.retries.saturating_add(1))
                .then_some(&subject.planned_job)
                .and_then(|job| job.steps.iter().find(|step| step.id == request.step_id))
                .ok_or(ControlPlaneError::RunnerBrokerCapabilityDenied)?;
            let metadata = super::secrets_policy::secret_metadata_id_tx(
                &mut tx,
                &request.secret_metadata_id,
                true,
            )
            .await?
            .ok_or_else(|| ControlPlaneError::NotFound {
                kind: "secret metadata",
                id: request.secret_metadata_id.clone(),
            })?;
            let declared = step.capabilities.secrets.iter().find(|secret| {
                secret.metadata_id == metadata.id
                    && secret.name == metadata.name
                    && secret.purpose.as_deref().unwrap_or_default() == request.purpose
            });
            let binding = declared.and_then(|secret| secret.resolution.as_ref());
            if declared.is_none()
                || binding.is_none_or(|binding| binding.scope != metadata.scope)
                || metadata.tenant_id != subject.tenant_id
                || metadata.provider != "built-in"
                || metadata.provider_reference.is_some()
                || metadata.status != "active"
            {
                return Err(ControlPlaneError::RunnerBrokerCapabilityDenied);
            }
            let secret_version = binding
                .and_then(|binding| binding.metadata_version)
                .filter(|version| {
                    metadata
                        .current_version
                        .is_some_and(|current| *version <= current)
                })
                .ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "signed built-in secret binding has no eligible exact version".to_owned(),
                    )
                })?;
            let replay: Option<String> = sqlx::query_scalar(
                "SELECT id FROM runner_secret_leases
                 WHERE execution_lease_id=$1 AND fencing_generation=$2
                   AND job_attempt=$3 AND step_id=$4
                   AND secret_metadata_id=$5 AND purpose=$6 FOR UPDATE",
            )
            .bind(&request.execution_lease_id)
            .bind(postgres_i64(
                request.fencing_generation,
                "lease generation",
            )?)
            .bind(i32::try_from(request.job_attempt).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "job attempt",
                }
            })?)
            .bind(&request.step_id)
            .bind(&request.secret_metadata_id)
            .bind(&request.purpose)
            .fetch_optional(&mut *tx)
            .await?;
            if replay.is_some() {
                return Err(ControlPlaneError::RunnerBrokerReplay);
            }
            let identity = SecretIdentity::new(
                metadata.tenant_id.clone(),
                metadata.scope.clone(),
                metadata.name.clone(),
            )?;
            let vault = super::secrets_policy::load_vault(
                &mut tx,
                &metadata.tenant_id,
                &metadata.scope,
                master_key,
                self.installation_id(),
            )
            .await?;
            let plaintext = vault.reveal_for_administration(&identity, Some(secret_version))?;
            let mut id_bytes = [0_u8; 16];
            OsRng
                .try_fill_bytes(&mut id_bytes)
                .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
            let id = format!("secret-lease-{}", hex::encode(id_bytes));
            let record = RunnerSecretLeaseRecord {
                id: id.clone(),
                execution_lease_id: subject.lease.id.clone(),
                fencing_generation: subject.lease.fencing_generation,
                installation_fencing_epoch: subject.lease.installation_fencing_epoch,
                runner_id: request.runner_id.clone(),
                tenant_id: subject.tenant_id,
                repository_id: subject.repository_id,
                run_id: subject.run_id,
                job_id: request.job_id.clone(),
                job_attempt: request.job_attempt,
                step_id: request.step_id.clone(),
                secret_metadata_id: metadata.id,
                secret_version,
                purpose: request.purpose.clone(),
                guest_key_fingerprint: request.guest_key_fingerprint.clone(),
                runner_posture_digest: request.runner_posture_digest.clone(),
                issued_unix_ms: request.issued_unix_ms,
                expires_unix_ms: request.expires_unix_ms,
                state: "delivered".to_owned(),
                revoked_unix_ms: None,
            };
            let insert = sqlx::query(
                "INSERT INTO runner_secret_leases
                 (id,execution_lease_id,fencing_generation,installation_fencing_epoch,
                  runner_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,
                  secret_metadata_id,secret_version,purpose,guest_key_fingerprint,
                  runner_posture_digest,issued_unix_ms,expires_unix_ms,state,revoked_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'delivered',NULL)",
            )
            .bind(&record.id)
            .bind(&record.execution_lease_id)
            .bind(postgres_i64(record.fencing_generation, "lease generation")?)
            .bind(postgres_i64(record.installation_fencing_epoch, "installation epoch")?)
            .bind(&record.runner_id)
            .bind(&record.tenant_id)
            .bind(&record.repository_id)
            .bind(&record.run_id)
            .bind(&record.job_id)
            .bind(i32::try_from(record.job_attempt).map_err(|_| ControlPlaneError::IntegerRange { field: "job attempt" })?)
            .bind(&record.step_id)
            .bind(&record.secret_metadata_id)
            .bind(postgres_i64(record.secret_version, "secret version")?)
            .bind(&record.purpose)
            .bind(record.guest_key_fingerprint.as_str())
            .bind(record.runner_posture_digest.as_str())
            .bind(postgres_i64(record.issued_unix_ms, "secret issue")?)
            .bind(postgres_i64(record.expires_unix_ms, "secret expiry")?)
            .execute(&mut *tx)
            .await;
            if let Err(error) = insert {
                if error
                    .as_database_error()
                    .and_then(|db| db.code())
                    .is_some_and(|code| code == "23505")
                {
                    return Err(ControlPlaneError::RunnerBrokerReplay);
                }
                return Err(error.into());
            }
            super::api_tokens::append(
                &mut tx,
                self.installation_id(),
                AuditEventData {
                    observed_unix_ms: request.issued_unix_ms,
                    tenant_id: record.tenant_id.clone(),
                    actor: AuditPrincipal {
                        kind: "runner".to_owned(),
                        id: record.runner_id.clone(),
                    },
                    action: "runner.secret.deliver".to_owned(),
                    resource: AuditResource {
                        kind: "secret_lease".to_owned(),
                        id: record.id.clone(),
                    },
                    result: "success".to_owned(),
                    request_id: format!("runner-broker:{}", record.id),
                    decision_id: None,
                    metadata: std::collections::BTreeMap::from([
                        (
                            "execution_lease_id".to_owned(),
                            AuditValue::String(record.execution_lease_id.clone()),
                        ),
                        (
                            "step_id".to_owned(),
                            AuditValue::String(record.step_id.clone()),
                        ),
                        (
                            "secret_metadata_id".to_owned(),
                            AuditValue::String(record.secret_metadata_id.clone()),
                        ),
                    ]),
                },
            )
            .await?;
            tx.commit().await?;
            Ok(DeliveredRunnerSecret {
                lease: record,
                plaintext,
            })
        })
    }

    fn put_copied_runner_secret_lease<'a>(
        &'a self,
        record: &'a RunnerSecretLeaseRecord,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_secret_record(record)?;
            let mut tx = self.pool.begin().await?;
            let lease = validate_postgres_lease_fence(
                &mut tx,
                &record.execution_lease_id,
                &record.runner_id,
                record.fencing_generation,
                record.installation_fencing_epoch,
            )
            .await?;
            if record.expires_unix_ms > lease.expires_unix_ms {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let changed = sqlx::query(
                "INSERT INTO runner_secret_leases
                 (id,execution_lease_id,fencing_generation,installation_fencing_epoch,
                  runner_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,
                  secret_metadata_id,secret_version,purpose,guest_key_fingerprint,
                  runner_posture_digest,issued_unix_ms,expires_unix_ms,state,revoked_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(&record.id)
            .bind(&record.execution_lease_id)
            .bind(postgres_i64(record.fencing_generation, "lease generation")?)
            .bind(postgres_i64(
                record.installation_fencing_epoch,
                "installation epoch",
            )?)
            .bind(&record.runner_id)
            .bind(&record.tenant_id)
            .bind(&record.repository_id)
            .bind(&record.run_id)
            .bind(&record.job_id)
            .bind(i32::try_from(record.job_attempt).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "job attempt",
                }
            })?)
            .bind(&record.step_id)
            .bind(&record.secret_metadata_id)
            .bind(postgres_i64(record.secret_version, "secret version")?)
            .bind(&record.purpose)
            .bind(record.guest_key_fingerprint.as_str())
            .bind(record.runner_posture_digest.as_str())
            .bind(postgres_i64(record.issued_unix_ms, "secret lease issued")?)
            .bind(postgres_i64(record.expires_unix_ms, "secret lease expiry")?)
            .bind(&record.state)
            .bind(
                record
                    .revoked_unix_ms
                    .map(|value| postgres_i64(value, "secret lease revoked"))
                    .transpose()?,
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed == 0 {
                let existing = postgres_secret_lease_tx(&mut tx, &record.id).await?;
                if existing != *record {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            }
            tx.commit().await?;
            Ok(changed == 1)
        })
    }

    fn runner_secret_lease_record<'a>(
        &'a self,
        lease_id: &'a str,
    ) -> StoreFuture<'a, RunnerSecretLeaseRecord> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let record = postgres_secret_lease_tx(&mut tx, lease_id).await?;
            tx.commit().await?;
            Ok(record)
        })
    }

    fn revoke_runner_secret_lease_record<'a>(
        &'a self,
        lease_id: &'a str,
        execution_lease_id: &'a str,
        fencing_generation: u64,
        runner_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerSecretLeaseRecord> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let record = postgres_secret_lease_tx(&mut tx, lease_id).await?;
            if record.execution_lease_id != execution_lease_id
                || record.fencing_generation != fencing_generation
                || record.runner_id != runner_id
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let lease = validate_postgres_lease_fence(
                &mut tx,
                execution_lease_id,
                runner_id,
                fencing_generation,
                record.installation_fencing_epoch,
            )
            .await?;
            if lease.state != runtrue_scheduler::LeaseState::Active
                || now_unix_ms >= lease.expires_unix_ms
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            if record.state == "delivered" {
                let changed = sqlx::query(
                    "UPDATE runner_secret_leases SET state='revoked',revoked_unix_ms=$2
                     WHERE id=$1 AND state='delivered'",
                )
                .bind(lease_id)
                .bind(postgres_i64(now_unix_ms, "secret lease revoked")?)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::RunnerBrokerReplay);
                }
            } else if record.state != "revoked" {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let record = postgres_secret_lease_tx(&mut tx, lease_id).await?;
            tx.commit().await?;
            Ok(record)
        })
    }

    fn authorize_runner_oidc_grant<'a>(
        &'a self,
        request: &'a AuthorizeRunnerOidcRequest,
    ) -> StoreFuture<'a, OidcGrant> {
        Box::pin(async move {
            validate_postgres_oidc_authorization_request(request)?;
            let mut tx = self.pool.begin().await?;
            let subject = postgres_runner_oidc_subject(
                &mut tx,
                &request.execution_lease_id,
                &request.runner_id,
                request.fencing_generation,
                &request.job_id,
                request.job_attempt,
                &request.step_id,
                &request.audience,
                &request.runner_posture_digest,
                request.now_unix_ms,
            )
            .await?;
            let grant_id = postgres_runner_oidc_grant_id(
                &subject.lease,
                request.job_attempt,
                &request.step_id,
                &request.runner_posture_digest,
            );
            let grant = OidcGrant {
                grant_id: grant_id.clone(),
                tenant_id: subject.lease.tenant_id.clone(),
                repository_id: subject.repository_id,
                run_id: subject.run_id,
                job_id: subject.lease.job_id.clone(),
                step_id: request.step_id.clone(),
                capsule_digest: subject.lease.capsule_digest.clone(),
                execution_lease_id: subject.lease.id.clone(),
                fencing_generation: subject.lease.fencing_generation,
                trust: subject.trust,
                runner_pool_id: Some(subject.runner_pool_id),
                environment: subject.environment,
                ref_name: subject.ref_name,
                source_commit: subject.source_commit,
                approval_subject_digest: Some(subject.approval_subject_digest),
                runner_posture_digest: Some(request.runner_posture_digest.clone()),
                allowed_audiences: subject.allowed_audiences,
                expires_unix_seconds: subject.lease.expires_unix_ms / 1000,
            };
            grant.validate()?;
            let changed = sqlx::query(
                "INSERT INTO oidc_grants(id,grant_json) VALUES($1,$2)
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(&grant_id)
            .bind(serde_json::to_vec(&grant)?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed == 0 {
                let stored: Vec<u8> = sqlx::query_scalar(
                    "SELECT grant_json FROM oidc_grants
                     WHERE id=$1 AND revoked_unix_ms IS NULL FOR UPDATE",
                )
                .bind(&grant_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
                if serde_json::from_slice::<OidcGrant>(&stored)? != grant {
                    return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                }
            }
            let binding_changed = sqlx::query(
                "INSERT INTO runner_oidc_grants
                 (grant_id,execution_lease_id,fencing_generation,installation_fencing_epoch,
                  runner_id,job_attempt,step_id,runner_posture_digest,state,authorized_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,'authorized',$9)
                 ON CONFLICT(grant_id) DO NOTHING",
            )
            .bind(&grant_id)
            .bind(&subject.lease.id)
            .bind(postgres_i64(
                subject.lease.fencing_generation,
                "lease generation",
            )?)
            .bind(postgres_i64(
                subject.lease.installation_fencing_epoch,
                "installation epoch",
            )?)
            .bind(&request.runner_id)
            .bind(i32::try_from(request.job_attempt).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "job attempt",
                }
            })?)
            .bind(&request.step_id)
            .bind(request.runner_posture_digest.as_str())
            .bind(postgres_i64(request.now_unix_ms, "OIDC authorization")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if binding_changed == 0 {
                let exact: bool = sqlx::query_scalar(
                    "SELECT execution_lease_id=$2 AND fencing_generation=$3
                       AND installation_fencing_epoch=$4 AND runner_id=$5
                       AND job_attempt=$6 AND step_id=$7 AND runner_posture_digest=$8
                       AND state='authorized' FROM runner_oidc_grants WHERE grant_id=$1",
                )
                .bind(&grant_id)
                .bind(&subject.lease.id)
                .bind(postgres_i64(
                    subject.lease.fencing_generation,
                    "lease generation",
                )?)
                .bind(postgres_i64(
                    subject.lease.installation_fencing_epoch,
                    "installation epoch",
                )?)
                .bind(&request.runner_id)
                .bind(i32::try_from(request.job_attempt).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "job attempt",
                    }
                })?)
                .bind(&request.step_id)
                .bind(request.runner_posture_digest.as_str())
                .fetch_one(&mut *tx)
                .await?;
                if !exact {
                    return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                }
            }
            tx.commit().await?;
            Ok(grant)
        })
    }

    fn record_runner_oidc_token<'a>(
        &'a self,
        request: &'a RecordRunnerOidcIssuance,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            validate_postgres_oidc_issuance_request(request)?;
            let mut tx = self.pool.begin().await?;
            let grant_bytes: Vec<u8> = sqlx::query_scalar(
                "SELECT g.grant_json FROM oidc_grants g JOIN runner_oidc_grants r
                 ON r.grant_id=g.id WHERE g.id=$1 AND g.revoked_unix_ms IS NULL
                 AND r.state='authorized' FOR UPDATE OF g,r",
            )
            .bind(&request.grant_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
            let grant: OidcGrant = serde_json::from_slice(&grant_bytes)?;
            if grant.runner_posture_digest.as_ref() != Some(&request.runner_posture_digest)
                || !grant.allowed_audiences.contains(&request.audience)
                || grant.expires_unix_seconds.saturating_mul(1000) < request.expires_unix_ms
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let subject = postgres_runner_oidc_subject(
                &mut tx,
                &grant.execution_lease_id,
                &request.runner_id,
                grant.fencing_generation,
                &grant.job_id,
                request.job_attempt,
                &grant.step_id,
                &request.audience,
                &request.runner_posture_digest,
                request.issued_unix_ms,
            )
            .await?;
            if grant.grant_id
                != postgres_runner_oidc_grant_id(
                    &subject.lease,
                    request.job_attempt,
                    &grant.step_id,
                    &request.runner_posture_digest,
                )
                || request.expires_unix_ms > subject.lease.expires_unix_ms
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let inserted = sqlx::query(
                "INSERT INTO oidc_issuances
                 (grant_id,audience,jti,issued_unix_ms,expires_unix_ms)
                 VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            )
            .bind(&request.grant_id)
            .bind(&request.audience)
            .bind(&request.jti)
            .bind(postgres_i64(request.issued_unix_ms, "OIDC issuance")?)
            .bind(postgres_i64(request.expires_unix_ms, "OIDC expiry")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if inserted != 1 {
                return Err(ControlPlaneError::RunnerBrokerReplay);
            }
            sqlx::query(
                "INSERT INTO runner_oidc_issuances
                 (jti,grant_id,execution_lease_id,fencing_generation,
                  installation_fencing_epoch,runner_id,tenant_id,repository_id,run_id,
                  job_id,job_attempt,step_id,audience,runner_posture_digest,
                  issued_unix_ms,expires_unix_ms,state)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'issued')",
            )
            .bind(&request.jti)
            .bind(&grant.grant_id)
            .bind(&grant.execution_lease_id)
            .bind(postgres_i64(grant.fencing_generation, "lease generation")?)
            .bind(postgres_i64(
                subject.lease.installation_fencing_epoch,
                "installation epoch",
            )?)
            .bind(&request.runner_id)
            .bind(&grant.tenant_id)
            .bind(&grant.repository_id)
            .bind(&grant.run_id)
            .bind(&grant.job_id)
            .bind(i32::try_from(request.job_attempt).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "job attempt",
                }
            })?)
            .bind(&grant.step_id)
            .bind(&request.audience)
            .bind(request.runner_posture_digest.as_str())
            .bind(postgres_i64(request.issued_unix_ms, "OIDC issuance")?)
            .bind(postgres_i64(request.expires_unix_ms, "OIDC expiry")?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        })
    }

    fn append_runner_log_frames<'a>(
        &'a self,
        request: &'a AppendRunnerLogsRequest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            if request.frames.is_empty()
                || request.frames.len() > 256
                || request.fencing_generation == 0
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let mut tx = self.pool.begin().await?;
            let readiness = sqlx::query(
                "SELECT fencing_epoch,safe_mode FROM installation_state
                 WHERE singleton=TRUE FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await?;
            if readiness.try_get::<bool, _>("safe_mode")? {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let epoch = postgres_u64(readiness.try_get("fencing_epoch")?, "fencing_epoch")?;
            let lease = validate_postgres_lease_fence(
                &mut tx,
                &request.execution_lease_id,
                &request.runner_id,
                request.fencing_generation,
                epoch,
            )
            .await?;
            if lease.state != runtrue_scheduler::LeaseState::Active
                || now_unix_ms >= lease.expires_unix_ms
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            for frame in &request.frames {
                if frame.execution_lease_id != lease.id
                    || frame.fencing_generation != lease.fencing_generation
                    || frame.job_attempt == 0
                    || frame.payload.len() > 64 * 1024
                    || !matches!(frame.stream.as_str(), "stdout" | "stderr")
                {
                    return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                }
                let next: i64 = sqlx::query_scalar(
                    "SELECT COALESCE(MAX(sequence)+1,0) FROM runner_log_frames
                     WHERE execution_lease_id=$1 AND job_attempt=$2 AND step_id=$3 AND stream=$4",
                )
                .bind(&frame.execution_lease_id)
                .bind(i32::try_from(frame.job_attempt).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "job attempt",
                    }
                })?)
                .bind(&frame.step_id)
                .bind(&frame.stream)
                .fetch_one(&mut *tx)
                .await?;
                if postgres_u64(next, "runner log sequence")? != frame.sequence {
                    return Err(ControlPlaneError::RunnerBrokerReplay);
                }
                sqlx::query(
                    "INSERT INTO runner_log_frames
                     (execution_lease_id,fencing_generation,job_attempt,step_id,stream,
                      sequence,monotonic_nanoseconds,wall_time_unix_ms,payload,redaction_state)
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                )
                .bind(&frame.execution_lease_id)
                .bind(postgres_i64(frame.fencing_generation, "lease generation")?)
                .bind(i32::try_from(frame.job_attempt).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "job attempt",
                    }
                })?)
                .bind(&frame.step_id)
                .bind(&frame.stream)
                .bind(postgres_i64(frame.sequence, "runner log sequence")?)
                .bind(postgres_i64(
                    frame.monotonic_nanoseconds,
                    "runner log monotonic time",
                )?)
                .bind(postgres_i64(
                    frame.wall_time_unix_ms,
                    "runner log wall time",
                )?)
                .bind(&frame.payload)
                .bind(&frame.redaction_state)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(())
        })
    }

    fn record_runner_blob_transfer<'a>(
        &'a self,
        request: &'a RecordRunnerBlobUpload,
        runner_id: &'a str,
        direction: &'a str,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            if !matches!(direction, "upload" | "download")
                || (direction == "download" && request.ticket_kind != "cache")
                || !matches!(request.ticket_kind.as_str(), "cache" | "artifact")
                || request.fencing_generation == 0
                || request.job_attempt == 0
                || request.maximum_ticket_bytes == 0
                || request.size_bytes > request.maximum_ticket_bytes
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let mut tx = self.pool.begin().await?;
            let epoch: i64 = sqlx::query_scalar(
                "SELECT fencing_epoch FROM installation_state WHERE singleton=TRUE FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await?;
            let lease = validate_postgres_lease_fence(
                &mut tx,
                &request.execution_lease_id,
                runner_id,
                request.fencing_generation,
                postgres_u64(epoch, "fencing_epoch")?,
            )
            .await?;
            if lease.state != runtrue_scheduler::LeaseState::Active
                || request.recorded_unix_ms >= lease.expires_unix_ms
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let inserted = sqlx::query(
                "INSERT INTO runner_object_transfers
                 (ticket_id,object_digest,ticket_kind,direction,execution_lease_id,
                  fencing_generation,job_attempt,expected_size_bytes,transferred_size_bytes,
                  maximum_ticket_bytes,state,reserved_unix_ms,updated_unix_ms,verified_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,'verified',$10,$10,$10)
                 ON CONFLICT(ticket_id,object_digest,direction) DO NOTHING",
            )
            .bind(&request.ticket_id)
            .bind(request.blob_digest.as_str())
            .bind(&request.ticket_kind)
            .bind(direction)
            .bind(&request.execution_lease_id)
            .bind(postgres_i64(
                request.fencing_generation,
                "lease generation",
            )?)
            .bind(i32::try_from(request.job_attempt).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "job attempt",
                }
            })?)
            .bind(postgres_i64(request.size_bytes, "blob size")?)
            .bind(postgres_i64(
                request.maximum_ticket_bytes,
                "blob ticket maximum",
            )?)
            .bind(postgres_i64(
                request.recorded_unix_ms,
                "blob transfer time",
            )?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            let exact: bool = sqlx::query_scalar(
                "SELECT ticket_kind=$3 AND execution_lease_id=$4 AND fencing_generation=$5
                    AND job_attempt=$6 AND transferred_size_bytes=$7 AND maximum_ticket_bytes=$8
                 FROM runner_object_transfers
                 WHERE ticket_id=$1 AND object_digest=$2 AND direction=$9",
            )
            .bind(&request.ticket_id)
            .bind(request.blob_digest.as_str())
            .bind(&request.ticket_kind)
            .bind(&request.execution_lease_id)
            .bind(postgres_i64(
                request.fencing_generation,
                "lease generation",
            )?)
            .bind(i32::try_from(request.job_attempt).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "job attempt",
                }
            })?)
            .bind(postgres_i64(request.size_bytes, "blob size")?)
            .bind(postgres_i64(
                request.maximum_ticket_bytes,
                "blob ticket maximum",
            )?)
            .bind(direction)
            .fetch_one(&mut *tx)
            .await?;
            if !exact {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            if direction == "upload" && inserted == 1 {
                sqlx::query(
                    "INSERT INTO runner_blob_uploads
                     (ticket_id,blob_digest,ticket_kind,execution_lease_id,fencing_generation,
                      job_attempt,size_bytes,maximum_ticket_bytes,recorded_unix_ms)
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                )
                .bind(&request.ticket_id)
                .bind(request.blob_digest.as_str())
                .bind(&request.ticket_kind)
                .bind(&request.execution_lease_id)
                .bind(postgres_i64(
                    request.fencing_generation,
                    "lease generation",
                )?)
                .bind(i32::try_from(request.job_attempt).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "job attempt",
                    }
                })?)
                .bind(postgres_i64(request.size_bytes, "blob size")?)
                .bind(postgres_i64(
                    request.maximum_ticket_bytes,
                    "blob ticket maximum",
                )?)
                .bind(postgres_i64(
                    request.recorded_unix_ms,
                    "blob transfer time",
                )?)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(inserted == 0)
        })
    }

    fn record_runner_data_commit_journal<'a>(
        &'a self,
        request: &'a RunnerDataCommit,
        runner_id: &'a str,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            if request.job_attempt == 0
                || request.fencing_generation == 0
                || (request.kind == crate::RunnerDataCommitKind::Artifact
                    && request.output_name.is_none())
                || (request.kind == crate::RunnerDataCommitKind::Cache
                    && request.output_name.is_some())
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let mut tx = self.pool.begin().await?;
            let epoch: i64 = sqlx::query_scalar(
                "SELECT fencing_epoch FROM installation_state WHERE singleton=TRUE FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await?;
            let lease = validate_postgres_lease_fence(
                &mut tx,
                &request.lease_id,
                runner_id,
                request.fencing_generation,
                postgres_u64(epoch, "fencing_epoch")?,
            )
            .await?;
            if lease.state != runtrue_scheduler::LeaseState::Active
                || lease.job_id != request.job_id
                || lease.tenant_id != request.tenant_id
                || request.committed_unix_ms >= lease.expires_unix_ms
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let changed = sqlx::query(
                "INSERT INTO runner_data_commits
                 (kind,object_id,tenant_id,repository_id,run_id,job_id,job_attempt,
                  step_id,output_name,lease_id,fencing_generation,ticket_id,committed_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                 ON CONFLICT(ticket_id) DO NOTHING",
            )
            .bind(request.kind.as_str())
            .bind(&request.object_id)
            .bind(&request.tenant_id)
            .bind(&request.repository_id)
            .bind(&request.run_id)
            .bind(&request.job_id)
            .bind(i32::try_from(request.job_attempt).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "job attempt",
                }
            })?)
            .bind(&request.step_id)
            .bind(&request.output_name)
            .bind(&request.lease_id)
            .bind(postgres_i64(
                request.fencing_generation,
                "lease generation",
            )?)
            .bind(&request.ticket_id)
            .bind(postgres_i64(request.committed_unix_ms, "data commit time")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed == 0 {
                let exact: bool = sqlx::query_scalar(
                    "SELECT kind=$2 AND object_id=$3 AND tenant_id=$4 AND repository_id=$5
                     AND run_id=$6 AND job_id=$7 AND job_attempt=$8 AND step_id=$9
                     AND output_name IS NOT DISTINCT FROM $10 AND lease_id=$11
                     AND fencing_generation=$12 FROM runner_data_commits WHERE ticket_id=$1",
                )
                .bind(&request.ticket_id)
                .bind(request.kind.as_str())
                .bind(&request.object_id)
                .bind(&request.tenant_id)
                .bind(&request.repository_id)
                .bind(&request.run_id)
                .bind(&request.job_id)
                .bind(i32::try_from(request.job_attempt).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "job attempt",
                    }
                })?)
                .bind(&request.step_id)
                .bind(&request.output_name)
                .bind(&request.lease_id)
                .bind(postgres_i64(
                    request.fencing_generation,
                    "lease generation",
                )?)
                .fetch_one(&mut *tx)
                .await?;
                if !exact {
                    return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                }
            }
            tx.commit().await?;
            Ok(changed == 0)
        })
    }

    fn set_runner_scheduler_quota<'a>(
        &'a self,
        tenant_id: &'a str,
        maximum_running_jobs: u32,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            if tenant_id.is_empty() || maximum_running_jobs == 0 {
                return Err(ControlPlaneError::InvalidInput(
                    "scheduler quota must identify a tenant and permit at least one job",
                ));
            }
            sqlx::query(
                "INSERT INTO tenant_scheduler_quotas
                 (tenant_id,maximum_running_jobs,updated_unix_ms) VALUES($1,$2,$3)
                 ON CONFLICT(tenant_id) DO UPDATE SET
                   maximum_running_jobs=excluded.maximum_running_jobs,
                   updated_unix_ms=excluded.updated_unix_ms",
            )
            .bind(tenant_id)
            .bind(i32::try_from(maximum_running_jobs).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "scheduler quota",
                }
            })?)
            .bind(postgres_i64(now_unix_ms, "scheduler quota update")?)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn maintain_runner_scheduler(&self, now_unix_ms: u64) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            maintain_postgres_scheduler_tx(&mut tx, now_unix_ms).await?;
            tx.commit().await?;
            Ok(())
        })
    }

    fn offer_next_runner_lease<'a>(
        &'a self,
        runner_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, Option<Lease>> {
        Box::pin(async move {
            if runner_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput("runner id is empty"));
            }
            let mut tx = self.pool.begin().await?;
            maintain_postgres_scheduler_tx(&mut tx, now_unix_ms).await?;
            let readiness = sqlx::query(
                "SELECT fencing_epoch,safe_mode FROM installation_state
                 WHERE singleton=TRUE FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await?;
            if readiness.try_get::<bool, _>("safe_mode")? {
                return Err(ControlPlaneError::InstallationSafeMode);
            }
            let epoch = postgres_u64(readiness.try_get("fencing_epoch")?, "fencing_epoch")?;

            if let Some(id) = sqlx::query_scalar::<_, String>(
                "SELECT id FROM leases WHERE runner_id=$1
                 AND state='offered' AND accept_by_unix_ms>$2 AND expires_unix_ms>$2
                 ORDER BY issued_unix_ms,id LIMIT 1 FOR UPDATE",
            )
            .bind(runner_id)
            .bind(postgres_i64(now_unix_ms, "lease offer lookup")?)
            .fetch_optional(&mut *tx)
            .await?
            {
                let lease = postgres_lease_tx(&mut tx, &id).await?;
                tx.commit().await?;
                return Ok(Some(lease));
            }

            let runner_row = sqlx::query(
                "SELECT r.runner_json,r.status,p.tenant_id,p.status AS pool_status,p.region
                 FROM runners r JOIN runner_pools p ON p.id=r.pool_id WHERE r.id=$1 FOR UPDATE",
            )
            .bind(runner_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| ControlPlaneError::NotFound {
                kind: "runner",
                id: runner_id.to_owned(),
            })?;
            let mut runner: RunnerRecord = serde_json::from_slice(
                runner_row.try_get::<Vec<u8>, _>("runner_json")?.as_slice(),
            )?;
            let tenant_id: String = runner_row.try_get("tenant_id")?;
            let durable_status: String = runner_row.try_get("status")?;
            if runner.id != runner_id
                || runner.tenant_id != tenant_id
                || runner_status_name(runner.status) != durable_status
            {
                return Err(ControlPlaneError::CorruptState(
                    "runner registry fields do not match its authoritative pool".to_owned(),
                ));
            }
            if runner_row.try_get::<String, _>("pool_status")? != "active"
                || runner.status != runtrue_scheduler::RunnerStatus::Online
            {
                tx.commit().await?;
                return Ok(None);
            }
            let pool_region: Option<String> = runner_row.try_get("region")?;
            if pool_region
                .as_ref()
                .is_some_and(|region| runner.region.as_ref() != Some(region))
            {
                return Err(ControlPlaneError::RunnerInventoryMismatch);
            }
            if runner.ephemeral {
                let already_used: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM leases WHERE runner_id=$1)")
                        .bind(runner_id)
                        .fetch_one(&mut *tx)
                        .await?;
                if already_used {
                    tx.commit().await?;
                    return Ok(None);
                }
            }
            let posture_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM runner_enrollment_postures WHERE runner_id=$1)",
            )
            .bind(runner_id)
            .fetch_one(&mut *tx)
            .await?;
            if !posture_exists {
                return Err(ControlPlaneError::RunnerReenrollmentRequired);
            }

            let quota: i64 = sqlx::query_scalar(
                "SELECT COALESCE((SELECT maximum_running_jobs FROM tenant_scheduler_quotas
                 WHERE tenant_id=$1),1000)::BIGINT",
            )
            .bind(&tenant_id)
            .fetch_one(&mut *tx)
            .await?;
            let reserved: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM leases WHERE tenant_id=$1
                 AND state IN ('offered','active','cancel_requested')",
            )
            .bind(&tenant_id)
            .fetch_one(&mut *tx)
            .await?;
            if reserved >= quota {
                tx.commit().await?;
                return Ok(None);
            }

            let reserved_rows = sqlx::query(
                "SELECT j.requirements_json FROM leases l JOIN jobs j ON j.id=l.job_id
                 WHERE l.runner_id=$1 AND l.state IN ('offered','active','cancel_requested')",
            )
            .bind(runner_id)
            .fetch_all(&mut *tx)
            .await?;
            let mut reserved_cpus = 0_u32;
            let mut reserved_memory = 0_u64;
            let mut reserved_storage = 0_u64;
            let mut reserved_requirements = Vec::new();
            for row in reserved_rows {
                let requirements: runtrue_scheduler::SchedulingRequirements =
                    serde_json::from_slice(&row.try_get::<Vec<u8>, _>("requirements_json")?)?;
                reserved_cpus = reserved_cpus.saturating_add(requirements.cpu);
                reserved_memory = reserved_memory.saturating_add(requirements.memory_bytes);
                reserved_storage = reserved_storage.saturating_add(requirements.storage_bytes);
                reserved_requirements.push(requirements);
            }
            runner.used_cpus = runner.used_cpus.max(reserved_cpus);
            runner.used_memory_bytes = runner.used_memory_bytes.max(reserved_memory);
            runner.used_storage_bytes = runner.used_storage_bytes.max(reserved_storage);

            let rows = sqlx::query(
                "SELECT j.id,j.run_id,j.job_key,j.attempt,j.requirements_json,
                        j.concurrency_group,j.created_unix_ms,r.repository_id,r.priority,
                        r.capsule_id,c.digest,c.canonical_capsule
                 FROM jobs j JOIN runs r ON r.id=j.run_id
                 JOIN repositories repo ON repo.id=r.repository_id
                 JOIN capsules c ON c.id=r.capsule_id
                 WHERE j.status='queued' AND r.remote=TRUE
                   AND r.status IN ('created','running') AND repo.tenant_id=$1
                   AND (j.concurrency_group IS NULL OR NOT EXISTS(
                     SELECT 1 FROM jobs other JOIN runs other_run ON other_run.id=other.run_id
                     JOIN repositories other_repo ON other_repo.id=other_run.repository_id
                     WHERE other.id<>j.id AND other.concurrency_group=j.concurrency_group
                       AND other_repo.tenant_id=$1
                       AND other.status IN ('leased','preparing','running','finalizing')))
                 ORDER BY r.priority DESC,j.created_unix_ms,j.id
                 LIMIT 128 FOR UPDATE OF j SKIP LOCKED",
            )
            .bind(&tenant_id)
            .fetch_all(&mut *tx)
            .await?;

            for row in rows {
                let job_id: String = row.try_get("id")?;
                let requirements: runtrue_scheduler::SchedulingRequirements =
                    serde_json::from_slice(&row.try_get::<Vec<u8>, _>("requirements_json")?)?;
                let isolation_capacity_available = match requirements.isolation {
                    runtrue_workflow_ir::Isolation::Wasm => {
                        reserved_requirements.iter().all(|reserved| {
                            reserved.isolation == runtrue_workflow_ir::Isolation::Wasm
                        }) && reserved_requirements.len() < runner.max_concurrent_wasm_jobs as usize
                    }
                    runtrue_workflow_ir::Isolation::Oci
                    | runtrue_workflow_ir::Isolation::Microvm
                    | runtrue_workflow_ir::Isolation::Native => reserved_requirements.is_empty(),
                };
                if !isolation_capacity_available || !runner_serves(&runner, &requirements) {
                    continue;
                }
                let canonical: Vec<u8> = row.try_get("canonical_capsule")?;
                let capsule: runtrue_workflow_ir::ExecutionCapsule =
                    serde_json::from_slice(&canonical)?;
                let digest = capsule.digest()?;
                if capsule.canonical_bytes()? != canonical
                    || digest.as_str() != row.try_get::<String, _>("digest")?
                {
                    return Err(ControlPlaneError::NonCanonicalCapsule);
                }
                let job_key: String = row.try_get("job_key")?;
                let Some(planned) = postgres_materialized_planned_job(
                    &mut tx,
                    &row.try_get::<String, _>("run_id")?,
                    &job_key,
                    &capsule,
                    &digest,
                )
                .await?
                else {
                    continue;
                };
                if row.try_get::<i32, _>("attempt")? != 1
                    || postgres_planned_requirements(&planned) != requirements
                    || row.try_get::<Option<String>, _>("concurrency_group")? != planned.concurrency
                {
                    return Err(ControlPlaneError::CorruptState(
                        "queued job differs from its signed capsule".to_owned(),
                    ));
                }
                if !capsule.context.source_trust.satisfies(planned.trust) {
                    sqlx::query(
                        "UPDATE jobs SET status='blocked_policy',completed_unix_ms=$2
                         WHERE id=$1 AND status='queued'",
                    )
                    .bind(&job_id)
                    .bind(postgres_i64(now_unix_ms, "job completion")?)
                    .execute(&mut *tx)
                    .await?;
                    conclude_postgres_run_for_job(&mut tx, &job_id, now_unix_ms).await?;
                    continue;
                }
                if capsule.approval.workflow_definition || capsule.approval.privileged_execution {
                    match postgres_runner_approval_subject(
                        &mut tx,
                        &row.try_get::<String, _>("run_id")?,
                        &capsule,
                    )
                    .await
                    {
                        Ok(_) => {}
                        Err(ControlPlaneError::ApprovalRequired) => continue,
                        Err(error) => return Err(error),
                    }
                }
                if let Some(rejection) = sqlx::query(
                    "SELECT rejection_count,last_code,updated_unix_ms
                     FROM runner_job_rejections WHERE runner_id=$1 AND job_id=$2",
                )
                .bind(runner_id)
                .bind(&job_id)
                .fetch_optional(&mut *tx)
                .await?
                {
                    let rejection_count = postgres_u64(
                        rejection.try_get("rejection_count")?,
                        "runner job rejection count",
                    )?;
                    let rejection_code: String = rejection.try_get("last_code")?;
                    let rejection_time = postgres_u64(
                        rejection.try_get("updated_unix_ms")?,
                        "runner job rejection update",
                    )?;
                    if rejection_code == "image_admission_pending"
                        && now_unix_ms < rejection_time.saturating_add(1_000)
                    {
                        continue;
                    }
                    if rejection_code != "image_admission_pending"
                        && rejection_count >= MAX_POSTGRES_RUNNER_JOB_REJECTIONS
                    {
                        if all_postgres_eligible_runners_exhausted(
                            &mut tx,
                            &tenant_id,
                            &job_id,
                            &requirements,
                        )
                        .await?
                        {
                            sqlx::query(
                                "UPDATE jobs SET status='blocked_policy',completed_unix_ms=$2
                                 WHERE id=$1 AND status='queued'",
                            )
                            .bind(&job_id)
                            .bind(postgres_i64(now_unix_ms, "job completion")?)
                            .execute(&mut *tx)
                            .await?;
                            conclude_postgres_run_for_job(&mut tx, &job_id, now_unix_ms).await?;
                        }
                        continue;
                    }
                }
                if !postgres_deployment_gate_ready(
                    &mut tx,
                    &tenant_id,
                    &job_id,
                    1,
                    planned.environment.as_deref(),
                    epoch,
                    now_unix_ms,
                )
                .await?
                {
                    continue;
                }
                let hard_deadline = now_unix_ms
                    .checked_add(300_000)
                    .and_then(|value| value.checked_add(planned.timeout_ms))
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "lease hard deadline",
                    })?;
                let accept_by = now_unix_ms
                    .checked_add(runtrue_scheduler::DEFAULT_ACCEPT_WINDOW_MS)
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "lease accept deadline",
                    })?
                    .min(hard_deadline);
                let expires = now_unix_ms
                    .checked_add(runtrue_scheduler::DEFAULT_LEASE_DURATION_MS)
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "lease expiry",
                    })?
                    .min(hard_deadline);
                if accept_by <= now_unix_ms || expires <= accept_by {
                    continue;
                }
                sqlx::query(
                    "INSERT INTO job_fencing(job_id,last_generation) VALUES($1,0)
                     ON CONFLICT(job_id) DO NOTHING",
                )
                .bind(&job_id)
                .execute(&mut *tx)
                .await?;
                let generation: i64 = sqlx::query_scalar(
                    "UPDATE job_fencing SET last_generation=last_generation+1
                     WHERE job_id=$1 RETURNING last_generation",
                )
                .bind(&job_id)
                .fetch_one(&mut *tx)
                .await?;
                let lease_id = new_postgres_lease_id()?;
                sqlx::query(
                    "INSERT INTO leases
                     (id,job_id,tenant_id,runner_id,fencing_generation,
                      installation_fencing_epoch,capsule_digest,state,issued_unix_ms,
                      accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms)
                     VALUES($1,$2,$3,$4,$5,$6,$7,'offered',$8,$9,$10,$11)",
                )
                .bind(&lease_id)
                .bind(&job_id)
                .bind(&tenant_id)
                .bind(runner_id)
                .bind(generation)
                .bind(postgres_i64(epoch, "installation epoch")?)
                .bind(digest.as_str())
                .bind(postgres_i64(now_unix_ms, "lease issued")?)
                .bind(postgres_i64(accept_by, "lease accept deadline")?)
                .bind(postgres_i64(expires, "lease expiry")?)
                .bind(postgres_i64(hard_deadline, "lease hard deadline")?)
                .execute(&mut *tx)
                .await?;
                bind_postgres_deployment_gate(
                    &mut tx,
                    &tenant_id,
                    &job_id,
                    1,
                    &lease_id,
                    postgres_u64(generation, "lease generation")?,
                    epoch,
                    hard_deadline,
                    now_unix_ms,
                )
                .await?;
                let changed =
                    sqlx::query("UPDATE jobs SET status='leased' WHERE id=$1 AND status='queued'")
                        .bind(&job_id)
                        .execute(&mut *tx)
                        .await?
                        .rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                }
                sqlx::query(
                    "INSERT INTO runner_scheduler_cursors(runner_id,last_job_id,updated_unix_ms)
                     VALUES($1,$2,$3) ON CONFLICT(runner_id) DO UPDATE SET
                     last_job_id=excluded.last_job_id,updated_unix_ms=excluded.updated_unix_ms",
                )
                .bind(runner_id)
                .bind(&job_id)
                .bind(postgres_i64(now_unix_ms, "scheduler cursor")?)
                .execute(&mut *tx)
                .await?;
                let lease = postgres_lease_tx(&mut tx, &lease_id).await?;
                tx.commit().await?;
                return Ok(Some(lease));
            }
            tx.commit().await?;
            Ok(None)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_runner_lease<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        generation: u64,
        epoch: u64,
        result_digest: &'a ContentDigest,
        requested_job_state: JobState,
        credential_taint: CredentialTaintState,
        job_attempt: u32,
        artifact_ids: &'a [String],
        cache_entry_ids: &'a [String],
        required_artifact_names: &'a [String],
        completed_unix_ms: u64,
    ) -> StoreFuture<'a, Lease> {
        Box::pin(async move {
            if !requested_job_state.is_terminal() {
                return Err(ControlPlaneError::InvalidInput(
                    "lease completion requires a terminal job state",
                ));
            }
            let mut tx = self.pool.begin().await?;
            let lease =
                validate_postgres_lease_fence(&mut tx, lease_id, runner_id, generation, epoch)
                    .await?;
            let row = sqlx::query(
                "SELECT l.terminal_job_state,l.terminal_credential_taint,l.hard_deadline_unix_ms,
                        j.attempt,j.status AS job_status,r.cancel_reason
                 FROM leases l JOIN jobs j ON j.id=l.job_id JOIN runs r ON r.id=j.run_id
                 WHERE l.id=$1 FOR UPDATE OF l,j,r",
            )
            .bind(lease_id)
            .fetch_one(&mut *tx)
            .await?;
            let durable_attempt =
                u32::try_from(row.try_get::<i32, _>("attempt")?).map_err(|_| {
                    ControlPlaneError::CorruptState("negative PostgreSQL job attempt".to_owned())
                })?;
            if job_attempt != 0 && job_attempt != durable_attempt {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let effective_attempt = durable_attempt;
            let stored_taint: String = row.try_get("terminal_credential_taint")?;
            let effective_taint = monotonic_credential_taint(&stored_taint, credential_taint)?;
            if !effective_taint.permits_replay_or_checkpoint()
                && (!artifact_ids.is_empty() || !cache_entry_ids.is_empty())
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let final_job_state = if row.try_get::<Option<String>, _>("cancel_reason")?.is_some() {
                JobState::Canceled
            } else {
                requested_job_state
            };
            let current_job_state =
                parse_postgres_job_state(&row.try_get::<String, _>("job_status")?)?;

            let stored_objects =
                postgres_result_objects(&mut tx, &lease.job_id, effective_attempt).await?;
            if lease.state == runtrue_scheduler::LeaseState::Completed {
                let exact = lease.terminal_result_digest.as_ref() == Some(result_digest)
                    && row
                        .try_get::<Option<String>, _>("terminal_job_state")?
                        .as_deref()
                        == Some(postgres_job_state_name(final_job_state))
                    && stored_taint == effective_taint.as_str()
                    && stored_objects.0 == artifact_ids
                    && stored_objects.1 == cache_entry_ids;
                if exact {
                    tx.commit().await?;
                    return Ok(lease);
                }
                return Err(ControlPlaneError::ConflictingCompletion);
            }
            if !matches!(
                lease.state,
                runtrue_scheduler::LeaseState::Active
                    | runtrue_scheduler::LeaseState::CancelRequested
            ) {
                return Err(ControlPlaneError::InvalidLeaseState {
                    expected: "active or cancel_requested",
                    actual: lease_state_name(lease.state),
                });
            }
            if current_job_state != final_job_state
                && !current_job_state.can_transition_to(final_job_state)
            {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "job",
                    from: postgres_job_state_name(current_job_state),
                    to: postgres_job_state_name(final_job_state),
                });
            }
            let hard_deadline =
                postgres_u64(row.try_get("hard_deadline_unix_ms")?, "lease hard deadline")?;
            if completed_unix_ms >= hard_deadline || completed_unix_ms >= lease.expires_unix_ms {
                let expired_state = if final_job_state == JobState::Canceled {
                    JobState::Canceled
                } else if completed_unix_ms >= hard_deadline {
                    JobState::TimedOut
                } else {
                    JobState::Lost
                };
                expire_postgres_lease_with_job(&mut tx, &lease, expired_state, completed_unix_ms)
                    .await?;
                conclude_postgres_run_for_job(&mut tx, &lease.job_id, completed_unix_ms).await?;
                tx.commit().await?;
                return Err(ControlPlaneError::LeaseExpired);
            }
            if (!artifact_ids.is_empty()
                || !cache_entry_ids.is_empty()
                || !required_artifact_names.is_empty())
                && job_attempt == 0
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            if !stored_objects.0.is_empty() || !stored_objects.1.is_empty() {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let mut artifact_names = BTreeSet::new();
            for (kind, ids) in [("artifact", artifact_ids), ("cache", cache_entry_ids)] {
                let mut seen = BTreeSet::new();
                for (ordinal, object_id) in ids.iter().enumerate() {
                    if object_id.is_empty() || !seen.insert(object_id) {
                        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                    }
                    let output_name: Option<String> = sqlx::query_scalar(
                        "SELECT output_name FROM runner_data_commits
                         WHERE kind=$1 AND object_id=$2 AND tenant_id=$3 AND job_id=$4
                           AND run_id=(SELECT run_id FROM jobs WHERE id=$4)
                           AND repository_id=(SELECT r.repository_id FROM runs r
                             JOIN jobs j ON j.run_id=r.id WHERE j.id=$4)
                           AND job_attempt=$5 AND lease_id=$6 AND fencing_generation=$7",
                    )
                    .bind(kind)
                    .bind(object_id)
                    .bind(&lease.tenant_id)
                    .bind(&lease.job_id)
                    .bind(i32::try_from(effective_attempt).map_err(|_| {
                        ControlPlaneError::IntegerRange {
                            field: "job attempt",
                        }
                    })?)
                    .bind(lease_id)
                    .bind(postgres_i64(generation, "lease generation")?)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
                    if kind == "artifact"
                        && !artifact_names.insert(
                            output_name.ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?,
                        )
                    {
                        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                    }
                    sqlx::query(
                        "INSERT INTO job_result_objects
                         (job_id,job_attempt,kind,object_id,ordinal) VALUES($1,$2,$3,$4,$5)",
                    )
                    .bind(&lease.job_id)
                    .bind(i32::try_from(effective_attempt).map_err(|_| {
                        ControlPlaneError::IntegerRange {
                            field: "job attempt",
                        }
                    })?)
                    .bind(kind)
                    .bind(object_id)
                    .bind(
                        i64::try_from(ordinal).map_err(|_| ControlPlaneError::IntegerRange {
                            field: "completion object ordinal",
                        })?,
                    )
                    .execute(&mut *tx)
                    .await?;
                }
            }
            let required: BTreeSet<_> = required_artifact_names.iter().cloned().collect();
            if final_job_state == JobState::Succeeded && artifact_names != required {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            sqlx::query(
                "UPDATE leases SET state='completed',terminal_result_digest=$2,
                 terminal_job_state=$3,terminal_credential_taint=$4,completed_unix_ms=$5
                 WHERE id=$1",
            )
            .bind(lease_id)
            .bind(result_digest.as_str())
            .bind(postgres_job_state_name(final_job_state))
            .bind(effective_taint.as_str())
            .bind(postgres_i64(completed_unix_ms, "lease completion")?)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE jobs SET status=$2,completed_unix_ms=$3 WHERE id=$1")
                .bind(&lease.job_id)
                .bind(postgres_job_state_name(final_job_state))
                .bind(postgres_i64(completed_unix_ms, "job completion")?)
                .execute(&mut *tx)
                .await?;
            revoke_postgres_brokers(&mut tx, &lease, completed_unix_ms, "revoked").await?;
            if !effective_taint.permits_replay_or_checkpoint() {
                sqlx::query(
                    "DELETE FROM runner_log_frames
                     WHERE execution_lease_id=$1
                       AND redaction_state <> 'credential_taint_unredacted_operator_opt_in'",
                )
                .bind(lease_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query("DELETE FROM job_result_objects WHERE job_id=$1")
                    .bind(&lease.job_id)
                    .execute(&mut *tx)
                    .await?;
            }
            conclude_postgres_run_for_job(&mut tx, &lease.job_id, completed_unix_ms).await?;
            let completed = postgres_lease_tx(&mut tx, lease_id).await?;
            tx.commit().await?;
            Ok(completed)
        })
    }

    fn runner_run_credential_taint<'a>(
        &'a self,
        run_id: &'a str,
    ) -> StoreFuture<'a, CredentialTaintState> {
        Box::pin(async move {
            if run_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput("run id is empty"));
            }
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runs WHERE id=$1)")
                .bind(run_id)
                .fetch_one(&self.pool)
                .await?;
            if !exists {
                return Err(ControlPlaneError::NotFound {
                    kind: "run",
                    id: run_id.to_owned(),
                });
            }
            let values = sqlx::query_scalar::<_, String>(
                "SELECT l.terminal_credential_taint FROM leases l
                 JOIN jobs j ON j.id=l.job_id WHERE j.run_id=$1",
            )
            .bind(run_id)
            .fetch_all(&self.pool)
            .await?;
            let mut aggregate = CredentialTaintState::None;
            if values.is_empty() {
                return Ok(CredentialTaintState::Unknown);
            }
            for value in values {
                if value == "unobserved" {
                    aggregate = CredentialTaintState::Unknown;
                    continue;
                }
                match CredentialTaintState::parse(&value).map_err(|_| {
                    ControlPlaneError::CorruptState(
                        "invalid terminal credential taint state".to_owned(),
                    )
                })? {
                    CredentialTaintState::CredentialReleased => {
                        return Ok(CredentialTaintState::CredentialReleased)
                    }
                    CredentialTaintState::Unknown => aggregate = CredentialTaintState::Unknown,
                    CredentialTaintState::None => {}
                }
            }
            Ok(aggregate)
        })
    }

    fn validate_runner_completion_artifact_claims<'a>(
        &'a self,
        lease_id: &'a str,
        runner_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        job_attempt: u32,
        claims: &'a [(String, String)],
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            if validate_runner_text(lease_id).is_err()
                || validate_runner_text(runner_id).is_err()
                || fencing_generation == 0
                || installation_fencing_epoch == 0
                || claims.len() > 128
                || (!claims.is_empty() && job_attempt == 0)
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let mut object_ids = BTreeSet::new();
            let mut declaration_names = BTreeSet::new();
            for (object_id, declaration_name) in claims {
                if validate_runner_text(object_id).is_err()
                    || validate_runner_text(declaration_name).is_err()
                    || !object_ids.insert(object_id.as_str())
                    || !declaration_names.insert(declaration_name.as_str())
                {
                    return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                }
            }
            let fence = postgres_i64(fencing_generation, "lease generation")
                .map_err(|_| ControlPlaneError::RunnerBrokerBindingMismatch)?;
            let epoch = postgres_i64(installation_fencing_epoch, "installation epoch")
                .map_err(|_| ControlPlaneError::RunnerBrokerBindingMismatch)?;
            let mut tx = self.pool.begin().await?;
            let scope = sqlx::query(
                "SELECT l.tenant_id,j.run_id,r.repository_id,l.job_id,j.attempt,l.state
                 FROM leases l JOIN jobs j ON j.id=l.job_id
                 JOIN runs r ON r.id=j.run_id
                 JOIN repositories repo ON repo.id=r.repository_id
                 JOIN job_fencing f ON f.job_id=j.id
                 CROSS JOIN installation_state i
                 WHERE l.id=$1 AND l.runner_id=$2 AND l.fencing_generation=$3
                   AND l.installation_fencing_epoch=$4 AND f.last_generation=$3
                   AND i.singleton=TRUE AND i.fencing_epoch=$4 AND i.safe_mode=FALSE
                   AND repo.tenant_id=l.tenant_id
                   AND l.state IN('active','cancel_requested','completed')
                 FOR SHARE OF l,j,r,repo,f,i",
            )
            .bind(lease_id)
            .bind(runner_id)
            .bind(fence)
            .bind(epoch)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
            let tenant_id: String = scope.try_get("tenant_id")?;
            let run_id: String = scope.try_get("run_id")?;
            let repository_id: String = scope.try_get("repository_id")?;
            let job_id: String = scope.try_get("job_id")?;
            let durable_attempt: i32 = scope.try_get("attempt")?;
            let lease_state: String = scope.try_get("state")?;
            if (job_attempt != 0 && i32::try_from(job_attempt).ok() != Some(durable_attempt))
                || (!claims.is_empty() && i32::try_from(job_attempt).ok() != Some(durable_attempt))
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            for (object_id, declaration_name) in claims {
                let exact: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM runner_data_commits c
                     WHERE c.kind='artifact' AND c.object_id=$1 AND c.output_name=$2
                       AND c.tenant_id=$3 AND c.repository_id=$4 AND c.run_id=$5
                       AND c.job_id=$6 AND c.job_attempt=$7 AND c.lease_id=$8
                       AND c.fencing_generation=$9)",
                )
                .bind(object_id)
                .bind(declaration_name)
                .bind(&tenant_id)
                .bind(&repository_id)
                .bind(&run_id)
                .bind(&job_id)
                .bind(durable_attempt)
                .bind(lease_id)
                .bind(fence)
                .fetch_one(&mut *tx)
                .await?;
                if !exact {
                    return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                }
            }
            if lease_state == "completed" {
                let rows = sqlx::query(
                    "SELECT o.object_id,c.output_name FROM job_result_objects o
                     JOIN runner_data_commits c ON c.kind=o.kind AND c.object_id=o.object_id
                     WHERE o.job_id=$1 AND o.job_attempt=$2 AND o.kind='artifact'
                       AND c.tenant_id=$3 AND c.repository_id=$4 AND c.run_id=$5
                       AND c.job_id=$1 AND c.job_attempt=$2 AND c.lease_id=$6
                       AND c.fencing_generation=$7 ORDER BY o.ordinal",
                )
                .bind(&job_id)
                .bind(durable_attempt)
                .bind(&tenant_id)
                .bind(&repository_id)
                .bind(&run_id)
                .bind(lease_id)
                .bind(fence)
                .fetch_all(&mut *tx)
                .await?;
                if rows.len() != claims.len()
                    || rows.iter().zip(claims).any(|(row, claim)| {
                        row.try_get::<String, _>("object_id").ok().as_ref() != Some(&claim.0)
                            || row
                                .try_get::<Option<String>, _>("output_name")
                                .ok()
                                .flatten()
                                .as_deref()
                                != Some(claim.1.as_str())
                    })
                {
                    return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                }
            }
            tx.commit().await?;
            Ok(())
        })
    }

    fn runner_logs_for_run<'a>(
        &'a self,
        run_id: &'a str,
        maximum_frames: usize,
    ) -> StoreFuture<'a, Vec<RunnerLogFrameRecord>> {
        Box::pin(async move {
            if run_id.is_empty() || maximum_frames == 0 || maximum_frames > 10_000 {
                return Err(ControlPlaneError::InvalidInput(
                    "runner log query requires a run id and a limit between 1 and 10000",
                ));
            }
            let rows = sqlx::query(
                "SELECT f.* FROM runner_log_frames f
                 JOIN leases l ON l.id=f.execution_lease_id
                 JOIN jobs j ON j.id=l.job_id
                 WHERE j.run_id=$1 AND l.state='completed'
                   AND (l.terminal_credential_taint='none'
                        OR f.redaction_state='credential_taint_unredacted_operator_opt_in')
                 ORDER BY f.wall_time_unix_ms,f.execution_lease_id,f.job_attempt,
                          f.step_id,f.stream,f.sequence LIMIT $2",
            )
            .bind(run_id)
            .bind(
                i64::try_from(maximum_frames).map_err(|_| ControlPlaneError::IntegerRange {
                    field: "runner log query limit",
                })?,
            )
            .fetch_all(&self.pool)
            .await?;
            rows.into_iter()
                .map(|row| {
                    Ok(RunnerLogFrameRecord {
                        execution_lease_id: row.try_get("execution_lease_id")?,
                        fencing_generation: postgres_u64(
                            row.try_get("fencing_generation")?,
                            "runner log fencing generation",
                        )?,
                        job_attempt: u32::try_from(row.try_get::<i32, _>("job_attempt")?).map_err(
                            |_| ControlPlaneError::IntegerRange {
                                field: "runner log job attempt",
                            },
                        )?,
                        step_id: row.try_get("step_id")?,
                        stream: row.try_get("stream")?,
                        sequence: postgres_u64(row.try_get("sequence")?, "runner log sequence")?,
                        monotonic_nanoseconds: postgres_u64(
                            row.try_get("monotonic_nanoseconds")?,
                            "runner log monotonic timestamp",
                        )?,
                        wall_time_unix_ms: postgres_u64(
                            row.try_get("wall_time_unix_ms")?,
                            "runner log wall timestamp",
                        )?,
                        payload: row.try_get("payload")?,
                        redaction_state: row.try_get("redaction_state")?,
                    })
                })
                .collect()
        })
    }
}

#[cfg(feature = "postgres")]
struct PostgresRunnerOidcSubject {
    lease: Lease,
    repository_id: String,
    run_id: String,
    runner_pool_id: String,
    trust: String,
    environment: Option<String>,
    ref_name: Option<String>,
    source_commit: String,
    approval_subject_digest: ContentDigest,
    allowed_audiences: BTreeSet<String>,
}

#[cfg(feature = "postgres")]
struct PostgresRunnerSecretSubject {
    lease: Lease,
    repository_id: String,
    run_id: String,
    tenant_id: String,
    capsule_id: String,
    capsule: runtrue_workflow_ir::ExecutionCapsule,
    planned_job: runtrue_workflow_ir::PlannedJob,
}

#[cfg(feature = "postgres")]
fn validate_runner_text(value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty() || value.len() > 4_096 || value.contains('\0') {
        Err(ControlPlaneError::InvalidInput(
            "empty, oversized, or NUL text",
        ))
    } else {
        Ok(())
    }
}

#[cfg(feature = "postgres")]
fn validate_postgres_runner_secret_request(
    request: &IssueRunnerSecretRequest,
) -> Result<(), ControlPlaneError> {
    for value in [
        &request.execution_lease_id,
        &request.runner_id,
        &request.job_id,
        &request.step_id,
        &request.secret_metadata_id,
    ] {
        validate_runner_text(value)?;
    }
    if request.purpose.len() > 4_096
        || request.purpose.contains('\0')
        || request.fencing_generation == 0
        || request.job_attempt == 0
        || request.expires_unix_ms <= request.issued_unix_ms
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn postgres_runner_secret_subject(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &IssueRunnerSecretRequest,
) -> Result<PostgresRunnerSecretSubject, ControlPlaneError> {
    let row = sqlx::query(
        "SELECT j.run_id,j.job_key,r.repository_id,r.capsule_id,repo.tenant_id,
                c.digest,c.canonical_capsule,rr.runner_json,rr.pool_id,
                p.inventory_digest,p.posture_digest
         FROM leases l JOIN jobs j ON j.id=l.job_id
         JOIN job_fencing f ON f.job_id=j.id
         JOIN runs r ON r.id=j.run_id
         JOIN repositories repo ON repo.id=r.repository_id
         JOIN capsules c ON c.id=r.capsule_id
         JOIN runners rr ON rr.id=l.runner_id
         JOIN runner_enrollment_postures p ON p.runner_id=rr.id
         CROSS JOIN installation_state i
         WHERE l.id=$1 AND l.runner_id=$2 AND l.fencing_generation=$3
           AND l.job_id=$4 AND f.last_generation=$3
           AND l.installation_fencing_epoch=i.fencing_epoch
           AND i.singleton=TRUE AND i.safe_mode=FALSE
           AND l.state='active' AND l.issued_unix_ms<=$5
           AND l.expires_unix_ms>$5 AND l.hard_deadline_unix_ms>$5
           AND repo.tenant_id=l.tenant_id
         FOR UPDATE OF l,j,f,r,rr,p",
    )
    .bind(&request.execution_lease_id)
    .bind(&request.runner_id)
    .bind(postgres_i64(
        request.fencing_generation,
        "lease generation",
    )?)
    .bind(&request.job_id)
    .bind(postgres_i64(request.issued_unix_ms, "secret issue")?)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
    let lease = postgres_lease_tx(tx, &request.execution_lease_id).await?;
    if request.expires_unix_ms > lease.expires_unix_ms {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    let runner: RunnerRecord = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("runner_json")?)?;
    let inventory = ContentDigest::parse(row.try_get::<String, _>("inventory_digest")?)?;
    let posture = authoritative_runner_posture_digest(&runner, &inventory)?;
    if posture != request.runner_posture_digest
        || row.try_get::<String, _>("posture_digest")? != posture.as_str()
        || row.try_get::<String, _>("pool_id")? != runner.pool_id
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    let canonical: Vec<u8> = row.try_get("canonical_capsule")?;
    let capsule: runtrue_workflow_ir::ExecutionCapsule = serde_json::from_slice(&canonical)?;
    let digest = capsule.digest()?;
    if capsule.canonical_bytes()? != canonical
        || digest.as_str() != row.try_get::<String, _>("digest")?
        || digest != lease.capsule_digest
        || row.try_get::<String, _>("tenant_id")? != lease.tenant_id
    {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let run_id: String = row.try_get("run_id")?;
    let job_key: String = row.try_get("job_key")?;
    let planned_job = postgres_materialized_planned_job(tx, &run_id, &job_key, &capsule, &digest)
        .await?
        .ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
    Ok(PostgresRunnerSecretSubject {
        lease,
        repository_id: row.try_get("repository_id")?,
        run_id,
        tenant_id: row.try_get("tenant_id")?,
        capsule_id: row.try_get("capsule_id")?,
        capsule,
        planned_job,
    })
}

#[cfg(feature = "postgres")]
pub(super) async fn validate_postgres_oidc_grant_subject(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    grant: &OidcGrant,
) -> Result<(), ControlPlaneError> {
    let posture = grant
        .runner_posture_digest
        .as_ref()
        .ok_or(ControlPlaneError::StaleOidcGrant)?;
    let audience = grant
        .allowed_audiences
        .iter()
        .next()
        .ok_or(ControlPlaneError::StaleOidcGrant)?;
    let row = sqlx::query(
        "SELECT l.runner_id,l.installation_fencing_epoch,l.issued_unix_ms,j.attempt
         FROM leases l JOIN jobs j ON j.id=l.job_id WHERE l.id=$1",
    )
    .bind(&grant.execution_lease_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(ControlPlaneError::StaleOidcGrant)?;
    let runner_id: String = row.try_get("runner_id")?;
    let attempt = u32::try_from(row.try_get::<i32, _>("attempt")?)
        .map_err(|_| ControlPlaneError::StaleOidcGrant)?;
    let issued = postgres_u64(row.try_get("issued_unix_ms")?, "lease issue")?;
    let subject = postgres_runner_oidc_subject(
        tx,
        &grant.execution_lease_id,
        &runner_id,
        grant.fencing_generation,
        &grant.job_id,
        attempt,
        &grant.step_id,
        audience,
        posture,
        issued,
    )
    .await
    .map_err(|_| ControlPlaneError::StaleOidcGrant)?;
    if subject.lease.tenant_id != grant.tenant_id
        || subject.repository_id != grant.repository_id
        || subject.run_id != grant.run_id
        || subject.lease.job_id != grant.job_id
        || subject.lease.capsule_digest != grant.capsule_digest
        || subject.trust != grant.trust
        || grant.runner_pool_id.as_deref() != Some(subject.runner_pool_id.as_str())
        || subject.environment != grant.environment
        || subject.ref_name != grant.ref_name
        || subject.source_commit != grant.source_commit
        || grant.approval_subject_digest.as_ref() != Some(&subject.approval_subject_digest)
        || grant.allowed_audiences != subject.allowed_audiences
        || grant.expires_unix_seconds != subject.lease.expires_unix_ms / 1000
    {
        return Err(ControlPlaneError::StaleOidcGrant);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_postgres_oidc_authorization_request(
    request: &AuthorizeRunnerOidcRequest,
) -> Result<(), ControlPlaneError> {
    if request.execution_lease_id.is_empty()
        || request.runner_id.is_empty()
        || request.job_id.is_empty()
        || request.step_id.is_empty()
        || request.audience.is_empty()
        || request.fencing_generation == 0
        || request.job_attempt == 0
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_postgres_oidc_issuance_request(
    request: &RecordRunnerOidcIssuance,
) -> Result<(), ControlPlaneError> {
    if request.grant_id.is_empty()
        || request.audience.is_empty()
        || request.jti.is_empty()
        || request.runner_id.is_empty()
        || request.job_attempt == 0
        || request.expires_unix_ms <= request.issued_unix_ms
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn postgres_runner_oidc_grant_id(
    lease: &Lease,
    job_attempt: u32,
    step_id: &str,
    posture_digest: &ContentDigest,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"runtrue.runner.oidc-grant.v1\0");
    for value in [
        lease.id.as_bytes(),
        lease.fencing_generation.to_be_bytes().as_slice(),
        lease.job_id.as_bytes(),
        job_attempt.to_be_bytes().as_slice(),
        step_id.as_bytes(),
        posture_digest.as_str().as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("runner-grant-{}", hex::encode(hasher.finalize()))
}

#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
async fn postgres_runner_oidc_subject(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease_id: &str,
    runner_id: &str,
    generation: u64,
    job_id: &str,
    job_attempt: u32,
    step_id: &str,
    audience: &str,
    posture_digest: &ContentDigest,
    now_unix_ms: u64,
) -> Result<PostgresRunnerOidcSubject, ControlPlaneError> {
    let epoch: i64 =
        sqlx::query_scalar("SELECT fencing_epoch FROM installation_state WHERE singleton=TRUE")
            .fetch_one(&mut **tx)
            .await?;
    let lease = validate_postgres_lease_fence(
        tx,
        lease_id,
        runner_id,
        generation,
        postgres_u64(epoch, "installation epoch")?,
    )
    .await?;
    let hard_deadline: i64 =
        sqlx::query_scalar("SELECT hard_deadline_unix_ms FROM leases WHERE id=$1")
            .bind(lease_id)
            .fetch_one(&mut **tx)
            .await?;
    if lease.job_id != job_id
        || lease.state != runtrue_scheduler::LeaseState::Active
        || now_unix_ms < lease.issued_unix_ms
        || now_unix_ms >= lease.expires_unix_ms
        || now_unix_ms >= postgres_u64(hard_deadline, "lease hard deadline")?
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    let row = sqlx::query(
        "SELECT j.run_id,j.job_key,j.attempt,r.repository_id,r.capsule_id,
                repo.tenant_id,c.digest,c.canonical_capsule,rr.runner_json,
                rr.pool_id,p.inventory_digest,p.posture_digest
         FROM jobs j JOIN runs r ON r.id=j.run_id
         JOIN repositories repo ON repo.id=r.repository_id
         JOIN capsules c ON c.id=r.capsule_id
         JOIN runners rr ON rr.id=$2
         JOIN runner_enrollment_postures p ON p.runner_id=rr.id
         WHERE j.id=$1 FOR UPDATE OF j,r,rr,p",
    )
    .bind(job_id)
    .bind(runner_id)
    .fetch_one(&mut **tx)
    .await?;
    let durable_attempt = u32::try_from(row.try_get::<i32, _>("attempt")?).map_err(|_| {
        ControlPlaneError::CorruptState("negative PostgreSQL job attempt".to_owned())
    })?;
    if durable_attempt != job_attempt || row.try_get::<String, _>("tenant_id")? != lease.tenant_id {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    let runner: RunnerRecord = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("runner_json")?)?;
    let inventory = ContentDigest::parse(row.try_get::<String, _>("inventory_digest")?)?;
    let authoritative = authoritative_runner_posture_digest(&runner, &inventory)?;
    if authoritative != *posture_digest
        || row.try_get::<String, _>("posture_digest")? != posture_digest.as_str()
        || row.try_get::<String, _>("pool_id")? != runner.pool_id
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    let canonical: Vec<u8> = row.try_get("canonical_capsule")?;
    let capsule: runtrue_workflow_ir::ExecutionCapsule = serde_json::from_slice(&canonical)?;
    let digest = capsule.digest()?;
    if capsule.canonical_bytes()? != canonical
        || digest.as_str() != row.try_get::<String, _>("digest")?
        || digest != lease.capsule_digest
    {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let run_id: String = row.try_get("run_id")?;
    let job_key: String = row.try_get("job_key")?;
    let planned = postgres_materialized_planned_job(tx, &run_id, &job_key, &capsule, &digest)
        .await?
        .ok_or(ControlPlaneError::RunnerBrokerCapabilityDenied)?;
    if job_attempt > planned.retries.saturating_add(1) {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    let step = planned
        .steps
        .iter()
        .find(|step| step.id == step_id)
        .ok_or(ControlPlaneError::RunnerBrokerCapabilityDenied)?;
    if !step
        .capabilities
        .oidc_audiences
        .iter()
        .any(|declared| declared == audience)
    {
        return Err(ControlPlaneError::RunnerBrokerCapabilityDenied);
    }
    let approval_subject_digest = postgres_runner_approval_subject(tx, &run_id, &capsule).await?;
    let ref_name = match capsule.context.event_context.get("event.ref") {
        Some(runtrue_workflow_ir::ScalarValue::String(value)) => Some(value.clone()),
        Some(_) => return Err(ControlPlaneError::RunnerBrokerBindingMismatch),
        None => None,
    };
    let trust = match serde_json::to_value(capsule.context.source_trust)? {
        serde_json::Value::String(value) => value,
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "capsule trust is not a string".to_owned(),
            ))
        }
    };
    Ok(PostgresRunnerOidcSubject {
        lease,
        repository_id: row.try_get("repository_id")?,
        run_id,
        runner_pool_id: runner.pool_id,
        trust,
        environment: planned.environment,
        ref_name,
        source_commit: capsule.context.source_commit,
        approval_subject_digest,
        allowed_audiences: step.capabilities.oidc_audiences.iter().cloned().collect(),
    })
}

#[cfg(feature = "postgres")]
async fn postgres_runner_approval_subject(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    run_id: &str,
    capsule: &runtrue_workflow_ir::ExecutionCapsule,
) -> Result<ContentDigest, ControlPlaneError> {
    let mut digest = None;
    for (required, kind) in [
        (capsule.approval.workflow_definition, "workflow-definition"),
        (
            capsule.approval.privileged_execution,
            "privileged-execution",
        ),
    ] {
        if !required {
            continue;
        }
        let encoded: Option<String> = sqlx::query_scalar(
            "SELECT subject_digest FROM run_approval_authorizations
             WHERE run_id=$1 AND kind=$2",
        )
        .bind(run_id)
        .bind(kind)
        .fetch_optional(&mut **tx)
        .await?;
        let value = encoded
            .map(ContentDigest::parse)
            .transpose()?
            .ok_or(ControlPlaneError::ApprovalRequired)?;
        if digest.as_ref().is_some_and(|existing| existing != &value) {
            return Err(ControlPlaneError::ApprovalRequired);
        }
        digest = Some(value);
    }
    digest.ok_or(ControlPlaneError::ApprovalRequired)
}

#[cfg(feature = "postgres")]
pub(super) async fn postgres_materialized_planned_job(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    run_id: &str,
    job_key: &str,
    capsule: &runtrue_workflow_ir::ExecutionCapsule,
    capsule_digest: &ContentDigest,
) -> Result<Option<runtrue_workflow_ir::PlannedJob>, ControlPlaneError> {
    if let Some(job) = capsule.jobs.iter().find(|job| job.id == job_key) {
        return Ok(Some(job.clone()));
    }
    let rows = sqlx::query(
        "SELECT template_id,parent_capsule_digest,canonical_job_set,job_set_digest,
                generated_job_count FROM expanded_job_sets WHERE run_id=$1 ORDER BY template_id",
    )
    .bind(run_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut found = None;
    for row in rows {
        let canonical: Vec<u8> = row.try_get("canonical_job_set")?;
        let expanded: runtrue_workflow_ir::ExpandedJobSet = serde_json::from_slice(&canonical)?;
        if expanded.canonical_bytes()? != canonical
            || expanded.parent_capsule_digest != *capsule_digest
            || row.try_get::<String, _>("parent_capsule_digest")? != capsule_digest.as_str()
            || ContentDigest::sha256(&canonical).as_str()
                != row.try_get::<String, _>("job_set_digest")?
            || usize::try_from(row.try_get::<i32, _>("generated_job_count")?).ok()
                != Some(expanded.jobs.len())
            || expanded.generated_job_ids
                != expanded
                    .jobs
                    .iter()
                    .map(|job| job.id.clone())
                    .collect::<Vec<_>>()
        {
            return Err(ControlPlaneError::CorruptState(
                "expanded job set no longer matches its signed parent".to_owned(),
            ));
        }
        let template_id: String = row.try_get("template_id")?;
        let template = capsule
            .dynamic_jobs
            .iter()
            .find(|template| template.id == template_id)
            .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "expanded job template is absent from its parent".to_owned(),
                )
            })?;
        for job in expanded.jobs {
            let mut normalized = job.clone();
            normalized.id = template.template.id.clone();
            normalized.matrix.clear();
            if normalized != template.template {
                return Err(ControlPlaneError::CorruptState(
                    "expanded job changed its signed template".to_owned(),
                ));
            }
            if job.id == job_key && found.replace(job).is_some() {
                return Err(ControlPlaneError::CorruptState(
                    "expanded job identifier is duplicated".to_owned(),
                ));
            }
        }
    }
    Ok(found)
}

#[cfg(feature = "postgres")]
async fn postgres_deployment_gate_ready(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    job_id: &str,
    job_attempt: u32,
    signed_environment: Option<&str>,
    epoch: u64,
    now_unix_ms: u64,
) -> Result<bool, ControlPlaneError> {
    let request = sqlx::query(
        "SELECT id,environment_id,environment_version,policy_epoch,status,
                concurrency_fence,execution_lease_id,installation_fencing_epoch,
                approval_subject_digest,approval_request_id
         FROM deployment_requests WHERE tenant_id=$1 AND job_id=$2 AND job_attempt=$3
         FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(job_id)
    .bind(i64::from(job_attempt))
    .fetch_optional(&mut **tx)
    .await?;
    let Some(environment_name) = signed_environment else {
        if request.is_some() {
            return Err(ControlPlaneError::CorruptState(
                "deployment request targets a job without a signed environment".to_owned(),
            ));
        }
        return Ok(true);
    };
    let Some(request) = request else {
        return Ok(false);
    };
    if request.try_get::<String, _>("status")? != "ready"
        || request
            .try_get::<Option<String>, _>("execution_lease_id")?
            .is_some()
        || request.try_get::<Option<i64>, _>("installation_fencing_epoch")?
            != Some(postgres_i64(epoch, "installation epoch")?)
    {
        return Ok(false);
    }
    let environment_id: String = request.try_get("environment_id")?;
    let environment = sqlx::query(
        "SELECT name,status,version,required_policy_epoch,protection_rules_json,
                secret_provider_configuration_id,signing_provider_configuration_id
         FROM environments WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(&environment_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(environment) = environment else {
        return Ok(false);
    };
    let environment_version: i64 = request.try_get("environment_version")?;
    let policy_epoch: i64 = request.try_get("policy_epoch")?;
    if environment.try_get::<String, _>("name")? != environment_name
        || environment.try_get::<String, _>("status")? != "active"
        || environment.try_get::<i64, _>("version")? != environment_version
        || environment.try_get::<i64, _>("required_policy_epoch")? != policy_epoch
    {
        return Ok(false);
    }
    let active_policy: Option<i64> =
        sqlx::query_scalar("SELECT policy_epoch FROM tenant_policy_states WHERE tenant_id=$1")
            .bind(tenant_id)
            .fetch_optional(&mut **tx)
            .await?;
    if active_policy != Some(policy_epoch) {
        return Ok(false);
    }
    for (column, capability) in [
        ("secret_provider_configuration_id", "external-secret"),
        ("signing_provider_configuration_id", "signing"),
    ] {
        if let Some(provider_id) = environment.try_get::<Option<String>, _>(column)? {
            let active: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM tenant_provider_configurations
                 WHERE tenant_id=$1 AND id=$2 AND capability=$3 AND status='active')",
            )
            .bind(tenant_id)
            .bind(provider_id)
            .bind(capability)
            .fetch_one(&mut **tx)
            .await?;
            if !active {
                return Ok(false);
            }
        }
    }
    let request_id: String = request.try_get("id")?;
    let gate = sqlx::query(
        "SELECT id,concurrency_fence,execution_lease_id,installation_fencing_epoch,
                state,expires_unix_ms FROM environment_concurrency_leases
         WHERE tenant_id=$1 AND deployment_request_id=$2 AND state='active'
         ORDER BY concurrency_fence DESC LIMIT 1 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(&request_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(gate) = gate else {
        return Ok(false);
    };
    if gate.try_get::<String, _>("state")? != "active"
        || gate.try_get::<i64, _>("expires_unix_ms")? <= postgres_i64(now_unix_ms, "gate expiry")?
        || gate
            .try_get::<Option<String>, _>("execution_lease_id")?
            .is_some()
        || gate.try_get::<i64, _>("installation_fencing_epoch")?
            != postgres_i64(epoch, "installation epoch")?
        || request.try_get::<Option<i64>, _>("concurrency_fence")?
            != Some(gate.try_get("concurrency_fence")?)
    {
        return Ok(false);
    }
    let rules: crate::EnvironmentProtectionRules =
        serde_json::from_slice(&environment.try_get::<Vec<u8>, _>("protection_rules_json")?)?;
    if rules.require_approval {
        let Some(approval_id) = request.try_get::<Option<String>, _>("approval_request_id")? else {
            return Ok(false);
        };
        let authorized: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM approval_requests
             WHERE id=$1 AND status='consumed' AND subject_digest=$2)",
        )
        .bind(approval_id)
        .bind(request.try_get::<String, _>("approval_subject_digest")?)
        .fetch_one(&mut **tx)
        .await?;
        if !authorized {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
async fn bind_postgres_deployment_gate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    job_id: &str,
    job_attempt: u32,
    lease_id: &str,
    generation: u64,
    epoch: u64,
    hard_deadline_unix_ms: u64,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let request = sqlx::query(
        "SELECT id,concurrency_fence,version FROM deployment_requests
         WHERE tenant_id=$1 AND job_id=$2 AND job_attempt=$3 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(job_id)
    .bind(i64::from(job_attempt))
    .fetch_optional(&mut **tx)
    .await?;
    let Some(request) = request else {
        return Ok(());
    };
    let request_id: String = request.try_get("id")?;
    let fence: i64 = request
        .try_get::<Option<i64>, _>("concurrency_fence")?
        .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
    let gate_changed = sqlx::query(
        "UPDATE environment_concurrency_leases SET execution_lease_id=$3,
         lease_fencing_generation=$4,expires_unix_ms=$5
         WHERE tenant_id=$1 AND deployment_request_id=$2 AND state='active'
           AND execution_lease_id IS NULL AND concurrency_fence=$6
           AND installation_fencing_epoch=$7",
    )
    .bind(tenant_id)
    .bind(&request_id)
    .bind(lease_id)
    .bind(postgres_i64(generation, "lease generation")?)
    .bind(postgres_i64(hard_deadline_unix_ms, "lease hard deadline")?)
    .bind(fence)
    .bind(postgres_i64(epoch, "installation epoch")?)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if gate_changed != 1 {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    let version: i64 = request.try_get("version")?;
    let request_changed = sqlx::query(
        "UPDATE deployment_requests SET status='leased',execution_lease_id=$3,
         lease_fencing_generation=$4,updated_unix_ms=$5,version=$6
         WHERE tenant_id=$1 AND id=$2 AND status='ready'
           AND concurrency_fence=$7 AND execution_lease_id IS NULL AND version=$8",
    )
    .bind(tenant_id)
    .bind(&request_id)
    .bind(lease_id)
    .bind(postgres_i64(generation, "lease generation")?)
    .bind(postgres_i64(now_unix_ms, "deployment lease binding")?)
    .bind(
        version
            .checked_add(1)
            .ok_or(ControlPlaneError::IntegerRange {
                field: "deployment request version",
            })?,
    )
    .bind(fence)
    .bind(version)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if request_changed != 1 {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn maintain_postgres_scheduler_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let now = postgres_i64(now_unix_ms, "scheduler maintenance")?;
    let rows = sqlx::query(
        "SELECT id FROM leases
         WHERE state IN ('offered','active','cancel_requested')
           AND ((state='offered' AND accept_by_unix_ms<=$1)
             OR (state<>'offered' AND expires_unix_ms<=$1)
             OR hard_deadline_unix_ms<=$1)
         ORDER BY hard_deadline_unix_ms,id LIMIT 256 FOR UPDATE SKIP LOCKED",
    )
    .bind(now)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        let id: String = row.try_get("id")?;
        let lease = postgres_lease_tx(tx, &id).await?;
        if lease.state == runtrue_scheduler::LeaseState::Offered {
            sqlx::query(
                "UPDATE leases SET state='expired',completed_unix_ms=$2
                 WHERE id=$1 AND state='offered'",
            )
            .bind(&id)
            .bind(now)
            .execute(&mut **tx)
            .await?;
            sqlx::query("UPDATE jobs SET status='queued' WHERE id=$1 AND status='leased'")
                .bind(&lease.job_id)
                .execute(&mut **tx)
                .await?;
            revoke_postgres_brokers(tx, &lease, now_unix_ms, "expired").await?;
            continue;
        }
        let hard_deadline: i64 =
            sqlx::query_scalar("SELECT hard_deadline_unix_ms FROM leases WHERE id=$1")
                .bind(&id)
                .fetch_one(&mut **tx)
                .await?;
        let state = if lease.state == runtrue_scheduler::LeaseState::CancelRequested {
            JobState::Canceled
        } else if now_unix_ms >= postgres_u64(hard_deadline, "lease hard deadline")? {
            JobState::TimedOut
        } else {
            JobState::Lost
        };
        expire_postgres_lease_with_job(tx, &lease, state, now_unix_ms).await?;
        conclude_postgres_run_for_job(tx, &lease.job_id, now_unix_ms).await?;
    }

    let offline_before = postgres_i64(now_unix_ms.saturating_sub(60_000), "runner offline")?;
    let runner_rows = sqlx::query(
        "SELECT id,runner_json FROM runners WHERE status='online' AND updated_unix_ms<=$1
         ORDER BY updated_unix_ms,id LIMIT 256 FOR UPDATE SKIP LOCKED",
    )
    .bind(offline_before)
    .fetch_all(&mut **tx)
    .await?;
    for row in runner_rows {
        let id: String = row.try_get("id")?;
        let mut runner: RunnerRecord =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("runner_json")?)?;
        runner.status = runtrue_scheduler::RunnerStatus::Offline;
        sqlx::query(
            "UPDATE runners SET status='offline',runner_json=$2,updated_unix_ms=$3
             WHERE id=$1 AND status='online'",
        )
        .bind(&id)
        .bind(serde_json::to_vec(&runner)?)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn revoke_postgres_brokers(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: &Lease,
    now_unix_ms: u64,
    next_state: &str,
) -> Result<(), ControlPlaneError> {
    if !matches!(next_state, "revoked" | "expired") {
        return Err(ControlPlaneError::InvalidInput(
            "invalid broker terminal state",
        ));
    }
    let now = postgres_i64(now_unix_ms, "broker revocation")?;
    sqlx::query(
        "UPDATE runner_secret_leases SET state=$3,revoked_unix_ms=$4
         WHERE execution_lease_id=$1 AND fencing_generation=$2 AND state='delivered'",
    )
    .bind(&lease.id)
    .bind(postgres_i64(lease.fencing_generation, "lease generation")?)
    .bind(next_state)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE runner_oidc_issuances SET state=$3,revoked_unix_ms=$4
         WHERE execution_lease_id=$1 AND fencing_generation=$2 AND state='issued'",
    )
    .bind(&lease.id)
    .bind(postgres_i64(lease.fencing_generation, "lease generation")?)
    .bind(next_state)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE runner_oidc_grants SET state=$3,revoked_unix_ms=$4
         WHERE execution_lease_id=$1 AND fencing_generation=$2 AND state='authorized'",
    )
    .bind(&lease.id)
    .bind(postgres_i64(lease.fencing_generation, "lease generation")?)
    .bind(next_state)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE oidc_grants SET revoked_unix_ms=$3 WHERE revoked_unix_ms IS NULL
         AND id IN (SELECT grant_id FROM runner_oidc_grants
           WHERE execution_lease_id=$1 AND fencing_generation=$2 AND state=$4)",
    )
    .bind(&lease.id)
    .bind(postgres_i64(lease.fencing_generation, "lease generation")?)
    .bind(now)
    .bind(next_state)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn expire_postgres_lease_with_job(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: &Lease,
    job_state: JobState,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let now = postgres_i64(now_unix_ms, "lease expiration")?;
    sqlx::query("UPDATE leases SET state='expired',completed_unix_ms=$2 WHERE id=$1")
        .bind(&lease.id)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE jobs SET status=$2,completed_unix_ms=$3 WHERE id=$1")
        .bind(&lease.job_id)
        .bind(postgres_job_state_name(job_state))
        .bind(now)
        .execute(&mut **tx)
        .await?;
    revoke_postgres_brokers(tx, lease, now_unix_ms, "expired").await
}

#[cfg(feature = "postgres")]
async fn conclude_postgres_run_for_job(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let run = sqlx::query(
        "SELECT r.id,r.cancel_reason FROM runs r JOIN jobs j ON j.run_id=r.id
         WHERE j.id=$1 FOR UPDATE OF r",
    )
    .bind(job_id)
    .fetch_one(&mut **tx)
    .await?;
    let run_id: String = run.try_get("id")?;
    let statuses = sqlx::query_scalar::<_, String>("SELECT status FROM jobs WHERE run_id=$1")
        .bind(&run_id)
        .fetch_all(&mut **tx)
        .await?;
    if statuses.iter().any(|status| {
        !matches!(
            status.as_str(),
            "succeeded"
                | "failed"
                | "canceled"
                | "timed_out"
                | "lost"
                | "rejected"
                | "skipped"
                | "blocked_policy"
        )
    }) {
        return Ok(());
    }
    let status = if run.try_get::<Option<String>, _>("cancel_reason")?.is_some()
        || statuses.iter().any(|state| state == "canceled")
    {
        "canceled"
    } else if statuses.iter().any(|state| {
        matches!(
            state.as_str(),
            "failed" | "timed_out" | "lost" | "rejected" | "blocked_policy"
        )
    }) {
        "failed"
    } else {
        "succeeded"
    };
    sqlx::query(
        "UPDATE runs SET status=$2,started_unix_ms=COALESCE(started_unix_ms,created_unix_ms),
         completed_unix_ms=$3 WHERE id=$1 AND status IN ('created','running')",
    )
    .bind(&run_id)
    .bind(status)
    .bind(postgres_i64(now_unix_ms, "run completion")?)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn postgres_result_objects(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: &str,
    attempt: u32,
) -> Result<(Vec<String>, Vec<String>), ControlPlaneError> {
    let attempt = i32::try_from(attempt).map_err(|_| ControlPlaneError::IntegerRange {
        field: "job attempt",
    })?;
    let artifacts = sqlx::query_scalar::<_, String>(
        "SELECT object_id FROM job_result_objects
         WHERE job_id=$1 AND job_attempt=$2 AND kind='artifact' ORDER BY ordinal",
    )
    .bind(job_id)
    .bind(attempt)
    .fetch_all(&mut **tx)
    .await?;
    let caches = sqlx::query_scalar::<_, String>(
        "SELECT object_id FROM job_result_objects
         WHERE job_id=$1 AND job_attempt=$2 AND kind='cache' ORDER BY ordinal",
    )
    .bind(job_id)
    .bind(attempt)
    .fetch_all(&mut **tx)
    .await?;
    Ok((artifacts, caches))
}

#[cfg(feature = "postgres")]
fn monotonic_credential_taint(
    stored: &str,
    incoming: CredentialTaintState,
) -> Result<CredentialTaintState, ControlPlaneError> {
    let result = match (stored, incoming) {
        ("unobserved", value) => value,
        ("none", value) => value,
        ("unknown", CredentialTaintState::Unknown) => CredentialTaintState::Unknown,
        ("unknown", CredentialTaintState::CredentialReleased) => {
            CredentialTaintState::CredentialReleased
        }
        ("credential_released", CredentialTaintState::CredentialReleased) => {
            CredentialTaintState::CredentialReleased
        }
        ("unknown", CredentialTaintState::None)
        | ("credential_released", CredentialTaintState::Unknown | CredentialTaintState::None) => {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        }
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "invalid terminal credential taint state".to_owned(),
            ))
        }
    };
    Ok(result)
}

#[cfg(feature = "postgres")]
fn postgres_job_state_name(state: JobState) -> &'static str {
    match state {
        JobState::Created => "created",
        JobState::BlockedPolicy => "blocked_policy",
        JobState::AwaitingApproval => "awaiting_approval",
        JobState::Queued => "queued",
        JobState::Leased => "leased",
        JobState::Preparing => "preparing",
        JobState::Running => "running",
        JobState::Finalizing => "finalizing",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
        JobState::Canceled => "canceled",
        JobState::TimedOut => "timed_out",
        JobState::Lost => "lost",
        JobState::Rejected => "rejected",
        JobState::Skipped => "skipped",
    }
}

#[cfg(feature = "postgres")]
fn parse_postgres_job_state(value: &str) -> Result<JobState, ControlPlaneError> {
    let state = match value {
        "created" => JobState::Created,
        "blocked_policy" => JobState::BlockedPolicy,
        "awaiting_approval" => JobState::AwaitingApproval,
        "queued" => JobState::Queued,
        "leased" => JobState::Leased,
        "preparing" => JobState::Preparing,
        "running" => JobState::Running,
        "finalizing" => JobState::Finalizing,
        "succeeded" => JobState::Succeeded,
        "failed" => JobState::Failed,
        "canceled" => JobState::Canceled,
        "timed_out" => JobState::TimedOut,
        "lost" => JobState::Lost,
        "rejected" => JobState::Rejected,
        "skipped" => JobState::Skipped,
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "unknown PostgreSQL job state".to_owned(),
            ))
        }
    };
    Ok(state)
}

#[cfg(feature = "postgres")]
fn postgres_planned_requirements(
    planned: &runtrue_workflow_ir::PlannedJob,
) -> runtrue_scheduler::SchedulingRequirements {
    runtrue_scheduler::SchedulingRequirements {
        os: planned.runner.os,
        arch: planned.runner.arch,
        isolation: planned.runner.isolation,
        cpu: u32::from(planned.runner.cpu),
        memory_bytes: planned.runner.memory_bytes,
        storage_bytes: planned.runner.storage_bytes.unwrap_or(0),
        region: planned.runner.region.clone(),
        required_capabilities: planned.runner.capabilities.iter().cloned().collect(),
        allowed_pools: BTreeSet::new(),
    }
}

#[cfg(feature = "postgres")]
fn new_postgres_lease_id() -> Result<String, ControlPlaneError> {
    let mut id = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut id)
        .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
    Ok(format!("lease-{}", hex::encode(id)))
}

#[cfg(feature = "postgres")]
async fn validate_postgres_lease_fence(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease_id: &str,
    runner_id: &str,
    generation: u64,
    epoch: u64,
) -> Result<Lease, ControlPlaneError> {
    let active_epoch: i64 = sqlx::query_scalar(
        "SELECT fencing_epoch FROM installation_state WHERE singleton=TRUE FOR UPDATE",
    )
    .fetch_one(&mut **tx)
    .await?;
    let active_epoch = postgres_u64(active_epoch, "fencing_epoch")?;
    if epoch != active_epoch {
        return Err(ControlPlaneError::StaleInstallationEpoch {
            expected: active_epoch,
            actual: epoch,
        });
    }
    let lease = postgres_lease_tx(tx, lease_id).await?;
    if lease.runner_id != runner_id {
        return Err(ControlPlaneError::WrongRunner);
    }
    let authoritative: i64 =
        sqlx::query_scalar("SELECT last_generation FROM job_fencing WHERE job_id=$1 FOR UPDATE")
            .bind(&lease.job_id)
            .fetch_one(&mut **tx)
            .await?;
    let authoritative = postgres_u64(authoritative, "lease generation")?;
    if generation != lease.fencing_generation || generation != authoritative {
        return Err(ControlPlaneError::StaleLeaseGeneration {
            expected: authoritative,
            actual: generation,
        });
    }
    if lease.installation_fencing_epoch != epoch {
        return Err(ControlPlaneError::StaleInstallationEpoch {
            expected: active_epoch,
            actual: lease.installation_fencing_epoch,
        });
    }
    Ok(lease)
}

#[cfg(feature = "postgres")]
async fn postgres_lease_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease_id: &str,
) -> Result<Lease, ControlPlaneError> {
    let row = sqlx::query(
        "SELECT id,job_id,tenant_id,runner_id,fencing_generation,
         installation_fencing_epoch,capsule_digest,issued_unix_ms,
         accept_by_unix_ms,expires_unix_ms,state,terminal_result_digest
         FROM leases WHERE id=$1 FOR UPDATE",
    )
    .bind(lease_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| ControlPlaneError::NotFound {
        kind: "lease",
        id: lease_id.to_owned(),
    })?;
    let state: String = row.try_get("state")?;
    Ok(Lease {
        id: row.try_get("id")?,
        job_id: row.try_get("job_id")?,
        tenant_id: row.try_get("tenant_id")?,
        runner_id: row.try_get("runner_id")?,
        fencing_generation: postgres_u64(row.try_get("fencing_generation")?, "lease generation")?,
        installation_fencing_epoch: postgres_u64(
            row.try_get("installation_fencing_epoch")?,
            "installation epoch",
        )?,
        capsule_digest: ContentDigest::parse(row.try_get::<String, _>("capsule_digest")?)?,
        issued_unix_ms: postgres_u64(row.try_get("issued_unix_ms")?, "lease issued")?,
        accept_by_unix_ms: postgres_u64(
            row.try_get("accept_by_unix_ms")?,
            "lease accept deadline",
        )?,
        expires_unix_ms: postgres_u64(row.try_get("expires_unix_ms")?, "lease expiry")?,
        state: parse_lease_state(&state)?,
        terminal_result_digest: row
            .try_get::<Option<String>, _>("terminal_result_digest")?
            .map(ContentDigest::parse)
            .transpose()?,
    })
}

#[cfg(feature = "postgres")]
fn parse_lease_state(value: &str) -> Result<runtrue_scheduler::LeaseState, ControlPlaneError> {
    use runtrue_scheduler::LeaseState;
    match value {
        "offered" => Ok(LeaseState::Offered),
        "active" => Ok(LeaseState::Active),
        "cancel_requested" => Ok(LeaseState::CancelRequested),
        "completed" => Ok(LeaseState::Completed),
        "rejected" => Ok(LeaseState::Rejected),
        "expired" => Ok(LeaseState::Expired),
        _ => Err(ControlPlaneError::CorruptState(
            "unknown PostgreSQL lease state".to_owned(),
        )),
    }
}

#[cfg(feature = "postgres")]
async fn postgres_secret_lease_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
) -> Result<RunnerSecretLeaseRecord, ControlPlaneError> {
    let row = sqlx::query("SELECT * FROM runner_secret_leases WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| ControlPlaneError::NotFound {
            kind: "runner secret lease",
            id: id.to_owned(),
        })?;
    Ok(RunnerSecretLeaseRecord {
        id: row.try_get("id")?,
        execution_lease_id: row.try_get("execution_lease_id")?,
        fencing_generation: postgres_u64(row.try_get("fencing_generation")?, "lease generation")?,
        installation_fencing_epoch: postgres_u64(
            row.try_get("installation_fencing_epoch")?,
            "installation epoch",
        )?,
        runner_id: row.try_get("runner_id")?,
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        run_id: row.try_get("run_id")?,
        job_id: row.try_get("job_id")?,
        job_attempt: u32::try_from(row.try_get::<i32, _>("job_attempt")?).map_err(|_| {
            ControlPlaneError::CorruptState("PostgreSQL job attempt is negative".to_owned())
        })?,
        step_id: row.try_get("step_id")?,
        secret_metadata_id: row.try_get("secret_metadata_id")?,
        secret_version: postgres_u64(row.try_get("secret_version")?, "secret version")?,
        purpose: row.try_get("purpose")?,
        guest_key_fingerprint: ContentDigest::parse(
            row.try_get::<String, _>("guest_key_fingerprint")?,
        )?,
        runner_posture_digest: ContentDigest::parse(
            row.try_get::<String, _>("runner_posture_digest")?,
        )?,
        issued_unix_ms: postgres_u64(row.try_get("issued_unix_ms")?, "secret lease issued")?,
        expires_unix_ms: postgres_u64(row.try_get("expires_unix_ms")?, "secret lease expiry")?,
        state: row.try_get("state")?,
        revoked_unix_ms: row
            .try_get::<Option<i64>, _>("revoked_unix_ms")?
            .map(|value| postgres_u64(value, "secret lease revoked"))
            .transpose()?,
    })
}

#[cfg(feature = "postgres")]
impl RunnerFleetEnrollmentStore for PostgresInstallationStore {
    fn put_runner_pool_configuration<'a>(
        &'a self,
        configuration: &'a RunnerPoolConfiguration,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            validate_pool_configuration(configuration)?;
            let mut tx = self.pool.begin().await?;
            let existing = sqlx::query(
                "SELECT tenant_id,name,region,status,created_unix_ms
                 FROM runner_pools WHERE id=$1 FOR UPDATE",
            )
            .bind(&configuration.pool.id)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(row) = existing {
                let status: String = row.try_get("status")?;
                let same = row.try_get::<String, _>("tenant_id")? == configuration.pool.tenant_id
                    && row.try_get::<String, _>("name")? == configuration.pool.name
                    && row.try_get::<Option<String>, _>("region")? == configuration.pool.region
                    && status == pool_status_name(configuration.pool.status)
                    && postgres_u64(row.try_get("created_unix_ms")?, "pool creation")?
                        == configuration.pool.created_unix_ms;
                if !same {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            } else {
                sqlx::query(
                    "INSERT INTO runner_pools(id,tenant_id,name,region,status,created_unix_ms)
                     VALUES($1,$2,$3,$4,$5,$6)",
                )
                .bind(&configuration.pool.id)
                .bind(&configuration.pool.tenant_id)
                .bind(&configuration.pool.name)
                .bind(&configuration.pool.region)
                .bind(pool_status_name(configuration.pool.status))
                .bind(postgres_i64(
                    configuration.pool.created_unix_ms,
                    "pool creation",
                )?)
                .execute(&mut *tx)
                .await?;
            }
            if let Some(policy) = &configuration.scaling_policy {
                sqlx::query(
                    "INSERT INTO runner_pool_scaling_policies
                     (pool_id,baseline_runtime_compatibility_digest,minimum_workers,
                      minimum_idle_workers,maximum_workers,scale_up_batch,idle_timeout_ms,
                      offline_grace_ms,cooldown_ms,enabled,updated_unix_ms)
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                     ON CONFLICT(pool_id) DO UPDATE SET
                      baseline_runtime_compatibility_digest=excluded.baseline_runtime_compatibility_digest,
                      minimum_workers=excluded.minimum_workers,
                      minimum_idle_workers=excluded.minimum_idle_workers,
                      maximum_workers=excluded.maximum_workers,
                      scale_up_batch=excluded.scale_up_batch,
                      idle_timeout_ms=excluded.idle_timeout_ms,
                      offline_grace_ms=excluded.offline_grace_ms,
                      cooldown_ms=excluded.cooldown_ms,enabled=excluded.enabled,
                      updated_unix_ms=excluded.updated_unix_ms",
                )
                .bind(&policy.pool_id)
                .bind(
                    policy
                        .baseline_runtime_compatibility_digest
                        .as_ref()
                        .map(ContentDigest::as_str),
                )
                .bind(i32::try_from(policy.minimum_workers).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "minimum workers",
                    }
                })?)
                .bind(i32::try_from(policy.minimum_idle_workers).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "minimum idle workers",
                    }
                })?)
                .bind(i32::try_from(policy.maximum_workers).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "maximum workers",
                    }
                })?)
                .bind(i32::try_from(policy.scale_up_batch).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "scale up batch",
                    }
                })?)
                .bind(postgres_i64(policy.idle_timeout_ms, "idle timeout")?)
                .bind(postgres_i64(policy.offline_grace_ms, "offline grace")?)
                .bind(postgres_i64(policy.cooldown_ms, "autoscaler cooldown")?)
                .bind(policy.enabled)
                .bind(postgres_i64(policy.updated_unix_ms, "policy update")?)
                .execute(&mut *tx)
                .await?;
            }
            for template in &configuration.templates {
                sqlx::query(
                    "INSERT INTO runner_pool_templates
                     (pool_id,runtime_compatibility_digest,provider,provider_template_id,
                      runner_template_digest,created_unix_ms,updated_unix_ms)
                     VALUES($1,$2,$3,$4,$5,$6,$7)
                     ON CONFLICT(pool_id,runtime_compatibility_digest) DO UPDATE SET
                      provider=excluded.provider,
                      provider_template_id=excluded.provider_template_id,
                      runner_template_digest=excluded.runner_template_digest,
                      updated_unix_ms=excluded.updated_unix_ms",
                )
                .bind(&template.pool_id)
                .bind(template.runtime_compatibility_digest.as_str())
                .bind(&template.provider)
                .bind(&template.provider_template_id)
                .bind(template.runner_template_digest.as_str())
                .bind(postgres_i64(template.created_unix_ms, "template creation")?)
                .bind(postgres_i64(template.updated_unix_ms, "template update")?)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(())
        })
    }

    fn runner_pool_configuration<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, RunnerPoolConfiguration> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let row = sqlx::query("SELECT * FROM runner_pools WHERE id=$1")
                .bind(pool_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| ControlPlaneError::NotFound {
                    kind: "runner pool",
                    id: pool_id.to_owned(),
                })?;
            let pool = postgres_pool(row)?;
            let policy = sqlx::query("SELECT * FROM runner_pool_scaling_policies WHERE pool_id=$1")
                .bind(pool_id)
                .fetch_optional(&mut *tx)
                .await?
                .map(postgres_policy)
                .transpose()?;
            let templates = sqlx::query(
                "SELECT * FROM runner_pool_templates WHERE pool_id=$1
                 ORDER BY runtime_compatibility_digest",
            )
            .bind(pool_id)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(postgres_template)
            .collect::<Result<Vec<_>, _>>()?;
            tx.commit().await?;
            Ok(RunnerPoolConfiguration {
                pool,
                scaling_policy: policy,
                templates,
            })
        })
    }

    fn inspect_pool_enrollment_token<'a>(
        &'a self,
        token: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, EnrollmentTokenRecord> {
        Box::pin(async move {
            validate_token(token)?;
            let hash = enrollment_token_hash(token);
            let mut tx = self.pool.begin().await?;
            let record = postgres_enrollment_token_tx(&mut tx, &hash).await?;
            validate_usable_token(&record, now_unix_ms)?;
            let status: Option<String> =
                sqlx::query_scalar("SELECT status FROM runner_pools WHERE id=$1")
                    .bind(&record.pool_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            let status = status.ok_or_else(|| ControlPlaneError::NotFound {
                kind: "runner pool",
                id: record.pool_id.clone(),
            })?;
            if parse_pool_status(&status)? != RunnerPoolStatus::Active {
                return Err(ControlPlaneError::InvalidInput("runner pool is disabled"));
            }
            tx.commit().await?;
            Ok(record)
        })
    }

    fn replay_pool_enrollment<'a>(
        &'a self,
        token: &'a str,
        request_digest: &'a ContentDigest,
    ) -> StoreFuture<'a, Option<RunnerEnrollmentReplay>> {
        Box::pin(async move {
            validate_token(token)?;
            let hash = enrollment_token_hash(token);
            let token_id: String =
                sqlx::query_scalar("SELECT id FROM enrollment_tokens WHERE token_hash=$1")
                    .bind(hash.as_str())
                    .fetch_optional(&self.pool)
                    .await?
                    .ok_or(ControlPlaneError::InvalidEnrollmentToken)?;
            let replay =
                sqlx::query("SELECT * FROM runner_enrollment_replays WHERE enrollment_token_id=$1")
                    .bind(token_id)
                    .fetch_optional(&self.pool)
                    .await?
                    .map(postgres_enrollment_replay)
                    .transpose()?;
            match replay {
                Some(value) if value.request_digest == *request_digest => Ok(Some(value)),
                Some(_) => Err(ControlPlaneError::EnrollmentTokenConsumed),
                None => Ok(None),
            }
        })
    }

    fn launch_claim_for_enrollment_token<'a>(
        &'a self,
        enrollment_token_id: &'a str,
    ) -> StoreFuture<'a, Option<RunnerLaunchClaimRecord>> {
        Box::pin(async move {
            if enrollment_token_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput(
                    "enrollment token id is empty",
                ));
            }
            sqlx::query("SELECT * FROM runner_launch_claims WHERE enrollment_token_id=$1")
                .bind(enrollment_token_id)
                .fetch_optional(&self.pool)
                .await?
                .map(postgres_launch_claim)
                .transpose()
        })
    }

    fn software_update_claim_for_enrollment_token<'a>(
        &'a self,
        enrollment_token_id: &'a str,
    ) -> StoreFuture<'a, Option<RunnerSoftwareUpdateClaim>> {
        Box::pin(async move {
            if enrollment_token_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput(
                    "enrollment token id is empty",
                ));
            }
            sqlx::query("SELECT * FROM runner_software_update_claims WHERE enrollment_token_id=$1")
                .bind(enrollment_token_id)
                .fetch_optional(&self.pool)
                .await?
                .map(postgres_software_update_claim)
                .transpose()
        })
    }

    fn put_runner_release<'a>(
        &'a self,
        registration: &'a VerifiedRunnerUpdateReleaseRegistration,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(postgres_put_verified_runner_release(
            self,
            registration,
            now_unix_ms,
        ))
    }
    fn put_pool_update_policy<'a>(
        &'a self,
        policy: &'a RunnerPoolUpdatePolicy,
    ) -> StoreFuture<'a, ()> {
        Box::pin(postgres_put_update_policy(self, policy))
    }
    fn replacements<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerReplacementRecord>> {
        Box::pin(postgres_replacements(self, pool_id))
    }
    fn plan_autoscaled_replacement<'a>(
        &'a self,
        plan: AutoscaledReplacementPlan<'a>,
    ) -> StoreFuture<'a, PlannedRunnerReplacement> {
        Box::pin(postgres_plan_replacement(self, plan))
    }
    fn activate_replacement<'a>(
        &'a self,
        replacement_id: &'a str,
        owner_id: &'a str,
        fencing_generation: u64,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerReplacementRecord> {
        Box::pin(postgres_activate_replacement(
            self,
            replacement_id,
            owner_id,
            fencing_generation,
            now_unix_ms,
        ))
    }
    fn put_fixed_runner_slot<'a>(&'a self, slot: &'a RunnerSlotRecord) -> StoreFuture<'a, ()> {
        Box::pin(postgres_put_runner_slot(self, slot))
    }

    fn fixed_runner_slot<'a>(&'a self, slot_id: &'a str) -> StoreFuture<'a, RunnerSlotRecord> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM runner_slots WHERE id=$1")
                .bind(slot_id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| ControlPlaneError::NotFound {
                    kind: "runner slot",
                    id: slot_id.to_owned(),
                })?;
            Ok(RunnerSlotRecord {
                id: row.try_get("id")?,
                pool_id: row.try_get("pool_id")?,
                updater_identity_digest: ContentDigest::parse(
                    row.try_get::<String, _>("updater_identity_digest")?,
                )?,
                active_generation: postgres_u64(
                    row.try_get("active_generation")?,
                    "slot generation",
                )?,
                active_runner_id: row.try_get("active_runner_id")?,
                created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "slot creation")?,
                updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "slot update")?,
            })
        })
    }
    fn create_fixed_update_claim<'a>(
        &'a self,
        slot_id: &'a str,
        identity_proof_digest: &'a ContentDigest,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, IssuedRunnerSoftwareUpdateClaim> {
        Box::pin(postgres_create_fixed_claim(
            self,
            slot_id,
            identity_proof_digest,
            now_unix_ms,
            expires_unix_ms,
        ))
    }

    fn validate_pool_runner_inventory<'a>(
        &'a self,
        runner_id: &'a str,
        inventory_digest: &'a ContentDigest,
    ) -> StoreFuture<'a, ContentDigest> {
        Box::pin(async move {
            if runner_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput("runner id is empty"));
            }
            let mut tx = self.pool.begin().await?;
            let mut persisted = postgres_runner_tx(&mut tx, runner_id).await?;
            let binding = sqlx::query(
                "SELECT inventory_digest,posture_digest FROM runner_enrollment_postures
                 WHERE runner_id=$1 FOR UPDATE",
            )
            .bind(runner_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(binding) = binding else {
                persisted.runner.status = runtrue_scheduler::RunnerStatus::Quarantined;
                sqlx::query("UPDATE runners SET status='quarantined',runner_json=$2 WHERE id=$1")
                    .bind(runner_id)
                    .bind(serde_json::to_vec(&persisted.runner)?)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                return Err(ControlPlaneError::RunnerReenrollmentRequired);
            };
            let expected_inventory =
                ContentDigest::parse(binding.try_get::<String, _>("inventory_digest")?)?;
            let expected_posture =
                ContentDigest::parse(binding.try_get::<String, _>("posture_digest")?)?;
            let authoritative =
                authoritative_runner_posture_digest(&persisted.runner, &expected_inventory)?;
            if expected_inventory != *inventory_digest || expected_posture != authoritative {
                return Err(ControlPlaneError::RunnerInventoryMismatch);
            }
            tx.commit().await?;
            Ok(authoritative)
        })
    }

    fn update_pool_runner_locality<'a>(
        &'a self,
        runner_id: &'a str,
        locality: &'a BTreeSet<ContentDigest>,
        package_tiers: &'a BTreeMap<ContentDigest, runtrue_scheduler::PackagePreparationTier>,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, PersistedRunner> {
        Box::pin(async move {
            if runner_id.is_empty()
                || locality.len() > 10_000
                || package_tiers.len() > 10_000
                || package_tiers
                    .keys()
                    .any(|digest| !locality.contains(digest))
            {
                return Err(ControlPlaneError::InvalidInput(
                    "runner locality binding is invalid",
                ));
            }
            let mut tx = self.pool.begin().await?;
            let mut persisted = postgres_runner_tx(&mut tx, runner_id).await?;
            if !matches!(
                persisted.runner.status,
                runtrue_scheduler::RunnerStatus::Online | runtrue_scheduler::RunnerStatus::Draining
            ) {
                return Err(ControlPlaneError::InvalidInput(
                    "offline runner cannot update locality",
                ));
            }
            persisted.runner.locality = locality.clone();
            persisted.runner.package_tiers = package_tiers.clone();
            persisted.updated_unix_ms = now_unix_ms;
            sqlx::query("UPDATE runners SET runner_json=$2,updated_unix_ms=$3 WHERE id=$1")
                .bind(runner_id)
                .bind(serde_json::to_vec(&persisted.runner)?)
                .bind(postgres_i64(now_unix_ms, "runner locality update")?)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(persisted)
        })
    }

    fn runner_pools(&self) -> StoreFuture<'_, Vec<RunnerPoolRecord>> {
        Box::pin(async move {
            sqlx::query("SELECT * FROM runner_pools ORDER BY id")
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(postgres_pool)
                .collect()
        })
    }

    fn runner_pools_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerPoolRecord>> {
        Box::pin(async move {
            if tenant_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput(
                    "runner pool tenant is empty",
                ));
            }
            sqlx::query("SELECT * FROM runner_pools WHERE tenant_id=$1 ORDER BY id")
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(postgres_pool)
                .collect()
        })
    }

    fn pool_runners(&self) -> StoreFuture<'_, Vec<PersistedRunner>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT runner_json,created_unix_ms,updated_unix_ms FROM runners ORDER BY id",
            )
            .fetch_all(&self.pool)
            .await?;
            let mut runners = rows
                .into_iter()
                .map(postgres_runner)
                .collect::<Result<Vec<_>, _>>()?;
            runners.retain(|value| !value.runner.retired);
            Ok(runners)
        })
    }

    fn pool_runners_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<PersistedRunner>> {
        Box::pin(async move {
            if tenant_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput("runner tenant is empty"));
            }
            let rows = sqlx::query(
                "SELECT r.runner_json,r.created_unix_ms,r.updated_unix_ms
                 FROM runners r JOIN runner_pools p ON p.id=r.pool_id
                 WHERE p.tenant_id=$1 ORDER BY r.id",
            )
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
            let mut runners = rows
                .into_iter()
                .map(postgres_runner)
                .collect::<Result<Vec<_>, _>>()?;
            runners.retain(|value| !value.runner.retired);
            Ok(runners)
        })
    }

    fn pool_templates<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerPoolTemplateRecord>> {
        Box::pin(async move {
            if pool_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput(
                    "runner template pool is empty",
                ));
            }
            sqlx::query(
                "SELECT * FROM runner_pool_templates WHERE pool_id=$1
                 ORDER BY runtime_compatibility_digest",
            )
            .bind(pool_id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(postgres_template)
            .collect()
        })
    }

    fn fleet_requests<'a>(
        &'a self,
        pool_id: &'a str,
    ) -> StoreFuture<'a, Vec<RunnerFleetRequestRecord>> {
        Box::pin(async move {
            if pool_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput(
                    "runner fleet pool is empty",
                ));
            }
            sqlx::query(
                "SELECT * FROM runner_fleet_requests WHERE pool_id=$1
                 ORDER BY created_unix_ms,id LIMIT 10000",
            )
            .bind(pool_id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(postgres_fleet_request)
            .collect()
        })
    }

    fn fleet_request<'a>(
        &'a self,
        request_id: &'a str,
    ) -> StoreFuture<'a, RunnerFleetRequestRecord> {
        Box::pin(async move {
            if request_id.is_empty() {
                return Err(ControlPlaneError::InvalidInput(
                    "runner fleet request id is empty",
                ));
            }
            let row = sqlx::query("SELECT * FROM runner_fleet_requests WHERE id=$1")
                .bind(request_id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| ControlPlaneError::NotFound {
                    kind: "runner fleet request",
                    id: request_id.to_owned(),
                })?;
            postgres_fleet_request(row)
        })
    }

    fn drain_pool_runner<'a>(
        &'a self,
        runner_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, PersistedRunner> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let mut persisted = postgres_runner_tx(&mut tx, runner_id).await?;
            if persisted.runner.status == runtrue_scheduler::RunnerStatus::Revoked {
                return Err(ControlPlaneError::InvalidInput(
                    "a revoked runner cannot enter draining state",
                ));
            }
            persisted.runner.status = runtrue_scheduler::RunnerStatus::Draining;
            persisted.updated_unix_ms = now_unix_ms;
            sqlx::query(
                "UPDATE runners SET status='draining',runner_json=$2,updated_unix_ms=$3
                 WHERE id=$1",
            )
            .bind(runner_id)
            .bind(serde_json::to_vec(&persisted.runner)?)
            .bind(postgres_i64(now_unix_ms, "runner drain update")?)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE runner_fleet_requests SET state='draining',updated_unix_ms=$2
                 WHERE runner_id=$1 AND state='online'",
            )
            .bind(runner_id)
            .bind(postgres_i64(now_unix_ms, "fleet drain update")?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(persisted)
        })
    }

    fn acquire_autoscaler_lease<'a>(
        &'a self,
        pool_id: &'a str,
        owner_id: &'a str,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerAutoscalerLease> {
        Box::pin(async move {
            if pool_id.is_empty()
                || owner_id.is_empty()
                || expires_unix_ms <= now_unix_ms
                || expires_unix_ms.saturating_sub(now_unix_ms) > 5 * 60 * 1_000
            {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid runner autoscaler lease lifetime",
                ));
            }
            let mut tx = self.pool.begin().await?;
            let pool_exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runner_pools WHERE id=$1)")
                    .bind(pool_id)
                    .fetch_one(&mut *tx)
                    .await?;
            if !pool_exists {
                return Err(ControlPlaneError::NotFound {
                    kind: "runner pool",
                    id: pool_id.to_owned(),
                });
            }
            let existing = sqlx::query(
                "SELECT owner_id,fencing_generation,expires_unix_ms
                 FROM runner_autoscaler_leases WHERE pool_id=$1 FOR UPDATE",
            )
            .bind(pool_id)
            .fetch_optional(&mut *tx)
            .await?;
            let generation = if let Some(row) = existing {
                let existing_owner: String = row.try_get("owner_id")?;
                let existing_expiry =
                    postgres_u64(row.try_get("expires_unix_ms")?, "autoscaler expiry")?;
                if existing_owner != owner_id && existing_expiry > now_unix_ms {
                    return Err(ControlPlaneError::InvalidInput(
                        "runner autoscaler lease is held by another owner",
                    ));
                }
                postgres_u64(row.try_get("fencing_generation")?, "autoscaler generation")?
                    .checked_add(1)
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "autoscaler generation",
                    })?
            } else {
                1
            };
            sqlx::query(
                "INSERT INTO runner_autoscaler_leases
                 (pool_id,owner_id,fencing_generation,acquired_unix_ms,expires_unix_ms)
                 VALUES($1,$2,$3,$4,$5)
                 ON CONFLICT(pool_id) DO UPDATE SET owner_id=excluded.owner_id,
                  fencing_generation=excluded.fencing_generation,
                  acquired_unix_ms=excluded.acquired_unix_ms,
                  expires_unix_ms=excluded.expires_unix_ms",
            )
            .bind(pool_id)
            .bind(owner_id)
            .bind(postgres_i64(generation, "autoscaler generation")?)
            .bind(postgres_i64(now_unix_ms, "autoscaler acquisition")?)
            .bind(postgres_i64(expires_unix_ms, "autoscaler expiry")?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(RunnerAutoscalerLease {
                pool_id: pool_id.to_owned(),
                owner_id: owner_id.to_owned(),
                fencing_generation: generation,
                acquired_unix_ms: now_unix_ms,
                expires_unix_ms,
            })
        })
    }

    fn create_fleet_request<'a>(
        &'a self,
        request: &'a RunnerFleetRequestRecord,
        owner_id: &'a str,
        fencing_generation: u64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            if request.state != RunnerFleetRequestState::Requested
                || request.provider_request_id.is_some()
                || request.provider_instance_id.is_some()
                || request.runner_id.is_some()
                || request.failure_code.is_some()
                || request.created_unix_ms != request.updated_unix_ms
            {
                return Err(ControlPlaneError::InvalidInput(
                    "new runner fleet request is not pristine",
                ));
            }
            let mut tx = self.pool.begin().await?;
            require_postgres_autoscaler_lease(
                &mut tx,
                &request.pool_id,
                owner_id,
                fencing_generation,
                request.created_unix_ms,
            )
            .await?;
            let changed = sqlx::query(
                "INSERT INTO runner_fleet_requests
                 (id,pool_id,runtime_compatibility_digest,provider,provider_template_id,
                  runner_template_digest,state,created_unix_ms,updated_unix_ms)
                 SELECT $1,$2,$3,$4,$5,$6,'requested',$7,$7
                 WHERE EXISTS(SELECT 1 FROM runner_pool_templates
                  WHERE pool_id=$2 AND runtime_compatibility_digest=$3 AND provider=$4
                    AND provider_template_id=$5 AND runner_template_digest=$6)
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(&request.id)
            .bind(&request.pool_id)
            .bind(request.runtime_compatibility_digest.as_str())
            .bind(&request.provider)
            .bind(&request.provider_template_id)
            .bind(request.runner_template_digest.as_str())
            .bind(postgres_i64(
                request.created_unix_ms,
                "fleet request creation",
            )?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                let existing = sqlx::query("SELECT * FROM runner_fleet_requests WHERE id=$1")
                    .bind(&request.id)
                    .fetch_optional(&mut *tx)
                    .await?
                    .map(postgres_fleet_request)
                    .transpose()?;
                if existing.as_ref() != Some(request) {
                    return Err(ControlPlaneError::InvalidInput(
                        "runner fleet request has no exact registered template or conflicts with an idempotent replay",
                    ));
                }
            }
            tx.commit().await?;
            Ok(())
        })
    }

    fn transition_fleet_request<'a>(
        &'a self,
        request_id: &'a str,
        expected: RunnerFleetRequestState,
        next: RunnerFleetRequestState,
        provider_request_id: Option<&'a str>,
        provider_instance_id: Option<&'a str>,
        runner_id: Option<&'a str>,
        failure_code: Option<&'a str>,
        owner_id: &'a str,
        fencing_generation: u64,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunnerFleetRequestRecord> {
        Box::pin(async move {
            if !expected.can_transition_to(next) {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "runner fleet request",
                    from: fleet_state_name(expected),
                    to: fleet_state_name(next),
                });
            }
            let mut tx = self.pool.begin().await?;
            let current = postgres_fleet_request_tx(&mut tx, request_id).await?;
            require_postgres_autoscaler_lease(
                &mut tx,
                &current.pool_id,
                owner_id,
                fencing_generation,
                now_unix_ms,
            )
            .await?;
            if current.state != expected {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "runner fleet request",
                    from: fleet_state_name(current.state),
                    to: fleet_state_name(next),
                });
            }
            if next == RunnerFleetRequestState::Draining {
                let bound_runner =
                    current
                        .runner_id
                        .as_deref()
                        .ok_or(ControlPlaneError::InvalidTransition {
                            entity: "runner fleet request",
                            from: fleet_state_name(expected),
                            to: "draining",
                        })?;
                let row =
                    sqlx::query("SELECT status,runner_json FROM runners WHERE id=$1 FOR UPDATE")
                        .bind(bound_runner)
                        .fetch_optional(&mut *tx)
                        .await?
                        .ok_or_else(|| ControlPlaneError::NotFound {
                            kind: "runner",
                            id: bound_runner.to_owned(),
                        })?;
                let status: String = row.try_get("status")?;
                if !matches!(status.as_str(), "online" | "draining") {
                    return Err(ControlPlaneError::InvalidTransition {
                        entity: "autoscaled runner",
                        from: "not-online",
                        to: "draining",
                    });
                }
                let bytes: Vec<u8> = row.try_get("runner_json")?;
                let mut runner: RunnerRecord = serde_json::from_slice(&bytes)?;
                runner.status = runtrue_scheduler::RunnerStatus::Draining;
                sqlx::query(
                    "UPDATE runners SET status='draining',runner_json=$2,updated_unix_ms=$3
                     WHERE id=$1",
                )
                .bind(bound_runner)
                .bind(serde_json::to_vec(&runner)?)
                .bind(postgres_i64(now_unix_ms, "runner drain")?)
                .execute(&mut *tx)
                .await?;
            }
            if expected == RunnerFleetRequestState::Draining
                && next == RunnerFleetRequestState::Terminating
            {
                let bound_runner =
                    current
                        .runner_id
                        .as_deref()
                        .ok_or(ControlPlaneError::InvalidTransition {
                            entity: "runner fleet request",
                            from: "draining",
                            to: "terminating",
                        })?;
                let row =
                    sqlx::query("SELECT status,runner_json FROM runners WHERE id=$1 FOR UPDATE")
                        .bind(bound_runner)
                        .fetch_one(&mut *tx)
                        .await?;
                let status: String = row.try_get("status")?;
                let bytes: Vec<u8> = row.try_get("runner_json")?;
                let runner: RunnerRecord = serde_json::from_slice(&bytes)?;
                let open_leases: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM leases
                     WHERE runner_id=$1 AND state IN ('offered','active','cancel_requested')",
                )
                .bind(bound_runner)
                .fetch_one(&mut *tx)
                .await?;
                if status != "draining" || runner.active_jobs != 0 || open_leases != 0 {
                    return Err(ControlPlaneError::InvalidTransition {
                        entity: "autoscaled runner drain",
                        from: "work-or-authority-open",
                        to: "terminating",
                    });
                }
            }
            if expected == RunnerFleetRequestState::Terminating
                && next == RunnerFleetRequestState::Terminated
            {
                if let Some(bound_runner) = current.runner_id.as_deref() {
                    let mut persisted = postgres_runner_tx(&mut tx, bound_runner).await?;
                    persisted.runner.status = runtrue_scheduler::RunnerStatus::Revoked;
                    sqlx::query("UPDATE runners SET status='revoked',runner_json=$2,updated_unix_ms=$3 WHERE id=$1").bind(bound_runner).bind(serde_json::to_vec(&persisted.runner)?).bind(postgres_i64(now_unix_ms,"runner retirement")?).execute(&mut *tx).await?;
                    sqlx::query("UPDATE runner_certificates SET status='revoked',revoked_unix_ms=$2 WHERE runner_id=$1 AND status IN('active','overlap')").bind(bound_runner).bind(postgres_i64(now_unix_ms,"runner retirement")?).execute(&mut *tx).await?;
                    sqlx::query("UPDATE runner_replacements SET state='completed',updated_unix_ms=$2 WHERE source_fleet_request_id=$1 AND state='draining-source'").bind(request_id).bind(postgres_i64(now_unix_ms,"replacement completion")?).execute(&mut *tx).await?;
                }
            }
            let changed = sqlx::query(
                "UPDATE runner_fleet_requests SET state=$3,
                  provider_request_id=COALESCE($4,provider_request_id),
                  provider_instance_id=COALESCE($5,provider_instance_id),
                  runner_id=COALESCE($6,runner_id),failure_code=COALESCE($7,failure_code),
                  updated_unix_ms=$8 WHERE id=$1 AND state=$2",
            )
            .bind(request_id)
            .bind(fleet_state_name(expected))
            .bind(fleet_state_name(next))
            .bind(provider_request_id)
            .bind(provider_instance_id)
            .bind(runner_id)
            .bind(failure_code)
            .bind(postgres_i64(now_unix_ms, "fleet request update")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "runner fleet request",
                    from: fleet_state_name(expected),
                    to: fleet_state_name(next),
                });
            }
            if matches!(
                next,
                RunnerFleetRequestState::Failed | RunnerFleetRequestState::Quarantined
            ) {
                sqlx::query("UPDATE runner_replacements SET state='failed',failure_code=COALESCE($2,'candidate-failed'),updated_unix_ms=$3 WHERE target_fleet_request_id=$1 AND state IN('requested','claim-issued','enrolled','probationary')").bind(request_id).bind(failure_code).bind(postgres_i64(now_unix_ms,"replacement failure")?).execute(&mut *tx).await?;
            }
            let request = postgres_fleet_request_tx(&mut tx, request_id).await?;
            tx.commit().await?;
            Ok(request)
        })
    }

    fn create_pool_enrollment_token<'a>(
        &'a self,
        pool_id: &'a str,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, IssuedEnrollmentToken> {
        Box::pin(async move {
            if expires_unix_ms <= now_unix_ms {
                return Err(ControlPlaneError::InvalidInput(
                    "enrollment expiry must be in the future",
                ));
            }
            let (id, token, token_hash) = new_enrollment_token()?;
            let mut tx = self.pool.begin().await?;
            require_postgres_active_pool(&mut tx, pool_id).await?;
            sqlx::query(
                "INSERT INTO enrollment_tokens
                 (id,pool_id,token_hash,created_unix_ms,expires_unix_ms)
                 VALUES($1,$2,$3,$4,$5)",
            )
            .bind(&id)
            .bind(pool_id)
            .bind(token_hash.as_str())
            .bind(postgres_i64(now_unix_ms, "enrollment creation")?)
            .bind(postgres_i64(expires_unix_ms, "enrollment expiry")?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(IssuedEnrollmentToken {
                metadata: EnrollmentTokenRecord {
                    id,
                    pool_id: pool_id.to_owned(),
                    created_unix_ms: now_unix_ms,
                    expires_unix_ms,
                    consumed_unix_ms: None,
                },
                token: EnrollmentToken::new(token),
            })
        })
    }

    fn create_pool_enrollment_token_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        pool_id: &'a str,
        lifetime_seconds: u64,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, EnrollmentTokenIssueResult> {
        Box::pin(async move {
            let expected_expiry = lifetime_seconds
                .checked_mul(1_000)
                .and_then(|delta| now_unix_ms.checked_add(delta))
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "enrollment expiry",
                })?;
            if idempotency_key.is_empty()
                || idempotency_key.len() > 256
                || idempotency_key.contains('\0')
                || lifetime_seconds == 0
                || expires_unix_ms != expected_expiry
            {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid enrollment idempotency request",
                ));
            }
            let operation = format!("runner-pool.enrollment-token.create:{pool_id}");
            let request_hash =
                ContentDigest::sha256(serde_json::to_vec(&(pool_id, lifetime_seconds))?);
            let mut tx = self.pool.begin().await?;
            require_postgres_active_pool(&mut tx, pool_id).await?;
            let existing = sqlx::query(
                "SELECT request_hash,enrollment_token_id FROM runner_enrollment_idempotency
                 WHERE operation=$1 AND idempotency_key=$2 FOR UPDATE",
            )
            .bind(&operation)
            .bind(idempotency_key)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(row) = existing {
                if row.try_get::<String, _>("request_hash")? != request_hash.as_str() {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let token_id: String = row.try_get("enrollment_token_id")?;
                let token = postgres_enrollment_token_by_id_tx(&mut tx, &token_id).await?;
                tx.commit().await?;
                return Ok(EnrollmentTokenIssueResult::Replayed(token));
            }
            let (id, token, token_hash) = new_enrollment_token()?;
            sqlx::query(
                "INSERT INTO enrollment_tokens
                 (id,pool_id,token_hash,created_unix_ms,expires_unix_ms)
                 VALUES($1,$2,$3,$4,$5)",
            )
            .bind(&id)
            .bind(pool_id)
            .bind(token_hash.as_str())
            .bind(postgres_i64(now_unix_ms, "enrollment creation")?)
            .bind(postgres_i64(expires_unix_ms, "enrollment expiry")?)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO runner_enrollment_idempotency
                 (operation,idempotency_key,request_hash,enrollment_token_id,created_unix_ms)
                 VALUES($1,$2,$3,$4,$5)",
            )
            .bind(&operation)
            .bind(idempotency_key)
            .bind(request_hash.as_str())
            .bind(&id)
            .bind(postgres_i64(now_unix_ms, "enrollment creation")?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(EnrollmentTokenIssueResult::Issued(IssuedEnrollmentToken {
                metadata: EnrollmentTokenRecord {
                    id,
                    pool_id: pool_id.to_owned(),
                    created_unix_ms: now_unix_ms,
                    expires_unix_ms,
                    consumed_unix_ms: None,
                },
                token: EnrollmentToken::new(token),
            }))
        })
    }

    fn consume_pool_enrollment_token<'a>(
        &'a self,
        token: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, EnrollmentTokenRecord> {
        Box::pin(async move {
            validate_token(token)?;
            let hash = enrollment_token_hash(token);
            let mut tx = self.pool.begin().await?;
            let record = postgres_enrollment_token_tx(&mut tx, &hash).await?;
            validate_usable_token(&record, now_unix_ms)?;
            let changed = sqlx::query(
                "UPDATE enrollment_tokens SET consumed_unix_ms=$2
                 WHERE id=$1 AND consumed_unix_ms IS NULL AND expires_unix_ms>$2",
            )
            .bind(&record.id)
            .bind(postgres_i64(now_unix_ms, "enrollment consumption")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::EnrollmentTokenConsumed);
            }
            tx.commit().await?;
            Ok(EnrollmentTokenRecord {
                consumed_unix_ms: Some(now_unix_ms),
                ..record
            })
        })
    }

    fn create_launch_claim<'a>(
        &'a self,
        fleet_request_id: &'a str,
        provider_instance_id: &'a str,
        identity_proof_digest: &'a ContentDigest,
        owner_id: &'a str,
        fencing_generation: u64,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, IssuedRunnerLaunchClaim> {
        Box::pin(async move {
            if expires_unix_ms <= now_unix_ms
                || expires_unix_ms.saturating_sub(now_unix_ms) > 15 * 60 * 1_000
                || provider_instance_id.is_empty()
            {
                return Err(ControlPlaneError::InvalidInput(
                    "launch claim lifetime must be at most fifteen minutes",
                ));
            }
            let (enrollment_id, token, token_hash) = new_enrollment_token()?;
            let claim_id = enrollment_id.replacen("enroll-", "launch-", 1);
            let mut tx = self.pool.begin().await?;
            let request = postgres_fleet_request_tx(&mut tx, fleet_request_id).await?;
            require_postgres_autoscaler_lease(
                &mut tx,
                &request.pool_id,
                owner_id,
                fencing_generation,
                now_unix_ms,
            )
            .await?;
            if request.state != RunnerFleetRequestState::Provisioning {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "runner fleet request",
                    from: fleet_state_name(request.state),
                    to: "bootstrapping",
                });
            }
            sqlx::query(
                "INSERT INTO enrollment_tokens
                 (id,pool_id,token_hash,created_unix_ms,expires_unix_ms)
                 VALUES($1,$2,$3,$4,$5)",
            )
            .bind(&enrollment_id)
            .bind(&request.pool_id)
            .bind(token_hash.as_str())
            .bind(postgres_i64(now_unix_ms, "launch claim creation")?)
            .bind(postgres_i64(expires_unix_ms, "launch claim expiry")?)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO runner_launch_claims
                 (id,fleet_request_id,enrollment_token_id,pool_id,provider,
                  provider_instance_id,runner_template_digest,identity_proof_digest,
                  created_unix_ms,expires_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            )
            .bind(&claim_id)
            .bind(&request.id)
            .bind(&enrollment_id)
            .bind(&request.pool_id)
            .bind(&request.provider)
            .bind(provider_instance_id)
            .bind(request.runner_template_digest.as_str())
            .bind(identity_proof_digest.as_str())
            .bind(postgres_i64(now_unix_ms, "launch claim creation")?)
            .bind(postgres_i64(expires_unix_ms, "launch claim expiry")?)
            .execute(&mut *tx)
            .await?;
            let replacement_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM runner_replacements WHERE target_fleet_request_id=$1)",
            )
            .bind(&request.id)
            .fetch_one(&mut *tx)
            .await?;
            if replacement_exists {
                let update_claim_id = claim_id.replacen("launch-", "update-", 1);
                let inserted = sqlx::query(
                    "INSERT INTO runner_software_update_claims
                     (id,replacement_id,enrollment_token_id,pool_id,mode,source_runner_id,
                      source_posture_digest,fleet_request_id,provider,provider_instance_id,
                      runner_template_digest,identity_proof_digest,generation,artifact_digest,
                      installed_digest,release_id,component_profile_digest,update_root_digest,
                      targets_metadata_digest,snapshot_metadata_digest,timestamp_metadata_digest,
                      policy_version,channel,rollout_ring,protocol_min,protocol_max,
                      required_attestation_grade,attestation_nonce_digest,created_unix_ms,expires_unix_ms)
                     SELECT $1,r.id,$2,r.pool_id,'autoscaled',r.source_runner_id,
                            r.source_posture_digest,r.target_fleet_request_id,$3,$4,$5,$6,
                            r.generation,u.artifact_digest,u.installed_digest,u.id,
                            u.component_profile_digest,u.update_root_digest,u.targets_metadata_digest,
                            u.snapshot_metadata_digest,u.timestamp_metadata_digest,r.policy_version,
                            r.channel,r.rollout_ring,p.protocol_min,p.protocol_max,
                            p.required_attestation_grade,$6,$7,$8
                     FROM runner_replacements r
                     JOIN runner_update_releases u ON u.id=r.release_id AND u.revoked_unix_ms IS NULL
                     JOIN runner_pool_update_policies p ON p.pool_id=r.pool_id
                        AND p.version=r.policy_version AND p.enabled AND NOT p.paused
                     WHERE r.target_fleet_request_id=$9 AND r.state='requested'
                       AND p.runner_template_digest=$5 AND p.channel=r.channel",
                )
                .bind(&update_claim_id).bind(&enrollment_id).bind(&request.provider)
                .bind(provider_instance_id).bind(request.runner_template_digest.as_str())
                .bind(identity_proof_digest.as_str())
                .bind(postgres_i64(now_unix_ms,"update claim creation")?)
                .bind(postgres_i64(expires_unix_ms,"update claim expiry")?)
                .bind(&request.id).execute(&mut *tx).await?.rows_affected();
                if inserted != 1 {
                    return Err(ControlPlaneError::InvalidInput(
                        "software replacement policy or release changed before claim issue",
                    ));
                }
                sqlx::query("UPDATE runner_replacements SET state='claim-issued',updated_unix_ms=$2 WHERE target_fleet_request_id=$1 AND state='requested'")
                    .bind(&request.id).bind(postgres_i64(now_unix_ms,"replacement claim issue")?)
                    .execute(&mut *tx).await?;
            }
            let changed = sqlx::query(
                "UPDATE runner_fleet_requests SET state='bootstrapping',
                 provider_instance_id=$2,updated_unix_ms=$3
                 WHERE id=$1 AND state='provisioning'",
            )
            .bind(&request.id)
            .bind(provider_instance_id)
            .bind(postgres_i64(now_unix_ms, "launch claim creation")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "runner fleet request",
                    from: "provisioning",
                    to: "bootstrapping",
                });
            }
            tx.commit().await?;
            Ok(IssuedRunnerLaunchClaim {
                metadata: RunnerLaunchClaimRecord {
                    id: claim_id,
                    fleet_request_id: request.id,
                    enrollment_token_id: enrollment_id,
                    pool_id: request.pool_id,
                    provider: request.provider,
                    provider_instance_id: provider_instance_id.to_owned(),
                    runner_template_digest: request.runner_template_digest,
                    identity_proof_digest: identity_proof_digest.clone(),
                    created_unix_ms: now_unix_ms,
                    expires_unix_ms,
                    consumed_unix_ms: None,
                    runner_id: None,
                },
                token: RunnerLaunchClaimToken::new(token),
            })
        })
    }

    fn complete_pool_enrollment<'a>(
        &'a self,
        completion: PoolEnrollmentCompletion<'a>,
    ) -> StoreFuture<'a, RunnerEnrollmentReplay> {
        Box::pin(async move {
            let PoolEnrollmentCompletion {
                token,
                request_digest,
                runner,
                certificate,
                certificate_chain_pem,
                inventory_digest,
                selected_protocol_version,
                now_unix_ms,
            } = completion;
            validate_token(token)?;
            validate_new_runner_and_certificate(runner, certificate, now_unix_ms)?;
            if certificate_chain_pem.is_empty() || certificate_chain_pem.len() > 256 * 1024 {
                return Err(ControlPlaneError::InvalidInput(
                    "runner enrollment certificate chain is empty or exceeds its bound",
                ));
            }
            let posture = authoritative_runner_posture_digest(runner, inventory_digest)?;
            let hash = enrollment_token_hash(token);
            let mut tx = self.pool.begin().await?;
            let record = postgres_enrollment_token_tx(&mut tx, &hash).await?;
            if record.consumed_unix_ms.is_some() {
                let replay = sqlx::query(
                    "SELECT * FROM runner_enrollment_replays WHERE enrollment_token_id=$1",
                )
                .bind(&record.id)
                .fetch_optional(&mut *tx)
                .await?
                .map(postgres_enrollment_replay)
                .transpose()?;
                return match replay {
                    Some(value) if value.request_digest == *request_digest => Ok(value),
                    _ => Err(ControlPlaneError::EnrollmentTokenConsumed),
                };
            }
            validate_usable_token(&record, now_unix_ms)?;
            if record.pool_id != runner.pool_id {
                return Err(ControlPlaneError::CertificateIdentityMismatch);
            }
            let software = sqlx::query(
                "SELECT c.replacement_id,c.source_runner_id,c.source_posture_digest,c.generation
                 FROM runner_software_update_claims c
                 JOIN runner_replacements r ON r.id=c.replacement_id AND r.state='claim-issued'
                 JOIN runner_pool_update_policies p ON p.pool_id=c.pool_id AND p.version=c.policy_version
                    AND p.enabled AND NOT p.paused AND p.release_id=c.release_id
                 JOIN runner_update_releases u ON u.id=c.release_id AND u.revoked_unix_ms IS NULL
                 WHERE c.enrollment_token_id=$1 AND c.consumed_unix_ms IS NULL
                   AND c.canceled_unix_ms IS NULL AND c.expires_unix_ms>$2 FOR UPDATE",
            ).bind(&record.id).bind(postgres_i64(now_unix_ms,"update claim validation")?)
                .fetch_optional(&mut *tx).await?;
            if software.is_some()
                != (runner.status == runtrue_scheduler::RunnerStatus::Probationary)
            {
                return Err(ControlPlaneError::CertificateIdentityMismatch);
            }
            if let Some(update) = software.as_ref() {
                let source_id: String = update.try_get("source_runner_id")?;
                let expected: String = update.try_get("source_posture_digest")?;
                let current: Option<String> = sqlx::query_scalar(
                    "SELECT posture_digest FROM runner_enrollment_postures WHERE runner_id=$1",
                )
                .bind(source_id)
                .fetch_optional(&mut *tx)
                .await?;
                if current.as_deref() != Some(&expected) {
                    return Err(ControlPlaneError::InvalidInput(
                        "software update source posture changed",
                    ));
                }
            }
            let pool = require_postgres_active_pool(&mut tx, &record.pool_id).await?;
            if runner.tenant_id != pool.tenant_id
                || pool
                    .region
                    .as_ref()
                    .is_some_and(|region| runner.region.as_ref() != Some(region))
            {
                return Err(ControlPlaneError::CertificateIdentityMismatch);
            }
            sqlx::query(
                "INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$5)",
            )
            .bind(&runner.id)
            .bind(&runner.pool_id)
            .bind(runner_status_name(runner.status))
            .bind(serde_json::to_vec(runner)?)
            .bind(postgres_i64(now_unix_ms, "runner enrollment")?)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO runner_enrollment_postures
                 (runner_id,inventory_digest,posture_digest,created_unix_ms)
                 VALUES($1,$2,$3,$4)",
            )
            .bind(&runner.id)
            .bind(inventory_digest.as_str())
            .bind(posture.as_str())
            .bind(postgres_i64(now_unix_ms, "runner enrollment")?)
            .execute(&mut *tx)
            .await?;
            insert_postgres_certificate(&mut tx, certificate).await?;
            let changed = sqlx::query(
                "UPDATE enrollment_tokens SET consumed_unix_ms=$2
                 WHERE id=$1 AND consumed_unix_ms IS NULL AND expires_unix_ms>$2",
            )
            .bind(&record.id)
            .bind(postgres_i64(now_unix_ms, "enrollment consumption")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::EnrollmentTokenConsumed);
            }
            let claim = sqlx::query_scalar::<_, String>(
                "SELECT fleet_request_id FROM runner_launch_claims
                 WHERE enrollment_token_id=$1 FOR UPDATE",
            )
            .bind(&record.id)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(request_id) = claim {
                let claim_changed = sqlx::query(
                    "UPDATE runner_launch_claims SET consumed_unix_ms=$2,runner_id=$3
                     WHERE enrollment_token_id=$1 AND consumed_unix_ms IS NULL AND runner_id IS NULL",
                )
                .bind(&record.id)
                .bind(postgres_i64(now_unix_ms, "launch claim consumption")?)
                .bind(&runner.id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                let request_changed = sqlx::query(
                    "UPDATE runner_fleet_requests SET state='enrolled',runner_id=$2,
                     updated_unix_ms=$3 WHERE id=$1 AND state='bootstrapping'",
                )
                .bind(&request_id)
                .bind(&runner.id)
                .bind(postgres_i64(now_unix_ms, "fleet enrollment")?)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if claim_changed != 1 || request_changed != 1 {
                    return Err(ControlPlaneError::InvalidTransition {
                        entity: "runner launch claim",
                        from: "bootstrapping",
                        to: "enrolled",
                    });
                }
            }
            if let Some(update) = software {
                let replacement_id: String = update.try_get("replacement_id")?;
                let generation: i64 = update.try_get("generation")?;
                let claim_changed=sqlx::query("UPDATE runner_software_update_claims SET consumed_unix_ms=$2,runner_id=$3 WHERE enrollment_token_id=$1 AND consumed_unix_ms IS NULL AND canceled_unix_ms IS NULL")
                    .bind(&record.id).bind(postgres_i64(now_unix_ms,"update claim consumption")?).bind(&runner.id).execute(&mut *tx).await?.rows_affected();
                let replacement_changed=sqlx::query("UPDATE runner_replacements SET target_runner_id=$2,target_posture_digest=$3,state='probationary',updated_unix_ms=$4 WHERE id=$1 AND generation=$5 AND state='claim-issued'")
                    .bind(replacement_id).bind(&runner.id).bind(posture.as_str()).bind(postgres_i64(now_unix_ms,"replacement enrollment")?).bind(generation).execute(&mut *tx).await?.rows_affected();
                if claim_changed != 1 || replacement_changed != 1 {
                    return Err(ControlPlaneError::InvalidTransition {
                        entity: "software update claim",
                        from: "claim-issued",
                        to: "probationary",
                    });
                }
            }
            sqlx::query("INSERT INTO runner_enrollment_replays(enrollment_token_id,request_digest,runner_id,pool_id,certificate_chain_pem,certificate_expires_unix_ms,authoritative_posture_digest,selected_protocol_version,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                .bind(&record.id).bind(request_digest.as_str()).bind(&runner.id).bind(&runner.pool_id)
                .bind(certificate_chain_pem).bind(postgres_i64(certificate.not_after_unix_ms,"enrollment replay certificate expiry")?)
                .bind(posture.as_str()).bind(i32::try_from(selected_protocol_version).map_err(|_|ControlPlaneError::IntegerRange{field:"selected protocol version"})?)
                .bind(postgres_i64(now_unix_ms,"enrollment replay creation")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(RunnerEnrollmentReplay {
                request_digest: request_digest.clone(),
                runner_id: runner.id.clone(),
                pool_id: runner.pool_id.clone(),
                certificate_chain_pem: certificate_chain_pem.to_vec(),
                certificate_expires_unix_ms: certificate.not_after_unix_ms,
                authoritative_posture_digest: posture,
                selected_protocol_version,
                created_unix_ms: now_unix_ms,
            })
        })
    }

    fn authenticate_pool_runner_certificate<'a>(
        &'a self,
        fingerprint: &'a ContentDigest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, AuthenticatedRunnerCertificate> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            expire_postgres_certificates(&mut tx, now_unix_ms).await?;
            let certificate = postgres_certificate_tx(&mut tx, fingerprint).await?;
            if !certificate_authorized(&certificate, now_unix_ms) {
                return Err(ControlPlaneError::RunnerCertificateUnauthorized);
            }
            let runner = postgres_runner_tx(&mut tx, &certificate.runner_id).await?;
            let pool = require_postgres_active_pool(&mut tx, &certificate.pool_id).await?;
            if runner.runner.pool_id != pool.id
                || matches!(
                    runner.runner.status,
                    runtrue_scheduler::RunnerStatus::Revoked
                        | runtrue_scheduler::RunnerStatus::Quarantined
                )
            {
                return Err(ControlPlaneError::RunnerCertificateUnauthorized);
            }
            tx.commit().await?;
            Ok(AuthenticatedRunnerCertificate {
                runner,
                certificate,
            })
        })
    }

    fn rotate_pool_runner_certificate<'a>(
        &'a self,
        authenticated_fingerprint: &'a ContentDigest,
        runner_id: &'a str,
        csr_digest: &'a ContentDigest,
        certificate: &'a RunnerCertificateRecord,
        certificate_chain_pem: &'a [u8],
        now_unix_ms: u64,
        overlap_millis: u64,
    ) -> StoreFuture<'a, IdempotentResult<RunnerCertificateRotationRecord>> {
        Box::pin(async move {
            if certificate_chain_pem.is_empty() || certificate_chain_pem.len() > 256 * 1024 {
                return Err(ControlPlaneError::InvalidRunnerCertificateChain);
            }
            let mut tx = self.pool.begin().await?;
            if let Some(existing) =
                postgres_certificate_rotation_tx(&mut tx, authenticated_fingerprint).await?
            {
                if existing.runner_id != runner_id || existing.csr_digest != *csr_digest {
                    return Err(ControlPlaneError::RunnerCertificateRotationConflict);
                }
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value: existing,
                    replayed: true,
                });
            }
            validate_new_certificate(certificate, now_unix_ms)?;
            if certificate.runner_id != runner_id
                || overlap_millis == 0
                || certificate.fingerprint == *authenticated_fingerprint
            {
                return Err(ControlPlaneError::CertificateIdentityMismatch);
            }
            expire_postgres_certificates(&mut tx, now_unix_ms).await?;
            let current = postgres_certificate_tx(&mut tx, authenticated_fingerprint).await?;
            if current.runner_id != runner_id
                || current.pool_id != certificate.pool_id
                || current.status != crate::RunnerCertificateStatus::Active
                || !certificate_authorized(&current, now_unix_ms)
            {
                return Err(ControlPlaneError::RunnerCertificateUnauthorized);
            }
            let runner = postgres_runner_tx(&mut tx, runner_id).await?;
            require_postgres_active_pool(&mut tx, &current.pool_id).await?;
            if matches!(
                runner.runner.status,
                runtrue_scheduler::RunnerStatus::Revoked
                    | runtrue_scheduler::RunnerStatus::Quarantined
            ) {
                return Err(ControlPlaneError::RunnerCertificateUnauthorized);
            }
            let requested_overlap =
                now_unix_ms
                    .checked_add(overlap_millis)
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "certificate overlap deadline",
                    })?;
            sqlx::query(
                "UPDATE runner_certificates SET status='revoked',revoked_unix_ms=$2
                 WHERE runner_id=$1 AND status='overlap'",
            )
            .bind(runner_id)
            .bind(postgres_i64(now_unix_ms, "certificate revoked")?)
            .execute(&mut *tx)
            .await?;
            let overlap_until = requested_overlap.min(current.not_after_unix_ms);
            let changed = sqlx::query(
                "UPDATE runner_certificates SET status='overlap',overlap_until_unix_ms=$2
                 WHERE fingerprint=$1 AND status='active'",
            )
            .bind(authenticated_fingerprint.as_str())
            .bind(postgres_i64(overlap_until, "certificate overlap deadline")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::RunnerCertificateUnauthorized);
            }
            insert_postgres_certificate(&mut tx, certificate).await?;
            let record = RunnerCertificateRotationRecord {
                old_fingerprint: authenticated_fingerprint.clone(),
                runner_id: runner_id.to_owned(),
                pool_id: current.pool_id,
                csr_digest: csr_digest.clone(),
                new_certificate: certificate.clone(),
                certificate_chain_pem: certificate_chain_pem.to_vec(),
                created_unix_ms: now_unix_ms,
            };
            sqlx::query(
                "INSERT INTO runner_certificate_rotations
                 (old_fingerprint,runner_id,pool_id,csr_digest,new_fingerprint,
                  new_certificate_json,certificate_chain_pem,created_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(record.old_fingerprint.as_str())
            .bind(&record.runner_id)
            .bind(&record.pool_id)
            .bind(record.csr_digest.as_str())
            .bind(record.new_certificate.fingerprint.as_str())
            .bind(serde_json::to_vec(&record.new_certificate)?)
            .bind(&record.certificate_chain_pem)
            .bind(postgres_i64(
                record.created_unix_ms,
                "certificate rotation",
            )?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: record,
                replayed: false,
            })
        })
    }

    fn pool_runner_certificate<'a>(
        &'a self,
        fingerprint: &'a ContentDigest,
    ) -> StoreFuture<'a, RunnerCertificateRecord> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let certificate = postgres_certificate_tx(&mut tx, fingerprint).await?;
            tx.commit().await?;
            Ok(certificate)
        })
    }

    fn pool_runner_certificate_rotation<'a>(
        &'a self,
        old_fingerprint: &'a ContentDigest,
    ) -> StoreFuture<'a, Option<RunnerCertificateRotationRecord>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let rotation = postgres_certificate_rotation_tx(&mut tx, old_fingerprint).await?;
            tx.commit().await?;
            Ok(rotation)
        })
    }

    fn register_pool_runner<'a>(
        &'a self,
        runner: &'a RunnerRecord,
        inventory_digest: &'a ContentDigest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ContentDigest> {
        Box::pin(async move {
            if runner.id.is_empty()
                || runner.pool_id.is_empty()
                || runner.tenant_id.is_empty()
                || runner.logical_cpus == 0
                || runner.memory_bytes == 0
                || runner.storage_bytes == 0
                || runner.isolation_backends.is_empty()
            {
                return Err(ControlPlaneError::InvalidInput("invalid runner inventory"));
            }
            let posture = authoritative_runner_posture_digest(runner, inventory_digest)?;
            let mut tx = self.pool.begin().await?;
            let pool = require_postgres_active_pool(&mut tx, &runner.pool_id).await?;
            if runner.tenant_id != pool.tenant_id
                || pool
                    .region
                    .as_ref()
                    .is_some_and(|region| runner.region.as_ref() != Some(region))
            {
                return Err(ControlPlaneError::InvalidInput(
                    "runner does not match its authoritative pool",
                ));
            }
            sqlx::query(
                "INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$5)",
            )
            .bind(&runner.id)
            .bind(&runner.pool_id)
            .bind(runner_status_name(runner.status))
            .bind(serde_json::to_vec(runner)?)
            .bind(postgres_i64(now_unix_ms, "runner registration")?)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO runner_enrollment_postures
                 (runner_id,inventory_digest,posture_digest,created_unix_ms)
                 VALUES($1,$2,$3,$4)",
            )
            .bind(&runner.id)
            .bind(inventory_digest.as_str())
            .bind(posture.as_str())
            .bind(postgres_i64(now_unix_ms, "runner registration")?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(posture)
        })
    }

    fn pool_runner<'a>(&'a self, runner_id: &'a str) -> StoreFuture<'a, PersistedRunner> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let runner = postgres_runner_tx(&mut tx, runner_id).await?;
            tx.commit().await?;
            Ok(runner)
        })
    }

    fn set_pool_runner_connected<'a>(
        &'a self,
        runner_id: &'a str,
        connected: bool,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, PersistedRunner> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let mut persisted = postgres_runner_tx(&mut tx, runner_id).await?;
            if matches!(
                persisted.runner.status,
                runtrue_scheduler::RunnerStatus::Revoked
                    | runtrue_scheduler::RunnerStatus::Quarantined
            ) {
                return Err(ControlPlaneError::InvalidInput(
                    "runner connection state cannot be updated",
                ));
            }
            persisted.runner.status = if connected {
                runtrue_scheduler::RunnerStatus::Online
            } else {
                runtrue_scheduler::RunnerStatus::Offline
            };
            persisted.runner.last_heartbeat_unix_ms = now_unix_ms;
            persisted.updated_unix_ms = now_unix_ms;
            sqlx::query(
                "UPDATE runners SET status=$2,runner_json=$3,updated_unix_ms=$4 WHERE id=$1",
            )
            .bind(runner_id)
            .bind(runner_status_name(persisted.runner.status))
            .bind(serde_json::to_vec(&persisted.runner)?)
            .bind(postgres_i64(now_unix_ms, "runner connection update")?)
            .execute(&mut *tx)
            .await?;
            if connected {
                sqlx::query(
                    "UPDATE runner_fleet_requests SET state='online',updated_unix_ms=$2
                     WHERE runner_id=$1 AND state='enrolled'",
                )
                .bind(runner_id)
                .bind(postgres_i64(now_unix_ms, "runner online transition")?)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(persisted)
        })
    }

    fn pool_fleet_snapshot<'a>(
        &'a self,
        pool_id: &'a str,
        observed_unix_ms: u64,
    ) -> StoreFuture<'a, crate::RunnerPoolFleetSnapshot> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let pool = sqlx::query("SELECT tenant_id FROM runner_pools WHERE id=$1")
                .bind(pool_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| ControlPlaneError::NotFound {
                    kind: "runner pool",
                    id: pool_id.to_owned(),
                })?;
            let tenant_id: String = pool.try_get("tenant_id")?;
            let queued = sqlx::query(
                "SELECT j.requirements_json FROM jobs j JOIN runs r ON r.id=j.run_id
                 JOIN repositories repo ON repo.id=r.repository_id
                 WHERE repo.tenant_id=$1 AND j.status='queued' AND r.remote=TRUE
                   AND r.status IN ('created','running') ORDER BY j.id",
            )
            .bind(&tenant_id)
            .fetch_all(&mut *tx)
            .await?;
            let rows = sqlx::query(
                "SELECT runner_json,created_unix_ms,updated_unix_ms FROM runners
                 WHERE pool_id=$1 ORDER BY id",
            )
            .bind(pool_id)
            .fetch_all(&mut *tx)
            .await?;
            let runners = rows
                .into_iter()
                .map(|row| {
                    Ok(PersistedRunner {
                        runner: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("runner_json")?)?,
                        created_unix_ms: postgres_u64(
                            row.try_get("created_unix_ms")?,
                            "runner creation",
                        )?,
                        updated_unix_ms: postgres_u64(
                            row.try_get("updated_unix_ms")?,
                            "runner update",
                        )?,
                    })
                })
                .collect::<Result<Vec<_>, ControlPlaneError>>()?;
            let reserved_rows = sqlx::query(
                "SELECT l.runner_id,j.requirements_json FROM leases l
                 JOIN jobs j ON j.id=l.job_id JOIN runners rr ON rr.id=l.runner_id
                 WHERE rr.pool_id=$1 AND l.state IN ('offered','active','cancel_requested')
                 ORDER BY l.runner_id,l.id",
            )
            .bind(pool_id)
            .fetch_all(&mut *tx)
            .await?;
            let mut reserved_by_runner = std::collections::BTreeMap::<
                String,
                Vec<runtrue_scheduler::SchedulingRequirements>,
            >::new();
            for row in reserved_rows {
                reserved_by_runner
                    .entry(row.try_get("runner_id")?)
                    .or_default()
                    .push(serde_json::from_slice(
                        &row.try_get::<Vec<u8>, _>("requirements_json")?,
                    )?);
            }
            let mut demand = std::collections::BTreeMap::new();
            for row in queued {
                let requirements: runtrue_scheduler::SchedulingRequirements =
                    serde_json::from_slice(&row.try_get::<Vec<u8>, _>("requirements_json")?)?;
                if !requirements.allowed_pools.is_empty()
                    && !requirements.allowed_pools.contains(pool_id)
                {
                    continue;
                }
                let digest = runtime_digest(&requirements)?;
                demand
                    .entry(digest)
                    .or_insert_with(|| (requirements, 0_u64))
                    .1 += 1;
            }
            let pending = sqlx::query(
                "SELECT runtime_compatibility_digest,COUNT(*)::BIGINT AS count
                 FROM runner_fleet_requests WHERE pool_id=$1 AND state IN
                 ('requested','provisioning','bootstrapping','enrolled')
                 GROUP BY runtime_compatibility_digest",
            )
            .bind(pool_id)
            .fetch_all(&mut *tx)
            .await?;
            let pending = pending
                .into_iter()
                .map(|row| {
                    Ok((
                        ContentDigest::parse(
                            row.try_get::<String, _>("runtime_compatibility_digest")?,
                        )?,
                        postgres_u64(row.try_get("count")?, "pending workers")?,
                    ))
                })
                .collect::<Result<std::collections::BTreeMap<_, _>, ControlPlaneError>>()?;
            let groups = demand
                .into_iter()
                .map(|(digest, (requirements, queued_jobs))| {
                    let active_slots = runners
                        .iter()
                        .filter(|value| {
                            value.runner.status == runtrue_scheduler::RunnerStatus::Online
                        })
                        .map(|value| {
                            reserved_by_runner.get(&value.runner.id).map_or(0, |items| {
                                items.iter().filter(|item| *item == &requirements).count() as u64
                            })
                        })
                        .sum();
                    let available_slots = runners
                        .iter()
                        .filter(|value| {
                            value.runner.status == runtrue_scheduler::RunnerStatus::Online
                        })
                        .map(|value| {
                            postgres_available_slots(
                                &value.runner,
                                &requirements,
                                reserved_by_runner
                                    .get(&value.runner.id)
                                    .map_or(&[], Vec::as_slice),
                            )
                        })
                        .sum();
                    let slots_per_worker =
                        if requirements.isolation == runtrue_workflow_ir::Isolation::Wasm {
                            runners
                                .iter()
                                .filter(|value| runner_serves(&value.runner, &requirements))
                                .map(|value| u64::from(value.runner.max_concurrent_wasm_jobs))
                                .min()
                                .unwrap_or(1)
                        } else {
                            1
                        };
                    let pending_workers = pending.get(&digest).copied().unwrap_or(0);
                    crate::RunnerDemandGroup {
                        runtime_compatibility_digest: digest.clone(),
                        requirements,
                        queued_jobs,
                        active_slots,
                        available_slots,
                        pending_slots: pending_workers.saturating_mul(slots_per_worker),
                        slots_per_worker,
                    }
                })
                .collect();
            let mut snapshot = crate::RunnerPoolFleetSnapshot {
                pool_id: pool_id.to_owned(),
                observed_unix_ms,
                demand: groups,
                online_workers: 0,
                draining_workers: 0,
                offline_workers: 0,
                quarantined_workers: 0,
            };
            for runner in runners {
                match runner.runner.status {
                    runtrue_scheduler::RunnerStatus::Online => snapshot.online_workers += 1,
                    runtrue_scheduler::RunnerStatus::Draining => snapshot.draining_workers += 1,
                    runtrue_scheduler::RunnerStatus::Quarantined => {
                        snapshot.quarantined_workers += 1
                    }
                    runtrue_scheduler::RunnerStatus::Probationary
                    | runtrue_scheduler::RunnerStatus::Offline
                    | runtrue_scheduler::RunnerStatus::Revoked => snapshot.offline_workers += 1,
                }
            }
            tx.commit().await?;
            Ok(snapshot)
        })
    }
}

fn validate_pool_configuration(
    configuration: &RunnerPoolConfiguration,
) -> Result<(), ControlPlaneError> {
    let pool = &configuration.pool;
    if pool.id.is_empty() || pool.tenant_id.is_empty() || pool.name.is_empty() {
        return Err(ControlPlaneError::InvalidInput("invalid runner pool"));
    }
    if let Some(policy) = &configuration.scaling_policy {
        if policy.pool_id != pool.id
            || policy.maximum_workers == 0
            || policy.minimum_workers > policy.maximum_workers
            || policy.minimum_idle_workers > policy.maximum_workers
            || policy.scale_up_batch == 0
            || policy.scale_up_batch > policy.maximum_workers
            || policy.idle_timeout_ms == 0
            || policy.offline_grace_ms == 0
            || policy.cooldown_ms == 0
            || ((policy.minimum_workers > 0 || policy.minimum_idle_workers > 0)
                && policy.baseline_runtime_compatibility_digest.is_none())
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid runner pool scaling policy",
            ));
        }
    }
    for template in &configuration.templates {
        if template.pool_id != pool.id
            || template.provider.is_empty()
            || template.provider_template_id.is_empty()
            || template.updated_unix_ms < template.created_unix_ms
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid runner pool template",
            ));
        }
    }
    Ok(())
}

fn pool_status_name(status: RunnerPoolStatus) -> &'static str {
    match status {
        RunnerPoolStatus::Active => "active",
        RunnerPoolStatus::Disabled => "disabled",
    }
}

#[cfg(feature = "postgres")]
fn runner_status_name(status: runtrue_scheduler::RunnerStatus) -> &'static str {
    match status {
        runtrue_scheduler::RunnerStatus::Probationary => "probationary",
        runtrue_scheduler::RunnerStatus::Online => "online",
        runtrue_scheduler::RunnerStatus::Draining => "draining",
        runtrue_scheduler::RunnerStatus::Quarantined => "quarantined",
        runtrue_scheduler::RunnerStatus::Offline => "offline",
        runtrue_scheduler::RunnerStatus::Revoked => "revoked",
    }
}

#[cfg(feature = "postgres")]
fn transient_postgres_rejection(code: &str) -> bool {
    matches!(
        code,
        "capsule_fetch_failed"
            | "image_admission_pending"
            | "unsupported_isolation"
            | "trusted_native_disabled"
            | "job_resource_limit"
            | "executor_preflight_rejected"
            | "accept_deadline_elapsed"
            | "lease_window_too_short"
    )
}

#[cfg(feature = "postgres")]
fn runtime_digest(
    requirements: &runtrue_scheduler::SchedulingRequirements,
) -> Result<ContentDigest, ControlPlaneError> {
    let mut encoded = b"runtrue.runner.runtime-compatibility.v1\0".to_vec();
    encoded.extend_from_slice(&serde_json::to_vec(requirements)?);
    Ok(ContentDigest::sha256(encoded))
}

#[cfg(feature = "postgres")]
fn runner_serves(
    runner: &RunnerRecord,
    requirements: &runtrue_scheduler::SchedulingRequirements,
) -> bool {
    runner.status == runtrue_scheduler::RunnerStatus::Online
        && runner.os == requirements.os
        && runner.arch == requirements.arch
        && runner.isolation_backends.contains(&requirements.isolation)
        && requirements
            .region
            .as_ref()
            .is_none_or(|region| runner.region.as_ref() == Some(region))
        && (requirements.allowed_pools.is_empty()
            || requirements.allowed_pools.contains(&runner.pool_id))
        && requirements
            .required_capabilities
            .is_subset(&runner.verified_capabilities)
        && runner.logical_cpus.saturating_sub(runner.used_cpus) >= requirements.cpu
        && runner.memory_bytes.saturating_sub(runner.used_memory_bytes) >= requirements.memory_bytes
        && runner
            .storage_bytes
            .saturating_sub(runner.used_storage_bytes)
            >= requirements.storage_bytes
}

#[cfg(feature = "postgres")]
const MAX_POSTGRES_RUNNER_JOB_REJECTIONS: u64 = 3;

#[cfg(feature = "postgres")]
async fn all_postgres_eligible_runners_exhausted(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    job_id: &str,
    requirements: &runtrue_scheduler::SchedulingRequirements,
) -> Result<bool, ControlPlaneError> {
    let rows = sqlx::query(
        "SELECT r.id,r.runner_json,p.status,p.region
         FROM runners r JOIN runner_pools p ON p.id=r.pool_id
         WHERE p.tenant_id=$1 ORDER BY r.id",
    )
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut eligible = Vec::new();
    for row in rows {
        if row.try_get::<String, _>("status")? != "active" {
            continue;
        }
        let pool_region: Option<String> = row.try_get("region")?;
        let mut runner: RunnerRecord =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("runner_json")?)?;
        if pool_region
            .as_deref()
            .is_some_and(|region| runner.region.as_deref() != Some(region))
        {
            continue;
        }
        runner.used_cpus = 0;
        runner.used_memory_bytes = 0;
        runner.used_storage_bytes = 0;
        if runner_serves(&runner, requirements) {
            eligible.push(row.try_get::<String, _>("id")?);
        }
    }
    if eligible.is_empty() {
        return Ok(false);
    }
    for runner_id in eligible {
        let exhausted: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM runner_job_rejections
                WHERE runner_id=$1 AND job_id=$2
                  AND rejection_count >= $3
                  AND last_code <> 'image_admission_pending')",
        )
        .bind(runner_id)
        .bind(job_id)
        .bind(
            i64::try_from(MAX_POSTGRES_RUNNER_JOB_REJECTIONS).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "runner rejection threshold",
                }
            })?,
        )
        .fetch_one(&mut **tx)
        .await?;
        if !exhausted {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(feature = "postgres")]
fn postgres_available_slots(
    runner: &RunnerRecord,
    requirements: &runtrue_scheduler::SchedulingRequirements,
    reserved: &[runtrue_scheduler::SchedulingRequirements],
) -> u64 {
    if !runner_serves(runner, requirements) {
        return 0;
    }
    if requirements.isolation != runtrue_workflow_ir::Isolation::Wasm {
        return u64::from(reserved.is_empty());
    }
    if reserved
        .iter()
        .any(|item| item.isolation != runtrue_workflow_ir::Isolation::Wasm)
    {
        return 0;
    }
    let used_cpu = reserved
        .iter()
        .fold(0_u64, |sum, item| sum.saturating_add(u64::from(item.cpu)));
    let used_memory = reserved
        .iter()
        .fold(0_u64, |sum, item| sum.saturating_add(item.memory_bytes));
    let used_storage = reserved
        .iter()
        .fold(0_u64, |sum, item| sum.saturating_add(item.storage_bytes));
    let concurrency =
        u64::from(runner.max_concurrent_wasm_jobs).saturating_sub(reserved.len() as u64);
    let cpu = u64::from(runner.logical_cpus).saturating_sub(used_cpu)
        / u64::from(requirements.cpu.max(1));
    let memory = runner.memory_bytes.saturating_sub(used_memory) / requirements.memory_bytes.max(1);
    let storage = if requirements.storage_bytes == 0 {
        u64::MAX
    } else {
        runner.storage_bytes.saturating_sub(used_storage) / requirements.storage_bytes
    };
    concurrency.min(cpu).min(memory).min(storage)
}

#[cfg(feature = "postgres")]
fn parse_pool_status(value: &str) -> Result<RunnerPoolStatus, ControlPlaneError> {
    match value {
        "active" => Ok(RunnerPoolStatus::Active),
        "disabled" => Ok(RunnerPoolStatus::Disabled),
        _ => Err(ControlPlaneError::CorruptState(
            "unknown PostgreSQL runner pool status".to_owned(),
        )),
    }
}

#[cfg(feature = "postgres")]
fn postgres_pool(row: sqlx::postgres::PgRow) -> Result<RunnerPoolRecord, ControlPlaneError> {
    Ok(RunnerPoolRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        region: row.try_get("region")?,
        status: parse_pool_status(row.try_get::<String, _>("status")?.as_str())?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "pool creation")?,
    })
}

#[cfg(feature = "postgres")]
fn pg_u32(value: i32, field: &'static str) -> Result<u32, ControlPlaneError> {
    u32::try_from(value)
        .map_err(|_| ControlPlaneError::CorruptState(format!("PostgreSQL {field} is negative")))
}

#[cfg(feature = "postgres")]
fn postgres_policy(
    row: sqlx::postgres::PgRow,
) -> Result<RunnerPoolScalingPolicy, ControlPlaneError> {
    Ok(RunnerPoolScalingPolicy {
        pool_id: row.try_get("pool_id")?,
        baseline_runtime_compatibility_digest: row
            .try_get::<Option<String>, _>("baseline_runtime_compatibility_digest")?
            .map(ContentDigest::parse)
            .transpose()?,
        minimum_workers: pg_u32(row.try_get("minimum_workers")?, "minimum workers")?,
        minimum_idle_workers: pg_u32(row.try_get("minimum_idle_workers")?, "minimum idle workers")?,
        maximum_workers: pg_u32(row.try_get("maximum_workers")?, "maximum workers")?,
        scale_up_batch: pg_u32(row.try_get("scale_up_batch")?, "scale up batch")?,
        idle_timeout_ms: postgres_u64(row.try_get("idle_timeout_ms")?, "idle timeout")?,
        offline_grace_ms: postgres_u64(row.try_get("offline_grace_ms")?, "offline grace")?,
        cooldown_ms: postgres_u64(row.try_get("cooldown_ms")?, "autoscaler cooldown")?,
        enabled: row.try_get("enabled")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "policy update")?,
    })
}

#[cfg(feature = "postgres")]
fn postgres_template(
    row: sqlx::postgres::PgRow,
) -> Result<RunnerPoolTemplateRecord, ControlPlaneError> {
    Ok(RunnerPoolTemplateRecord {
        pool_id: row.try_get("pool_id")?,
        runtime_compatibility_digest: ContentDigest::parse(
            row.try_get::<String, _>("runtime_compatibility_digest")?,
        )?,
        provider: row.try_get("provider")?,
        provider_template_id: row.try_get("provider_template_id")?,
        runner_template_digest: ContentDigest::parse(
            row.try_get::<String, _>("runner_template_digest")?,
        )?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "template creation")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "template update")?,
    })
}

#[cfg(feature = "postgres")]
async fn require_postgres_active_pool(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_id: &str,
) -> Result<RunnerPoolRecord, ControlPlaneError> {
    let row = sqlx::query("SELECT * FROM runner_pools WHERE id=$1 AND status='active' FOR UPDATE")
        .bind(pool_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| ControlPlaneError::NotFound {
            kind: "active runner pool",
            id: pool_id.to_owned(),
        })?;
    postgres_pool(row)
}

#[cfg(feature = "postgres")]
async fn require_postgres_autoscaler_lease(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_id: &str,
    owner_id: &str,
    generation: u64,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM runner_autoscaler_leases
         WHERE pool_id=$1 AND owner_id=$2 AND fencing_generation=$3 AND expires_unix_ms>$4)",
    )
    .bind(pool_id)
    .bind(owner_id)
    .bind(postgres_i64(generation, "autoscaler generation")?)
    .bind(postgres_i64(now_unix_ms, "autoscaler observation")?)
    .fetch_one(&mut **tx)
    .await?;
    if valid {
        Ok(())
    } else {
        Err(ControlPlaneError::RunnerAutoscalerLeaseLost)
    }
}

#[cfg(feature = "postgres")]
async fn postgres_fleet_request_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: &str,
) -> Result<RunnerFleetRequestRecord, ControlPlaneError> {
    let row = sqlx::query("SELECT * FROM runner_fleet_requests WHERE id=$1 FOR UPDATE")
        .bind(request_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| ControlPlaneError::NotFound {
            kind: "runner fleet request",
            id: request_id.to_owned(),
        })?;
    postgres_fleet_request(row)
}

#[cfg(feature = "postgres")]
fn postgres_fleet_request(
    row: sqlx::postgres::PgRow,
) -> Result<RunnerFleetRequestRecord, ControlPlaneError> {
    Ok(RunnerFleetRequestRecord {
        id: row.try_get("id")?,
        pool_id: row.try_get("pool_id")?,
        runtime_compatibility_digest: ContentDigest::parse(
            row.try_get::<String, _>("runtime_compatibility_digest")?,
        )?,
        provider: row.try_get("provider")?,
        provider_template_id: row.try_get("provider_template_id")?,
        runner_template_digest: ContentDigest::parse(
            row.try_get::<String, _>("runner_template_digest")?,
        )?,
        state: parse_fleet_state(row.try_get::<String, _>("state")?.as_str())?,
        provider_request_id: row.try_get("provider_request_id")?,
        provider_instance_id: row.try_get("provider_instance_id")?,
        runner_id: row.try_get("runner_id")?,
        failure_code: row.try_get("failure_code")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "fleet creation")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "fleet update")?,
    })
}

#[cfg(feature = "postgres")]
fn postgres_launch_claim(
    row: sqlx::postgres::PgRow,
) -> Result<RunnerLaunchClaimRecord, ControlPlaneError> {
    Ok(RunnerLaunchClaimRecord {
        id: row.try_get("id")?,
        fleet_request_id: row.try_get("fleet_request_id")?,
        enrollment_token_id: row.try_get("enrollment_token_id")?,
        pool_id: row.try_get("pool_id")?,
        provider: row.try_get("provider")?,
        provider_instance_id: row.try_get("provider_instance_id")?,
        runner_template_digest: ContentDigest::parse(
            row.try_get::<String, _>("runner_template_digest")?,
        )?,
        identity_proof_digest: ContentDigest::parse(
            row.try_get::<String, _>("identity_proof_digest")?,
        )?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "launch claim creation")?,
        expires_unix_ms: postgres_u64(row.try_get("expires_unix_ms")?, "launch claim expiry")?,
        consumed_unix_ms: row
            .try_get::<Option<i64>, _>("consumed_unix_ms")?
            .map(|value| postgres_u64(value, "launch claim consumption"))
            .transpose()?,
        runner_id: row.try_get("runner_id")?,
    })
}

#[cfg(feature = "postgres")]
fn postgres_enrollment_replay(
    row: sqlx::postgres::PgRow,
) -> Result<RunnerEnrollmentReplay, ControlPlaneError> {
    Ok(RunnerEnrollmentReplay {
        request_digest: ContentDigest::parse(row.try_get::<String, _>("request_digest")?)?,
        runner_id: row.try_get("runner_id")?,
        pool_id: row.try_get("pool_id")?,
        certificate_chain_pem: row.try_get("certificate_chain_pem")?,
        certificate_expires_unix_ms: postgres_u64(
            row.try_get("certificate_expires_unix_ms")?,
            "enrollment replay certificate expiry",
        )?,
        authoritative_posture_digest: ContentDigest::parse(
            row.try_get::<String, _>("authoritative_posture_digest")?,
        )?,
        selected_protocol_version: u32::try_from(
            row.try_get::<i32, _>("selected_protocol_version")?,
        )
        .map_err(|_| ControlPlaneError::IntegerRange {
            field: "selected protocol version",
        })?,
        created_unix_ms: postgres_u64(
            row.try_get("created_unix_ms")?,
            "enrollment replay creation",
        )?,
    })
}

#[cfg(feature = "postgres")]
fn postgres_software_update_claim(
    row: sqlx::postgres::PgRow,
) -> Result<RunnerSoftwareUpdateClaim, ControlPlaneError> {
    let mode = match row.try_get::<String, _>("mode")?.as_str() {
        "autoscaled" => RunnerReplacementMode::Autoscaled,
        "fixed-host" => RunnerReplacementMode::FixedHost,
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "unknown PostgreSQL runner replacement mode".to_owned(),
            ))
        }
    };
    let digest = |name: &str| -> Result<ContentDigest, ControlPlaneError> {
        Ok(ContentDigest::parse(row.try_get::<String, _>(name)?)?)
    };
    let optional_digest = |name: &str| -> Result<Option<ContentDigest>, ControlPlaneError> {
        row.try_get::<Option<String>, _>(name)?
            .map(ContentDigest::parse)
            .transpose()
            .map_err(Into::into)
    };
    let optional_time = |name: &str| -> Result<Option<u64>, ControlPlaneError> {
        row.try_get::<Option<i64>, _>(name)?
            .map(|value| postgres_u64(value, "software update claim time"))
            .transpose()
    };
    Ok(RunnerSoftwareUpdateClaim {
        id: row.try_get("id")?,
        replacement_id: row.try_get("replacement_id")?,
        enrollment_token_id: row.try_get("enrollment_token_id")?,
        pool_id: row.try_get("pool_id")?,
        mode,
        source_runner_id: row.try_get("source_runner_id")?,
        source_posture_digest: digest("source_posture_digest")?,
        runner_slot_id: row.try_get("runner_slot_id")?,
        fleet_request_id: row.try_get("fleet_request_id")?,
        provider: row.try_get("provider")?,
        provider_instance_id: row.try_get("provider_instance_id")?,
        updater_identity_digest: optional_digest("updater_identity_digest")?,
        runner_template_digest: digest("runner_template_digest")?,
        identity_proof_digest: digest("identity_proof_digest")?,
        generation: postgres_u64(row.try_get("generation")?, "update generation")?,
        artifact_digest: digest("artifact_digest")?,
        installed_digest: digest("installed_digest")?,
        release_id: row.try_get("release_id")?,
        component_profile_digest: digest("component_profile_digest")?,
        update_root_digest: digest("update_root_digest")?,
        targets_metadata_digest: digest("targets_metadata_digest")?,
        snapshot_metadata_digest: digest("snapshot_metadata_digest")?,
        timestamp_metadata_digest: digest("timestamp_metadata_digest")?,
        policy_version: postgres_u64(row.try_get("policy_version")?, "update policy version")?,
        channel: row.try_get("channel")?,
        rollout_ring: u32::try_from(postgres_u64(row.try_get("rollout_ring")?, "rollout ring")?)
            .map_err(|_| ControlPlaneError::IntegerRange {
                field: "rollout ring",
            })?,
        protocol_min: u32::try_from(row.try_get::<i32, _>("protocol_min")?).map_err(|_| {
            ControlPlaneError::IntegerRange {
                field: "protocol minimum",
            }
        })?,
        protocol_max: u32::try_from(row.try_get::<i32, _>("protocol_max")?).map_err(|_| {
            ControlPlaneError::IntegerRange {
                field: "protocol maximum",
            }
        })?,
        required_attestation_grade: row.try_get("required_attestation_grade")?,
        attestation_nonce_digest: digest("attestation_nonce_digest")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "update claim creation")?,
        expires_unix_ms: postgres_u64(row.try_get("expires_unix_ms")?, "update claim expiry")?,
        canceled_unix_ms: optional_time("canceled_unix_ms")?,
        consumed_unix_ms: optional_time("consumed_unix_ms")?,
        runner_id: row.try_get("runner_id")?,
    })
}

#[cfg(feature = "postgres")]
fn postgres_replacement(
    row: sqlx::postgres::PgRow,
) -> Result<RunnerReplacementRecord, ControlPlaneError> {
    let mode = match row.try_get::<String, _>("mode")?.as_str() {
        "autoscaled" => RunnerReplacementMode::Autoscaled,
        "fixed-host" => RunnerReplacementMode::FixedHost,
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "unknown replacement mode".to_owned(),
            ))
        }
    };
    let state = match row.try_get::<String, _>("state")?.as_str() {
        "requested" => RunnerReplacementState::Requested,
        "claim-issued" => RunnerReplacementState::ClaimIssued,
        "enrolled" => RunnerReplacementState::Enrolled,
        "probationary" => RunnerReplacementState::Probationary,
        "active" => RunnerReplacementState::Active,
        "draining-source" => RunnerReplacementState::DrainingSource,
        "completed" => RunnerReplacementState::Completed,
        "failed" => RunnerReplacementState::Failed,
        "canceled" => RunnerReplacementState::Canceled,
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "unknown replacement state".to_owned(),
            ))
        }
    };
    Ok(RunnerReplacementRecord {
        id: row.try_get("id")?,
        pool_id: row.try_get("pool_id")?,
        mode,
        source_runner_id: row.try_get("source_runner_id")?,
        source_posture_digest: ContentDigest::parse(
            row.try_get::<String, _>("source_posture_digest")?,
        )?,
        target_runner_id: row.try_get("target_runner_id")?,
        target_posture_digest: row
            .try_get::<Option<String>, _>("target_posture_digest")?
            .map(ContentDigest::parse)
            .transpose()?,
        runner_slot_id: row.try_get("runner_slot_id")?,
        source_fleet_request_id: row.try_get("source_fleet_request_id")?,
        target_fleet_request_id: row.try_get("target_fleet_request_id")?,
        generation: postgres_u64(row.try_get("generation")?, "replacement generation")?,
        policy_version: postgres_u64(row.try_get("policy_version")?, "replacement policy")?,
        release_id: row.try_get("release_id")?,
        channel: row.try_get("channel")?,
        rollout_ring: u32::try_from(postgres_u64(row.try_get("rollout_ring")?, "rollout ring")?)
            .map_err(|_| ControlPlaneError::IntegerRange {
                field: "rollout ring",
            })?,
        state,
        failure_code: row.try_get("failure_code")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "replacement creation")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "replacement update")?,
    })
}

#[cfg(feature = "postgres")]
async fn postgres_put_verified_runner_release(
    store: &PostgresInstallationStore,
    registration: &VerifiedRunnerUpdateReleaseRegistration,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let release = &registration.release;
    if release.profile.digest().map_err(|_| {
        ControlPlaneError::InvalidInput("runner update release profile is malformed")
    })? != release.component_profile_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "runner update release profile digest does not match",
        ));
    }
    let mut tx = store.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,5931329278539179821))")
        .bind(&release.channel)
        .execute(&mut *tx)
        .await?;
    let existing:Option<String>=sqlx::query_scalar("SELECT trusted_state_json::TEXT FROM runner_update_trust_states WHERE channel=$1 FOR UPDATE").bind(&release.channel).fetch_optional(&mut *tx).await?;
    let trusted = match (existing, &registration.bootstrap_trusted_state) {
        (Some(json), None) => serde_json::from_str::<runtrue_update::TrustedState>(&json)
            .map_err(|_| ControlPlaneError::InvalidInput("stored update trust state is invalid"))?,
        (None, Some(state)) => state.clone(),
        (Some(_), Some(_)) => {
            return Err(ControlPlaneError::InvalidInput(
                "update trust is already initialized for this channel",
            ))
        }
        (None, None) => {
            return Err(ControlPlaneError::InvalidInput(
                "first release for a channel requires a pinned bootstrap trust state",
            ))
        }
    };
    let verified = trusted
        .verify_release_metadata(
            &registration.bundle,
            &registration.target_path,
            now_unix_ms / 1000,
        )
        .map_err(|_| ControlPlaneError::InvalidInput("signed update metadata was rejected"))?;
    release
        .profile
        .verify_signed_target(&verified.target)
        .map_err(|_| {
            ControlPlaneError::InvalidInput(
                "signed component profile does not match the selected target",
            )
        })?;
    let root = runtrue_update::root_envelope_digest(&verified.next_state.trusted_root)
        .map_err(|_| ControlPlaneError::InvalidInput("verified update root is invalid"))?;
    let targets = ContentDigest::sha256(
        runtrue_update::canonical_bytes(&registration.bundle.targets)
            .map_err(|_| ControlPlaneError::InvalidInput("verified targets metadata is invalid"))?,
    );
    let snapshot = ContentDigest::sha256(
        runtrue_update::canonical_bytes(&registration.bundle.snapshot).map_err(|_| {
            ControlPlaneError::InvalidInput("verified snapshot metadata is invalid")
        })?,
    );
    let timestamp = ContentDigest::sha256(
        runtrue_update::canonical_bytes(&registration.bundle.timestamp).map_err(|_| {
            ControlPlaneError::InvalidInput("verified timestamp metadata is invalid")
        })?,
    );
    if release.update_root_digest != root
        || release.targets_metadata_digest != targets
        || release.snapshot_metadata_digest != snapshot
        || release.timestamp_metadata_digest != timestamp
    {
        return Err(ControlPlaneError::InvalidInput(
            "release metadata identities do not match the independently verified chain",
        ));
    }
    let state =
        String::from_utf8(verified.next_state.canonical_bytes().map_err(|_| {
            ControlPlaneError::InvalidInput("verified update trust state is invalid")
        })?)
        .map_err(|_| ControlPlaneError::InvalidInput("verified update trust state is not JSON"))?;
    let now = postgres_i64(now_unix_ms, "release verification")?;
    sqlx::query("INSERT INTO runner_update_trust_states(channel,update_root_digest,trusted_state_json,created_unix_ms,updated_unix_ms) VALUES($1,$2,CAST($3 AS JSONB),$4,$4) ON CONFLICT(channel) DO UPDATE SET update_root_digest=excluded.update_root_digest,trusted_state_json=excluded.trusted_state_json,updated_unix_ms=excluded.updated_unix_ms").bind(&release.channel).bind(root.as_str()).bind(state).bind(now).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO runner_update_releases(id,component_name,release_version,channel,artifact_name,artifact_length,artifact_digest,artifact_media_type,platform,architecture,installed_digest,runner_version,engine_version,protocol_min,protocol_max,package_format,component_profile_json,component_profile_digest,update_root_digest,targets_metadata_digest,snapshot_metadata_digest,timestamp_metadata_digest,created_unix_ms,revoked_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,CAST($17 AS JSONB),$18,$19,$20,$21,$22,$23,$24)")
        .bind(&release.id).bind(&release.profile.component_name).bind(&release.profile.release_version).bind(&release.channel).bind(&release.profile.artifact_name).bind(postgres_i64(release.profile.artifact_length,"artifact length")?).bind(release.profile.artifact_digest.as_str()).bind(&release.profile.artifact_media_type).bind(&release.profile.platform).bind(&release.profile.architecture).bind(release.profile.installed_digest.as_str()).bind(&release.profile.runner_version).bind(&release.profile.engine_version).bind(i32::try_from(release.profile.protocol_min).map_err(|_|ControlPlaneError::IntegerRange{field:"protocol minimum"})?).bind(i32::try_from(release.profile.protocol_max).map_err(|_|ControlPlaneError::IntegerRange{field:"protocol maximum"})?).bind(&release.profile.package_format).bind(serde_json::to_string(&release.profile)?).bind(release.component_profile_digest.as_str()).bind(release.update_root_digest.as_str()).bind(release.targets_metadata_digest.as_str()).bind(release.snapshot_metadata_digest.as_str()).bind(release.timestamp_metadata_digest.as_str()).bind(postgres_i64(release.created_unix_ms,"release creation")?).bind(release.revoked_unix_ms.map(|v|postgres_i64(v,"release revocation")).transpose()?).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn postgres_put_update_policy(
    store: &PostgresInstallationStore,
    policy: &RunnerPoolUpdatePolicy,
) -> Result<(), ControlPlaneError> {
    if policy.version == 0
        || policy.failure_threshold == 0
        || policy.rings.is_empty()
        || !crate::types::valid_update_windows(&policy.maintenance_windows)
        || policy.protocol_min == 0
        || policy.protocol_max < policy.protocol_min
    {
        return Err(ControlPlaneError::InvalidInput(
            "runner update policy bounds are invalid",
        ));
    }
    let mut tx = store.pool.begin().await?;
    let exact:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runner_update_releases r JOIN runner_pool_templates t ON t.pool_id=$1 WHERE r.id=$2 AND r.revoked_unix_ms IS NULL AND r.channel=$3 AND r.protocol_min<=$4 AND r.protocol_max>=$5 AND t.runtime_compatibility_digest=$6 AND t.provider=$7 AND t.provider_template_id=$8 AND t.runner_template_digest=$9)").bind(&policy.pool_id).bind(&policy.release_id).bind(&policy.channel).bind(i32::try_from(policy.protocol_max).unwrap_or(i32::MAX)).bind(i32::try_from(policy.protocol_min).unwrap_or(i32::MAX)).bind(policy.runtime_compatibility_digest.as_str()).bind(&policy.provider).bind(&policy.provider_template_id).bind(policy.runner_template_digest.as_str()).fetch_one(&mut *tx).await?;
    let latest: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version),0) FROM runner_pool_update_policies WHERE pool_id=$1",
    )
    .bind(&policy.pool_id)
    .fetch_one(&mut *tx)
    .await?;
    if !exact || policy.version != postgres_u64(latest, "policy version")?.saturating_add(1) {
        return Err(ControlPlaneError::InvalidInput(
            "runner update policy has no exact release/template mapping or version",
        ));
    }
    sqlx::query(
        "UPDATE runner_pool_update_policies SET enabled=FALSE WHERE pool_id=$1 AND enabled",
    )
    .bind(&policy.pool_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO runner_pool_update_policies(pool_id,version,enabled,release_id,runtime_compatibility_digest,provider,provider_template_id,runner_template_digest,channel,maintenance_window_json,rings_json,minimum_healthy,maximum_surge,maximum_unavailable,failure_threshold,required_attestation_grade,protocol_min,protocol_max,paused,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,CAST($10 AS JSONB),CAST($11 AS JSONB),$12,$13,$14,$15,$16,$17,$18,$19,$20)").bind(&policy.pool_id).bind(postgres_i64(policy.version,"policy version")?).bind(policy.enabled).bind(&policy.release_id).bind(policy.runtime_compatibility_digest.as_str()).bind(&policy.provider).bind(&policy.provider_template_id).bind(policy.runner_template_digest.as_str()).bind(&policy.channel).bind(serde_json::to_string(&policy.maintenance_windows)?).bind(serde_json::to_string(&policy.rings)?).bind(i64::from(policy.minimum_healthy)).bind(i64::from(policy.maximum_surge)).bind(i64::from(policy.maximum_unavailable)).bind(i64::from(policy.failure_threshold)).bind(&policy.required_attestation_grade).bind(i32::try_from(policy.protocol_min).unwrap_or(i32::MAX)).bind(i32::try_from(policy.protocol_max).unwrap_or(i32::MAX)).bind(policy.paused).bind(postgres_i64(policy.created_unix_ms,"policy creation")?).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn postgres_replacements(
    store: &PostgresInstallationStore,
    pool_id: &str,
) -> Result<Vec<RunnerReplacementRecord>, ControlPlaneError> {
    sqlx::query(
        "SELECT * FROM runner_replacements WHERE pool_id=$1 ORDER BY generation,id LIMIT 10000",
    )
    .bind(pool_id)
    .fetch_all(&store.pool)
    .await?
    .into_iter()
    .map(postgres_replacement)
    .collect()
}

#[cfg(feature = "postgres")]
async fn postgres_put_runner_slot(
    store: &PostgresInstallationStore,
    slot: &RunnerSlotRecord,
) -> Result<(), ControlPlaneError> {
    if slot.active_runner_id.is_some() != (slot.active_generation > 0) {
        return Err(ControlPlaneError::InvalidInput(
            "runner slot active identity and generation are inconsistent",
        ));
    }
    let changed=sqlx::query("INSERT INTO runner_slots(id,pool_id,updater_identity_digest,active_generation,active_runner_id,created_unix_ms,updated_unix_ms) SELECT $1,$2,$3,$4,$5,$6,$7 WHERE $5 IS NULL OR EXISTS(SELECT 1 FROM runners WHERE id=$5 AND pool_id=$2 AND status NOT IN('revoked','quarantined'))").bind(&slot.id).bind(&slot.pool_id).bind(slot.updater_identity_digest.as_str()).bind(postgres_i64(slot.active_generation,"slot generation")?).bind(&slot.active_runner_id).bind(postgres_i64(slot.created_unix_ms,"slot creation")?).bind(postgres_i64(slot.updated_unix_ms,"slot update")?).execute(&store.pool).await?.rows_affected();
    if changed != 1 {
        return Err(ControlPlaneError::InvalidInput(
            "runner slot active identity is not an eligible member of the pool",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn postgres_create_fixed_claim(
    store: &PostgresInstallationStore,
    slot_id: &str,
    identity_proof_digest: &ContentDigest,
    now_unix_ms: u64,
    expires_unix_ms: u64,
) -> Result<IssuedRunnerSoftwareUpdateClaim, ControlPlaneError> {
    if expires_unix_ms <= now_unix_ms || expires_unix_ms.saturating_sub(now_unix_ms) > 900_000 {
        return Err(ControlPlaneError::InvalidInput(
            "software update claim lifetime must be at most fifteen minutes",
        ));
    }
    let (enrollment_id, token, token_hash) = new_enrollment_token()?;
    let suffix = enrollment_id
        .strip_prefix("enroll-")
        .unwrap_or(&enrollment_id);
    let replacement_id = format!("replace-{suffix}");
    let claim_id = format!("update-{suffix}");
    let mut tx = store.pool.begin().await?;
    let slot=sqlx::query("SELECT pool_id,updater_identity_digest,active_generation,active_runner_id FROM runner_slots WHERE id=$1 FOR UPDATE").bind(slot_id).fetch_optional(&mut *tx).await?.ok_or_else(||ControlPlaneError::NotFound{kind:"runner slot",id:slot_id.to_owned()})?;
    let pool_id: String = slot.try_get("pool_id")?;
    let updater: String = slot.try_get("updater_identity_digest")?;
    let active_generation = postgres_u64(slot.try_get("active_generation")?, "slot generation")?;
    let source_id: String = slot
        .try_get::<Option<String>, _>("active_runner_id")?
        .ok_or(ControlPlaneError::InvalidInput(
            "runner slot has no active source",
        ))?;
    let source = postgres_runner_tx(&mut tx, &source_id).await?;
    let open:i64=sqlx::query_scalar("SELECT COUNT(*) FROM leases WHERE runner_id=$1 AND state IN('offered','active','cancel_requested')").bind(&source_id).fetch_one(&mut *tx).await?;
    if source.runner.status != runtrue_scheduler::RunnerStatus::Draining
        || source.runner.active_jobs != 0
        || open != 0
    {
        return Err(ControlPlaneError::InvalidInput(
            "fixed-host source is not completely drained",
        ));
    }
    let source_posture: String = sqlx::query_scalar(
        "SELECT posture_digest FROM runner_enrollment_postures WHERE runner_id=$1",
    )
    .bind(&source_id)
    .fetch_one(&mut *tx)
    .await?;
    let policy=sqlx::query("SELECT p.version,p.release_id,p.runner_template_digest,p.channel,p.protocol_min,p.protocol_max,p.required_attestation_grade,u.artifact_digest,u.installed_digest,u.component_profile_digest,u.update_root_digest,u.targets_metadata_digest,u.snapshot_metadata_digest,u.timestamp_metadata_digest,p.maintenance_window_json::TEXT AS maintenance_windows FROM runner_pool_update_policies p JOIN runner_update_releases u ON u.id=p.release_id AND u.revoked_unix_ms IS NULL WHERE p.pool_id=$1 AND p.enabled AND NOT p.paused ORDER BY p.version DESC LIMIT 1 FOR UPDATE").bind(&pool_id).fetch_optional(&mut *tx).await?.ok_or(ControlPlaneError::InvalidInput("automatic runner updates are disabled or paused"))?;
    let windows: Vec<String> =
        serde_json::from_str(&policy.try_get::<String, _>("maintenance_windows")?)?;
    if !crate::types::update_window_allows(&windows, now_unix_ms) {
        return Err(ControlPlaneError::InvalidInput(
            "runner update is outside its UTC maintenance window",
        ));
    }
    let latest_generation: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(generation),$2) FROM runner_replacements WHERE runner_slot_id=$1",
    )
    .bind(slot_id)
    .bind(postgres_i64(active_generation, "slot generation")?)
    .fetch_one(&mut *tx)
    .await?;
    let generation = postgres_u64(latest_generation, "latest slot replacement generation")?
        .checked_add(1)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "slot generation",
        })?;
    let policy_version: i64 = policy.try_get("version")?;
    let release_id: String = policy.try_get("release_id")?;
    let template: String = policy.try_get("runner_template_digest")?;
    let channel: String = policy.try_get("channel")?;
    sqlx::query("UPDATE runner_software_update_claims SET canceled_unix_ms=$2 WHERE runner_slot_id=$1 AND consumed_unix_ms IS NULL AND canceled_unix_ms IS NULL").bind(slot_id).bind(postgres_i64(now_unix_ms,"claim cancellation")?).execute(&mut *tx).await?;
    sqlx::query("UPDATE runner_replacements SET state='canceled',failure_code='superseded',updated_unix_ms=$2 WHERE runner_slot_id=$1 AND state IN('requested','claim-issued')").bind(slot_id).bind(postgres_i64(now_unix_ms,"replacement cancellation")?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO enrollment_tokens(id,pool_id,token_hash,created_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,$5)").bind(&enrollment_id).bind(&pool_id).bind(token_hash.as_str()).bind(postgres_i64(now_unix_ms,"claim creation")?).bind(postgres_i64(expires_unix_ms,"claim expiry")?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO runner_replacements(id,pool_id,mode,source_runner_id,source_posture_digest,runner_slot_id,generation,policy_version,release_id,channel,rollout_ring,state,created_unix_ms,updated_unix_ms) VALUES($1,$2,'fixed-host',$3,$4,$5,$6,$7,$8,$9,0,'claim-issued',$10,$10)").bind(&replacement_id).bind(&pool_id).bind(&source_id).bind(&source_posture).bind(slot_id).bind(postgres_i64(generation,"replacement generation")?).bind(policy_version).bind(&release_id).bind(&channel).bind(postgres_i64(now_unix_ms,"replacement creation")?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO runner_software_update_claims(id,replacement_id,enrollment_token_id,pool_id,mode,source_runner_id,source_posture_digest,runner_slot_id,updater_identity_digest,runner_template_digest,identity_proof_digest,generation,artifact_digest,installed_digest,release_id,component_profile_digest,update_root_digest,targets_metadata_digest,snapshot_metadata_digest,timestamp_metadata_digest,policy_version,channel,rollout_ring,protocol_min,protocol_max,required_attestation_grade,attestation_nonce_digest,created_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,'fixed-host',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,0,$22,$23,$24,$10,$25,$26)").bind(&claim_id).bind(&replacement_id).bind(&enrollment_id).bind(&pool_id).bind(&source_id).bind(&source_posture).bind(slot_id).bind(&updater).bind(&template).bind(identity_proof_digest.as_str()).bind(postgres_i64(generation,"claim generation")?).bind(policy.try_get::<String,_>("artifact_digest")?).bind(policy.try_get::<String,_>("installed_digest")?).bind(&release_id).bind(policy.try_get::<String,_>("component_profile_digest")?).bind(policy.try_get::<String,_>("update_root_digest")?).bind(policy.try_get::<String,_>("targets_metadata_digest")?).bind(policy.try_get::<String,_>("snapshot_metadata_digest")?).bind(policy.try_get::<String,_>("timestamp_metadata_digest")?).bind(policy_version).bind(&channel).bind(policy.try_get::<i32,_>("protocol_min")?).bind(policy.try_get::<i32,_>("protocol_max")?).bind(policy.try_get::<String,_>("required_attestation_grade")?).bind(postgres_i64(now_unix_ms,"claim creation")?).bind(postgres_i64(expires_unix_ms,"claim expiry")?).execute(&mut *tx).await?;
    let metadata = postgres_software_update_claim(
        sqlx::query("SELECT * FROM runner_software_update_claims WHERE id=$1")
            .bind(&claim_id)
            .fetch_one(&mut *tx)
            .await?,
    )?;
    tx.commit().await?;
    Ok(IssuedRunnerSoftwareUpdateClaim {
        metadata,
        token: RunnerLaunchClaimToken::new(token),
    })
}

#[cfg(feature = "postgres")]
async fn postgres_plan_replacement(
    store: &PostgresInstallationStore,
    plan: AutoscaledReplacementPlan<'_>,
) -> Result<PlannedRunnerReplacement, ControlPlaneError> {
    let AutoscaledReplacementPlan {
        pool_id,
        source_runner_id,
        replacement_id,
        fleet_request_id,
        owner_id,
        fencing_generation,
        now_unix_ms,
    } = plan;
    let mut tx = store.pool.begin().await?;
    require_postgres_autoscaler_lease(&mut tx, pool_id, owner_id, fencing_generation, now_unix_ms)
        .await?;
    let policy=sqlx::query("SELECT version,release_id,runtime_compatibility_digest,provider,provider_template_id,runner_template_digest,channel,maximum_surge,maximum_unavailable,failure_threshold,protocol_min,protocol_max,jsonb_array_length(rings_json) AS ring_count,maintenance_window_json::TEXT AS maintenance_windows,minimum_healthy FROM runner_pool_update_policies WHERE pool_id=$1 AND enabled AND NOT paused ORDER BY version DESC LIMIT 1 FOR UPDATE").bind(pool_id).fetch_optional(&mut *tx).await?.ok_or(ControlPlaneError::InvalidInput("automatic runner updates are disabled or paused"))?;
    let windows: Vec<String> =
        serde_json::from_str(&policy.try_get::<String, _>("maintenance_windows")?)?;
    if !crate::types::update_window_allows(&windows, now_unix_ms) {
        return Err(ControlPlaneError::InvalidInput(
            "runner update is outside its UTC maintenance window",
        ));
    }
    let source = postgres_runner_tx(&mut tx, source_runner_id).await?;
    if source.runner.pool_id != pool_id
        || source.runner.status != runtrue_scheduler::RunnerStatus::Online
    {
        return Err(ControlPlaneError::InvalidInput(
            "runner update source is not online",
        ));
    }
    let source_posture: String = sqlx::query_scalar(
        "SELECT posture_digest FROM runner_enrollment_postures WHERE runner_id=$1",
    )
    .bind(source_runner_id)
    .fetch_one(&mut *tx)
    .await?;
    let source_fleet: Option<String> = sqlx::query_scalar(
        "SELECT id FROM runner_fleet_requests WHERE runner_id=$1 AND state='online'",
    )
    .bind(source_runner_id)
    .fetch_optional(&mut *tx)
    .await?;
    let version = postgres_u64(policy.try_get("version")?, "policy version")?;
    let surge = postgres_u64(policy.try_get("maximum_surge")?, "maximum surge")?;
    let max_unavailable = postgres_u64(
        policy.try_get("maximum_unavailable")?,
        "maximum unavailable",
    )?;
    let minimum_healthy = postgres_u64(policy.try_get("minimum_healthy")?, "minimum healthy")?;
    let threshold = postgres_u64(policy.try_get("failure_threshold")?, "failure threshold")?;
    let inflight:i64=sqlx::query_scalar("SELECT COUNT(*) FROM runner_replacements WHERE pool_id=$1 AND state IN('requested','claim-issued','enrolled','probationary','active','draining-source')").bind(pool_id).fetch_one(&mut *tx).await?;
    let unavailable:i64=sqlx::query_scalar("SELECT COUNT(*) FROM runners WHERE pool_id=$1 AND status IN('offline','draining','quarantined','revoked')").bind(pool_id).fetch_one(&mut *tx).await?;
    let healthy: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM runners WHERE pool_id=$1 AND status='online'")
            .bind(pool_id)
            .fetch_one(&mut *tx)
            .await?;
    let completed_ring:i64=sqlx::query_scalar("SELECT COALESCE(MAX(rollout_ring),-1) FROM runner_replacements WHERE pool_id=$1 AND policy_version=$2 AND state='completed'").bind(pool_id).bind(postgres_i64(version,"policy version")?).fetch_one(&mut *tx).await?;
    let ring_count: i32 = policy.try_get("ring_count")?;
    let rollout_ring = (completed_ring + 1)
        .min(i64::from(ring_count.saturating_sub(1)))
        .max(0);
    let failures:i64=sqlx::query_scalar("SELECT COUNT(*) FROM runner_replacements WHERE pool_id=$1 AND policy_version=$2 AND rollout_ring=$3 AND state='failed'").bind(pool_id).bind(postgres_i64(version,"policy version")?).bind(rollout_ring).fetch_one(&mut *tx).await?;
    if postgres_u64(failures, "failures")? >= threshold {
        sqlx::query(
            "UPDATE runner_pool_update_policies SET paused=TRUE WHERE pool_id=$1 AND version=$2",
        )
        .bind(pool_id)
        .bind(postgres_i64(version, "policy version")?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Err(ControlPlaneError::InvalidInput(
            "runner update rollout paused after reaching its ring failure threshold",
        ));
    }
    if postgres_u64(inflight, "inflight")? >= surge
        || postgres_u64(unavailable, "unavailable")? > max_unavailable
        || postgres_u64(healthy, "healthy")? < minimum_healthy
    {
        return Err(ControlPlaneError::InvalidInput(
            "runner update rollout bounds do not permit another replacement",
        ));
    }
    let release_id: String = policy.try_get("release_id")?;
    let protocol_min: i32 = policy.try_get("protocol_min")?;
    let protocol_max: i32 = policy.try_get("protocol_max")?;
    let release_ok:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runner_update_releases WHERE id=$1 AND revoked_unix_ms IS NULL AND protocol_min<=$2 AND protocol_max>=$3)").bind(&release_id).bind(protocol_max).bind(protocol_min).fetch_one(&mut *tx).await?;
    if !release_ok {
        return Err(ControlPlaneError::InvalidInput(
            "runner update release is revoked or incompatible",
        ));
    }
    let generation: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(generation),0)+1 FROM runner_replacements WHERE pool_id=$1",
    )
    .bind(pool_id)
    .fetch_one(&mut *tx)
    .await?;
    let runtime: String = policy.try_get("runtime_compatibility_digest")?;
    let provider: String = policy.try_get("provider")?;
    let provider_template: String = policy.try_get("provider_template_id")?;
    let template: String = policy.try_get("runner_template_digest")?;
    let channel: String = policy.try_get("channel")?;
    let inserted=sqlx::query("INSERT INTO runner_fleet_requests(id,pool_id,runtime_compatibility_digest,provider,provider_template_id,runner_template_digest,state,created_unix_ms,updated_unix_ms) SELECT $1,$2,$3,$4,$5,$6,'requested',$7,$7 WHERE EXISTS(SELECT 1 FROM runner_pool_templates WHERE pool_id=$2 AND runtime_compatibility_digest=$3 AND provider=$4 AND provider_template_id=$5 AND runner_template_digest=$6)").bind(fleet_request_id).bind(pool_id).bind(&runtime).bind(&provider).bind(&provider_template).bind(&template).bind(postgres_i64(now_unix_ms,"replacement creation")?).execute(&mut *tx).await?.rows_affected();
    if inserted != 1 {
        return Err(ControlPlaneError::InvalidInput(
            "replacement has no exact template",
        ));
    }
    sqlx::query("INSERT INTO runner_replacements(id,pool_id,mode,source_runner_id,source_posture_digest,source_fleet_request_id,target_fleet_request_id,generation,policy_version,release_id,channel,rollout_ring,state,created_unix_ms,updated_unix_ms) VALUES($1,$2,'autoscaled',$3,$4,$5,$6,$7,$8,$9,$10,$11,'requested',$12,$12)").bind(replacement_id).bind(pool_id).bind(source_runner_id).bind(&source_posture).bind(source_fleet).bind(fleet_request_id).bind(generation).bind(postgres_i64(version,"policy version")?).bind(release_id).bind(channel).bind(rollout_ring).bind(postgres_i64(now_unix_ms,"replacement creation")?).execute(&mut *tx).await?;
    let request = postgres_fleet_request_tx(&mut tx, fleet_request_id).await?;
    let replacement = postgres_replacement(
        sqlx::query("SELECT * FROM runner_replacements WHERE id=$1")
            .bind(replacement_id)
            .fetch_one(&mut *tx)
            .await?,
    )?;
    tx.commit().await?;
    Ok(PlannedRunnerReplacement {
        replacement,
        fleet_request: request,
    })
}

#[cfg(feature = "postgres")]
async fn postgres_activate_replacement(
    store: &PostgresInstallationStore,
    replacement_id: &str,
    owner_id: &str,
    fencing_generation: u64,
    now_unix_ms: u64,
) -> Result<RunnerReplacementRecord, ControlPlaneError> {
    let mut tx = store.pool.begin().await?;
    let replacement = postgres_replacement(
        sqlx::query("SELECT * FROM runner_replacements WHERE id=$1 FOR UPDATE")
            .bind(replacement_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| ControlPlaneError::NotFound {
                kind: "runner replacement",
                id: replacement_id.to_owned(),
            })?,
    )?;
    if replacement.mode == RunnerReplacementMode::Autoscaled {
        require_postgres_autoscaler_lease(
            &mut tx,
            &replacement.pool_id,
            owner_id,
            fencing_generation,
            now_unix_ms,
        )
        .await?;
    }
    if replacement.state != RunnerReplacementState::Probationary {
        return Err(ControlPlaneError::InvalidTransition {
            entity: "runner replacement",
            from: "not-probationary",
            to: "active",
        });
    }
    let target = replacement
        .target_runner_id
        .as_deref()
        .ok_or(ControlPlaneError::CorruptState(
            "replacement target missing".to_owned(),
        ))?;
    let mut candidate = postgres_runner_tx(&mut tx, target).await?;
    let durable_posture: String = sqlx::query_scalar(
        "SELECT posture_digest FROM runner_enrollment_postures WHERE runner_id=$1",
    )
    .bind(target)
    .fetch_one(&mut *tx)
    .await?;
    if candidate.runner.status != runtrue_scheduler::RunnerStatus::Probationary
        || replacement.target_posture_digest.as_ref()
            != Some(&ContentDigest::parse(durable_posture)?)
        || now_unix_ms.saturating_sub(candidate.runner.last_heartbeat_unix_ms) > 120_000
    {
        return Err(ControlPlaneError::InvalidInput(
            "replacement candidate has not passed health checks",
        ));
    }
    candidate.runner.status = runtrue_scheduler::RunnerStatus::Online;
    if sqlx::query("UPDATE runners SET status='online',runner_json=$2,updated_unix_ms=$3 WHERE id=$1 AND status='probationary'").bind(target).bind(serde_json::to_vec(&candidate.runner)?).bind(postgres_i64(now_unix_ms,"replacement activation")?).execute(&mut *tx).await?.rows_affected() != 1 {
        return Err(ControlPlaneError::InvalidTransition { entity: "replacement candidate", from: "probationary", to: "online" });
    }
    let mut source = postgres_runner_tx(&mut tx, &replacement.source_runner_id).await?;
    let final_state = if replacement.mode == RunnerReplacementMode::FixedHost {
        let open:i64=sqlx::query_scalar("SELECT COUNT(*) FROM leases WHERE runner_id=$1 AND state IN('offered','active','cancel_requested')").bind(&replacement.source_runner_id).fetch_one(&mut *tx).await?;
        if source.runner.status != runtrue_scheduler::RunnerStatus::Draining
            || source.runner.active_jobs != 0
            || open != 0
        {
            return Err(ControlPlaneError::InvalidInput(
                "fixed-host source is not completely drained at activation",
            ));
        }
        source.runner.status = runtrue_scheduler::RunnerStatus::Revoked;
        if sqlx::query("UPDATE runners SET status='revoked',runner_json=$2,updated_unix_ms=$3 WHERE id=$1 AND status='draining'").bind(&replacement.source_runner_id).bind(serde_json::to_vec(&source.runner)?).bind(postgres_i64(now_unix_ms,"source retirement")?).execute(&mut *tx).await?.rows_affected() != 1 { return Err(ControlPlaneError::InvalidTransition{entity:"fixed-host source",from:"draining",to:"revoked"}); }
        sqlx::query("UPDATE runner_certificates SET status='revoked',revoked_unix_ms=$2 WHERE runner_id=$1 AND status IN('active','overlap')").bind(&replacement.source_runner_id).bind(postgres_i64(now_unix_ms,"source retirement")?).execute(&mut *tx).await?;
        let slot = replacement
            .runner_slot_id
            .as_deref()
            .ok_or(ControlPlaneError::CorruptState(
                "fixed replacement slot missing".to_owned(),
            ))?;
        if sqlx::query("UPDATE runner_slots SET active_generation=$2,active_runner_id=$3,updated_unix_ms=$4 WHERE id=$1 AND active_generation<$2 AND active_runner_id=$5").bind(slot).bind(postgres_i64(replacement.generation,"slot generation")?).bind(target).bind(postgres_i64(now_unix_ms,"slot activation")?).bind(&replacement.source_runner_id).execute(&mut *tx).await?.rows_affected() != 1 { return Err(ControlPlaneError::InvalidInput("fixed-host slot generation or source changed before activation")); }
        RunnerReplacementState::Completed
    } else {
        source.runner.status = runtrue_scheduler::RunnerStatus::Draining;
        sqlx::query("UPDATE runners SET status='draining',runner_json=$2,updated_unix_ms=$3 WHERE id=$1 AND status IN('online','offline')").bind(&replacement.source_runner_id).bind(serde_json::to_vec(&source.runner)?).bind(postgres_i64(now_unix_ms,"source drain")?).execute(&mut *tx).await?;
        if let Some(source_request) = replacement.source_fleet_request_id.as_deref() {
            sqlx::query("UPDATE runner_fleet_requests SET state='draining',updated_unix_ms=$2 WHERE id=$1 AND state='online'").bind(source_request).bind(postgres_i64(now_unix_ms,"source drain")?).execute(&mut *tx).await?;
        }
        RunnerReplacementState::DrainingSource
    };
    if sqlx::query("UPDATE runner_replacements SET state=$2,updated_unix_ms=$3 WHERE id=$1 AND state='probationary'").bind(replacement_id).bind(match final_state{RunnerReplacementState::Completed=>"completed",_=>"draining-source"}).bind(postgres_i64(now_unix_ms,"replacement activation")?).execute(&mut *tx).await?.rows_affected() != 1 { return Err(ControlPlaneError::InvalidTransition{entity:"runner replacement",from:"probationary",to:"active"}); }
    tx.commit().await?;
    Ok(RunnerReplacementRecord {
        state: final_state,
        updated_unix_ms: now_unix_ms,
        ..replacement
    })
}

#[cfg(feature = "postgres")]
fn validate_token(token: &str) -> Result<(), ControlPlaneError> {
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ControlPlaneError::InvalidEnrollmentToken);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn enrollment_token_hash(token: &str) -> ContentDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"runtrue.runner.enrollment-token.v1\0");
    hasher.update(token.as_bytes());
    ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
        .expect("SHA-256 is a valid content digest")
}

#[cfg(feature = "postgres")]
fn new_enrollment_token() -> Result<(String, String, ContentDigest), ControlPlaneError> {
    let mut raw = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut raw)
        .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
    let token = hex::encode(raw);
    raw.zeroize();
    let mut id = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut id)
        .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
    Ok((
        format!("enroll-{}", hex::encode(id)),
        token.clone(),
        enrollment_token_hash(&token),
    ))
}

#[cfg(feature = "postgres")]
async fn postgres_enrollment_token_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    hash: &ContentDigest,
) -> Result<EnrollmentTokenRecord, ControlPlaneError> {
    let row = sqlx::query(
        "SELECT id,pool_id,created_unix_ms,expires_unix_ms,consumed_unix_ms
         FROM enrollment_tokens WHERE token_hash=$1 FOR UPDATE",
    )
    .bind(hash.as_str())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(ControlPlaneError::InvalidEnrollmentToken)?;
    Ok(EnrollmentTokenRecord {
        id: row.try_get("id")?,
        pool_id: row.try_get("pool_id")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "enrollment creation")?,
        expires_unix_ms: postgres_u64(row.try_get("expires_unix_ms")?, "enrollment expiry")?,
        consumed_unix_ms: row
            .try_get::<Option<i64>, _>("consumed_unix_ms")?
            .map(|value| postgres_u64(value, "enrollment consumption"))
            .transpose()?,
    })
}

#[cfg(feature = "postgres")]
async fn postgres_enrollment_token_by_id_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
) -> Result<EnrollmentTokenRecord, ControlPlaneError> {
    let row = sqlx::query(
        "SELECT id,pool_id,created_unix_ms,expires_unix_ms,consumed_unix_ms
         FROM enrollment_tokens WHERE id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| {
        ControlPlaneError::CorruptState(
            "PostgreSQL idempotent enrollment token is missing".to_owned(),
        )
    })?;
    Ok(EnrollmentTokenRecord {
        id: row.try_get("id")?,
        pool_id: row.try_get("pool_id")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "enrollment creation")?,
        expires_unix_ms: postgres_u64(row.try_get("expires_unix_ms")?, "enrollment expiry")?,
        consumed_unix_ms: row
            .try_get::<Option<i64>, _>("consumed_unix_ms")?
            .map(|value| postgres_u64(value, "enrollment consumption"))
            .transpose()?,
    })
}

#[cfg(feature = "postgres")]
fn validate_usable_token(
    record: &EnrollmentTokenRecord,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    if record.consumed_unix_ms.is_some() {
        return Err(ControlPlaneError::EnrollmentTokenConsumed);
    }
    if now_unix_ms >= record.expires_unix_ms {
        return Err(ControlPlaneError::EnrollmentTokenExpired);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_new_runner_and_certificate(
    runner: &RunnerRecord,
    certificate: &RunnerCertificateRecord,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    if runner.id.is_empty()
        || runner.pool_id.is_empty()
        || runner.tenant_id.is_empty()
        || !matches!(
            runner.status,
            runtrue_scheduler::RunnerStatus::Offline
                | runtrue_scheduler::RunnerStatus::Probationary
        )
        || runner.id != certificate.runner_id
        || runner.pool_id != certificate.pool_id
    {
        return Err(ControlPlaneError::CertificateIdentityMismatch);
    }
    validate_new_certificate(certificate, now_unix_ms)?;
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_new_certificate(
    certificate: &RunnerCertificateRecord,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    if certificate.status != crate::RunnerCertificateStatus::Active
        || certificate.not_before_unix_ms > now_unix_ms
        || certificate.not_after_unix_ms <= now_unix_ms
        || certificate.issued_unix_ms > now_unix_ms
        || certificate.overlap_until_unix_ms.is_some()
        || certificate.revoked_unix_ms.is_some()
        || certificate.serial_hex.is_empty()
        || certificate.serial_hex.len() > 128
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid runner certificate metadata",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn insert_postgres_certificate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    certificate: &RunnerCertificateRecord,
) -> Result<(), ControlPlaneError> {
    sqlx::query(
        "INSERT INTO runner_certificates
         (fingerprint,runner_id,pool_id,serial_hex,not_before_unix_ms,not_after_unix_ms,
          status,issued_unix_ms,overlap_until_unix_ms,revoked_unix_ms)
         VALUES($1,$2,$3,$4,$5,$6,'active',$7,NULL,NULL)",
    )
    .bind(certificate.fingerprint.as_str())
    .bind(&certificate.runner_id)
    .bind(&certificate.pool_id)
    .bind(&certificate.serial_hex)
    .bind(postgres_i64(
        certificate.not_before_unix_ms,
        "certificate not before",
    )?)
    .bind(postgres_i64(
        certificate.not_after_unix_ms,
        "certificate not after",
    )?)
    .bind(postgres_i64(
        certificate.issued_unix_ms,
        "certificate issued",
    )?)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn expire_postgres_certificates(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let now = postgres_i64(now_unix_ms, "certificate expiration")?;
    sqlx::query(
        "UPDATE runner_certificates SET status='revoked',revoked_unix_ms=$1
         WHERE status='overlap' AND overlap_until_unix_ms<=$1",
    )
    .bind(now)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE runner_certificates SET status='revoked',revoked_unix_ms=$1
         WHERE status='active' AND not_after_unix_ms<=$1",
    )
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
fn certificate_authorized(certificate: &RunnerCertificateRecord, now_unix_ms: u64) -> bool {
    now_unix_ms >= certificate.not_before_unix_ms
        && now_unix_ms < certificate.not_after_unix_ms
        && match certificate.status {
            crate::RunnerCertificateStatus::Active => true,
            crate::RunnerCertificateStatus::Overlap => certificate
                .overlap_until_unix_ms
                .is_some_and(|deadline| now_unix_ms < deadline),
            crate::RunnerCertificateStatus::Revoked => false,
        }
}

#[cfg(feature = "postgres")]
async fn postgres_certificate_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    fingerprint: &ContentDigest,
) -> Result<RunnerCertificateRecord, ControlPlaneError> {
    let row = sqlx::query("SELECT * FROM runner_certificates WHERE fingerprint=$1 FOR UPDATE")
        .bind(fingerprint.as_str())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ControlPlaneError::RunnerCertificateUnauthorized)?;
    let status = match row.try_get::<String, _>("status")?.as_str() {
        "active" => crate::RunnerCertificateStatus::Active,
        "overlap" => crate::RunnerCertificateStatus::Overlap,
        "revoked" => crate::RunnerCertificateStatus::Revoked,
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "unknown PostgreSQL runner certificate status".to_owned(),
            ))
        }
    };
    Ok(RunnerCertificateRecord {
        fingerprint: ContentDigest::parse(row.try_get::<String, _>("fingerprint")?)?,
        runner_id: row.try_get("runner_id")?,
        pool_id: row.try_get("pool_id")?,
        serial_hex: row.try_get("serial_hex")?,
        not_before_unix_ms: postgres_u64(
            row.try_get("not_before_unix_ms")?,
            "certificate not before",
        )?,
        not_after_unix_ms: postgres_u64(
            row.try_get("not_after_unix_ms")?,
            "certificate not after",
        )?,
        status,
        issued_unix_ms: postgres_u64(row.try_get("issued_unix_ms")?, "certificate issued")?,
        overlap_until_unix_ms: row
            .try_get::<Option<i64>, _>("overlap_until_unix_ms")?
            .map(|value| postgres_u64(value, "certificate overlap deadline"))
            .transpose()?,
        revoked_unix_ms: row
            .try_get::<Option<i64>, _>("revoked_unix_ms")?
            .map(|value| postgres_u64(value, "certificate revoked"))
            .transpose()?,
    })
}

#[cfg(feature = "postgres")]
async fn postgres_runner_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    runner_id: &str,
) -> Result<PersistedRunner, ControlPlaneError> {
    let row = sqlx::query(
        "SELECT runner_json,created_unix_ms,updated_unix_ms FROM runners WHERE id=$1 FOR UPDATE",
    )
    .bind(runner_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| ControlPlaneError::NotFound {
        kind: "runner",
        id: runner_id.to_owned(),
    })?;
    postgres_runner(row)
}

#[cfg(feature = "postgres")]
fn postgres_runner(row: sqlx::postgres::PgRow) -> Result<PersistedRunner, ControlPlaneError> {
    Ok(PersistedRunner {
        runner: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("runner_json")?)?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "runner creation")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "runner update")?,
    })
}

#[cfg(feature = "postgres")]
async fn postgres_certificate_rotation_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    old_fingerprint: &ContentDigest,
) -> Result<Option<RunnerCertificateRotationRecord>, ControlPlaneError> {
    let row = sqlx::query(
        "SELECT old_fingerprint,runner_id,pool_id,csr_digest,new_certificate_json,
         certificate_chain_pem,created_unix_ms FROM runner_certificate_rotations
         WHERE old_fingerprint=$1 FOR UPDATE",
    )
    .bind(old_fingerprint.as_str())
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        Ok(RunnerCertificateRotationRecord {
            old_fingerprint: ContentDigest::parse(row.try_get::<String, _>("old_fingerprint")?)?,
            runner_id: row.try_get("runner_id")?,
            pool_id: row.try_get("pool_id")?,
            csr_digest: ContentDigest::parse(row.try_get::<String, _>("csr_digest")?)?,
            new_certificate: serde_json::from_slice(
                &row.try_get::<Vec<u8>, _>("new_certificate_json")?,
            )?,
            certificate_chain_pem: row.try_get("certificate_chain_pem")?,
            created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "certificate rotation")?,
        })
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{InstallationStateStore, RunCoreStore};
    use runtrue_scheduler::{LeaseState, SchedulingRequirements};
    use runtrue_workflow_ir::{
        ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
        OperatingSystem, ParityGrade, PermissionSet, PlannedJob, PlannedStep, RunnerRequirements,
        SourceTrust, StepAction, StepCapabilitySet, Trust, WorkflowIdentity,
        CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
    };
    #[cfg(feature = "postgres")]
    use runtrue_workflow_ir::{
        DynamicJobTemplate, DynamicMatrixSource, ExpandedJobSet, ScalarValue,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn configuration(prefix: &str) -> RunnerPoolConfiguration {
        let pool_id = format!("pool-{prefix}");
        let runtime = ContentDigest::sha256(format!("runtime-{prefix}"));
        RunnerPoolConfiguration {
            pool: RunnerPoolRecord {
                id: pool_id.clone(),
                tenant_id: format!("tenant-{prefix}"),
                name: format!("Pool {prefix}"),
                region: Some("test-region".to_owned()),
                status: RunnerPoolStatus::Active,
                created_unix_ms: 100,
            },
            scaling_policy: Some(RunnerPoolScalingPolicy {
                pool_id: pool_id.clone(),
                baseline_runtime_compatibility_digest: Some(runtime.clone()),
                minimum_workers: 1,
                minimum_idle_workers: 1,
                maximum_workers: 4,
                scale_up_batch: 2,
                idle_timeout_ms: 60_000,
                offline_grace_ms: 30_000,
                cooldown_ms: 5_000,
                enabled: true,
                updated_unix_ms: 101,
            }),
            templates: vec![RunnerPoolTemplateRecord {
                pool_id,
                runtime_compatibility_digest: runtime,
                provider: "contract".to_owned(),
                provider_template_id: format!("template-{prefix}"),
                runner_template_digest: ContentDigest::sha256(format!("template-{prefix}")),
                created_unix_ms: 100,
                updated_unix_ms: 101,
            }],
        }
    }

    fn oidc_capsule(prefix: &str) -> ExecutionCapsule {
        let capabilities = StepCapabilitySet {
            oidc_audiences: vec!["https://deploy.example".to_owned()],
            secrets: vec![runtrue_model::SecretReference {
                metadata_id: format!("secret-{prefix}"),
                name: "TOKEN".to_owned(),
                purpose: Some("publish".to_owned()),
                resolution: Some(runtrue_model::SecretResolutionBinding {
                    scope: format!("repository:repo-{prefix}"),
                    metadata_version: Some(1),
                    resolution_digest: ContentDigest::sha256(format!("secret-resolution-{prefix}")),
                    project_versions: Vec::new(),
                }),
            }],
            ..StepCapabilitySet::default()
        };
        ExecutionCapsule {
            schema_version: CAPSULE_SCHEMA_VERSION,
            engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
            compiler_version: format!("contract-{prefix}"),
            workflow: WorkflowIdentity {
                name: "runner-contract".to_owned(),
                digest: ContentDigest::sha256(format!("workflow-{prefix}")),
                source_path: ".runtrue/workflows/contract.yaml".to_owned(),
            },
            context: CapsuleContext {
                source_commit: "0123456789abcdef".to_owned(),
                source_tree_digest: None,
                base_commit: None,
                source_trust: SourceTrust::ProtectedBranch,
                normalized_event_digest: ContentDigest::sha256(format!("event-{prefix}")),
                normalized_event_json: None,
                scm: None,
                event_context: BTreeMap::new(),
                lockfile_digest: None,
                workflow_frontend: None,
                policy_version_ids: Vec::new(),
            },
            variables: BTreeMap::new(),
            permissions: PermissionSet::default(),
            jobs: vec![PlannedJob {
                id: "deploy".to_owned(),
                base_id: "deploy".to_owned(),
                name: "deploy".to_owned(),
                needs: Vec::new(),
                matrix: BTreeMap::new(),
                condition: None,
                trust: Trust::UntrustedOk,
                environment: None,
                runner: RunnerRequirements {
                    os: OperatingSystem::Linux,
                    arch: Architecture::Amd64,
                    isolation: Isolation::Microvm,
                    image: None,
                    cpu: 1,
                    memory_bytes: 1_024,
                    storage_bytes: Some(1_024),
                    region: Some("test-region".to_owned()),
                    capabilities: vec!["kvm".to_owned()],
                },
                permissions: PermissionSet::default(),
                timeout_ms: 60_000,
                retries: 0,
                concurrency: None,
                variables: BTreeMap::new(),
                services: Vec::new(),
                steps: vec![PlannedStep {
                    id: "publish".to_owned(),
                    name: "publish".to_owned(),
                    condition: None,
                    action: StepAction::Command {
                        program: "true".to_owned(),
                        args: Vec::new(),
                    },
                    inputs: BTreeMap::new(),
                    environment: BTreeMap::new(),
                    capabilities,
                    cache: None,
                    timeout_ms: None,
                    continue_on_error: false,
                    outputs: BTreeMap::new(),
                    working_directory: None,
                }],
                finalizers: Vec::new(),
                finalizer_timeout_ms: 120_000,
                value_outputs: BTreeMap::new(),
                outputs: BTreeMap::new(),
            }],
            dynamic_jobs: Vec::new(),
            approval: ApprovalRequirements {
                workflow_definition: false,
                privileged_execution: true,
                reasons: vec!["OIDC".to_owned()],
            },
            expected_parity: ParityGrade::AExact,
        }
    }

    #[cfg(feature = "postgres")]
    fn expanded_capsule(prefix: &str) -> (ExecutionCapsule, ExpandedJobSet) {
        let mut capsule = oidc_capsule(prefix);
        capsule.approval = ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        };
        let mut producer = capsule.jobs.remove(0);
        producer.id = "producer".to_owned();
        producer.base_id = "producer".to_owned();
        producer.name = "producer".to_owned();
        producer.steps.clear();
        let mut template_job = producer.clone();
        template_job.id = "fanout".to_owned();
        template_job.base_id = "fanout".to_owned();
        template_job.name = "fanout".to_owned();
        template_job.needs = vec!["producer".to_owned()];
        capsule.jobs = vec![producer];
        capsule.dynamic_jobs = vec![DynamicJobTemplate {
            id: "fanout".to_owned(),
            source: DynamicMatrixSource {
                producer_job_id: "producer".to_owned(),
                output_name: "matrix".to_owned(),
                maximum_jobs: 4,
            },
            template: template_job.clone(),
        }];
        let parent = capsule.digest().unwrap();
        let mut generated = template_job;
        generated.id = "fanout[0]".to_owned();
        generated
            .matrix
            .insert("shard".to_owned(), ScalarValue::Integer(0));
        let expanded = ExpandedJobSet {
            version: 1,
            parent_capsule_digest: parent,
            producer_job_id: "producer".to_owned(),
            producer_output_name: "matrix".to_owned(),
            matrix_input_digest: ContentDigest::sha256(b"matrix-input"),
            generated_job_ids: vec!["fanout[0]".to_owned()],
            jobs: vec![generated],
            policy_epoch: 1,
        };
        (capsule, expanded)
    }

    async fn runner_secret_contract(
        store: &impl RunnerLeaseBrokerStore,
        request: &IssueRunnerSecretRequest,
        master_key: &MasterKey,
    ) {
        let delivered = store
            .issue_runner_secret(request, master_key)
            .await
            .expect("deliver exact signed runner secret");
        assert_eq!(delivered.plaintext.as_bytes(), b"runner-secret-contract");
        assert_eq!(
            delivered.lease.execution_lease_id,
            request.execution_lease_id
        );
        assert_eq!(delivered.lease.secret_version, 1);
        assert_eq!(
            delivered.lease.guest_key_fingerprint,
            request.guest_key_fingerprint
        );
        assert_eq!(
            delivered.lease.runner_posture_digest,
            request.runner_posture_digest
        );
        let mut replay = request.clone();
        replay.guest_key_fingerprint = ContentDigest::sha256(b"substituted-guest-key");
        assert!(matches!(
            store.issue_runner_secret(&replay, master_key).await,
            Err(ControlPlaneError::RunnerBrokerReplay)
        ));
        let mut stale_posture = request.clone();
        stale_posture.runner_posture_digest = ContentDigest::sha256(b"stale-posture");
        assert!(matches!(
            store.issue_runner_secret(&stale_posture, master_key).await,
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
    }

    async fn runner_completion_claim_contract(
        store: &impl RunnerLeaseBrokerStore,
        lease: &Lease,
        claims: &[(String, String)],
    ) {
        store
            .validate_runner_completion_artifact_claims(
                &lease.id,
                &lease.runner_id,
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                1,
                claims,
            )
            .await
            .expect("validate exact runner artifact claims");
        for invalid in [
            vec![(claims[0].0.clone(), "substituted-name".to_owned())],
            vec![("cross-tenant-object".to_owned(), claims[0].1.clone())],
            vec![claims[0].clone(), claims[0].clone()],
        ] {
            assert!(matches!(
                store
                    .validate_runner_completion_artifact_claims(
                        &lease.id,
                        &lease.runner_id,
                        lease.fencing_generation,
                        lease.installation_fencing_epoch,
                        1,
                        &invalid,
                    )
                    .await,
                Err(ControlPlaneError::RunnerBrokerBindingMismatch)
            ));
        }
        assert!(matches!(
            store
                .validate_runner_completion_artifact_claims(
                    &lease.id,
                    &lease.runner_id,
                    lease.fencing_generation,
                    lease.installation_fencing_epoch,
                    2,
                    claims,
                )
                .await,
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
    }

    async fn fleet_fencing_contract(store: &impl RunnerFleetEnrollmentStore, prefix: &str) {
        let configuration = configuration(prefix);
        store
            .put_runner_pool_configuration(&configuration)
            .await
            .expect("configure pool");
        assert_eq!(
            store
                .runner_pool_configuration(&configuration.pool.id)
                .await
                .expect("read pool"),
            configuration
        );
        let runner = RunnerRecord {
            id: format!("fleet-runner-{prefix}"),
            tenant_id: configuration.pool.tenant_id.clone(),
            pool_id: configuration.pool.id.clone(),
            ephemeral: false,
            retired: false,
            os: runtrue_workflow_ir::OperatingSystem::Linux,
            arch: runtrue_workflow_ir::Architecture::Amd64,
            isolation_backends: std::collections::BTreeSet::from([
                runtrue_workflow_ir::Isolation::Microvm,
            ]),
            logical_cpus: 2,
            memory_bytes: 1 << 20,
            storage_bytes: 1 << 20,
            max_concurrent_wasm_jobs: 1,
            region: Some("test-region".to_owned()),
            verified_capabilities: std::collections::BTreeSet::new(),
            self_reported_capabilities: std::collections::BTreeSet::new(),
            status: runtrue_scheduler::RunnerStatus::Offline,
            active_jobs: 0,
            active_wasm_jobs: 0,
            used_cpus: 0,
            used_memory_bytes: 0,
            used_storage_bytes: 0,
            locality: std::collections::BTreeSet::new(),
            package_tiers: Default::default(),
            last_heartbeat_unix_ms: 110,
        };
        let inventory = ContentDigest::sha256(format!("inventory-{prefix}"));
        let posture = store
            .register_pool_runner(&runner, &inventory, 110)
            .await
            .expect("register runner inventory");
        assert_eq!(
            store
                .pool_runner(&runner.id)
                .await
                .expect("read registered runner")
                .runner,
            runner
        );
        assert_eq!(
            posture,
            crate::authoritative_runner_posture_digest(&runner, &inventory).unwrap()
        );
        assert_eq!(
            store
                .validate_pool_runner_inventory(&runner.id, &inventory)
                .await
                .unwrap(),
            posture
        );
        store
            .set_pool_runner_connected(&runner.id, true, 111)
            .await
            .expect("connect runner");
        let locality = BTreeSet::from([ContentDigest::sha256(format!("locality-{prefix}"))]);
        assert_eq!(
            store
                .update_pool_runner_locality(&runner.id, &locality, &BTreeMap::new(), 111)
                .await
                .unwrap()
                .runner
                .locality,
            locality
        );
        let online = store
            .pool_fleet_snapshot(&configuration.pool.id, 111)
            .await
            .expect("online fleet snapshot");
        assert_eq!(online.online_workers, 1);
        store
            .set_pool_runner_connected(&runner.id, false, 112)
            .await
            .expect("disconnect runner");
        let offline = store
            .pool_fleet_snapshot(&configuration.pool.id, 112)
            .await
            .expect("offline fleet snapshot");
        assert_eq!(offline.offline_workers, 1);
        let first = store
            .acquire_autoscaler_lease(&configuration.pool.id, "owner", 200, 20_000)
            .await
            .expect("first lease");
        let second = store
            .acquire_autoscaler_lease(&configuration.pool.id, "owner", 201, 20_001)
            .await
            .expect("same-owner replica fences first");
        assert_eq!(second.fencing_generation, first.fencing_generation + 1);
        let template = &configuration.templates[0];
        let request = RunnerFleetRequestRecord {
            id: format!("request-{prefix}"),
            pool_id: configuration.pool.id.clone(),
            runtime_compatibility_digest: template.runtime_compatibility_digest.clone(),
            provider: template.provider.clone(),
            provider_template_id: template.provider_template_id.clone(),
            runner_template_digest: template.runner_template_digest.clone(),
            state: RunnerFleetRequestState::Requested,
            provider_request_id: None,
            provider_instance_id: None,
            runner_id: None,
            failure_code: None,
            created_unix_ms: 202,
            updated_unix_ms: 202,
        };
        assert!(matches!(
            store
                .create_fleet_request(&request, "owner", first.fencing_generation)
                .await,
            Err(ControlPlaneError::RunnerAutoscalerLeaseLost)
        ));
        store
            .create_fleet_request(&request, "owner", second.fencing_generation)
            .await
            .expect("current owner creates request");
        assert!(store
            .runner_pools()
            .await
            .unwrap()
            .iter()
            .any(|pool| pool == &configuration.pool));
        assert_eq!(
            store
                .runner_pools_for_tenant(&configuration.pool.tenant_id)
                .await
                .unwrap(),
            vec![configuration.pool.clone()]
        );
        assert_eq!(
            store.pool_templates(&configuration.pool.id).await.unwrap(),
            configuration.templates
        );
        assert!(store
            .pool_runners()
            .await
            .unwrap()
            .iter()
            .any(|value| value.runner.id == runner.id));
        assert_eq!(
            store
                .pool_runners_for_tenant(&configuration.pool.tenant_id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store.fleet_requests(&configuration.pool.id).await.unwrap(),
            vec![request.clone()]
        );
        assert_eq!(store.fleet_request(&request.id).await.unwrap(), request);
        assert_eq!(
            store
                .drain_pool_runner(&runner.id, 203)
                .await
                .unwrap()
                .runner
                .status,
            runtrue_scheduler::RunnerStatus::Draining
        );
        let token = store
            .create_pool_enrollment_token(&configuration.pool.id, 300, 1_300)
            .await
            .expect("create enrollment token");
        assert_eq!(
            store
                .inspect_pool_enrollment_token(token.token.expose(), 300)
                .await
                .unwrap(),
            token.metadata
        );
        assert!(store
            .launch_claim_for_enrollment_token(&token.metadata.id)
            .await
            .unwrap()
            .is_none());
        let consumed = store
            .consume_pool_enrollment_token(token.token.expose(), 301)
            .await
            .expect("consume enrollment token");
        assert_eq!(consumed.consumed_unix_ms, Some(301));
        assert!(matches!(
            store
                .consume_pool_enrollment_token(token.token.expose(), 302)
                .await,
            Err(ControlPlaneError::EnrollmentTokenConsumed)
        ));
        let issued = store
            .create_pool_enrollment_token_idempotent(
                "enrollment-contract",
                &configuration.pool.id,
                2,
                400,
                2_400,
            )
            .await
            .expect("idempotent enrollment issue");
        let issued_id = match issued {
            EnrollmentTokenIssueResult::Issued(value) => value.metadata.id,
            EnrollmentTokenIssueResult::Replayed(_) => {
                panic!("first request unexpectedly replayed")
            }
        };
        let replay = store
            .create_pool_enrollment_token_idempotent(
                "enrollment-contract",
                &configuration.pool.id,
                2,
                401,
                2_401,
            )
            .await
            .expect("idempotent enrollment replay");
        match replay {
            EnrollmentTokenIssueResult::Replayed(value) => assert_eq!(value.id, issued_id),
            EnrollmentTokenIssueResult::Issued(_) => panic!("replay returned new bearer"),
        }
    }

    #[cfg(feature = "postgres")]
    async fn postgres_lease_completion_contract(
        store: &PostgresInstallationStore,
        configuration: &RunnerPoolConfiguration,
        prefix: &str,
    ) {
        let tenant_id = &configuration.pool.tenant_id;
        let repository_id = format!("repo-{prefix}");
        let capsule_id = format!("capsule-{prefix}");
        let run_id = format!("run-{prefix}");
        let job_id = format!("job-{prefix}");
        let runner_id = format!("runner-{prefix}");
        let lease_id = format!("lease-{prefix}");
        let capsule_digest = ContentDigest::sha256(format!("capsule-{prefix}"));
        let epoch: i64 =
            sqlx::query_scalar("SELECT fencing_epoch FROM installation_state WHERE singleton=TRUE")
                .fetch_one(store.pool())
                .await
                .unwrap();
        let epoch = u64::try_from(epoch).unwrap();
        sqlx::query(
            "INSERT INTO tenants
             (id,slug,name,status,settings_json,created_unix_ms,updated_unix_ms,version)
             VALUES($1,$2,$3,'active',$4,1,1,1) ON CONFLICT(id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(format!("tenant-{prefix}"))
        .bind(format!("Tenant {prefix}"))
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repositories
             (id,tenant_id,owner,name,default_branch,visibility,created_unix_ms)
             VALUES($1,$2,'owner',$3,'main','private',1)",
        )
        .bind(&repository_id)
        .bind(tenant_id)
        .bind(format!("repo-{prefix}"))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO capsules
             (id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms)
             VALUES($1,$2,$3,$4,$4,'key',1)",
        )
        .bind(&capsule_id)
        .bind(&repository_id)
        .bind(capsule_digest.as_str())
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO runs
             (id,repository_id,capsule_id,status,priority,remote,created_unix_ms,started_unix_ms)
             VALUES($1,$2,$3,'running',0,TRUE,1,2)",
        )
        .bind(&run_id)
        .bind(&repository_id)
        .bind(&capsule_id)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs
             (id,run_id,job_key,attempt,status,requirements_json,created_unix_ms)
             VALUES($1,$2,'job',1,'leased',$3,2)",
        )
        .bind(&job_id)
        .bind(&run_id)
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms)
             VALUES($1,$2,'online',$3,2,2)",
        )
        .bind(&runner_id)
        .bind(&configuration.pool.id)
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        let lease = Lease {
            id: lease_id.clone(),
            job_id: job_id.clone(),
            tenant_id: tenant_id.clone(),
            runner_id: runner_id.clone(),
            fencing_generation: 1,
            installation_fencing_epoch: epoch,
            capsule_digest,
            issued_unix_ms: 10,
            accept_by_unix_ms: 100,
            expires_unix_ms: 200,
            state: LeaseState::Offered,
            terminal_result_digest: None,
        };
        store.put_copied_lease(&lease, 300).await.unwrap();
        store
            .accept_runner_execution_lease(&lease_id, &runner_id, 1, epoch, 20)
            .await
            .unwrap();
        store
            .append_runner_log_frames(
                &AppendRunnerLogsRequest {
                    execution_lease_id: lease_id.clone(),
                    fencing_generation: 1,
                    runner_id: runner_id.clone(),
                    frames: vec![RunnerLogFrameRecord {
                        execution_lease_id: lease_id.clone(),
                        fencing_generation: 1,
                        job_attempt: 1,
                        step_id: "step".to_owned(),
                        stream: "stdout".to_owned(),
                        sequence: 0,
                        monotonic_nanoseconds: 1,
                        wall_time_unix_ms: 21,
                        payload: b"hello".to_vec(),
                        redaction_state: "redacted".to_owned(),
                    }],
                },
                21,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE jobs SET status='finalizing' WHERE id=$1")
            .bind(&job_id)
            .execute(store.pool())
            .await
            .unwrap();
        let result = ContentDigest::sha256(format!("result-{prefix}"));
        let completed = store
            .complete_runner_lease(
                &lease_id,
                &runner_id,
                1,
                epoch,
                &result,
                JobState::Succeeded,
                CredentialTaintState::None,
                1,
                &[],
                &[],
                &[],
                30,
            )
            .await
            .unwrap();
        assert_eq!(completed.state, LeaseState::Completed);
        assert_eq!(
            store.runner_logs_for_run(&run_id, 10).await.unwrap().len(),
            1
        );
        assert_eq!(
            store.runner_run_credential_taint(&run_id).await.unwrap(),
            CredentialTaintState::None
        );
        let run_status: String = sqlx::query_scalar("SELECT status FROM runs WHERE id=$1")
            .bind(&run_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(run_status, "succeeded");
        store
            .complete_runner_lease(
                &lease_id,
                &runner_id,
                1,
                epoch,
                &result,
                JobState::Succeeded,
                CredentialTaintState::None,
                1,
                &[],
                &[],
                &[],
                30,
            )
            .await
            .expect("exact terminal replay");
        assert!(matches!(
            store
                .complete_runner_lease(
                    &lease_id,
                    &runner_id,
                    1,
                    epoch,
                    &ContentDigest::sha256(b"conflicting result"),
                    JobState::Succeeded,
                    CredentialTaintState::None,
                    1,
                    &[],
                    &[],
                    &[],
                    30,
                )
                .await,
            Err(ControlPlaneError::ConflictingCompletion)
        ));
    }

    #[cfg(feature = "postgres")]
    async fn postgres_scheduler_oidc_contract(
        store: &PostgresInstallationStore,
        configuration: &RunnerPoolConfiguration,
        prefix: &str,
    ) {
        let prefix = format!("oidc-{prefix}");
        let tenant_id = &configuration.pool.tenant_id;
        let repository_id = format!("repo-{prefix}");
        let capsule_id = format!("capsule-{prefix}");
        let run_id = format!("run-{prefix}");
        let job_id = format!("job-{prefix}");
        let runner_id = format!("runner-{prefix}");
        let approval_id = format!("approval-{prefix}");
        let capsule = oidc_capsule(&prefix);
        let canonical = capsule.canonical_bytes().unwrap();
        let capsule_digest = capsule.digest().unwrap();
        let requirements = postgres_planned_requirements(&capsule.jobs[0]);
        sqlx::query(
            "INSERT INTO repositories
             (id,tenant_id,owner,name,default_branch,visibility,created_unix_ms)
             VALUES($1,$2,'owner',$3,'main','private',1)",
        )
        .bind(&repository_id)
        .bind(tenant_id)
        .bind(format!("repo-{prefix}"))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO capsules
             (id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms)
             VALUES($1,$2,$3,$4,$5,'key',1)",
        )
        .bind(&capsule_id)
        .bind(&repository_id)
        .bind(capsule_digest.as_str())
        .bind(&canonical)
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO runs
             (id,repository_id,capsule_id,status,priority,remote,created_unix_ms)
             VALUES($1,$2,$3,'created',10,TRUE,2)",
        )
        .bind(&run_id)
        .bind(&repository_id)
        .bind(&capsule_id)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs
             (id,run_id,job_key,attempt,status,requirements_json,created_unix_ms)
             VALUES($1,$2,'deploy',1,'queued',$3,3)",
        )
        .bind(&job_id)
        .bind(&run_id)
        .bind(serde_json::to_vec(&requirements).unwrap())
        .execute(store.pool())
        .await
        .unwrap();
        let approval_subject = ContentDigest::sha256(format!("approval-{prefix}"));
        sqlx::query(
            "INSERT INTO approval_requests
             (id,repository_id,capsule_id,subject_digest,status,request_json,
              created_unix_ms,expires_unix_ms)
             VALUES($1,$2,$3,$4,'consumed',$5,4,100000)",
        )
        .bind(&approval_id)
        .bind(&repository_id)
        .bind(&capsule_id)
        .bind(approval_subject.as_str())
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO run_approval_authorizations
             (run_id,approval_id,kind,subject_digest,one_shot,authorized_unix_ms)
             VALUES($1,$2,'privileged-execution',$3,FALSE,5)",
        )
        .bind(&run_id)
        .bind(&approval_id)
        .bind(approval_subject.as_str())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO capsule_api_metadata(capsule_id,approval_subject_digest,risk_score)
             VALUES($1,$2,10)",
        )
        .bind(&capsule_id)
        .bind(approval_subject.as_str())
        .execute(store.pool())
        .await
        .unwrap();
        let runner = RunnerRecord {
            id: runner_id.clone(),
            tenant_id: tenant_id.clone(),
            pool_id: configuration.pool.id.clone(),
            ephemeral: false,
            retired: false,
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation_backends: BTreeSet::from([Isolation::Microvm]),
            logical_cpus: 4,
            memory_bytes: 1 << 30,
            storage_bytes: 1 << 30,
            max_concurrent_wasm_jobs: 1,
            region: Some("test-region".to_owned()),
            verified_capabilities: BTreeSet::from(["kvm".to_owned()]),
            self_reported_capabilities: BTreeSet::new(),
            status: runtrue_scheduler::RunnerStatus::Online,
            active_jobs: 0,
            active_wasm_jobs: 0,
            used_cpus: 0,
            used_memory_bytes: 0,
            used_storage_bytes: 0,
            locality: BTreeSet::new(),
            package_tiers: Default::default(),
            last_heartbeat_unix_ms: 9_900,
        };
        let posture = store
            .register_pool_runner(
                &runner,
                &ContentDigest::sha256(format!("inventory-{prefix}")),
                9_900,
            )
            .await
            .unwrap();
        let lease = store
            .offer_next_runner_lease(&runner_id, 10_000)
            .await
            .unwrap()
            .expect("queued signed job offered");
        store
            .accept_runner_execution_lease(
                &lease.id,
                &runner_id,
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                10_001,
            )
            .await
            .unwrap();
        let master_key = MasterKey::from_bytes([43; 32]);
        let secret_metadata = crate::SecretMetadataReference {
            id: format!("secret-{prefix}"),
            tenant_id: tenant_id.clone(),
            scope: format!("repository:{repository_id}"),
            name: "TOKEN".to_owned(),
            provider: "built-in".to_owned(),
            provider_reference: None,
            secret_type: "token".to_owned(),
            status: "active".to_owned(),
            current_version: Some(1),
            created_unix_ms: 9_999,
            updated_unix_ms: 9_999,
        };
        let plaintext = runtrue_secrets::SecretPlaintext::new(b"runner-secret-contract".to_vec());
        crate::persistence::SecretConfigurationStore::create_secret(
            store,
            &format!("secret-create-{prefix}"),
            &secret_metadata,
            Some(&plaintext),
            &master_key,
        )
        .await
        .unwrap();
        let secret_request = IssueRunnerSecretRequest {
            execution_lease_id: lease.id.clone(),
            fencing_generation: lease.fencing_generation,
            runner_id: runner_id.clone(),
            job_id: job_id.clone(),
            job_attempt: 1,
            step_id: "publish".to_owned(),
            secret_metadata_id: secret_metadata.id.clone(),
            purpose: "publish".to_owned(),
            guest_key_fingerprint: ContentDigest::sha256(format!("guest-key-{prefix}")),
            runner_posture_digest: posture.clone(),
            issued_unix_ms: 10_002,
            expires_unix_ms: lease.expires_unix_ms,
        };
        runner_secret_contract(store, &secret_request, &master_key).await;
        let artifact_id = format!("artifact-{prefix}");
        sqlx::query(
            "INSERT INTO runner_data_commits
             (kind,object_id,tenant_id,repository_id,run_id,job_id,job_attempt,
              step_id,output_name,lease_id,fencing_generation,ticket_id,committed_unix_ms)
             VALUES('artifact',$1,$2,$3,$4,$5,1,'publish','package',$6,$7,$8,10003)",
        )
        .bind(&artifact_id)
        .bind(tenant_id)
        .bind(&repository_id)
        .bind(&run_id)
        .bind(&job_id)
        .bind(&lease.id)
        .bind(postgres_i64(lease.fencing_generation, "lease generation").unwrap())
        .bind(format!("artifact-ticket-{prefix}"))
        .execute(store.pool())
        .await
        .unwrap();
        let artifact_claims = vec![(artifact_id.clone(), "package".to_owned())];
        runner_completion_claim_contract(store, &lease, &artifact_claims).await;
        let grant = store
            .authorize_runner_oidc_grant(&AuthorizeRunnerOidcRequest {
                execution_lease_id: lease.id.clone(),
                fencing_generation: lease.fencing_generation,
                runner_id: runner_id.clone(),
                job_id: job_id.clone(),
                job_attempt: 1,
                step_id: "publish".to_owned(),
                audience: "https://deploy.example".to_owned(),
                runner_posture_digest: posture.clone(),
                now_unix_ms: 10_002,
            })
            .await
            .unwrap();
        let mut legacy_grant = grant.clone();
        legacy_grant.grant_id = format!("legacy-{}", grant.grant_id);
        crate::OidcGrantStore::store_grant(store, &legacy_grant)
            .await
            .unwrap();
        assert_eq!(
            crate::OidcGrantStore::authorize_grant(
                store,
                &legacy_grant.grant_id,
                &lease.id,
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &job_id,
                "publish",
                10_002,
            )
            .await
            .unwrap(),
            legacy_grant
        );
        crate::OidcGrantStore::record_issuance(
            store,
            &legacy_grant.grant_id,
            "https://deploy.example",
            &format!("legacy-jti-{prefix}"),
            10_003,
            20_000,
        )
        .await
        .unwrap();
        assert!(
            sqlx::query("UPDATE oidc_issuances SET jti='tampered' WHERE grant_id=$1")
                .bind(&legacy_grant.grant_id)
                .execute(store.pool())
                .await
                .is_err()
        );
        assert!(matches!(
            store
                .authorize_runner_oidc_grant(&AuthorizeRunnerOidcRequest {
                    audience: "https://attacker.example".to_owned(),
                    ..AuthorizeRunnerOidcRequest {
                        execution_lease_id: lease.id.clone(),
                        fencing_generation: lease.fencing_generation,
                        runner_id: runner_id.clone(),
                        job_id: job_id.clone(),
                        job_attempt: 1,
                        step_id: "publish".to_owned(),
                        audience: "https://deploy.example".to_owned(),
                        runner_posture_digest: posture.clone(),
                        now_unix_ms: 10_002,
                    }
                })
                .await,
            Err(ControlPlaneError::RunnerBrokerCapabilityDenied)
        ));
        store
            .record_runner_oidc_token(&RecordRunnerOidcIssuance {
                grant_id: grant.grant_id.clone(),
                audience: "https://deploy.example".to_owned(),
                jti: format!("jti-{prefix}"),
                runner_id: runner_id.clone(),
                runner_posture_digest: posture,
                job_attempt: 1,
                issued_unix_ms: 10_003,
                expires_unix_ms: 20_000,
            })
            .await
            .unwrap();
        sqlx::query("UPDATE jobs SET status='finalizing' WHERE id=$1")
            .bind(&job_id)
            .execute(store.pool())
            .await
            .unwrap();
        store
            .complete_runner_lease(
                &lease.id,
                &runner_id,
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &ContentDigest::sha256(format!("result-{prefix}")),
                JobState::Succeeded,
                CredentialTaintState::None,
                1,
                std::slice::from_ref(&artifact_id),
                &[],
                &["package".to_owned()],
                10_004,
            )
            .await
            .unwrap();
        runner_completion_claim_contract(store, &lease, &artifact_claims).await;
        let states = sqlx::query(
            "SELECT r.state,g.revoked_unix_ms IS NOT NULL AS revoked
             FROM runner_oidc_grants r JOIN oidc_grants g ON g.id=r.grant_id
             WHERE r.grant_id=$1",
        )
        .bind(&grant.grant_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(states.try_get::<String, _>("state").unwrap(), "revoked");
        assert!(states.try_get::<bool, _>("revoked").unwrap());
    }

    #[cfg(feature = "postgres")]
    async fn postgres_expanded_scheduler_contract(
        store: &PostgresInstallationStore,
        configuration: &RunnerPoolConfiguration,
        prefix: &str,
    ) {
        let expanded_prefix = format!("expanded-{prefix}");
        let tenant_id = &configuration.pool.tenant_id;
        let repository_id = format!("repo-{expanded_prefix}");
        let capsule_id = format!("capsule-{expanded_prefix}");
        let run_id = format!("run-{expanded_prefix}");
        let producer_job_id = format!("producer-{expanded_prefix}");
        let expanded_job_id = format!("expanded-{expanded_prefix}");
        let runner_id = format!("runner-oidc-{prefix}");
        let (capsule, expanded) = expanded_capsule(&expanded_prefix);
        let capsule_digest = capsule.digest().unwrap();
        let canonical = capsule.canonical_bytes().unwrap();
        let expanded_canonical = expanded.canonical_bytes().unwrap();
        sqlx::query(
            "INSERT INTO repositories
             (id,tenant_id,owner,name,default_branch,visibility,created_unix_ms)
             VALUES($1,$2,'owner',$3,'main','private',1)",
        )
        .bind(&repository_id)
        .bind(tenant_id)
        .bind(format!("repo-{expanded_prefix}"))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO capsules
             (id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms)
             VALUES($1,$2,$3,$4,$5,'key',1)",
        )
        .bind(&capsule_id)
        .bind(&repository_id)
        .bind(capsule_digest.as_str())
        .bind(&canonical)
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO runs
             (id,repository_id,capsule_id,status,priority,remote,created_unix_ms,started_unix_ms)
             VALUES($1,$2,$3,'running',5,TRUE,2,3)",
        )
        .bind(&run_id)
        .bind(&repository_id)
        .bind(&capsule_id)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs
             (id,run_id,job_key,attempt,status,requirements_json,created_unix_ms,completed_unix_ms)
             VALUES($1,$2,'producer',1,'succeeded',$3,3,4)",
        )
        .bind(&producer_job_id)
        .bind(&run_id)
        .bind(serde_json::to_vec(&postgres_planned_requirements(&capsule.jobs[0])).unwrap())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs
             (id,run_id,job_key,attempt,status,requirements_json,created_unix_ms)
             VALUES($1,$2,'fanout[0]',1,'queued',$3,5)",
        )
        .bind(&expanded_job_id)
        .bind(&run_id)
        .bind(serde_json::to_vec(&postgres_planned_requirements(&expanded.jobs[0])).unwrap())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO expanded_job_sets
             (id,tenant_id,repository_id,run_id,parent_capsule_digest,template_id,
              producer_job_id,producer_output_name,matrix_input_digest,policy_epoch,
              generated_job_count,canonical_job_set,job_set_digest,signing_key_id,
              signature,created_unix_ms)
             VALUES($1,$2,$3,$4,$5,'fanout',$6,'matrix',$7,1,1,$8,$9,'key',$10,5)",
        )
        .bind(format!("set-{expanded_prefix}"))
        .bind(tenant_id)
        .bind(&repository_id)
        .bind(&run_id)
        .bind(capsule_digest.as_str())
        .bind(&producer_job_id)
        .bind(expanded.matrix_input_digest.as_str())
        .bind(&expanded_canonical)
        .bind(ContentDigest::sha256(&expanded_canonical).as_str())
        .bind(b"signature".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        let lease = store
            .offer_next_runner_lease(&runner_id, 10_005)
            .await
            .unwrap()
            .expect("expanded signed job offered");
        assert_eq!(lease.job_id, expanded_job_id);
        store
            .accept_runner_execution_lease(
                &lease.id,
                &runner_id,
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                10_006,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE jobs SET status='finalizing' WHERE id=$1")
            .bind(&expanded_job_id)
            .execute(store.pool())
            .await
            .unwrap();
        store
            .complete_runner_lease(
                &lease.id,
                &runner_id,
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &ContentDigest::sha256(format!("result-{expanded_prefix}")),
                JobState::Succeeded,
                CredentialTaintState::None,
                1,
                &[],
                &[],
                &[],
                10_007,
            )
            .await
            .unwrap();
    }

    #[cfg(feature = "postgres")]
    async fn postgres_deployment_gate_scheduler_contract(
        store: &PostgresInstallationStore,
        configuration: &RunnerPoolConfiguration,
        prefix: &str,
    ) {
        let gate_prefix = format!("gate-{prefix}");
        let tenant_id = &configuration.pool.tenant_id;
        let repository_id = format!("repo-{gate_prefix}");
        let capsule_id = format!("capsule-{gate_prefix}");
        let run_id = format!("run-{gate_prefix}");
        let job_id = format!("job-{gate_prefix}");
        let source_job_id = format!("source-job-{gate_prefix}");
        let environment_id = format!("environment-{gate_prefix}");
        let deployment_id = format!("deployment-{gate_prefix}");
        let gate_id = format!("concurrency-{gate_prefix}");
        let runner_id = format!("runner-oidc-{prefix}");
        let epoch: i64 =
            sqlx::query_scalar("SELECT fencing_epoch FROM installation_state WHERE singleton=TRUE")
                .fetch_one(store.pool())
                .await
                .unwrap();
        let mut capsule = oidc_capsule(&gate_prefix);
        capsule.approval = ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        };
        capsule.jobs[0].environment = Some("production".to_owned());
        let canonical = capsule.canonical_bytes().unwrap();
        let capsule_digest = capsule.digest().unwrap();
        sqlx::query(
            "INSERT INTO repositories
             (id,tenant_id,owner,name,default_branch,visibility,created_unix_ms)
             VALUES($1,$2,'owner',$3,'main','private',1)",
        )
        .bind(&repository_id)
        .bind(tenant_id)
        .bind(format!("repo-{gate_prefix}"))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO capsules
             (id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms)
             VALUES($1,$2,$3,$4,$5,'key',1)",
        )
        .bind(&capsule_id)
        .bind(&repository_id)
        .bind(capsule_digest.as_str())
        .bind(&canonical)
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO runs
             (id,repository_id,capsule_id,status,priority,remote,created_unix_ms)
             VALUES($1,$2,$3,'created',20,TRUE,2)",
        )
        .bind(&run_id)
        .bind(&repository_id)
        .bind(&capsule_id)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs
             (id,run_id,job_key,attempt,status,requirements_json,created_unix_ms)
             VALUES($1,$2,'deploy',1,'queued',$3,3)",
        )
        .bind(&job_id)
        .bind(&run_id)
        .bind(serde_json::to_vec(&postgres_planned_requirements(&capsule.jobs[0])).unwrap())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs
             (id,run_id,job_key,attempt,status,requirements_json,created_unix_ms,completed_unix_ms)
             VALUES($1,$2,'artifact-source',1,'succeeded',$3,3,5)",
        )
        .bind(&source_job_id)
        .bind(&run_id)
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO tenant_policy_states
             (tenant_id,policy_epoch,decision_cache_generation,state_digest,state_json,
              version,actor_id,audit_correlation_id,updated_unix_ms)
             VALUES($1,1,1,$2,$3,1,'actor','audit',4)",
        )
        .bind(tenant_id)
        .bind(ContentDigest::sha256(format!("policy-{gate_prefix}")).as_str())
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        let rules = crate::EnvironmentProtectionRules {
            require_approval: false,
            minimum_approvals: 0,
            approval_ttl_ms: 0,
            approval_rule_digest: None,
            require_signed_artifact: false,
            required_artifact_classification: "internal".to_owned(),
            require_passed_scan: false,
            require_promotion_evidence: false,
            allowed_deployment_actors: Vec::new(),
            allowed_signing_purposes: Vec::new(),
            allowed_signer_policy_ids: Vec::new(),
        };
        let rules_json = serde_json::to_vec(&rules).unwrap();
        sqlx::query(
            "INSERT INTO environments
             (id,tenant_id,repository_id,name,deployment_target_reference,
              deployment_target_digest,status,protection_rules_json,protection_rules_digest,
              wait_timer_ms,concurrency_limit,required_policy_epoch,created_unix_ms,
              updated_unix_ms,version)
             VALUES($1,$2,$3,'production','cluster/prod',$4,'active',$5,$6,0,1,1,4,4,1)",
        )
        .bind(&environment_id)
        .bind(tenant_id)
        .bind(&repository_id)
        .bind(ContentDigest::sha256(b"cluster/prod").as_str())
        .bind(&rules_json)
        .bind(ContentDigest::sha256(&rules_json).as_str())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO environment_versions
             (tenant_id,environment_id,version,snapshot_digest,snapshot_json,created_unix_ms)
             VALUES($1,$2,1,$3,$4,4)",
        )
        .bind(tenant_id)
        .bind(&environment_id)
        .bind(ContentDigest::sha256(format!("environment-{gate_prefix}")).as_str())
        .bind(b"{}".as_slice())
        .execute(store.pool())
        .await
        .unwrap();
        let digest = ContentDigest::sha256(format!("deployment-{gate_prefix}"));
        let artifact_id = format!("artifact-{gate_prefix}");
        let artifact_lease_id = format!("artifact-lease-{gate_prefix}");
        sqlx::query(
            "INSERT INTO leases
             (id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,
              capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,
              hard_deadline_unix_ms,terminal_result_digest,terminal_job_state,
              terminal_credential_taint,completed_unix_ms)
             VALUES($1,$2,$3,$4,1,$5,$6,'completed',3,4,5,5,$7,'succeeded','none',5)",
        )
        .bind(&artifact_lease_id)
        .bind(&source_job_id)
        .bind(tenant_id)
        .bind(&runner_id)
        .bind(epoch)
        .bind(capsule_digest.as_str())
        .bind(digest.as_str())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO runner_data_commits
             (kind,object_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,
              output_name,lease_id,fencing_generation,ticket_id,committed_unix_ms)
             VALUES('artifact',$1,$2,$3,$4,$5,1,'deploy','bundle',$6,1,$7,5)",
        )
        .bind(&artifact_id)
        .bind(tenant_id)
        .bind(&repository_id)
        .bind(&run_id)
        .bind(&source_job_id)
        .bind(&artifact_lease_id)
        .bind(format!("artifact-ticket-{gate_prefix}"))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO job_result_objects(job_id,job_attempt,kind,object_id,ordinal)
             VALUES($1,1,'artifact',$2,0)",
        )
        .bind(&source_job_id)
        .bind(&artifact_id)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO artifacts_catalog
             (artifact_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,
              output_name,content_digest,manifest_digest,provenance_digest,size_bytes,
              media_type,classification,scan_state,retention_until_unix_seconds,
              legal_hold,state,created_unix_ms)
             VALUES($1,$2,$3,$4,$5,1,'deploy','bundle',$6,$6,$6,1,
                    'application/octet-stream','internal','passed',1000000,FALSE,'available',5)",
        )
        .bind(&artifact_id)
        .bind(tenant_id)
        .bind(&repository_id)
        .bind(&run_id)
        .bind(&source_job_id)
        .bind(digest.as_str())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO deployment_requests
             (id,tenant_id,environment_id,environment_version,policy_epoch,repository_id,
              run_id,job_id,job_attempt,artifact_id,artifact_source_run_id,
              artifact_source_job_id,artifact_source_job_attempt,artifact_digest,
              manifest_digest,provenance_digest,target_digest,deployment_capsule_digest,
              request_digest,approval_subject_digest,status,wait_until_unix_ms,
              concurrency_fence,installation_fencing_epoch,actor_id,audit_correlation_id,
              created_unix_ms,updated_unix_ms,version)
             VALUES($1,$2,$3,1,1,$4,$5,$6,1,$7,$5,$9,1,$8,$8,$8,$8,$8,$8,$8,
                    'ready',5,1,$10,'actor','audit',5,5,1)",
        )
        .bind(&deployment_id)
        .bind(tenant_id)
        .bind(&environment_id)
        .bind(&repository_id)
        .bind(&run_id)
        .bind(&job_id)
        .bind(&artifact_id)
        .bind(digest.as_str())
        .bind(&source_job_id)
        .bind(epoch)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO environment_concurrency_leases
             (id,tenant_id,environment_id,deployment_request_id,concurrency_fence,
              installation_fencing_epoch,state,acquired_unix_ms,expires_unix_ms)
             VALUES($1,$2,$3,$4,1,$5,'active',5,500000)",
        )
        .bind(&gate_id)
        .bind(tenant_id)
        .bind(&environment_id)
        .bind(&deployment_id)
        .bind(epoch)
        .execute(store.pool())
        .await
        .unwrap();
        let lease = store
            .offer_next_runner_lease(&runner_id, 10_008)
            .await
            .unwrap()
            .expect("deployment-gated job offered");
        assert_eq!(lease.job_id, job_id);
        let binding = sqlx::query(
            "SELECT d.status,d.execution_lease_id,g.execution_lease_id AS gate_lease
             FROM deployment_requests d JOIN environment_concurrency_leases g
             ON g.deployment_request_id=d.id WHERE d.id=$1",
        )
        .bind(&deployment_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(binding.try_get::<String, _>("status").unwrap(), "leased");
        assert_eq!(
            binding
                .try_get::<Option<String>, _>("execution_lease_id")
                .unwrap()
                .as_deref(),
            Some(lease.id.as_str())
        );
        assert_eq!(
            binding
                .try_get::<Option<String>, _>("gate_lease")
                .unwrap()
                .as_deref(),
            Some(lease.id.as_str())
        );
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn credential_taint_is_monotonic() {
        assert_eq!(
            monotonic_credential_taint("unobserved", CredentialTaintState::None).unwrap(),
            CredentialTaintState::None
        );
        assert_eq!(
            monotonic_credential_taint("unknown", CredentialTaintState::CredentialReleased)
                .unwrap(),
            CredentialTaintState::CredentialReleased
        );
        assert!(matches!(
            monotonic_credential_taint("unknown", CredentialTaintState::None),
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
    }

    #[tokio::test]
    async fn sqlite_runner_fleet_contract() {
        let store = ControlPlane::open_in_memory("runner-fleet-sqlite", 1).unwrap();
        fleet_fencing_contract(&store, "sqlite").await;
    }

    #[tokio::test]
    async fn sqlite_runner_secret_and_completion_claim_contract() {
        let store = ControlPlane::open_in_memory("runner-secret-sqlite", 1).unwrap();
        let prefix = "secret-sqlite";
        let configuration = configuration(prefix);
        crate::persistence::TenantIdentityStore::put_tenant_identity(
            &store,
            &crate::TenantIdentityRecord {
                id: configuration.pool.tenant_id.clone(),
                slug: "runner-secret-sqlite".to_owned(),
                name: "Runner secret SQLite".to_owned(),
                status: "active".to_owned(),
                settings: serde_json::json!({}),
                created_unix_ms: 1,
                updated_unix_ms: 1,
                version: 1,
            },
            None,
        )
        .await
        .unwrap();
        store
            .put_runner_pool_configuration(&configuration)
            .await
            .unwrap();
        let repository_id = format!("repo-{prefix}");
        let capsule_id = format!("capsule-{prefix}");
        let run_id = format!("run-{prefix}");
        let job_id = format!("job-{prefix}");
        let runner_id = format!("runner-{prefix}");
        let capsule = oidc_capsule(prefix);
        let canonical = capsule.canonical_bytes().unwrap();
        let capsule_digest = capsule.digest().unwrap();
        let approval_subject = ContentDigest::sha256(format!("approval-{prefix}"));
        let requirements = runtrue_scheduler::SchedulingRequirements {
            os: capsule.jobs[0].runner.os,
            arch: capsule.jobs[0].runner.arch,
            isolation: capsule.jobs[0].runner.isolation,
            cpu: u32::from(capsule.jobs[0].runner.cpu),
            memory_bytes: capsule.jobs[0].runner.memory_bytes,
            storage_bytes: capsule.jobs[0].runner.storage_bytes.unwrap_or(0),
            region: capsule.jobs[0].runner.region.clone(),
            required_capabilities: capsule.jobs[0]
                .runner
                .capabilities
                .iter()
                .cloned()
                .collect(),
            allowed_pools: BTreeSet::new(),
        };
        {
            let connection = store.connection().unwrap();
            connection.execute("INSERT INTO repositories(id,tenant_id,owner,name,default_branch,visibility,created_unix_ms) VALUES(?1,?2,'owner','repo','main','private',1)",rusqlite::params![repository_id,configuration.pool.tenant_id]).unwrap();
            connection.execute("INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES(?1,?2,?3,?4,'{}','key',1)",rusqlite::params![capsule_id,repository_id,capsule_digest.as_str(),canonical]).unwrap();
            connection.execute("INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms) VALUES(?1,?2,?3,'running',0,1,2)",rusqlite::params![run_id,repository_id,capsule_id]).unwrap();
            connection.execute("INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms) VALUES(?1,?2,'deploy',1,'leased',?3,3)",rusqlite::params![job_id,run_id,serde_json::to_string(&requirements).unwrap()]).unwrap();
            connection.execute("INSERT INTO approval_requests(id,repository_id,capsule_id,subject_digest,status,request_json,created_unix_ms,expires_unix_ms) VALUES('approval-secret-sqlite',?1,?2,?3,'consumed','{}',4,100000)",rusqlite::params![repository_id,capsule_id,approval_subject.as_str()]).unwrap();
            connection.execute("INSERT INTO capsule_api_metadata(capsule_id,approval_subject_digest,risk_score) VALUES(?1,?2,10)",rusqlite::params![capsule_id,approval_subject.as_str()]).unwrap();
            connection.execute("INSERT INTO run_approval_authorizations(run_id,approval_id,kind,subject_digest,one_shot,authorized_unix_ms) VALUES(?1,'approval-secret-sqlite','privileged-execution',?2,0,5)",rusqlite::params![run_id,approval_subject.as_str()]).unwrap();
        }
        let runner = RunnerRecord {
            id: runner_id.clone(),
            tenant_id: configuration.pool.tenant_id.clone(),
            pool_id: configuration.pool.id.clone(),
            ephemeral: false,
            retired: false,
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation_backends: BTreeSet::from([Isolation::Microvm]),
            logical_cpus: 4,
            memory_bytes: 1 << 30,
            storage_bytes: 1 << 30,
            max_concurrent_wasm_jobs: 1,
            region: Some("test-region".to_owned()),
            verified_capabilities: BTreeSet::from(["kvm".to_owned()]),
            self_reported_capabilities: BTreeSet::new(),
            status: runtrue_scheduler::RunnerStatus::Online,
            active_jobs: 0,
            active_wasm_jobs: 0,
            used_cpus: 0,
            used_memory_bytes: 0,
            used_storage_bytes: 0,
            locality: BTreeSet::new(),
            package_tiers: Default::default(),
            last_heartbeat_unix_ms: 9_900,
        };
        let posture = store
            .register_pool_runner(
                &runner,
                &ContentDigest::sha256(format!("inventory-{prefix}")),
                9_900,
            )
            .await
            .unwrap();
        let lease = Lease {
            id: format!("lease-{prefix}"),
            job_id: job_id.clone(),
            tenant_id: configuration.pool.tenant_id.clone(),
            runner_id: runner_id.clone(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            capsule_digest,
            issued_unix_ms: 10_000,
            accept_by_unix_ms: 10_100,
            expires_unix_ms: 20_000,
            state: LeaseState::Active,
            terminal_result_digest: None,
        };
        store.put_copied_lease(&lease, 20_000).await.unwrap();
        let master_key = MasterKey::from_bytes([43; 32]);
        let metadata = crate::SecretMetadataReference {
            id: format!("secret-{prefix}"),
            tenant_id: configuration.pool.tenant_id.clone(),
            scope: format!("repository:{repository_id}"),
            name: "TOKEN".to_owned(),
            provider: "built-in".to_owned(),
            provider_reference: None,
            secret_type: "token".to_owned(),
            status: "active".to_owned(),
            current_version: Some(1),
            created_unix_ms: 9_999,
            updated_unix_ms: 9_999,
        };
        let plaintext = runtrue_secrets::SecretPlaintext::new(b"runner-secret-contract".to_vec());
        crate::persistence::SecretConfigurationStore::create_secret(
            &store,
            "secret-create-sqlite",
            &metadata,
            Some(&plaintext),
            &master_key,
        )
        .await
        .unwrap();
        let request = IssueRunnerSecretRequest {
            execution_lease_id: lease.id.clone(),
            fencing_generation: 1,
            runner_id: runner_id.clone(),
            job_id: job_id.clone(),
            job_attempt: 1,
            step_id: "publish".to_owned(),
            secret_metadata_id: metadata.id,
            purpose: "publish".to_owned(),
            guest_key_fingerprint: ContentDigest::sha256(b"sqlite-guest-key"),
            runner_posture_digest: posture,
            issued_unix_ms: 10_002,
            expires_unix_ms: 20_000,
        };
        runner_secret_contract(&store, &request, &master_key).await;
        let artifact_id = format!("artifact-{prefix}");
        let claims = vec![(artifact_id.clone(), "package".to_owned())];
        {
            let connection = store.connection().unwrap();
            connection.execute("INSERT INTO runner_data_commits(kind,object_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,output_name,lease_id,fencing_generation,ticket_id,committed_unix_ms) VALUES('artifact',?1,?2,?3,?4,?5,1,'publish','package',?6,1,'artifact-ticket-sqlite',10003)",rusqlite::params![artifact_id,configuration.pool.tenant_id,repository_id,run_id,job_id,lease.id]).unwrap();
        }
        runner_completion_claim_contract(&store, &lease, &claims).await;
        {
            let connection = store.connection().unwrap();
            connection.execute("INSERT INTO job_result_objects(job_id,job_attempt,kind,object_id,ordinal) VALUES(?1,1,'artifact',?2,0)",rusqlite::params![job_id,artifact_id]).unwrap();
            connection
                .execute(
                    "UPDATE leases SET state='completed' WHERE id=?1",
                    [&lease.id],
                )
                .unwrap();
        }
        runner_completion_claim_contract(&store, &lease, &claims).await;
    }

    #[tokio::test]
    async fn sqlite_restore_fencing_is_atomic_and_expires_copied_authority() {
        let store = ControlPlane::open_in_memory("runner-restore-sqlite", 1).unwrap();
        let configuration = configuration("restore");
        store
            .put_runner_pool_configuration(&configuration)
            .await
            .unwrap();
        {
            let connection = store.connection().unwrap();
            connection
                .execute(
                "INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms)
             VALUES('runner-restore',?1,'offline','{}',10,10)",
                [&configuration.pool.id],
            )
            .unwrap();
            connection.execute(
            "INSERT INTO repositories(id,tenant_id,owner,name,default_branch,visibility,created_unix_ms)
             VALUES('repo-restore',?1,'owner','repo','main','private',10)",
            [&configuration.pool.tenant_id],
        ).unwrap();
            connection.execute(
            "INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms)
             VALUES('capsule-restore','repo-restore',?1,X'7B7D','{}','key',10)",
            [ContentDigest::sha256(b"capsule").as_str()],
        ).unwrap();
            connection.execute(
            "INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms)
             VALUES('run-restore','repo-restore','capsule-restore','running',0,1,10)",
            [],
        ).unwrap();
            connection.execute(
            "INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms)
             VALUES('job-restore','run-restore','job',1,'leased','{}',10)",
            [],
        ).unwrap();
        }
        let lease = Lease {
            id: "lease-restore".to_owned(),
            job_id: "job-restore".to_owned(),
            tenant_id: configuration.pool.tenant_id.clone(),
            runner_id: "runner-restore".to_owned(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            capsule_digest: ContentDigest::sha256(b"capsule"),
            issued_unix_ms: 20,
            accept_by_unix_ms: 200,
            expires_unix_ms: 500,
            state: LeaseState::Offered,
            terminal_result_digest: None,
        };
        store.put_copied_lease(&lease, 600).await.unwrap();
        let token = store
            .create_enrollment_token(&configuration.pool.id, 20, 500)
            .unwrap();
        store
            .acquire_runner_autoscaler_lease(&configuration.pool.id, "owner", 20, 500)
            .unwrap();
        let connection = store.connection().unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_restore_enrollment BEFORE UPDATE ON enrollment_tokens
             BEGIN SELECT RAISE(ABORT,'forced restore rollback'); END;",
            )
            .unwrap();
        drop(connection);
        assert!(store.enter_restore_safe_mode(100).is_err());
        assert_eq!(store.installation_fencing_epoch().unwrap(), 1);
        assert_eq!(
            store.lease("lease-restore").unwrap().state,
            LeaseState::Offered
        );
        let connection = store.connection().unwrap();
        connection
            .execute_batch("DROP TRIGGER fail_restore_enrollment;")
            .unwrap();
        drop(connection);
        let recovery = store.enter_restore_safe_mode(100).unwrap();
        assert_eq!(recovery.fencing_epoch, 2);
        assert_eq!(
            store.lease("lease-restore").unwrap().state,
            LeaseState::Expired
        );
        assert!(matches!(
            store.consume_enrollment_token(token.token.expose(), 100),
            Err(ControlPlaneError::EnrollmentTokenExpired)
        ));
        let request = RunnerFleetRequestRecord {
            id: "request-after-restore".to_owned(),
            pool_id: configuration.pool.id.clone(),
            runtime_compatibility_digest: configuration.templates[0]
                .runtime_compatibility_digest
                .clone(),
            provider: "contract".to_owned(),
            provider_template_id: "template-restore".to_owned(),
            runner_template_digest: configuration.templates[0].runner_template_digest.clone(),
            state: RunnerFleetRequestState::Requested,
            provider_request_id: None,
            provider_instance_id: None,
            runner_id: None,
            failure_code: None,
            created_unix_ms: 101,
            updated_unix_ms: 101,
        };
        assert!(matches!(
            store.create_runner_fleet_request(&request, "owner", 1),
            Err(ControlPlaneError::RunnerAutoscalerLeaseLost)
        ));
    }

    async fn restore_fencing_contract<S>(store: &S, original_lease: &Lease, enrollment_token: &str)
    where
        S: InstallationStateStore
            + RunnerLeaseBrokerStore
            + RunnerFleetEnrollmentStore
            + RunCoreStore,
    {
        let recovery = store
            .enter_restore_safe_mode(100)
            .await
            .expect("enter restore safe mode");
        assert_eq!(recovery.fencing_epoch, 2);
        assert!(recovery.safe_mode);
        assert_eq!(
            store
                .runner_execution_lease(&original_lease.id)
                .await
                .expect("read fenced lease")
                .state,
            LeaseState::Expired
        );
        let job = store
            .job(&original_lease.job_id)
            .await
            .expect("read fenced job");
        assert_eq!(job.status, JobState::Lost);
        assert_eq!(job.completed_unix_ms, Some(100));
        assert!(matches!(
            store
                .inspect_pool_enrollment_token(enrollment_token, 100)
                .await,
            Err(ControlPlaneError::EnrollmentTokenExpired)
        ));

        // Simulate an open copied lease appearing before activation. The
        // activation transaction must fail closed, then a second fence must
        // expire it before safe mode can be left.
        let copied_open_lease = Lease {
            id: format!("{}-copied-open", original_lease.id),
            fencing_generation: original_lease.fencing_generation + 1,
            installation_fencing_epoch: recovery.fencing_epoch,
            issued_unix_ms: 101,
            accept_by_unix_ms: 150,
            expires_unix_ms: 250,
            state: LeaseState::Offered,
            terminal_result_digest: None,
            ..original_lease.clone()
        };
        assert!(store
            .put_copied_lease(&copied_open_lease, 300)
            .await
            .expect("copy open lease during safe mode"));
        assert!(matches!(
            store.leave_restore_safe_mode(recovery.fencing_epoch).await,
            Err(ControlPlaneError::RestoreHasOpenLeases)
        ));
        store
            .advance_installation_fencing_epoch(3, 200)
            .await
            .expect("fence copied open lease");
        assert_eq!(
            store
                .runner_execution_lease(&copied_open_lease.id)
                .await
                .expect("read second fenced lease")
                .state,
            LeaseState::Expired
        );
        let active = store
            .leave_restore_safe_mode(3)
            .await
            .expect("activate fully fenced restore");
        assert!(!active.safe_mode);
    }

    fn restore_requirements() -> SchedulingRequirements {
        SchedulingRequirements {
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation: Isolation::Native,
            cpu: 1,
            memory_bytes: 1024,
            storage_bytes: 1024,
            region: None,
            required_capabilities: BTreeSet::new(),
            allowed_pools: BTreeSet::new(),
        }
    }

    #[tokio::test]
    async fn sqlite_restore_fencing_matches_active_job_contract() {
        let store = ControlPlane::open_in_memory("restore-parity", 1).unwrap();
        let configuration = configuration("restore-parity");
        store
            .put_runner_pool_configuration(&configuration)
            .await
            .unwrap();
        let requirements = serde_json::to_string(&restore_requirements()).unwrap();
        {
            let connection = store.connection().unwrap();
            connection.execute("INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms) VALUES('runner-restore-parity',?1,'online','{}',10,10)",[&configuration.pool.id]).unwrap();
            connection.execute("INSERT INTO repositories(id,tenant_id,owner,name,default_branch,visibility,created_unix_ms) VALUES('repo-restore-parity',?1,'owner','restore-parity','main','private',10)",[&configuration.pool.tenant_id]).unwrap();
            connection.execute("INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES('capsule-restore-parity','repo-restore-parity',?1,X'7B7D','{}','key',10)",[ContentDigest::sha256(b"restore-parity-capsule").as_str()]).unwrap();
            connection.execute("INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms,started_unix_ms) VALUES('run-restore-parity','repo-restore-parity','capsule-restore-parity','running',0,1,10,11)",[]).unwrap();
            connection.execute("INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms) VALUES('job-restore-parity','run-restore-parity','job',1,'running',?1,10)",[requirements]).unwrap();
        }
        let lease = Lease {
            id: "lease-restore-parity".to_owned(),
            job_id: "job-restore-parity".to_owned(),
            tenant_id: configuration.pool.tenant_id.clone(),
            runner_id: "runner-restore-parity".to_owned(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            capsule_digest: ContentDigest::sha256(b"restore-parity-capsule"),
            issued_unix_ms: 20,
            accept_by_unix_ms: 30,
            expires_unix_ms: 500,
            state: LeaseState::Active,
            terminal_result_digest: None,
        };
        store.put_copied_lease(&lease, 600).await.unwrap();
        let token = store
            .create_pool_enrollment_token(&configuration.pool.id, 20, 500)
            .await
            .unwrap();
        restore_fencing_contract(&store, &lease, token.token.expose()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_restore_fencing_matches_active_job_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "restore-fencing").await;
        let config = fixture.config();
        let store =
            PostgresInstallationStore::connect_and_migrate(config, "pg-restore-contract", 1)
                .await
                .unwrap();
        let configuration = configuration("restore-parity");
        store
            .put_runner_pool_configuration(&configuration)
            .await
            .unwrap();
        let requirements = serde_json::to_vec(&restore_requirements()).unwrap();
        sqlx::query("INSERT INTO tenants(id,slug,name,status,settings_json,created_unix_ms,updated_unix_ms,version) VALUES($1,$2,'Restore parity','active',$3,10,10,1)").bind(&configuration.pool.tenant_id).bind("restore-parity").bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms) VALUES('runner-restore-parity',$1,'online',$2,10,10)").bind(&configuration.pool.id).bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO repositories(id,tenant_id,owner,name,default_branch,visibility,created_unix_ms) VALUES('repo-restore-parity',$1,'owner','restore-parity','main','private',10)").bind(&configuration.pool.tenant_id).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES('capsule-restore-parity','repo-restore-parity',$1,$2,$3,'key',10)").bind(ContentDigest::sha256(b"restore-parity-capsule").as_str()).bind(b"{}".as_slice()).bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms,started_unix_ms) VALUES('run-restore-parity','repo-restore-parity','capsule-restore-parity','running',0,TRUE,10,11)").execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms) VALUES('job-restore-parity','run-restore-parity','job',1,'running',$1,10)").bind(requirements).execute(store.pool()).await.unwrap();
        let lease = Lease {
            id: "lease-restore-parity".to_owned(),
            job_id: "job-restore-parity".to_owned(),
            tenant_id: configuration.pool.tenant_id.clone(),
            runner_id: "runner-restore-parity".to_owned(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            capsule_digest: ContentDigest::sha256(b"restore-parity-capsule"),
            issued_unix_ms: 20,
            accept_by_unix_ms: 30,
            expires_unix_ms: 500,
            state: LeaseState::Active,
            terminal_result_digest: None,
        };
        store.put_copied_lease(&lease, 600).await.unwrap();
        let token = store
            .create_pool_enrollment_token(&configuration.pool.id, 20, 500)
            .await
            .unwrap();
        restore_fencing_contract(&store, &lease, token.token.expose()).await;
        store.close().await;
        fixture.cleanup().await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_runner_inventory_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "runner-inventory").await;
        let config = fixture.config();
        let store = PostgresInstallationStore::connect(config, "pg-contract", 17)
            .await
            .unwrap();
        let suffix = format!("inventory-pg-{}", std::process::id());
        fleet_fencing_contract(&store, &suffix).await;
        store.close().await;
        fixture.cleanup().await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_runner_fleet_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "runner-fleet").await;
        let config = fixture.config();
        let store = PostgresInstallationStore::connect(config, "pg-contract", 17)
            .await
            .unwrap();
        let suffix = format!("pg-{}", std::process::id());
        fleet_fencing_contract(&store, &suffix).await;
        let configuration = configuration(&suffix);
        postgres_lease_completion_contract(&store, &configuration, &suffix).await;
        postgres_scheduler_oidc_contract(&store, &configuration, &suffix).await;
        postgres_expanded_scheduler_contract(&store, &configuration, &suffix).await;
        postgres_deployment_gate_scheduler_contract(&store, &configuration, &suffix).await;
        store.close().await;
        fixture.cleanup().await;
    }
}
