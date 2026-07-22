use super::StoreFuture;
#[cfg(feature = "postgres")]
use crate::ControlPlaneError;
#[cfg(feature = "postgres")]
use crate::SigningResultState;
use crate::{
    AcquireEnvironmentGate, BindDeploymentLease, ControlPlane, DeploymentRecord,
    DeploymentRequestRecord, EnvironmentConcurrencyLeaseRecord, EnvironmentRecord,
    IdempotentResult, PublicSigningResult, R9AuditMetadata, SignerPolicyRecord,
    SigningResultJournalRecord, SigningResultReservation, TenantProviderConfiguration,
};

#[cfg(feature = "postgres")]
use super::PostgresInstallationStore;
#[cfg(feature = "postgres")]
use crate::DeploymentRequestStatus;
use runtrue_model::ContentDigest;
#[cfg(feature = "postgres")]
use runtrue_workflow_ir::ExecutionCapsule;
#[cfg(feature = "postgres")]
use sqlx::{Postgres, Row as _, Transaction};

#[cfg(feature = "postgres")]
pub(super) const POSTGRES_MIGRATION: &str =
    include_str!("../../migrations/postgres/0011_deployment_provider_state.sql");

pub trait DeploymentProviderStore: Send + Sync {
    fn put_provider<'a>(
        &'a self,
        record: &'a TenantProviderConfiguration,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool>;
    fn provider<'a>(
        &'a self,
        tenant_id: &'a str,
        provider_id: &'a str,
    ) -> StoreFuture<'a, TenantProviderConfiguration>;
    fn put_signer<'a>(
        &'a self,
        record: &'a SignerPolicyRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool>;
    fn signer<'a>(
        &'a self,
        tenant_id: &'a str,
        policy_id: &'a str,
    ) -> StoreFuture<'a, SignerPolicyRecord>;
    fn put_environment_record<'a>(
        &'a self,
        record: &'a EnvironmentRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool>;
    fn environment_record<'a>(
        &'a self,
        tenant_id: &'a str,
        environment_id: &'a str,
    ) -> StoreFuture<'a, EnvironmentRecord>;
}

pub trait DeploymentRequestStore: Send + Sync {
    fn reserve_request<'a>(
        &'a self,
        record: &'a DeploymentRequestRecord,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRequestRecord>>;
    fn request<'a>(
        &'a self,
        tenant_id: &'a str,
        request_id: &'a str,
    ) -> StoreFuture<'a, DeploymentRequestRecord>;
    #[allow(clippy::too_many_arguments)]
    fn start_request<'a>(
        &'a self,
        tenant_id: &'a str,
        request_id: &'a str,
        execution_lease_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        actor_id: &'a str,
        audit_correlation_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRequestRecord>>;
}

pub trait EnvironmentGateStore: Send + Sync {
    fn acquire_gate<'a>(
        &'a self,
        request: &'a AcquireEnvironmentGate,
    ) -> StoreFuture<'a, IdempotentResult<EnvironmentConcurrencyLeaseRecord>>;
    fn bind_gate_lease<'a>(
        &'a self,
        binding: &'a BindDeploymentLease,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRequestRecord>>;
}

pub trait SigningResultStore: Send + Sync {
    fn reserve_signing<'a>(
        &'a self,
        reservation: &'a SigningResultReservation,
    ) -> StoreFuture<'a, IdempotentResult<SigningResultJournalRecord>>;
    fn record_signed<'a>(
        &'a self,
        reservation: &'a SigningResultReservation,
        result: &'a PublicSigningResult,
    ) -> StoreFuture<'a, IdempotentResult<SigningResultJournalRecord>>;
    fn complete_signing<'a>(
        &'a self,
        tenant_id: &'a str,
        request_id: &'a str,
        request_digest: &'a ContentDigest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, IdempotentResult<SigningResultJournalRecord>>;
    fn signing<'a>(
        &'a self,
        tenant_id: &'a str,
        request_id: &'a str,
    ) -> StoreFuture<'a, SigningResultJournalRecord>;
}

pub trait DeploymentResultStore: Send + Sync {
    fn record_result<'a>(
        &'a self,
        record: &'a DeploymentRecord,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRecord>>;
    fn result<'a>(
        &'a self,
        tenant_id: &'a str,
        deployment_id: &'a str,
    ) -> StoreFuture<'a, DeploymentRecord>;
}

impl SigningResultStore for ControlPlane {
    fn reserve_signing<'a>(
        &'a self,
        r: &'a SigningResultReservation,
    ) -> StoreFuture<'a, IdempotentResult<SigningResultJournalRecord>> {
        let v = self.reserve_signing_result(r);
        Box::pin(async move { v })
    }
    fn record_signed<'a>(
        &'a self,
        r: &'a SigningResultReservation,
        result: &'a PublicSigningResult,
    ) -> StoreFuture<'a, IdempotentResult<SigningResultJournalRecord>> {
        let v = self.record_signed_result(r, result);
        Box::pin(async move { v })
    }
    fn complete_signing<'a>(
        &'a self,
        t: &'a str,
        id: &'a str,
        d: &'a ContentDigest,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<SigningResultJournalRecord>> {
        let v = self.complete_signing_result(t, id, d, now);
        Box::pin(async move { v })
    }
    fn signing<'a>(
        &'a self,
        t: &'a str,
        id: &'a str,
    ) -> StoreFuture<'a, SigningResultJournalRecord> {
        let v = self.signing_result(t, id);
        Box::pin(async move { v })
    }
}

impl DeploymentResultStore for ControlPlane {
    fn record_result<'a>(
        &'a self,
        r: &'a DeploymentRecord,
        a: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRecord>> {
        let v = self.record_deployment_result(r, a);
        Box::pin(async move { v })
    }
    fn result<'a>(&'a self, t: &'a str, id: &'a str) -> StoreFuture<'a, DeploymentRecord> {
        let v = self.deployment_result(t, id);
        Box::pin(async move { v })
    }
}

impl EnvironmentGateStore for ControlPlane {
    fn acquire_gate<'a>(
        &'a self,
        r: &'a AcquireEnvironmentGate,
    ) -> StoreFuture<'a, IdempotentResult<EnvironmentConcurrencyLeaseRecord>> {
        let v = self.acquire_environment_gate(r);
        Box::pin(async move { v })
    }
    fn bind_gate_lease<'a>(
        &'a self,
        r: &'a BindDeploymentLease,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRequestRecord>> {
        let v = self.bind_deployment_lease(r);
        Box::pin(async move { v })
    }
}

impl DeploymentRequestStore for ControlPlane {
    fn reserve_request<'a>(
        &'a self,
        r: &'a DeploymentRequestRecord,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRequestRecord>> {
        let v = self.reserve_deployment_request(r);
        Box::pin(async move { v })
    }
    fn request<'a>(&'a self, t: &'a str, id: &'a str) -> StoreFuture<'a, DeploymentRequestRecord> {
        let v = self.deployment_request(t, id);
        Box::pin(async move { v })
    }
    fn start_request<'a>(
        &'a self,
        t: &'a str,
        id: &'a str,
        l: &'a str,
        f: u64,
        e: u64,
        a: &'a str,
        c: &'a str,
        n: u64,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRequestRecord>> {
        let v = self.mark_deployment_started(t, id, l, f, e, a, c, n);
        Box::pin(async move { v })
    }
}

impl DeploymentProviderStore for ControlPlane {
    fn put_provider<'a>(
        &'a self,
        r: &'a TenantProviderConfiguration,
        e: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        let result = self.put_tenant_provider_configuration(r, e);
        Box::pin(async move { result })
    }
    fn provider<'a>(
        &'a self,
        t: &'a str,
        id: &'a str,
    ) -> StoreFuture<'a, TenantProviderConfiguration> {
        let result = self.tenant_provider_configuration(t, id);
        Box::pin(async move { result })
    }
    fn put_signer<'a>(
        &'a self,
        r: &'a SignerPolicyRecord,
        e: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        let result = self.put_signer_policy(r, e);
        Box::pin(async move { result })
    }
    fn signer<'a>(&'a self, t: &'a str, id: &'a str) -> StoreFuture<'a, SignerPolicyRecord> {
        let result = self.signer_policy(t, id);
        Box::pin(async move { result })
    }
    fn put_environment_record<'a>(
        &'a self,
        r: &'a EnvironmentRecord,
        e: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        let result = self.put_environment(r, e);
        Box::pin(async move { result })
    }
    fn environment_record<'a>(
        &'a self,
        t: &'a str,
        id: &'a str,
    ) -> StoreFuture<'a, EnvironmentRecord> {
        let result = self.environment(t, id);
        Box::pin(async move { result })
    }
}

#[cfg(feature = "postgres")]
impl DeploymentProviderStore for PostgresInstallationStore {
    fn put_provider<'a>(
        &'a self,
        r: &'a TenantProviderConfiguration,
        expected: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            crate::store::validate_provider_configuration(r)?;
            let mut tx = self.pool().begin().await?;
            let existing = provider_tx(&mut tx, &r.tenant_id, &r.id, true).await?;
            if let Some(old) = existing {
                if old == *r {
                    require_snapshot(
                        &mut tx,
                        "tenant_provider_configuration_versions",
                        "provider_configuration_id",
                        &r.tenant_id,
                        &r.id,
                        r.version,
                        crate::store::provider_configuration_snapshot(r)?,
                    )
                    .await?;
                    tx.commit().await?;
                    return Ok(false);
                }
                if expected != Some(old.version)
                    || r.version
                        != old
                            .version
                            .checked_add(1)
                            .ok_or(ControlPlaneError::IntegerRange {
                                field: "provider configuration version",
                            })?
                    || r.created_unix_ms != old.created_unix_ms
                    || r.tenant_id != old.tenant_id
                    || r.capability != old.capability
                    || r.provider_kind != old.provider_kind
                    || r.endpoint_origin != old.endpoint_origin
                    || r.credential_reference != old.credential_reference
                    || r.trust_bundle_digest != old.trust_bundle_digest
                    || r.public_key_digest != old.public_key_digest
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let changed=sqlx::query("UPDATE tenant_provider_configurations SET configuration_digest=$3,status=$4,updated_unix_ms=$5,version=$6 WHERE tenant_id=$1 AND id=$2 AND version=$7")
                    .bind(&r.tenant_id).bind(&r.id).bind(r.configuration_digest.as_str()).bind(&r.status).bind(i64v(r.updated_unix_ms,"provider update")?).bind(i64v(r.version,"provider version")?).bind(i64v(old.version,"provider expected version")?).execute(&mut *tx).await?.rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            } else {
                if expected.is_some() || r.version != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                sqlx::query("INSERT INTO tenant_provider_configurations(id,tenant_id,capability,provider_kind,endpoint_origin,credential_reference,trust_bundle_digest,public_key_digest,configuration_digest,status,created_unix_ms,updated_unix_ms,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1)")
                    .bind(&r.id).bind(&r.tenant_id).bind(&r.capability).bind(&r.provider_kind).bind(&r.endpoint_origin).bind(&r.credential_reference).bind(r.trust_bundle_digest.as_str()).bind(r.public_key_digest.as_ref().map(ContentDigest::as_str)).bind(r.configuration_digest.as_str()).bind(&r.status).bind(i64v(r.created_unix_ms,"provider creation")?).bind(i64v(r.updated_unix_ms,"provider update")?).execute(&mut *tx).await?;
            }
            insert_snapshot(
                &mut tx,
                "tenant_provider_configuration_versions",
                "provider_configuration_id",
                &r.tenant_id,
                &r.id,
                r.version,
                r.updated_unix_ms,
                crate::store::provider_configuration_snapshot(r)?,
            )
            .await?;
            tx.commit().await?;
            Ok(true)
        })
    }
    fn provider<'a>(
        &'a self,
        t: &'a str,
        id: &'a str,
    ) -> StoreFuture<'a, TenantProviderConfiguration> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let r = provider_tx(&mut tx, t, id, false)
                .await?
                .ok_or_else(|| not_found("provider configuration", id))?;
            crate::store::validate_provider_configuration(&r)?;
            require_snapshot(
                &mut tx,
                "tenant_provider_configuration_versions",
                "provider_configuration_id",
                t,
                id,
                r.version,
                crate::store::provider_configuration_snapshot(&r)?,
            )
            .await?;
            tx.commit().await?;
            Ok(r)
        })
    }
    fn put_signer<'a>(
        &'a self,
        r: &'a SignerPolicyRecord,
        expected: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            crate::store::validate_signer_policy(r)?;
            let mut tx = self.pool().begin().await?;
            let provider = provider_tx(&mut tx, &r.tenant_id, &r.provider_configuration_id, true)
                .await?
                .ok_or_else(|| not_found("provider configuration", &r.provider_configuration_id))?;
            if provider.capability != "signing"
                || provider.status != "active"
                || provider.configuration_digest != r.provider_configuration_digest
                || provider.version != r.provider_configuration_version
                || provider.public_key_digest.as_ref() != Some(&r.public_key_digest)
            {
                return Err(ControlPlaneError::EnvironmentGateNotReady);
            }
            require_snapshot(
                &mut tx,
                "tenant_provider_configuration_versions",
                "provider_configuration_id",
                &provider.tenant_id,
                &provider.id,
                provider.version,
                crate::store::provider_configuration_snapshot(&provider)?,
            )
            .await?;
            let old = signer_tx(&mut tx, &r.tenant_id, &r.id, true).await?;
            if let Some(old) = old {
                if old == *r {
                    require_snapshot(
                        &mut tx,
                        "signer_policy_versions",
                        "signer_policy_id",
                        &r.tenant_id,
                        &r.id,
                        r.version,
                        crate::store::signer_policy_snapshot(r)?,
                    )
                    .await?;
                    tx.commit().await?;
                    return Ok(false);
                }
                if expected != Some(old.version)
                    || r.version
                        != old
                            .version
                            .checked_add(1)
                            .ok_or(ControlPlaneError::IntegerRange {
                                field: "signer policy version",
                            })?
                    || r.created_unix_ms != old.created_unix_ms
                    || r.tenant_id != old.tenant_id
                    || r.provider_configuration_id != old.provider_configuration_id
                    || r.provider_configuration_digest != old.provider_configuration_digest
                    || r.provider_configuration_version != old.provider_configuration_version
                    || r.backend_key_reference != old.backend_key_reference
                    || r.purpose != old.purpose
                    || r.operation != old.operation
                    || r.public_key_digest != old.public_key_digest
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let changed=sqlx::query("UPDATE signer_policies SET policy_digest=$3,status=$4,updated_unix_ms=$5,version=$6 WHERE tenant_id=$1 AND id=$2 AND version=$7").bind(&r.tenant_id).bind(&r.id).bind(r.policy_digest.as_str()).bind(&r.status).bind(i64v(r.updated_unix_ms,"signer update")?).bind(i64v(r.version,"signer version")?).bind(i64v(old.version,"signer expected")?).execute(&mut *tx).await?.rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            } else {
                if expected.is_some() || r.version != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                sqlx::query("INSERT INTO signer_policies(id,tenant_id,provider_configuration_id,provider_configuration_digest,provider_configuration_version,backend_key_reference,purpose,operation,public_key_digest,policy_digest,status,created_unix_ms,updated_unix_ms,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1)").bind(&r.id).bind(&r.tenant_id).bind(&r.provider_configuration_id).bind(r.provider_configuration_digest.as_str()).bind(i64v(r.provider_configuration_version,"provider version")?).bind(&r.backend_key_reference).bind(&r.purpose).bind(&r.operation).bind(r.public_key_digest.as_str()).bind(r.policy_digest.as_str()).bind(&r.status).bind(i64v(r.created_unix_ms,"signer creation")?).bind(i64v(r.updated_unix_ms,"signer update")?).execute(&mut *tx).await?;
            }
            insert_snapshot(
                &mut tx,
                "signer_policy_versions",
                "signer_policy_id",
                &r.tenant_id,
                &r.id,
                r.version,
                r.updated_unix_ms,
                crate::store::signer_policy_snapshot(r)?,
            )
            .await?;
            tx.commit().await?;
            Ok(true)
        })
    }
    fn signer<'a>(&'a self, t: &'a str, id: &'a str) -> StoreFuture<'a, SignerPolicyRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let r = signer_tx(&mut tx, t, id, false)
                .await?
                .ok_or_else(|| not_found("signer policy", id))?;
            crate::store::validate_signer_policy(&r)?;
            require_snapshot(
                &mut tx,
                "signer_policy_versions",
                "signer_policy_id",
                t,
                id,
                r.version,
                crate::store::signer_policy_snapshot(&r)?,
            )
            .await?;
            tx.commit().await?;
            Ok(r)
        })
    }
    fn put_environment_record<'a>(
        &'a self,
        r: &'a EnvironmentRecord,
        expected: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let rules = crate::store::validate_environment(r)?;
            let mut tx = self.pool().begin().await?;
            let active:Option<i64>=sqlx::query_scalar("SELECT policy_epoch FROM tenant_policy_states WHERE tenant_id=$1 AND active_draft_id IS NOT NULL AND active_policy_digest IS NOT NULL").bind(&r.tenant_id).fetch_optional(&mut *tx).await?;
            if active.and_then(|v| u64::try_from(v).ok()) != Some(r.required_policy_epoch) {
                return Err(ControlPlaneError::EnvironmentGateNotReady);
            }
            let owner: Option<String> =
                sqlx::query_scalar("SELECT tenant_id FROM repositories WHERE id=$1 FOR SHARE")
                    .bind(&r.repository_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            if owner.as_deref() != Some(r.tenant_id.as_str()) {
                return Err(not_found("repository", &r.repository_id));
            }
            for (provider_id, capability) in [
                (
                    r.secret_provider_configuration_id.as_deref(),
                    "external-secret",
                ),
                (r.signing_provider_configuration_id.as_deref(), "signing"),
            ] {
                if let Some(id) = provider_id {
                    let p = provider_tx(&mut tx, &r.tenant_id, id, true)
                        .await?
                        .ok_or_else(|| not_found("provider configuration", id))?;
                    if p.capability != capability || p.status != "active" {
                        return Err(ControlPlaneError::EnvironmentGateNotReady);
                    }
                }
            }
            for id in &r.protection_rules.allowed_signer_policy_ids {
                let p = signer_tx(&mut tx, &r.tenant_id, id, true)
                    .await?
                    .ok_or_else(|| not_found("signer policy", id))?;
                if p.status != "active"
                    || Some(p.provider_configuration_id.as_str())
                        != r.signing_provider_configuration_id.as_deref()
                    || r.protection_rules
                        .allowed_signing_purposes
                        .binary_search(&p.purpose)
                        .is_err()
                {
                    return Err(ControlPlaneError::EnvironmentGateNotReady);
                }
                require_snapshot(
                    &mut tx,
                    "signer_policy_versions",
                    "signer_policy_id",
                    &p.tenant_id,
                    &p.id,
                    p.version,
                    crate::store::signer_policy_snapshot(&p)?,
                )
                .await?;
            }
            let old = environment_tx(&mut tx, &r.tenant_id, &r.id, true).await?;
            if let Some(old) = old {
                if old == *r {
                    require_snapshot(
                        &mut tx,
                        "environment_versions",
                        "environment_id",
                        &r.tenant_id,
                        &r.id,
                        r.version,
                        crate::store::environment_snapshot(r)?,
                    )
                    .await?;
                    tx.commit().await?;
                    return Ok(false);
                }
                if expected != Some(old.version)
                    || r.version
                        != old
                            .version
                            .checked_add(1)
                            .ok_or(ControlPlaneError::IntegerRange {
                                field: "environment version",
                            })?
                    || r.created_unix_ms != old.created_unix_ms
                    || r.tenant_id != old.tenant_id
                    || r.repository_id != old.repository_id
                    || r.last_concurrency_fence != old.last_concurrency_fence
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let changed=sqlx::query("UPDATE environments SET name=$3,deployment_target_reference=$4,deployment_target_digest=$5,status=$6,protection_rules_json=$7,protection_rules_digest=$8,wait_timer_ms=$9,concurrency_limit=$10,secret_provider_configuration_id=$11,signing_provider_configuration_id=$12,required_policy_epoch=$13,updated_unix_ms=$14,version=$15 WHERE tenant_id=$1 AND id=$2 AND version=$16").bind(&r.tenant_id).bind(&r.id).bind(&r.name).bind(&r.deployment_target_reference).bind(r.deployment_target_digest.as_str()).bind(&r.status).bind(&rules).bind(r.protection_rules_digest.as_str()).bind(i64v(r.wait_timer_ms,"environment wait")?).bind(i64::from(r.concurrency_limit)).bind(&r.secret_provider_configuration_id).bind(&r.signing_provider_configuration_id).bind(i64v(r.required_policy_epoch,"policy epoch")?).bind(i64v(r.updated_unix_ms,"environment update")?).bind(i64v(r.version,"environment version")?).bind(i64v(old.version,"environment expected version")?).execute(&mut *tx).await?.rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            } else {
                if expected.is_some() || r.version != 1 || r.last_concurrency_fence != 0 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                sqlx::query("INSERT INTO environments(id,tenant_id,repository_id,name,deployment_target_reference,deployment_target_digest,status,protection_rules_json,protection_rules_digest,wait_timer_ms,concurrency_limit,secret_provider_configuration_id,signing_provider_configuration_id,required_policy_epoch,last_concurrency_fence,created_unix_ms,updated_unix_ms,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,0,$15,$16,1)").bind(&r.id).bind(&r.tenant_id).bind(&r.repository_id).bind(&r.name).bind(&r.deployment_target_reference).bind(r.deployment_target_digest.as_str()).bind(&r.status).bind(&rules).bind(r.protection_rules_digest.as_str()).bind(i64v(r.wait_timer_ms,"environment wait")?).bind(i64::from(r.concurrency_limit)).bind(&r.secret_provider_configuration_id).bind(&r.signing_provider_configuration_id).bind(i64v(r.required_policy_epoch,"policy epoch")?).bind(i64v(r.created_unix_ms,"environment creation")?).bind(i64v(r.updated_unix_ms,"environment update")?).execute(&mut *tx).await?;
            }
            insert_snapshot(
                &mut tx,
                "environment_versions",
                "environment_id",
                &r.tenant_id,
                &r.id,
                r.version,
                r.updated_unix_ms,
                crate::store::environment_snapshot(r)?,
            )
            .await?;
            tx.commit().await?;
            Ok(true)
        })
    }
    fn environment_record<'a>(
        &'a self,
        t: &'a str,
        id: &'a str,
    ) -> StoreFuture<'a, EnvironmentRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let r = environment_tx(&mut tx, t, id, false)
                .await?
                .ok_or_else(|| not_found("environment", id))?;
            crate::store::validate_environment(&r)?;
            require_snapshot(
                &mut tx,
                "environment_versions",
                "environment_id",
                t,
                id,
                r.version,
                crate::store::environment_snapshot(&r)?,
            )
            .await?;
            tx.commit().await?;
            Ok(r)
        })
    }
}

#[cfg(feature = "postgres")]
const MAX_POSTGRES_GATE_LEASE_MS: u64 = 15 * 60 * 1_000;

#[cfg(feature = "postgres")]
async fn require_active_policy_epoch(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    policy_epoch: u64,
) -> Result<(), ControlPlaneError> {
    let active: Option<i64> = sqlx::query_scalar(
        "SELECT policy_epoch FROM tenant_policy_states
         WHERE tenant_id=$1 AND active_draft_id IS NOT NULL
           AND active_policy_digest IS NOT NULL FOR SHARE",
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await?;
    if active.and_then(|value| u64::try_from(value).ok()) != Some(policy_epoch) {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn append_request_event(
    tx: &mut Transaction<'_, Postgres>,
    record: &DeploymentRequestRecord,
) -> Result<(), ControlPlaneError> {
    let state_digest = ContentDigest::sha256(serde_json::to_vec(record)?);
    sqlx::query(
        "INSERT INTO deployment_request_events
         (deployment_request_id,tenant_id,version,status,state_digest,actor_id,
          audit_correlation_id,occurred_unix_ms)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(i64v(record.version, "deployment request version")?)
    .bind(record.status.as_str())
    .bind(state_digest.as_str())
    .bind(&record.actor_id)
    .bind(&record.audit_correlation_id)
    .bind(i64v(
        record.updated_unix_ms,
        "deployment request event time",
    )?)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn require_provider_capability(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    provider_id: Option<&str>,
    capability: &str,
) -> Result<(), ControlPlaneError> {
    let Some(provider_id) = provider_id else {
        return Ok(());
    };
    let provider = provider_tx(tx, tenant_id, provider_id, true)
        .await?
        .ok_or_else(|| not_found("provider configuration", provider_id))?;
    if provider.capability != capability || provider.status != "active" {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    require_snapshot(
        tx,
        "tenant_provider_configuration_versions",
        "provider_configuration_id",
        tenant_id,
        provider_id,
        provider.version,
        crate::store::provider_configuration_snapshot(&provider)?,
    )
    .await
}

#[cfg(feature = "postgres")]
async fn validate_deployment_inputs(
    tx: &mut Transaction<'_, Postgres>,
    record: &DeploymentRequestRecord,
    environment: &EnvironmentRecord,
) -> Result<(), ControlPlaneError> {
    require_snapshot(
        tx,
        "environment_versions",
        "environment_id",
        &record.tenant_id,
        &environment.id,
        environment.version,
        crate::store::environment_snapshot(environment)?,
    )
    .await?;

    let artifact = sqlx::query(
        "SELECT a.tenant_id,a.repository_id,a.run_id,a.job_id,a.job_attempt,
                a.content_digest,a.manifest_digest,a.provenance_digest,
                a.classification,a.scan_state,a.state,a.retention_until_unix_seconds
         FROM artifacts_catalog a
         JOIN runs r ON r.id=a.run_id
         JOIN jobs j ON j.id=a.job_id AND j.run_id=r.id
         JOIN repositories repo ON repo.id=r.repository_id
         WHERE a.artifact_id=$1 AND repo.tenant_id=$2 FOR SHARE OF a,r,j,repo",
    )
    .bind(&record.artifact_id)
    .bind(&record.tenant_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| not_found("artifact", &record.artifact_id))?;
    if artifact.try_get::<String, _>("tenant_id")? != record.tenant_id
        || artifact.try_get::<String, _>("repository_id")? != record.repository_id
        || artifact.try_get::<String, _>("run_id")? != record.artifact_source_run_id
        || artifact.try_get::<String, _>("job_id")? != record.artifact_source_job_id
        || u32::try_from(artifact.try_get::<i32, _>("job_attempt")?).ok()
            != Some(record.artifact_source_job_attempt)
        || artifact.try_get::<String, _>("content_digest")? != record.artifact_digest.as_str()
        || artifact.try_get::<String, _>("manifest_digest")? != record.manifest_digest.as_str()
        || artifact.try_get::<String, _>("provenance_digest")? != record.provenance_digest.as_str()
        || u64v(
            artifact.try_get("retention_until_unix_seconds")?,
            "artifact retention",
        )? <= record.created_unix_ms / 1_000
        || artifact.try_get::<String, _>("state")? != "available"
        || (!environment.protection_rules.require_promotion_evidence
            && artifact.try_get::<String, _>("classification")?
                != environment
                    .protection_rules
                    .required_artifact_classification)
        || (environment.protection_rules.require_passed_scan
            && artifact.try_get::<String, _>("scan_state")? != "passed")
        || environment.repository_id != record.repository_id
        || record.target_digest != environment.deployment_target_digest
    {
        return Err(ControlPlaneError::IdempotencyConflict);
    }

    let lineage = sqlx::query(
        "SELECT repo.tenant_id,r.repository_id,j.run_id,j.attempt,
                p.canonical_capsule,j.job_key
         FROM jobs j JOIN runs r ON r.id=j.run_id
         JOIN repositories repo ON repo.id=r.repository_id
         JOIN capsules p ON p.id=r.capsule_id
         WHERE j.id=$1 AND j.run_id=$2 FOR SHARE OF j,r,repo,p",
    )
    .bind(&record.job_id)
    .bind(&record.run_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| not_found("deployment job", &record.job_id))?;
    if lineage.try_get::<String, _>("tenant_id")? != record.tenant_id
        || lineage.try_get::<String, _>("repository_id")? != record.repository_id
        || lineage.try_get::<String, _>("run_id")? != record.run_id
        || u32::try_from(lineage.try_get::<i32, _>("attempt")?).ok() != Some(record.job_attempt)
    {
        return Err(not_found("deployment job", &record.job_id));
    }
    let canonical: Vec<u8> = lineage.try_get("canonical_capsule")?;
    let capsule: ExecutionCapsule = serde_json::from_slice(&canonical)?;
    if capsule.canonical_bytes()? != canonical {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let capsule_digest = capsule.digest()?;
    if capsule_digest != record.deployment_capsule_digest {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let job_key: String = lineage.try_get("job_key")?;
    let planned = super::runner_authority::postgres_materialized_planned_job(
        tx,
        &record.run_id,
        &job_key,
        &capsule,
        &capsule_digest,
    )
    .await?
    .ok_or_else(|| {
        ControlPlaneError::CorruptState(
            "deployment job is absent from its signed capsule".to_owned(),
        )
    })?;
    if planned.environment.as_deref() != Some(environment.name.as_str()) {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }

    if environment.protection_rules.require_promotion_evidence {
        let promoted_id = record
            .promoted_artifact_id
            .as_deref()
            .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
        let valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(
               SELECT 1 FROM artifact_promotions p
               JOIN artifact_promotion_bindings b ON b.promotion_id=p.id
               WHERE p.tenant_id=$1 AND p.source_artifact_id=$2
                 AND p.status='succeeded' AND p.promoted_artifact_id=$3
                 AND p.target_classification=$4
                 AND b.source_manifest_digest=$5
                 AND b.source_provenance_digest=$6
                 AND b.scan_evidence_digest IS NOT NULL)",
        )
        .bind(&record.tenant_id)
        .bind(&record.artifact_id)
        .bind(promoted_id)
        .bind(
            &environment
                .protection_rules
                .required_artifact_classification,
        )
        .bind(record.manifest_digest.as_str())
        .bind(record.provenance_digest.as_str())
        .fetch_one(&mut **tx)
        .await?;
        if !valid {
            return Err(ControlPlaneError::EnvironmentGateNotReady);
        }
    } else if record.promoted_artifact_id.is_some() {
        return Err(ControlPlaneError::InvalidInput(
            "unexpected promoted artifact identity",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn approval_status_name(status: runtrue_policy::ApprovalStatus) -> &'static str {
    match status {
        runtrue_policy::ApprovalStatus::Pending => "pending",
        runtrue_policy::ApprovalStatus::Approved => "approved",
        runtrue_policy::ApprovalStatus::Denied => "denied",
        runtrue_policy::ApprovalStatus::Expired => "expired",
        runtrue_policy::ApprovalStatus::Consumed => "consumed",
    }
}

#[cfg(feature = "postgres")]
async fn deployment_approval(
    tx: &mut Transaction<'_, Postgres>,
    record: &DeploymentRequestRecord,
    environment: &EnvironmentRecord,
    now_unix_ms: Option<u64>,
) -> Result<(), ControlPlaneError> {
    let approval_id = record
        .approval_request_id
        .as_deref()
        .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
    let row = sqlx::query(
        "SELECT a.request_json,a.status,a.subject_digest,a.created_unix_ms,a.expires_unix_ms
         FROM approval_requests a JOIN runs r ON r.id=$2 AND r.capsule_id=a.capsule_id
         JOIN repositories repo ON repo.id=a.repository_id
         WHERE a.id=$1 AND a.repository_id=$3 AND repo.tenant_id=$4 FOR UPDATE OF a",
    )
    .bind(approval_id)
    .bind(&record.run_id)
    .bind(&record.repository_id)
    .bind(&record.tenant_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
    let bytes: Vec<u8> = row.try_get("request_json")?;
    let mut approval: runtrue_policy::ApprovalRequest = serde_json::from_slice(&bytes)?;
    let required = u16::try_from(environment.protection_rules.minimum_approvals)
        .map_err(|_| ControlPlaneError::InvalidInput("invalid environment approval threshold"))?;
    let rule_digest = ContentDigest::sha256(serde_json::to_vec(&approval.rule)?);
    let max_expiry = record
        .created_unix_ms
        .checked_add(environment.protection_rules.approval_ttl_ms)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "environment approval expiry",
        })?;
    if serde_json::to_vec(&approval)? != bytes
        || approval.id != approval_id
        || approval.kind != runtrue_policy::ApprovalKind::EnvironmentDeployment
        || approval.subject_digest != record.approval_subject_digest
        || row.try_get::<String, _>("subject_digest")? != record.approval_subject_digest.as_str()
        || approval.rule.required_approvals < required
        || !approval.rule.one_shot
        || environment.protection_rules.approval_rule_digest.as_ref() != Some(&rule_digest)
        || approval.created_unix_ms > record.created_unix_ms
        || approval.expires_unix_ms > max_expiry
        || approval.created_unix_ms != u64v(row.try_get("created_unix_ms")?, "approval creation")?
        || approval.expires_unix_ms != u64v(row.try_get("expires_unix_ms")?, "approval expiry")?
        || approval_status_name(approval.status) != row.try_get::<String, _>("status")?
    {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    if let Some(now_unix_ms) = now_unix_ms {
        approval
            .authorize(&record.approval_subject_digest, now_unix_ms)
            .map_err(|_| ControlPlaneError::EnvironmentGateNotReady)?;
        sqlx::query("UPDATE approval_requests SET status=$2,request_json=$3 WHERE id=$1")
            .bind(approval_id)
            .bind(approval_status_name(approval.status))
            .bind(serde_json::to_vec(&approval)?)
            .execute(&mut **tx)
            .await?;
    } else if !matches!(
        approval.status,
        runtrue_policy::ApprovalStatus::Pending | runtrue_policy::ApprovalStatus::Approved
    ) {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
impl DeploymentRequestStore for PostgresInstallationStore {
    fn reserve_request<'a>(
        &'a self,
        r: &'a DeploymentRequestRecord,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRequestRecord>> {
        Box::pin(async move {
            crate::store::validate_deployment_request_shape(r)?;
            let mut tx = self.pool().begin().await?;
            if let Some(old) = request_tx(&mut tx, &r.tenant_id, &r.id, true).await? {
                if old == *r {
                    verify_request_event(&mut tx, &old).await?;
                    tx.commit().await?;
                    return Ok(IdempotentResult {
                        value: old,
                        replayed: true,
                    });
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let environment = environment_tx(&mut tx, &r.tenant_id, &r.environment_id, true)
                .await?
                .ok_or_else(|| not_found("environment", &r.environment_id))?;
            if environment.status != "active"
                || environment.version != r.environment_version
                || environment.required_policy_epoch != r.policy_epoch
            {
                return Err(ControlPlaneError::EnvironmentGateNotReady);
            }
            require_active_policy_epoch(&mut tx, &r.tenant_id, r.policy_epoch).await?;
            validate_deployment_inputs(&mut tx, r, &environment).await?;
            let expected_wait = r
                .created_unix_ms
                .checked_add(environment.wait_timer_ms)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "deployment wait deadline",
                })?;
            let expected_status = if environment.wait_timer_ms > 0 {
                DeploymentRequestStatus::WaitingTimer
            } else if environment.protection_rules.require_approval {
                DeploymentRequestStatus::AwaitingApproval
            } else {
                DeploymentRequestStatus::AwaitingConcurrency
            };
            if r.version != 1
                || r.status != expected_status
                || r.wait_until_unix_ms != expected_wait
                || r.concurrency_fence.is_some()
                || r.execution_lease_id.is_some()
                || r.lease_fencing_generation.is_some()
                || r.installation_fencing_epoch.is_some()
                || r.completed_unix_ms.is_some()
                || r.updated_unix_ms != r.created_unix_ms
                || environment.protection_rules.require_approval != r.approval_request_id.is_some()
                || (r.rollback_of_deployment_id.is_some() && r.approval_request_id.is_none())
            {
                return Err(ControlPlaneError::InvalidInput(
                    "deployment request is not an exact initial reservation",
                ));
            }
            if r.approval_request_id.is_some() {
                deployment_approval(&mut tx, r, &environment, None).await?;
            }
            if let Some(parent_id) = &r.rollback_of_deployment_id {
                let parent = sqlx::query(
                    "SELECT d.environment_id,q.approval_request_id,d.status
                     FROM deployments d JOIN deployment_requests q
                       ON q.id=d.deployment_request_id AND q.tenant_id=d.tenant_id
                     WHERE d.tenant_id=$1 AND d.id=$2 FOR SHARE OF d,q",
                )
                .bind(&r.tenant_id)
                .bind(parent_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| not_found("deployment", parent_id))?;
                if parent.try_get::<String, _>("environment_id")? != r.environment_id
                    || parent.try_get::<String, _>("status")? != "succeeded"
                    || parent.try_get::<Option<String>, _>("approval_request_id")?
                        == r.approval_request_id
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            }
            sqlx::query(
                "INSERT INTO deployment_requests
                 (id,tenant_id,environment_id,environment_version,policy_epoch,
                  repository_id,run_id,job_id,job_attempt,artifact_id,promoted_artifact_id,
                  artifact_source_run_id,artifact_source_job_id,artifact_source_job_attempt,
                  artifact_digest,manifest_digest,provenance_digest,target_digest,
                  deployment_capsule_digest,request_digest,approval_subject_digest,
                  approval_request_id,rollback_of_deployment_id,status,wait_until_unix_ms,
                  concurrency_fence,execution_lease_id,lease_fencing_generation,
                  installation_fencing_epoch,actor_id,audit_correlation_id,created_unix_ms,
                  updated_unix_ms,completed_unix_ms,version)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                        $17,$18,$19,$20,$21,$22,$23,$24,$25,NULL,NULL,NULL,NULL,$26,$27,
                        $28,$28,NULL,1)",
            )
            .bind(&r.id)
            .bind(&r.tenant_id)
            .bind(&r.environment_id)
            .bind(i64v(r.environment_version, "environment version")?)
            .bind(i64v(r.policy_epoch, "policy epoch")?)
            .bind(&r.repository_id)
            .bind(&r.run_id)
            .bind(&r.job_id)
            .bind(i64::from(r.job_attempt))
            .bind(&r.artifact_id)
            .bind(&r.promoted_artifact_id)
            .bind(&r.artifact_source_run_id)
            .bind(&r.artifact_source_job_id)
            .bind(i64::from(r.artifact_source_job_attempt))
            .bind(r.artifact_digest.as_str())
            .bind(r.manifest_digest.as_str())
            .bind(r.provenance_digest.as_str())
            .bind(r.target_digest.as_str())
            .bind(r.deployment_capsule_digest.as_str())
            .bind(r.request_digest.as_str())
            .bind(r.approval_subject_digest.as_str())
            .bind(&r.approval_request_id)
            .bind(&r.rollback_of_deployment_id)
            .bind(r.status.as_str())
            .bind(i64v(r.wait_until_unix_ms, "deployment wait")?)
            .bind(&r.actor_id)
            .bind(&r.audit_correlation_id)
            .bind(i64v(r.created_unix_ms, "deployment request creation")?)
            .execute(&mut *tx)
            .await?;
            append_request_event(&mut tx, r).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: r.clone(),
                replayed: false,
            })
        })
    }
    fn request<'a>(&'a self, t: &'a str, id: &'a str) -> StoreFuture<'a, DeploymentRequestRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let r = request_tx(&mut tx, t, id, false)
                .await?
                .ok_or_else(|| not_found("deployment request", id))?;
            crate::store::validate_deployment_request_shape(&r)?;
            verify_request_event(&mut tx, &r).await?;
            tx.commit().await?;
            Ok(r)
        })
    }
    fn start_request<'a>(
        &'a self,
        t: &'a str,
        id: &'a str,
        l: &'a str,
        f: u64,
        e: u64,
        actor: &'a str,
        correlation: &'a str,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRequestRecord>> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let r = request_tx(&mut tx, t, id, true)
                .await?
                .ok_or_else(|| not_found("deployment request", id))?;
            if r.status.as_str() == "in-progress"
                && r.execution_lease_id.as_deref() == Some(l)
                && r.lease_fencing_generation == Some(f)
                && r.installation_fencing_epoch == Some(e)
            {
                verify_request_event(&mut tx, &r).await?;
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value: r,
                    replayed: true,
                });
            }
            let valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM leases l JOIN jobs j ON j.id=l.job_id
                 WHERE l.tenant_id=$1 AND l.id=$2 AND l.job_id=$3 AND j.attempt=$4
                   AND l.fencing_generation=$5 AND l.installation_fencing_epoch=$6
                   AND l.state='active' AND l.issued_unix_ms<=$7
                   AND l.expires_unix_ms>$7 AND l.hard_deadline_unix_ms>$7)",
            )
            .bind(t)
            .bind(l)
            .bind(&r.job_id)
            .bind(i64::from(r.job_attempt))
            .bind(i64v(f, "lease fence")?)
            .bind(i64v(e, "installation epoch")?)
            .bind(i64v(now, "deployment start")?)
            .fetch_one(&mut *tx)
            .await?;
            let state = sqlx::query(
                "SELECT fencing_epoch,safe_mode FROM installation_state WHERE singleton=TRUE FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await?;
            if state.try_get::<bool, _>("safe_mode")?
                || u64v(state.try_get("fencing_epoch")?, "installation epoch")? != e
                || !valid
                || r.status != DeploymentRequestStatus::Leased
                || r.execution_lease_id.as_deref() != Some(l)
                || r.lease_fencing_generation != Some(f)
                || r.installation_fencing_epoch != Some(e)
            {
                return Err(ControlPlaneError::EnvironmentGateNotReady);
            }
            let environment = environment_tx(&mut tx, t, &r.environment_id, true)
                .await?
                .ok_or_else(|| not_found("environment", &r.environment_id))?;
            validate_deployment_inputs(&mut tx, &r, &environment).await?;
            let mut value = r;
            value.status = DeploymentRequestStatus::InProgress;
            value.actor_id = actor.to_owned();
            value.audit_correlation_id = correlation.to_owned();
            value.updated_unix_ms = now;
            value.version =
                value
                    .version
                    .checked_add(1)
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "deployment request version",
                    })?;
            let changed = sqlx::query(
                "UPDATE deployment_requests SET status='in-progress',actor_id=$3,
                 audit_correlation_id=$4,updated_unix_ms=$5,version=$6
                 WHERE tenant_id=$1 AND id=$2 AND status='leased'",
            )
            .bind(t)
            .bind(id)
            .bind(actor)
            .bind(correlation)
            .bind(i64v(now, "deployment start")?)
            .bind(i64v(value.version, "deployment request version")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            append_request_event(&mut tx, &value).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: false,
            })
        })
    }
}

#[cfg(feature = "postgres")]
impl EnvironmentGateStore for PostgresInstallationStore {
    fn acquire_gate<'a>(
        &'a self,
        r: &'a AcquireEnvironmentGate,
    ) -> StoreFuture<'a, IdempotentResult<EnvironmentConcurrencyLeaseRecord>> {
        Box::pin(async move {
            if r.installation_fencing_epoch == 0
                || r.gate_expires_unix_ms <= r.now_unix_ms
                || r.gate_expires_unix_ms - r.now_unix_ms > MAX_POSTGRES_GATE_LEASE_MS
            {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid environment gate lease bounds",
                ));
            }
            let mut tx = self.pool().begin().await?;
            let state = sqlx::query(
                "SELECT fencing_epoch,safe_mode FROM installation_state
                 WHERE singleton=TRUE FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await?;
            if state.try_get::<bool, _>("safe_mode")? {
                return Err(ControlPlaneError::InstallationSafeMode);
            }
            let current_epoch = u64v(state.try_get("fencing_epoch")?, "installation epoch")?;
            if current_epoch != r.installation_fencing_epoch {
                return Err(ControlPlaneError::StaleInstallationEpoch {
                    expected: current_epoch,
                    actual: r.installation_fencing_epoch,
                });
            }
            if let Some(g) = gate_tx(&mut tx, &r.tenant_id, &r.deployment_request_id, true).await? {
                let mut d = request_tx(&mut tx, &r.tenant_id, &r.deployment_request_id, true)
                    .await?
                    .ok_or_else(|| not_found("deployment request", &r.deployment_request_id))?;
                if g.id == r.gate_lease_id
                    && g.installation_fencing_epoch == r.installation_fencing_epoch
                    && g.state == "active"
                    && g.expires_unix_ms == r.gate_expires_unix_ms
                    && g.expires_unix_ms > r.now_unix_ms
                    && d.status.as_str() == "ready"
                    && d.concurrency_fence == Some(g.concurrency_fence)
                {
                    tx.commit().await?;
                    return Ok(IdempotentResult {
                        value: g,
                        replayed: true,
                    });
                }
                if g.expires_unix_ms > r.now_unix_ms {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let changed = sqlx::query(
                    "UPDATE environment_concurrency_leases SET state='expired',released_unix_ms=$3
                     WHERE tenant_id=$1 AND id=$2 AND state='active'",
                )
                .bind(&r.tenant_id)
                .bind(&g.id)
                .bind(i64v(r.now_unix_ms, "gate expiry")?)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                if d.status == DeploymentRequestStatus::Ready {
                    d.status = DeploymentRequestStatus::AwaitingConcurrency;
                    d.concurrency_fence = None;
                    d.installation_fencing_epoch = None;
                    d.actor_id.clone_from(&r.actor_id);
                    d.audit_correlation_id.clone_from(&r.audit_correlation_id);
                    d.updated_unix_ms = r.now_unix_ms;
                    d.version =
                        d.version
                            .checked_add(1)
                            .ok_or(ControlPlaneError::IntegerRange {
                                field: "deployment request version",
                            })?;
                    sqlx::query(
                        "UPDATE deployment_requests SET status='awaiting-concurrency',
                         concurrency_fence=NULL,installation_fencing_epoch=NULL,actor_id=$3,
                         audit_correlation_id=$4,updated_unix_ms=$5,version=$6
                         WHERE tenant_id=$1 AND id=$2 AND status='ready'",
                    )
                    .bind(&r.tenant_id)
                    .bind(&d.id)
                    .bind(&r.actor_id)
                    .bind(&r.audit_correlation_id)
                    .bind(i64v(r.now_unix_ms, "gate expiry")?)
                    .bind(i64v(d.version, "deployment request version")?)
                    .execute(&mut *tx)
                    .await?;
                    append_request_event(&mut tx, &d).await?;
                }
            }
            let mut deployment = request_tx(&mut tx, &r.tenant_id, &r.deployment_request_id, true)
                .await?
                .ok_or_else(|| not_found("deployment request", &r.deployment_request_id))?;
            let environment =
                environment_tx(&mut tx, &r.tenant_id, &deployment.environment_id, true)
                    .await?
                    .ok_or_else(|| not_found("environment", &deployment.environment_id))?;
            if environment.status != "active"
                || environment.version != deployment.environment_version
                || environment.required_policy_epoch != deployment.policy_epoch
                || r.now_unix_ms < deployment.wait_until_unix_ms
                || !matches!(
                    deployment.status,
                    DeploymentRequestStatus::WaitingTimer
                        | DeploymentRequestStatus::AwaitingApproval
                        | DeploymentRequestStatus::AwaitingConcurrency
                )
                || (!environment
                    .protection_rules
                    .allowed_deployment_actors
                    .is_empty()
                    && environment
                        .protection_rules
                        .allowed_deployment_actors
                        .binary_search(&r.actor_id)
                        .is_err())
            {
                return Err(ControlPlaneError::EnvironmentGateNotReady);
            }
            require_active_policy_epoch(&mut tx, &r.tenant_id, deployment.policy_epoch).await?;
            require_provider_capability(
                &mut tx,
                &r.tenant_id,
                environment.secret_provider_configuration_id.as_deref(),
                "external-secret",
            )
            .await?;
            require_provider_capability(
                &mut tx,
                &r.tenant_id,
                environment.signing_provider_configuration_id.as_deref(),
                "signing",
            )
            .await?;
            validate_deployment_inputs(&mut tx, &deployment, &environment).await?;
            if environment.protection_rules.require_approval {
                deployment_approval(&mut tx, &deployment, &environment, Some(r.now_unix_ms))
                    .await?;
            }

            let expired = sqlx::query(
                "SELECT deployment_request_id FROM environment_concurrency_leases
                 WHERE tenant_id=$1 AND environment_id=$2 AND state='active'
                   AND expires_unix_ms<=$3 ORDER BY expires_unix_ms,id LIMIT 1001 FOR UPDATE",
            )
            .bind(&r.tenant_id)
            .bind(&environment.id)
            .bind(i64v(r.now_unix_ms, "gate acquisition")?)
            .fetch_all(&mut *tx)
            .await?;
            if expired.len() > 1_000 {
                return Err(ControlPlaneError::CorruptState(
                    "environment has too many expired concurrency leases".to_owned(),
                ));
            }
            for row in expired {
                let request_id: String = row.try_get("deployment_request_id")?;
                sqlx::query(
                    "UPDATE environment_concurrency_leases SET state='expired',released_unix_ms=$3
                     WHERE tenant_id=$1 AND deployment_request_id=$2 AND state='active'",
                )
                .bind(&r.tenant_id)
                .bind(&request_id)
                .bind(i64v(r.now_unix_ms, "gate expiry")?)
                .execute(&mut *tx)
                .await?;
                if request_id != deployment.id {
                    if let Some(mut old) =
                        request_tx(&mut tx, &r.tenant_id, &request_id, true).await?
                    {
                        if old.status == DeploymentRequestStatus::Ready {
                            old.status = DeploymentRequestStatus::AwaitingConcurrency;
                            old.concurrency_fence = None;
                            old.installation_fencing_epoch = None;
                            old.actor_id.clone_from(&r.actor_id);
                            old.audit_correlation_id.clone_from(&r.audit_correlation_id);
                            old.updated_unix_ms = r.now_unix_ms;
                            old.version = old.version.checked_add(1).ok_or(
                                ControlPlaneError::IntegerRange {
                                    field: "deployment request version",
                                },
                            )?;
                            sqlx::query(
                                "UPDATE deployment_requests SET status='awaiting-concurrency',
                                 concurrency_fence=NULL,installation_fencing_epoch=NULL,
                                 actor_id=$3,audit_correlation_id=$4,updated_unix_ms=$5,version=$6
                                 WHERE tenant_id=$1 AND id=$2 AND status='ready'",
                            )
                            .bind(&r.tenant_id)
                            .bind(&request_id)
                            .bind(&r.actor_id)
                            .bind(&r.audit_correlation_id)
                            .bind(i64v(r.now_unix_ms, "gate expiry")?)
                            .bind(i64v(old.version, "deployment request version")?)
                            .execute(&mut *tx)
                            .await?;
                            append_request_event(&mut tx, &old).await?;
                        }
                    }
                }
            }
            let active: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM environment_concurrency_leases
                 WHERE tenant_id=$1 AND environment_id=$2 AND state='active'",
            )
            .bind(&r.tenant_id)
            .bind(&environment.id)
            .fetch_one(&mut *tx)
            .await?;
            if u64v(active, "active environment concurrency")?
                >= u64::from(environment.concurrency_limit)
            {
                return Err(ControlPlaneError::EnvironmentConcurrencyLimit);
            }
            let fence = environment.last_concurrency_fence.checked_add(1).ok_or(
                ControlPlaneError::IntegerRange {
                    field: "environment concurrency fence",
                },
            )?;
            let changed = sqlx::query(
                "UPDATE environments SET last_concurrency_fence=$3,
                 updated_unix_ms=GREATEST(updated_unix_ms,$4)
                 WHERE tenant_id=$1 AND id=$2 AND last_concurrency_fence=$5",
            )
            .bind(&r.tenant_id)
            .bind(&environment.id)
            .bind(i64v(fence, "environment concurrency fence")?)
            .bind(i64v(r.now_unix_ms, "gate acquisition")?)
            .bind(i64v(
                environment.last_concurrency_fence,
                "environment prior concurrency fence",
            )?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query(
                "INSERT INTO environment_concurrency_leases
                 (id,tenant_id,environment_id,deployment_request_id,concurrency_fence,
                  execution_lease_id,lease_fencing_generation,installation_fencing_epoch,
                  state,acquired_unix_ms,expires_unix_ms,released_unix_ms)
                 VALUES($1,$2,$3,$4,$5,NULL,NULL,$6,'active',$7,$8,NULL)",
            )
            .bind(&r.gate_lease_id)
            .bind(&r.tenant_id)
            .bind(&environment.id)
            .bind(&deployment.id)
            .bind(i64v(fence, "environment concurrency fence")?)
            .bind(i64v(r.installation_fencing_epoch, "installation epoch")?)
            .bind(i64v(r.now_unix_ms, "gate acquisition")?)
            .bind(i64v(r.gate_expires_unix_ms, "gate expiry")?)
            .execute(&mut *tx)
            .await?;
            deployment.status = DeploymentRequestStatus::Ready;
            deployment.concurrency_fence = Some(fence);
            deployment.installation_fencing_epoch = Some(r.installation_fencing_epoch);
            deployment.actor_id.clone_from(&r.actor_id);
            deployment
                .audit_correlation_id
                .clone_from(&r.audit_correlation_id);
            deployment.updated_unix_ms = r.now_unix_ms;
            deployment.version =
                deployment
                    .version
                    .checked_add(1)
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "deployment request version",
                    })?;
            let changed = sqlx::query(
                "UPDATE deployment_requests SET status='ready',concurrency_fence=$3,
                 installation_fencing_epoch=$4,actor_id=$5,audit_correlation_id=$6,
                 updated_unix_ms=$7,version=$8 WHERE tenant_id=$1 AND id=$2
                   AND status IN('waiting-timer','awaiting-approval','awaiting-concurrency')",
            )
            .bind(&r.tenant_id)
            .bind(&deployment.id)
            .bind(i64v(fence, "environment concurrency fence")?)
            .bind(i64v(r.installation_fencing_epoch, "installation epoch")?)
            .bind(&r.actor_id)
            .bind(&r.audit_correlation_id)
            .bind(i64v(r.now_unix_ms, "gate acquisition")?)
            .bind(i64v(deployment.version, "deployment request version")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            append_request_event(&mut tx, &deployment).await?;
            let lease = gate_tx(&mut tx, &r.tenant_id, &r.deployment_request_id, false)
                .await?
                .ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "environment concurrency lease disappeared".to_owned(),
                    )
                })?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: lease,
                replayed: false,
            })
        })
    }
    fn bind_gate_lease<'a>(
        &'a self,
        b: &'a BindDeploymentLease,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRequestRecord>> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let d = request_tx(&mut tx, &b.tenant_id, &b.deployment_request_id, true)
                .await?
                .ok_or_else(|| not_found("deployment request", &b.deployment_request_id))?;
            let g = gate_tx(&mut tx, &b.tenant_id, &b.deployment_request_id, true)
                .await?
                .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
            let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM leases l JOIN jobs j ON j.id=l.job_id WHERE l.tenant_id=$1 AND l.id=$2 AND l.job_id=$3 AND j.attempt=$4 AND l.fencing_generation=$5 AND l.installation_fencing_epoch=$6 AND l.state IN('offered','active') AND l.issued_unix_ms<=$7 AND l.expires_unix_ms>$7 AND l.hard_deadline_unix_ms>$7)").bind(&b.tenant_id).bind(&b.execution_lease_id).bind(&d.job_id).bind(i64::from(d.job_attempt)).bind(i64v(b.lease_fencing_generation,"lease fence")?).bind(i64v(b.installation_fencing_epoch,"installation epoch")?).bind(i64v(b.now_unix_ms,"binding time")?).fetch_one(&mut *tx).await?;
            let state = sqlx::query(
                "SELECT fencing_epoch,safe_mode FROM installation_state WHERE singleton=TRUE",
            )
            .fetch_one(&mut *tx)
            .await?;
            let epoch = u64v(state.try_get("fencing_epoch")?, "installation epoch")?;
            let safe: bool = state.try_get("safe_mode")?;
            if safe
                || epoch != b.installation_fencing_epoch
                || !valid
                || d.status.as_str() != "leased"
                || d.execution_lease_id.as_deref() != Some(&b.execution_lease_id)
                || d.lease_fencing_generation != Some(b.lease_fencing_generation)
                || d.installation_fencing_epoch != Some(b.installation_fencing_epoch)
                || g.execution_lease_id.as_deref() != Some(&b.execution_lease_id)
                || g.lease_fencing_generation != Some(b.lease_fencing_generation)
                || g.state != "active"
                || g.expires_unix_ms <= b.now_unix_ms
                || g.installation_fencing_epoch != b.installation_fencing_epoch
                || d.concurrency_fence != Some(g.concurrency_fence)
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            tx.commit().await?;
            Ok(IdempotentResult {
                value: d,
                replayed: true,
            })
        })
    }
}

#[cfg(feature = "postgres")]
async fn validate_signing_reservation(
    tx: &mut Transaction<'_, Postgres>,
    reservation: &SigningResultReservation,
) -> Result<(), ControlPlaneError> {
    validate_signing_reservation_shape(reservation)?;
    let deployment = request_tx(
        tx,
        &reservation.tenant_id,
        &reservation.deployment_request_id,
        true,
    )
    .await?
    .ok_or_else(|| not_found("deployment request", &reservation.deployment_request_id))?;
    let environment = environment_tx(
        tx,
        &reservation.tenant_id,
        &reservation.environment_id,
        true,
    )
    .await?
    .ok_or_else(|| not_found("environment", &reservation.environment_id))?;
    let provider = provider_tx(
        tx,
        &reservation.tenant_id,
        &reservation.provider_configuration_id,
        true,
    )
    .await?
    .ok_or_else(|| {
        not_found(
            "provider configuration",
            &reservation.provider_configuration_id,
        )
    })?;
    let policy = signer_tx(
        tx,
        &reservation.tenant_id,
        &reservation.signer_policy_id,
        true,
    )
    .await?
    .ok_or_else(|| not_found("signer policy", &reservation.signer_policy_id))?;
    require_snapshot(
        tx,
        "environment_versions",
        "environment_id",
        &environment.tenant_id,
        &environment.id,
        environment.version,
        crate::store::environment_snapshot(&environment)?,
    )
    .await?;
    require_snapshot(
        tx,
        "tenant_provider_configuration_versions",
        "provider_configuration_id",
        &provider.tenant_id,
        &provider.id,
        provider.version,
        crate::store::provider_configuration_snapshot(&provider)?,
    )
    .await?;
    require_snapshot(
        tx,
        "signer_policy_versions",
        "signer_policy_id",
        &policy.tenant_id,
        &policy.id,
        policy.version,
        crate::store::signer_policy_snapshot(&policy)?,
    )
    .await?;
    if environment.status != "active"
        || !environment.protection_rules.require_signed_artifact
        || environment.version != reservation.environment_version
        || environment.required_policy_epoch != reservation.policy_epoch
        || environment.signing_provider_configuration_id.as_deref()
            != Some(reservation.provider_configuration_id.as_str())
        || environment
            .protection_rules
            .allowed_signer_policy_ids
            .binary_search(&reservation.signer_policy_id)
            .is_err()
        || provider.capability != "signing"
        || provider.status != "active"
        || provider.configuration_digest != reservation.provider_configuration_digest
        || provider.version != reservation.provider_configuration_version
        || policy.status != "active"
        || policy.provider_configuration_id != reservation.provider_configuration_id
        || policy.policy_digest != reservation.signer_policy_digest
        || policy.version != reservation.signer_policy_version
        || policy.purpose != reservation.purpose
        || policy.operation != reservation.operation
        || deployment.environment_id != reservation.environment_id
        || deployment.repository_id != reservation.repository_id
        || deployment.run_id != reservation.run_id
        || deployment.job_id != reservation.job_id
        || deployment.job_attempt != reservation.job_attempt
        || deployment.policy_epoch != reservation.policy_epoch
        || deployment.environment_version != reservation.environment_version
        || deployment.approval_request_id.as_deref()
            != Some(reservation.approval_request_id.as_str())
        || deployment.approval_subject_digest != reservation.approval_subject_digest
        || deployment.artifact_digest != reservation.artifact_digest
        || deployment.provenance_digest != reservation.provenance_digest
        || deployment.execution_lease_id.as_deref() != Some(reservation.execution_lease_id.as_str())
        || deployment.lease_fencing_generation != Some(reservation.fencing_generation)
        || deployment.installation_fencing_epoch != Some(reservation.installation_fencing_epoch)
        || !matches!(
            deployment.status,
            DeploymentRequestStatus::Leased | DeploymentRequestStatus::InProgress
        )
    {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    validate_deployment_inputs(tx, &deployment, &environment).await?;

    let capsule_row = sqlx::query(
        "SELECT p.canonical_capsule,j.job_key FROM jobs j JOIN runs r ON r.id=j.run_id
         JOIN capsules p ON p.id=r.capsule_id WHERE j.id=$1 AND j.run_id=$2 FOR SHARE OF j,r,p",
    )
    .bind(&reservation.job_id)
    .bind(&reservation.run_id)
    .fetch_one(&mut **tx)
    .await?;
    let canonical: Vec<u8> = capsule_row.try_get("canonical_capsule")?;
    let capsule: ExecutionCapsule = serde_json::from_slice(&canonical)?;
    if capsule.canonical_bytes()? != canonical {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let capsule_digest = capsule.digest()?;
    let job_key: String = capsule_row.try_get("job_key")?;
    let job = super::runner_authority::postgres_materialized_planned_job(
        tx,
        &reservation.run_id,
        &job_key,
        &capsule,
        &capsule_digest,
    )
    .await?
    .ok_or_else(|| {
        ControlPlaneError::CorruptState("signing job is absent from its signed capsule".to_owned())
    })?;
    let step = job
        .steps
        .iter()
        .find(|step| step.id == reservation.step_id)
        .or_else(|| {
            job.finalizers
                .iter()
                .map(|finalizer| &finalizer.step)
                .find(|step| step.id == reservation.step_id)
        });
    let declared = step.is_some_and(|step| {
        step.capabilities.signing.iter().any(|capability| {
            capability.purpose == reservation.purpose
                && capability.key_policy == reservation.signer_policy_id
                && matches!(
                    (capability.operation, reservation.operation.as_str()),
                    (
                        runtrue_workflow_ir::SigningOperation::SignDigest,
                        "sign-digest"
                    ) | (
                        runtrue_workflow_ir::SigningOperation::SignAttestation,
                        "sign-attestation"
                    )
                )
        })
    });
    if !declared {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    let lease_valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM leases l JOIN jobs j ON j.id=l.job_id
         JOIN runs r ON r.id=j.run_id JOIN repositories repo ON repo.id=r.repository_id
         WHERE l.tenant_id=$1 AND l.id=$2 AND l.job_id=$3 AND j.attempt=$4
           AND j.run_id=$5 AND repo.tenant_id=$1 AND l.fencing_generation=$6
           AND l.installation_fencing_epoch=$7 AND l.state='active'
           AND l.issued_unix_ms<=$8 AND l.expires_unix_ms>$8
           AND l.hard_deadline_unix_ms>$8)",
    )
    .bind(&reservation.tenant_id)
    .bind(&reservation.execution_lease_id)
    .bind(&reservation.job_id)
    .bind(i64::from(reservation.job_attempt))
    .bind(&reservation.run_id)
    .bind(i64v(reservation.fencing_generation, "lease fence")?)
    .bind(i64v(
        reservation.installation_fencing_epoch,
        "installation epoch",
    )?)
    .bind(i64v(reservation.requested_unix_ms, "signing request")?)
    .fetch_one(&mut **tx)
    .await?;
    let state = sqlx::query(
        "SELECT fencing_epoch,safe_mode FROM installation_state WHERE singleton=TRUE FOR UPDATE",
    )
    .fetch_one(&mut **tx)
    .await?;
    if !lease_valid
        || state.try_get::<bool, _>("safe_mode")?
        || u64v(state.try_get("fencing_epoch")?, "installation epoch")?
            != reservation.installation_fencing_epoch
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
impl SigningResultStore for PostgresInstallationStore {
    fn reserve_signing<'a>(
        &'a self,
        r: &'a SigningResultReservation,
    ) -> StoreFuture<'a, IdempotentResult<SigningResultJournalRecord>> {
        Box::pin(async move {
            validate_signing_reservation_shape(r)?;
            let mut tx = self.pool().begin().await?;
            if let Some(old) = signing_result_tx(&mut tx, &r.tenant_id, &r.request_id, true).await?
            {
                if old.reservation == *r {
                    tx.commit().await?;
                    return Ok(IdempotentResult {
                        value: old,
                        replayed: true,
                    });
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            validate_signing_reservation(&mut tx, r).await?;
            let reservation_json = serde_json::to_vec(r)?;
            sqlx::query(
                "INSERT INTO signing_result_journal
                 (request_id,tenant_id,provider_configuration_id,
                  provider_configuration_digest,provider_configuration_version,
                  environment_id,deployment_request_id,repository_id,run_id,job_id,
                  job_attempt,step_id,execution_lease_id,fencing_generation,
                  installation_fencing_epoch,policy_epoch,environment_version,
                  approval_request_id,approval_subject_digest,artifact_digest,
                  provenance_digest,purpose,operation,signer_policy_id,signer_policy_digest,
                  signer_policy_version,request_digest,reservation_json,state,result_json,
                  result_digest,retry_attempts,requested_unix_ms,expires_unix_ms,
                  updated_unix_ms,completed_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
                        $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,'reserved',NULL,NULL,
                        0,$29,$30,$29,NULL)",
            )
            .bind(&r.request_id)
            .bind(&r.tenant_id)
            .bind(&r.provider_configuration_id)
            .bind(r.provider_configuration_digest.as_str())
            .bind(i64v(r.provider_configuration_version, "provider version")?)
            .bind(&r.environment_id)
            .bind(&r.deployment_request_id)
            .bind(&r.repository_id)
            .bind(&r.run_id)
            .bind(&r.job_id)
            .bind(i64::from(r.job_attempt))
            .bind(&r.step_id)
            .bind(&r.execution_lease_id)
            .bind(i64v(r.fencing_generation, "lease fence")?)
            .bind(i64v(r.installation_fencing_epoch, "installation epoch")?)
            .bind(i64v(r.policy_epoch, "policy epoch")?)
            .bind(i64v(r.environment_version, "environment version")?)
            .bind(&r.approval_request_id)
            .bind(r.approval_subject_digest.as_str())
            .bind(r.artifact_digest.as_str())
            .bind(r.provenance_digest.as_str())
            .bind(&r.purpose)
            .bind(&r.operation)
            .bind(&r.signer_policy_id)
            .bind(r.signer_policy_digest.as_str())
            .bind(i64v(r.signer_policy_version, "signer policy version")?)
            .bind(r.request_digest.as_str())
            .bind(reservation_json)
            .bind(i64v(r.requested_unix_ms, "signing request")?)
            .bind(i64v(r.expires_unix_ms, "signing expiry")?)
            .execute(&mut *tx)
            .await?;
            let value = SigningResultJournalRecord {
                reservation: r.clone(),
                state: SigningResultState::Reserved,
                retry_attempts: 0,
                updated_unix_ms: r.requested_unix_ms,
                completed_unix_ms: None,
            };
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: false,
            })
        })
    }

    fn record_signed<'a>(
        &'a self,
        r: &'a SigningResultReservation,
        result: &'a PublicSigningResult,
    ) -> StoreFuture<'a, IdempotentResult<SigningResultJournalRecord>> {
        Box::pin(async move {
            validate_signing_reservation_shape(r)?;
            validate_public_signing_result(r, result)?;
            let result_json = serde_json::to_vec(result)?;
            if result_json.len() > 1_048_576 {
                return Err(ControlPlaneError::InvalidInput(
                    "public signing result exceeds its bound",
                ));
            }
            let mut tx = self.pool().begin().await?;
            let old = signing_result_tx(&mut tx, &r.tenant_id, &r.request_id, true)
                .await?
                .ok_or_else(|| not_found("signing result", &r.request_id))?;
            if old.reservation != *r {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            match &old.state {
                SigningResultState::Signed(stored) | SigningResultState::Complete(stored)
                    if stored == result =>
                {
                    tx.commit().await?;
                    return Ok(IdempotentResult {
                        value: old,
                        replayed: true,
                    });
                }
                SigningResultState::Reserved => {}
                _ => return Err(ControlPlaneError::IdempotencyConflict),
            }
            let changed = sqlx::query(
                "UPDATE signing_result_journal SET state='signed',result_json=$3,result_digest=$4,retry_attempts=retry_attempts+1,updated_unix_ms=$5 WHERE tenant_id=$1 AND request_id=$2 AND state='reserved' AND retry_attempts<8",
            )
            .bind(&r.tenant_id)
            .bind(&r.request_id)
            .bind(result_json)
            .bind(result.result_digest.as_str())
            .bind(i64v(result.signed_unix_ms, "signing time")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let value = signing_result_tx(&mut tx, &r.tenant_id, &r.request_id, false)
                .await?
                .ok_or_else(|| not_found("signing result", &r.request_id))?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: false,
            })
        })
    }

    fn complete_signing<'a>(
        &'a self,
        tenant_id: &'a str,
        request_id: &'a str,
        request_digest: &'a ContentDigest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, IdempotentResult<SigningResultJournalRecord>> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let old = signing_result_tx(&mut tx, tenant_id, request_id, true)
                .await?
                .ok_or_else(|| not_found("signing result", request_id))?;
            if old.reservation.request_digest != *request_digest {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if matches!(old.state, SigningResultState::Complete(_)) {
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value: old,
                    replayed: true,
                });
            }
            let SigningResultState::Signed(result) = &old.state else {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "signing result",
                    from: "not-signed",
                    to: "complete",
                });
            };
            if now_unix_ms < result.signed_unix_ms {
                return Err(ControlPlaneError::InvalidInput(
                    "signing completion predates signature",
                ));
            }
            let changed = sqlx::query(
                "UPDATE signing_result_journal SET state='complete',updated_unix_ms=$3,completed_unix_ms=$3 WHERE tenant_id=$1 AND request_id=$2 AND state='signed'",
            )
            .bind(tenant_id)
            .bind(request_id)
            .bind(i64v(now_unix_ms, "signing completion")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let value = signing_result_tx(&mut tx, tenant_id, request_id, false)
                .await?
                .ok_or_else(|| not_found("signing result", request_id))?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: false,
            })
        })
    }

    fn signing<'a>(
        &'a self,
        tenant_id: &'a str,
        request_id: &'a str,
    ) -> StoreFuture<'a, SigningResultJournalRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let value = signing_result_tx(&mut tx, tenant_id, request_id, false)
                .await?
                .ok_or_else(|| not_found("signing result", request_id))?;
            tx.commit().await?;
            Ok(value)
        })
    }
}

#[cfg(feature = "postgres")]
impl DeploymentResultStore for PostgresInstallationStore {
    fn record_result<'a>(
        &'a self,
        record: &'a DeploymentRecord,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, IdempotentResult<DeploymentRecord>> {
        Box::pin(async move {
            validate_deployment_result(record, audit)?;
            let mut tx = self.pool().begin().await?;
            if let Some(old) =
                deployment_result_tx(&mut tx, &record.tenant_id, &record.id, true).await?
            {
                if old == *record {
                    tx.commit().await?;
                    return Ok(IdempotentResult {
                        value: old,
                        replayed: true,
                    });
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let mut request = request_tx(
                &mut tx,
                &record.tenant_id,
                &record.deployment_request_id,
                true,
            )
            .await?
            .ok_or_else(|| not_found("deployment request", &record.deployment_request_id))?;
            let environment =
                environment_tx(&mut tx, &record.tenant_id, &record.environment_id, true)
                    .await?
                    .ok_or_else(|| not_found("environment", &record.environment_id))?;
            validate_deployment_inputs(&mut tx, &request, &environment).await?;
            if request.status != DeploymentRequestStatus::InProgress
                || request.environment_id != record.environment_id
                || request.rollback_of_deployment_id != record.rollback_of_deployment_id
                || request.artifact_id != record.artifact_id
                || request.promoted_artifact_id != record.promoted_artifact_id
                || request.artifact_digest != record.artifact_digest
                || request.manifest_digest != record.manifest_digest
                || request.provenance_digest != record.provenance_digest
                || request.target_digest != record.target_digest
                || request.deployment_capsule_digest != record.deployment_capsule_digest
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if environment.protection_rules.require_signed_artifact {
                let signing_request_id = record
                    .signing_request_id
                    .as_deref()
                    .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
                let signing =
                    signing_result_tx(&mut tx, &record.tenant_id, signing_request_id, true)
                        .await?
                        .ok_or_else(|| not_found("signing result", signing_request_id))?;
                let SigningResultState::Complete(result) = signing.state else {
                    return Err(ControlPlaneError::EnvironmentGateNotReady);
                };
                if record.signing_result_digest.as_ref() != Some(&result.result_digest)
                    || record.signer_key_id.as_deref() != Some(result.signer_key_id.as_str())
                    || record.signing_algorithm.as_deref() != Some(result.algorithm.as_str())
                    || record.signature_digest.as_ref()
                        != Some(&ContentDigest::sha256(&result.signature))
                    || record.certificate_digest
                        != result.certificate.as_ref().map(ContentDigest::sha256)
                    || record.attestation_digest
                        != result.attestation.as_ref().map(ContentDigest::sha256)
                    || signing.reservation.deployment_request_id != record.deployment_request_id
                    || signing.reservation.artifact_digest != record.artifact_digest
                    || signing.reservation.provenance_digest != record.provenance_digest
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            } else if record.signing_request_id.is_some()
                || record.signing_result_digest.is_some()
                || record.signer_key_id.is_some()
                || record.signing_algorithm.is_some()
                || record.signature_digest.is_some()
                || record.certificate_digest.is_some()
                || record.attestation_digest.is_some()
            {
                return Err(ControlPlaneError::InvalidInput(
                    "unexpected signing result on unsigned environment",
                ));
            }
            let metadata = serde_json::to_vec(&record.metadata)?;
            sqlx::query(
                "INSERT INTO deployments
                 (id,tenant_id,environment_id,deployment_request_id,
                  rollback_of_deployment_id,artifact_id,promoted_artifact_id,
                  artifact_digest,manifest_digest,provenance_digest,target_digest,
                  deployment_capsule_digest,signing_request_id,signing_result_digest,
                  signer_key_id,signing_algorithm,signature_digest,certificate_digest,
                  attestation_digest,external_reference,status,result_digest,metadata_json,
                  metadata_digest,started_unix_ms,completed_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
                        $18,$19,$20,$21,$22,$23,$24,$25,$26)",
            )
            .bind(&record.id)
            .bind(&record.tenant_id)
            .bind(&record.environment_id)
            .bind(&record.deployment_request_id)
            .bind(&record.rollback_of_deployment_id)
            .bind(&record.artifact_id)
            .bind(&record.promoted_artifact_id)
            .bind(record.artifact_digest.as_str())
            .bind(record.manifest_digest.as_str())
            .bind(record.provenance_digest.as_str())
            .bind(record.target_digest.as_str())
            .bind(record.deployment_capsule_digest.as_str())
            .bind(&record.signing_request_id)
            .bind(
                record
                    .signing_result_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
            )
            .bind(&record.signer_key_id)
            .bind(&record.signing_algorithm)
            .bind(record.signature_digest.as_ref().map(ContentDigest::as_str))
            .bind(
                record
                    .certificate_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
            )
            .bind(
                record
                    .attestation_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
            )
            .bind(&record.external_reference)
            .bind(&record.status)
            .bind(record.result_digest.as_str())
            .bind(metadata)
            .bind(record.metadata_digest.as_str())
            .bind(i64v(record.started_unix_ms, "deployment start")?)
            .bind(i64v(
                record
                    .completed_unix_ms
                    .ok_or(ControlPlaneError::InvalidInput(
                        "deployment completion is missing",
                    ))?,
                "deployment completion",
            )?)
            .execute(&mut *tx)
            .await?;
            request.status = if record.status == "succeeded" {
                DeploymentRequestStatus::Succeeded
            } else {
                DeploymentRequestStatus::Failed
            };
            request.actor_id.clone_from(&audit.actor_id);
            request
                .audit_correlation_id
                .clone_from(&audit.correlation_id);
            request.updated_unix_ms = audit.occurred_unix_ms;
            request.completed_unix_ms = Some(audit.occurred_unix_ms);
            request.version =
                request
                    .version
                    .checked_add(1)
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "deployment request version",
                    })?;
            let changed = sqlx::query(
                "UPDATE deployment_requests SET status=$3,actor_id=$4,
                 audit_correlation_id=$5,updated_unix_ms=$6,completed_unix_ms=$6,version=$7
                 WHERE tenant_id=$1 AND id=$2 AND status='in-progress'",
            )
            .bind(&record.tenant_id)
            .bind(&record.deployment_request_id)
            .bind(request.status.as_str())
            .bind(&audit.actor_id)
            .bind(&audit.correlation_id)
            .bind(i64v(audit.occurred_unix_ms, "deployment completion")?)
            .bind(i64v(request.version, "deployment request version")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query(
                "UPDATE environment_concurrency_leases SET state='released',released_unix_ms=$3
                 WHERE tenant_id=$1 AND deployment_request_id=$2 AND state='active'",
            )
            .bind(&record.tenant_id)
            .bind(&record.deployment_request_id)
            .bind(i64v(audit.occurred_unix_ms, "deployment completion")?)
            .execute(&mut *tx)
            .await?;
            if record.status == "succeeded" {
                if let Some(parent_id) = &record.rollback_of_deployment_id {
                    sqlx::query(
                        "UPDATE deployments SET status='rolled-back'
                         WHERE tenant_id=$1 AND id=$2 AND status='succeeded'",
                    )
                    .bind(&record.tenant_id)
                    .bind(parent_id)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            append_request_event(&mut tx, &request).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: record.clone(),
                replayed: false,
            })
        })
    }

    fn result<'a>(
        &'a self,
        tenant_id: &'a str,
        deployment_id: &'a str,
    ) -> StoreFuture<'a, DeploymentRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let value = deployment_result_tx(&mut tx, tenant_id, deployment_id, false)
                .await?
                .ok_or_else(|| not_found("deployment", deployment_id))?;
            tx.commit().await?;
            Ok(value)
        })
    }
}

#[cfg(feature = "postgres")]
fn validate_signing_reservation_shape(
    r: &SigningResultReservation,
) -> Result<(), ControlPlaneError> {
    let bytes = serde_json::to_vec(r)?;
    if bytes.len() > 1_048_576
        || r.request_id.is_empty()
        || r.tenant_id.is_empty()
        || r.job_attempt == 0
        || r.fencing_generation == 0
        || r.installation_fencing_epoch == 0
        || r.policy_epoch == 0
        || r.environment_version == 0
        || r.provider_configuration_version == 0
        || r.signer_policy_version == 0
        || !matches!(r.operation.as_str(), "sign-digest" | "sign-attestation")
        || r.expires_unix_ms <= r.requested_unix_ms
        || r.expires_unix_ms - r.requested_unix_ms > 15 * 60 * 1_000
        || r.expected_request_digest()? != r.request_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid signing result reservation",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_public_signing_result(
    reservation: &SigningResultReservation,
    result: &PublicSigningResult,
) -> Result<(), ControlPlaneError> {
    if result.signature.is_empty()
        || result.signature.len() > 16 * 1024
        || result
            .certificate
            .as_ref()
            .is_some_and(|v| v.len() > 512 * 1024)
        || result
            .attestation
            .as_ref()
            .is_some_and(|v| v.len() > 512 * 1024)
        || result.signed_unix_ms < reservation.requested_unix_ms
        || result.signed_unix_ms >= reservation.expires_unix_ms
        || result.expected_result_digest()? != result.result_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid public signing result",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_deployment_result(
    record: &DeploymentRecord,
    audit: &R9AuditMetadata,
) -> Result<(), ControlPlaneError> {
    let metadata = serde_json::to_vec(&record.metadata)?;
    if metadata.len() > 1_048_576
        || record.id.is_empty()
        || record.tenant_id.is_empty()
        || !matches!(record.status.as_str(), "succeeded" | "failed")
        || record.completed_unix_ms != Some(audit.occurred_unix_ms)
        || record.started_unix_ms > audit.occurred_unix_ms
        || record.expected_metadata_digest()? != record.metadata_digest
        || record.expected_result_digest()? != record.result_digest
    {
        return Err(ControlPlaneError::InvalidInput("invalid deployment result"));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn signing_result_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    request_id: &str,
    lock: bool,
) -> Result<Option<SigningResultJournalRecord>, ControlPlaneError> {
    let q = format!(
        "SELECT request_id,tenant_id,request_digest,reservation_json,state,result_json,result_digest,retry_attempts,updated_unix_ms,completed_unix_ms FROM signing_result_journal WHERE tenant_id=$1 AND request_id=$2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let Some(row) = sqlx::query(&q)
        .bind(tenant_id)
        .bind(request_id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };
    let reservation_bytes: Vec<u8> = row.try_get("reservation_json")?;
    if reservation_bytes.len() > 1_048_576 {
        return Err(ControlPlaneError::CorruptState(
            "signing reservation exceeds its bound".into(),
        ));
    }
    let reservation: SigningResultReservation = serde_json::from_slice(&reservation_bytes)?;
    validate_signing_reservation_shape(&reservation)?;
    if serde_json::to_vec(&reservation)? != reservation_bytes
        || reservation.request_id != row.try_get::<String, _>("request_id")?
        || reservation.tenant_id != row.try_get::<String, _>("tenant_id")?
        || reservation.request_digest.as_str() != row.try_get::<String, _>("request_digest")?
    {
        return Err(ControlPlaneError::CorruptState(
            "signing reservation durable binding changed".into(),
        ));
    }
    let state_name: String = row.try_get("state")?;
    let result_bytes: Option<Vec<u8>> = row.try_get("result_json")?;
    let stored_digest: Option<String> = row.try_get("result_digest")?;
    let state = match (state_name.as_str(), result_bytes) {
        ("reserved", None) => SigningResultState::Reserved,
        ("aborted", None) => SigningResultState::Aborted,
        ("signed" | "complete", Some(bytes)) if bytes.len() <= 1_048_576 => {
            let result: PublicSigningResult = serde_json::from_slice(&bytes)?;
            if serde_json::to_vec(&result)? != bytes
                || result.expected_result_digest()? != result.result_digest
                || stored_digest.as_deref() != Some(result.result_digest.as_str())
            {
                return Err(ControlPlaneError::CorruptState(
                    "signing result digest changed".into(),
                ));
            }
            if state_name == "signed" {
                SigningResultState::Signed(result)
            } else {
                SigningResultState::Complete(result)
            }
        }
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "invalid signing result state".into(),
            ))
        }
    };
    let retry_attempts = u32::try_from(u64v(
        row.try_get("retry_attempts")?,
        "signing retry attempts",
    )?)
    .map_err(|_| ControlPlaneError::CorruptState("signing retry attempts exceed u32".into()))?;
    let updated_unix_ms = u64v(row.try_get("updated_unix_ms")?, "signing update")?;
    let completed_unix_ms = row
        .try_get::<Option<i64>, _>("completed_unix_ms")?
        .map(|v| u64v(v, "signing completion"))
        .transpose()?;
    if retry_attempts > 8
        || updated_unix_ms < reservation.requested_unix_ms
        || completed_unix_ms.is_some() != matches!(state, SigningResultState::Complete(_))
    {
        return Err(ControlPlaneError::CorruptState(
            "signing result state binding changed".into(),
        ));
    }
    Ok(Some(SigningResultJournalRecord {
        reservation,
        state,
        retry_attempts,
        updated_unix_ms,
        completed_unix_ms,
    }))
}

#[cfg(feature = "postgres")]
async fn deployment_result_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    deployment_id: &str,
    lock: bool,
) -> Result<Option<DeploymentRecord>, ControlPlaneError> {
    let q = format!(
        "SELECT * FROM deployments WHERE tenant_id=$1 AND id=$2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let Some(row) = sqlx::query(&q)
        .bind(tenant_id)
        .bind(deployment_id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };
    let metadata_bytes: Vec<u8> = row.try_get("metadata_json")?;
    if metadata_bytes.len() > 1_048_576 {
        return Err(ControlPlaneError::CorruptState(
            "deployment metadata exceeds its bound".into(),
        ));
    }
    let record = DeploymentRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        environment_id: row.try_get("environment_id")?,
        deployment_request_id: row.try_get("deployment_request_id")?,
        rollback_of_deployment_id: row.try_get("rollback_of_deployment_id")?,
        artifact_id: row.try_get("artifact_id")?,
        promoted_artifact_id: row.try_get("promoted_artifact_id")?,
        artifact_digest: digest(row.try_get("artifact_digest")?)?,
        manifest_digest: digest(row.try_get("manifest_digest")?)?,
        provenance_digest: digest(row.try_get("provenance_digest")?)?,
        target_digest: digest(row.try_get("target_digest")?)?,
        deployment_capsule_digest: digest(row.try_get("deployment_capsule_digest")?)?,
        signing_request_id: row.try_get("signing_request_id")?,
        signing_result_digest: row
            .try_get::<Option<String>, _>("signing_result_digest")?
            .map(digest)
            .transpose()?,
        signer_key_id: row.try_get("signer_key_id")?,
        signing_algorithm: row.try_get("signing_algorithm")?,
        signature_digest: row
            .try_get::<Option<String>, _>("signature_digest")?
            .map(digest)
            .transpose()?,
        certificate_digest: row
            .try_get::<Option<String>, _>("certificate_digest")?
            .map(digest)
            .transpose()?,
        attestation_digest: row
            .try_get::<Option<String>, _>("attestation_digest")?
            .map(digest)
            .transpose()?,
        external_reference: row.try_get("external_reference")?,
        status: row.try_get("status")?,
        result_digest: digest(row.try_get("result_digest")?)?,
        metadata: serde_json::from_slice(&metadata_bytes)?,
        metadata_digest: digest(row.try_get("metadata_digest")?)?,
        started_unix_ms: u64v(row.try_get("started_unix_ms")?, "deployment start")?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|v| u64v(v, "deployment completion"))
            .transpose()?,
    };
    let mut result_material = record.clone();
    if result_material.status == "rolled-back" {
        result_material.status = "succeeded".to_owned();
    }
    if serde_json::to_vec(&record.metadata)? != metadata_bytes
        || record.expected_metadata_digest()? != record.metadata_digest
        || result_material.expected_result_digest()? != record.result_digest
    {
        return Err(ControlPlaneError::CorruptState(
            "deployment result digest changed".into(),
        ));
    }
    Ok(Some(record))
}

#[cfg(feature = "postgres")]
async fn request_tx(
    tx: &mut Transaction<'_, Postgres>,
    t: &str,
    id: &str,
    lock: bool,
) -> Result<Option<DeploymentRequestRecord>, ControlPlaneError> {
    let q = format!(
        "SELECT row_to_json(r)::text FROM deployment_requests r WHERE tenant_id=$1 AND id=$2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    sqlx::query_scalar::<_, String>(&q)
        .bind(t)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(|json| serde_json::from_str(&json).map_err(Into::into))
        .transpose()
}

#[cfg(feature = "postgres")]
async fn gate_tx(
    tx: &mut Transaction<'_, Postgres>,
    t: &str,
    request: &str,
    lock: bool,
) -> Result<Option<EnvironmentConcurrencyLeaseRecord>, ControlPlaneError> {
    let q=format!("SELECT row_to_json(g)::text FROM environment_concurrency_leases g WHERE tenant_id=$1 AND deployment_request_id=$2 AND state='active'{}",if lock{" FOR UPDATE"}else{""});
    sqlx::query_scalar::<_, String>(&q)
        .bind(t)
        .bind(request)
        .fetch_optional(&mut **tx)
        .await?
        .map(|j| serde_json::from_str(&j).map_err(Into::into))
        .transpose()
}

#[cfg(feature = "postgres")]
async fn verify_request_event(
    tx: &mut Transaction<'_, Postgres>,
    r: &DeploymentRequestRecord,
) -> Result<(), ControlPlaneError> {
    let expected = ContentDigest::sha256(serde_json::to_vec(r)?);
    let row=sqlx::query("SELECT status,state_digest,actor_id,audit_correlation_id,occurred_unix_ms FROM deployment_request_events WHERE tenant_id=$1 AND deployment_request_id=$2 AND version=$3").bind(&r.tenant_id).bind(&r.id).bind(i64v(r.version,"deployment request version")?).fetch_optional(&mut **tx).await?;
    let Some(row) = row else {
        return Err(ControlPlaneError::CorruptState(
            "deployment request event is missing".into(),
        ));
    };
    if row.try_get::<String, _>("status")? != r.status.as_str()
        || row.try_get::<String, _>("state_digest")? != expected.as_str()
        || row.try_get::<String, _>("actor_id")? != r.actor_id
        || row.try_get::<String, _>("audit_correlation_id")? != r.audit_correlation_id
        || row.try_get::<i64, _>("occurred_unix_ms")?
            != i64v(r.updated_unix_ms, "deployment request event time")?
    {
        return Err(ControlPlaneError::CorruptState(
            "deployment request event binding changed".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn provider_tx(
    tx: &mut Transaction<'_, Postgres>,
    t: &str,
    id: &str,
    lock: bool,
) -> Result<Option<TenantProviderConfiguration>, ControlPlaneError> {
    let q = format!(
        "SELECT * FROM tenant_provider_configurations WHERE tenant_id=$1 AND id=$2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    sqlx::query(&q)
        .bind(t)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(|r| {
            Ok(TenantProviderConfiguration {
                id: r.try_get("id")?,
                tenant_id: r.try_get("tenant_id")?,
                capability: r.try_get("capability")?,
                provider_kind: r.try_get("provider_kind")?,
                endpoint_origin: r.try_get("endpoint_origin")?,
                credential_reference: r.try_get("credential_reference")?,
                trust_bundle_digest: digest(r.try_get("trust_bundle_digest")?)?,
                public_key_digest: r
                    .try_get::<Option<String>, _>("public_key_digest")?
                    .map(digest)
                    .transpose()?,
                configuration_digest: digest(r.try_get("configuration_digest")?)?,
                status: r.try_get("status")?,
                created_unix_ms: u64v(r.try_get("created_unix_ms")?, "provider creation")?,
                updated_unix_ms: u64v(r.try_get("updated_unix_ms")?, "provider update")?,
                version: u64v(r.try_get("version")?, "provider version")?,
            })
        })
        .transpose()
}
#[cfg(feature = "postgres")]
async fn signer_tx(
    tx: &mut Transaction<'_, Postgres>,
    t: &str,
    id: &str,
    lock: bool,
) -> Result<Option<SignerPolicyRecord>, ControlPlaneError> {
    let q = format!(
        "SELECT * FROM signer_policies WHERE tenant_id=$1 AND id=$2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    sqlx::query(&q)
        .bind(t)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(|r| {
            Ok(SignerPolicyRecord {
                id: r.try_get("id")?,
                tenant_id: r.try_get("tenant_id")?,
                provider_configuration_id: r.try_get("provider_configuration_id")?,
                provider_configuration_digest: digest(r.try_get("provider_configuration_digest")?)?,
                provider_configuration_version: u64v(
                    r.try_get("provider_configuration_version")?,
                    "provider version",
                )?,
                backend_key_reference: r.try_get("backend_key_reference")?,
                purpose: r.try_get("purpose")?,
                operation: r.try_get("operation")?,
                public_key_digest: digest(r.try_get("public_key_digest")?)?,
                policy_digest: digest(r.try_get("policy_digest")?)?,
                status: r.try_get("status")?,
                created_unix_ms: u64v(r.try_get("created_unix_ms")?, "signer creation")?,
                updated_unix_ms: u64v(r.try_get("updated_unix_ms")?, "signer update")?,
                version: u64v(r.try_get("version")?, "signer version")?,
            })
        })
        .transpose()
}
#[cfg(feature = "postgres")]
async fn environment_tx(
    tx: &mut Transaction<'_, Postgres>,
    t: &str,
    id: &str,
    lock: bool,
) -> Result<Option<EnvironmentRecord>, ControlPlaneError> {
    let q = format!(
        "SELECT * FROM environments WHERE tenant_id=$1 AND id=$2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    sqlx::query(&q)
        .bind(t)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(|r| {
            Ok(EnvironmentRecord {
                id: r.try_get("id")?,
                tenant_id: r.try_get("tenant_id")?,
                repository_id: r.try_get("repository_id")?,
                name: r.try_get("name")?,
                deployment_target_reference: r.try_get("deployment_target_reference")?,
                deployment_target_digest: digest(r.try_get("deployment_target_digest")?)?,
                status: r.try_get("status")?,
                protection_rules: serde_json::from_slice(
                    &r.try_get::<Vec<u8>, _>("protection_rules_json")?,
                )?,
                protection_rules_digest: digest(r.try_get("protection_rules_digest")?)?,
                wait_timer_ms: u64v(r.try_get("wait_timer_ms")?, "environment wait")?,
                concurrency_limit: u32::try_from(u64v(
                    r.try_get("concurrency_limit")?,
                    "environment concurrency",
                )?)
                .map_err(|_| {
                    ControlPlaneError::CorruptState("environment concurrency exceeds u32".into())
                })?,
                secret_provider_configuration_id: r.try_get("secret_provider_configuration_id")?,
                signing_provider_configuration_id: r
                    .try_get("signing_provider_configuration_id")?,
                required_policy_epoch: u64v(r.try_get("required_policy_epoch")?, "policy epoch")?,
                last_concurrency_fence: u64v(
                    r.try_get("last_concurrency_fence")?,
                    "environment concurrency fence",
                )?,
                created_unix_ms: u64v(r.try_get("created_unix_ms")?, "environment creation")?,
                updated_unix_ms: u64v(r.try_get("updated_unix_ms")?, "environment update")?,
                version: u64v(r.try_get("version")?, "environment version")?,
            })
        })
        .transpose()
}
#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
async fn insert_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    id_col: &str,
    t: &str,
    id: &str,
    v: u64,
    created: u64,
    s: (Vec<u8>, ContentDigest),
) -> Result<(), ControlPlaneError> {
    let q=format!("INSERT INTO {table}(tenant_id,{id_col},version,snapshot_digest,snapshot_json,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6)");
    sqlx::query(&q)
        .bind(t)
        .bind(id)
        .bind(i64v(v, "snapshot version")?)
        .bind(s.1.as_str())
        .bind(s.0)
        .bind(i64v(created, "snapshot creation")?)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
#[cfg(feature = "postgres")]
async fn require_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    id_col: &str,
    t: &str,
    id: &str,
    v: u64,
    s: (Vec<u8>, ContentDigest),
) -> Result<(), ControlPlaneError> {
    let q=format!("SELECT snapshot_digest,snapshot_json FROM {table} WHERE tenant_id=$1 AND {id_col}=$2 AND version=$3");
    let row = sqlx::query(&q)
        .bind(t)
        .bind(id)
        .bind(i64v(v, "snapshot version")?)
        .fetch_optional(&mut **tx)
        .await?;
    if row.map(|r| (r.get::<String, _>(0), r.get::<Vec<u8>, _>(1))) != Some((s.1.to_string(), s.0))
    {
        return Err(ControlPlaneError::CorruptState(format!(
            "{table} snapshot is missing or changed"
        )));
    }
    Ok(())
}
#[cfg(feature = "postgres")]
fn digest(v: String) -> Result<ContentDigest, ControlPlaneError> {
    ContentDigest::parse(v).map_err(|e| ControlPlaneError::CorruptState(e.to_string()))
}
#[cfg(feature = "postgres")]
fn i64v(v: u64, field: &'static str) -> Result<i64, ControlPlaneError> {
    i64::try_from(v).map_err(|_| ControlPlaneError::IntegerRange { field })
}
#[cfg(feature = "postgres")]
fn u64v(v: i64, field: &'static str) -> Result<u64, ControlPlaneError> {
    u64::try_from(v).map_err(|_| ControlPlaneError::CorruptState(format!("negative {field}")))
}
#[cfg(feature = "postgres")]
fn not_found(kind: &'static str, id: &str) -> ControlPlaneError {
    ControlPlaneError::NotFound {
        kind,
        id: id.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlPlaneError;
    #[cfg(feature = "postgres")]
    #[cfg(feature = "postgres")]
    use crate::{DeploymentRequestStatus, EnvironmentProtectionRules};
    use crate::{TenantIdentityRecord, TenantIdentityStore};
    #[cfg(feature = "postgres")]
    use runtrue_workflow_ir::{
        ApprovalRequirements, Architecture, CapsuleContext, Isolation, OperatingSystem,
        ParityGrade, PermissionSet, PlannedJob, PlannedStep, RunnerRequirements, SigningCapability,
        SigningOperation, StepAction, StepCapabilitySet, Trust, WorkflowIdentity,
        CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
    };
    #[cfg(feature = "postgres")]
    use std::collections::BTreeMap;

    fn tenant() -> TenantIdentityRecord {
        TenantIdentityRecord {
            id: "deployment-tenant".into(),
            slug: "deployment-tenant".into(),
            name: "Deployment tenant".into(),
            status: "active".into(),
            settings: serde_json::json!({}),
            created_unix_ms: 1,
            updated_unix_ms: 1,
            version: 1,
        }
    }
    fn provider() -> TenantProviderConfiguration {
        let mut r = TenantProviderConfiguration {
            id: "signing-provider".into(),
            tenant_id: "deployment-tenant".into(),
            capability: "signing".into(),
            provider_kind: "remote-signer".into(),
            endpoint_origin: "https://signer.example.test".into(),
            credential_reference: "signer-identity://deployment".into(),
            trust_bundle_digest: ContentDigest::sha256(b"trust"),
            public_key_digest: Some(ContentDigest::sha256(b"public")),
            configuration_digest: ContentDigest::sha256([]),
            status: "active".into(),
            created_unix_ms: 10,
            updated_unix_ms: 10,
            version: 1,
        };
        r.configuration_digest = r.expected_configuration_digest().unwrap();
        r
    }
    async fn contract(store: &(impl DeploymentProviderStore + TenantIdentityStore)) {
        let _ = store.put_tenant_identity(&tenant(), None).await;
        let p = provider();
        assert!(store.put_provider(&p, None).await.unwrap());
        assert!(!store.put_provider(&p, None).await.unwrap());
        assert_eq!(store.provider(&p.tenant_id, &p.id).await.unwrap(), p);
        let mut changed = p.clone();
        changed.endpoint_origin = "https://attacker.example.test".into();
        changed.version = 2;
        changed.updated_unix_ms = 11;
        changed.configuration_digest = changed.expected_configuration_digest().unwrap();
        assert!(matches!(
            store.put_provider(&changed, Some(1)).await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));
        let mut s = SignerPolicyRecord {
            id: "release-policy".into(),
            tenant_id: p.tenant_id.clone(),
            provider_configuration_id: p.id.clone(),
            provider_configuration_digest: p.configuration_digest.clone(),
            provider_configuration_version: 1,
            backend_key_reference: "signer-key://release".into(),
            purpose: "release-artifact".into(),
            operation: "sign-digest".into(),
            public_key_digest: p.public_key_digest.clone().unwrap(),
            policy_digest: ContentDigest::sha256([]),
            status: "active".into(),
            created_unix_ms: 12,
            updated_unix_ms: 12,
            version: 1,
        };
        s.policy_digest = s.expected_policy_digest().unwrap();
        assert!(store.put_signer(&s, None).await.unwrap());
        assert!(!store.put_signer(&s, None).await.unwrap());
        assert_eq!(store.signer(&s.tenant_id, &s.id).await.unwrap(), s);
    }
    #[cfg(feature = "postgres")]
    fn environment() -> EnvironmentRecord {
        let mut r = EnvironmentRecord {
            id: "production".into(),
            tenant_id: "deployment-tenant".into(),
            repository_id: "deployment-repo".into(),
            name: "production".into(),
            deployment_target_reference: "deployment-target://production".into(),
            deployment_target_digest: ContentDigest::sha256([]),
            status: "active".into(),
            protection_rules: EnvironmentProtectionRules {
                require_approval: false,
                minimum_approvals: 0,
                approval_ttl_ms: 0,
                approval_rule_digest: None,
                require_signed_artifact: false,
                required_artifact_classification: "release".into(),
                require_passed_scan: false,
                require_promotion_evidence: false,
                allowed_deployment_actors: vec![],
                allowed_signing_purposes: vec![],
                allowed_signer_policy_ids: vec![],
            },
            protection_rules_digest: ContentDigest::sha256([]),
            wait_timer_ms: 0,
            concurrency_limit: 1,
            secret_provider_configuration_id: None,
            signing_provider_configuration_id: None,
            required_policy_epoch: 1,
            last_concurrency_fence: 0,
            created_unix_ms: 30,
            updated_unix_ms: 30,
            version: 1,
        };
        r.deployment_target_digest = r.expected_deployment_target_digest();
        r.protection_rules_digest = r.expected_protection_rules_digest().unwrap();
        r
    }
    #[cfg(feature = "postgres")]
    fn request_fixture() -> DeploymentRequestRecord {
        let mut r = DeploymentRequestRecord {
            id: "request".into(),
            tenant_id: "deployment-tenant".into(),
            environment_id: "production".into(),
            environment_version: 1,
            policy_epoch: 1,
            repository_id: "deployment-repo".into(),
            run_id: "run".into(),
            job_id: "job".into(),
            job_attempt: 1,
            artifact_id: "artifact".into(),
            promoted_artifact_id: None,
            artifact_source_run_id: "source-run".into(),
            artifact_source_job_id: "source-job".into(),
            artifact_source_job_attempt: 1,
            artifact_digest: ContentDigest::sha256(b"artifact"),
            manifest_digest: ContentDigest::sha256(b"manifest"),
            provenance_digest: ContentDigest::sha256(b"provenance"),
            target_digest: environment().deployment_target_digest,
            deployment_capsule_digest: ContentDigest::sha256(b"capsule"),
            request_digest: ContentDigest::sha256([]),
            approval_subject_digest: ContentDigest::sha256([]),
            approval_request_id: None,
            rollback_of_deployment_id: None,
            status: DeploymentRequestStatus::AwaitingConcurrency,
            wait_until_unix_ms: 40,
            concurrency_fence: None,
            execution_lease_id: None,
            lease_fencing_generation: None,
            installation_fencing_epoch: None,
            actor_id: "deployer".into(),
            audit_correlation_id: "reserve".into(),
            created_unix_ms: 40,
            updated_unix_ms: 40,
            completed_unix_ms: None,
            version: 1,
        };
        r.request_digest = r.expected_request_digest().unwrap();
        r.approval_subject_digest = r.expected_approval_subject_digest().unwrap();
        r
    }
    #[cfg(feature = "postgres")]
    fn deployment_capsule() -> ExecutionCapsule {
        let deploy_job = PlannedJob {
            id: "deploy".to_owned(),
            base_id: "deploy".to_owned(),
            name: "deploy".to_owned(),
            needs: Vec::new(),
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::UntrustedOk,
            environment: Some("production".to_owned()),
            runner: RunnerRequirements {
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Microvm,
                image: None,
                cpu: 1,
                memory_bytes: 1_024,
                storage_bytes: Some(1_024),
                region: Some("test".to_owned()),
                capabilities: vec!["kvm".to_owned()],
            },
            permissions: PermissionSet::default(),
            timeout_ms: 60_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: Vec::new(),
            finalizers: Vec::new(),
            finalizer_timeout_ms: 120_000,
            value_outputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
        };
        let mut signing_job = deploy_job.clone();
        signing_job.id = "sign-deploy".to_owned();
        signing_job.base_id = "sign-deploy".to_owned();
        signing_job.name = "sign deploy".to_owned();
        signing_job.environment = Some("signed-production".to_owned());
        signing_job.steps = vec![PlannedStep {
            id: "sign".to_owned(),
            name: "sign".to_owned(),
            condition: None,
            action: StepAction::Component {
                reference: "runtrue/sign@v1".to_owned(),
            },
            inputs: BTreeMap::new(),
            environment: BTreeMap::new(),
            capabilities: StepCapabilitySet {
                signing: vec![SigningCapability {
                    purpose: "release-artifact".to_owned(),
                    operation: SigningOperation::SignDigest,
                    key_policy: "release-policy".to_owned(),
                }],
                ..StepCapabilitySet::default()
            },
            cache: None,
            timeout_ms: None,
            continue_on_error: false,
            outputs: BTreeMap::new(),
            working_directory: None,
        }];
        ExecutionCapsule {
            schema_version: CAPSULE_SCHEMA_VERSION,
            engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
            compiler_version: "deployment-test".to_owned(),
            workflow: WorkflowIdentity {
                name: "deploy".to_owned(),
                digest: ContentDigest::sha256(b"workflow"),
                source_path: ".runtrue/workflows/deploy.yaml".to_owned(),
            },
            context: CapsuleContext {
                source_commit: "0123456789abcdef".to_owned(),
                source_tree_digest: None,
                base_commit: None,
                source_trust: Default::default(),
                normalized_event_digest: ContentDigest::sha256(b"event"),
                normalized_event_json: None,
                scm: None,
                event_context: BTreeMap::new(),
                lockfile_digest: None,
                workflow_frontend: None,
                policy_version_ids: Vec::new(),
            },
            variables: BTreeMap::new(),
            permissions: PermissionSet::default(),
            jobs: vec![deploy_job, signing_job],
            dynamic_jobs: Vec::new(),
            approval: ApprovalRequirements {
                workflow_definition: false,
                privileged_execution: false,
                reasons: Vec::new(),
            },
            expected_parity: ParityGrade::AExact,
        }
    }
    #[tokio::test]
    async fn sqlite_provider_signer_contract() {
        let s = ControlPlane::open_in_memory("deployment-provider", 1).unwrap();
        contract(&s).await
    }
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_provider_signer_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "provider-signer").await;
        let s = PostgresInstallationStore::connect(fixture.config(), "deployment-provider", 1)
            .await
            .unwrap();
        contract(&s).await;
        s.close().await;
        fixture.cleanup().await;
    }
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_environment_version_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "environment-version").await;
        let s = PostgresInstallationStore::connect(fixture.config(), "deployment-environment", 1)
            .await
            .unwrap();
        s.put_tenant_identity(&tenant(), None).await.unwrap();
        contract(&s).await;
        sqlx::query("INSERT INTO repositories(id,tenant_id,owner,name,default_branch,visibility,created_unix_ms) VALUES('deployment-repo','deployment-tenant','owner','repo','main','private',2)").execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO human_users(id,display_name,primary_email,status,created_unix_ms,updated_unix_ms,version) VALUES('policy-author','Policy Author','policy@example.test','active',3,3,1)").execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO policy_bundle_drafts(id,tenant_id,author_id,policy_digest,draft_json,status,audit_correlation_id,created_unix_ms,updated_unix_ms) VALUES('active-policy','deployment-tenant','policy-author',$1,$2,'activated','policy',4,4)").bind(ContentDigest::sha256(b"policy").as_str()).bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO tenant_policy_states(tenant_id,policy_epoch,decision_cache_generation,active_draft_id,active_policy_digest,state_digest,state_json,version,actor_id,audit_correlation_id,updated_unix_ms) VALUES('deployment-tenant',1,1,'active-policy',$1,$2,$3,1,'policy-author','policy',5)").bind(ContentDigest::sha256(b"policy").as_str()).bind(ContentDigest::sha256(b"state").as_str()).bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        let r = environment();
        assert!(s.put_environment_record(&r, None).await.unwrap());
        assert!(!s.put_environment_record(&r, None).await.unwrap());
        assert_eq!(s.environment_record(&r.tenant_id, &r.id).await.unwrap(), r);
        let mut updated = r.clone();
        updated.concurrency_limit = 2;
        updated.updated_unix_ms = 31;
        updated.version = 2;
        updated.protection_rules_digest = updated.expected_protection_rules_digest().unwrap();
        assert!(s.put_environment_record(&updated, Some(1)).await.unwrap());
        assert_eq!(
            s.environment_record(&updated.tenant_id, &updated.id)
                .await
                .unwrap(),
            updated
        );
        let capsule_digest = ContentDigest::sha256(b"capsule");
        sqlx::query("INSERT INTO capsules VALUES('capsule','deployment-repo',$1,$2,$3,'key',32)")
            .bind(capsule_digest.as_str())
            .bind(b"capsule".as_slice())
            .bind(b"{}".as_slice())
            .execute(s.pool())
            .await
            .unwrap();
        for run in ["run", "source-run"] {
            sqlx::query("INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms) VALUES($1,'deployment-repo','capsule','queued',0,false,33)").bind(run).execute(s.pool()).await.unwrap();
        }
        sqlx::query("INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms) VALUES('job','run','deploy',1,'queued',$1,34),('source-job','source-run','source',1,'succeeded',$1,34)").bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO runner_pools(id,tenant_id,name,status,created_unix_ms) VALUES('environment-pool','deployment-tenant','environment-pool','active',34)").execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms) VALUES('environment-runner','environment-pool','online',$1,34,34)").bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES('environment-source-lease','source-job','deployment-tenant','environment-runner',1,1,$1,'active',34,35,200,200)").bind(capsule_digest.as_str()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO runner_data_commits(kind,object_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,output_name,lease_id,fencing_generation,ticket_id,committed_unix_ms) VALUES('artifact','artifact','deployment-tenant','deployment-repo','source-run','source-job',1,'build','bundle','environment-source-lease',1,'environment-ticket',35)").execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO job_result_objects(job_id,job_attempt,kind,object_id,ordinal) VALUES('source-job',1,'artifact','artifact',0)").execute(s.pool()).await.unwrap();
        let mut request = request_fixture();
        request.environment_version = 2;
        request.status = DeploymentRequestStatus::Ready;
        request.concurrency_fence = Some(1);
        request.installation_fencing_epoch = Some(1);
        request.request_digest = request.expected_request_digest().unwrap();
        request.approval_subject_digest = request.expected_approval_subject_digest().unwrap();
        sqlx::query("INSERT INTO artifacts_catalog(artifact_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,output_name,content_digest,manifest_digest,provenance_digest,size_bytes,media_type,classification,scan_state,retention_until_unix_seconds,legal_hold,state,created_unix_ms) VALUES('artifact','deployment-tenant','deployment-repo','source-run','source-job',1,'build','bundle',$1,$2,$3,128,'application/octet-stream','release','passed',3600,false,'available',35)")
            .bind(request.artifact_digest.as_str()).bind(request.manifest_digest.as_str()).bind(request.provenance_digest.as_str()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO deployment_requests SELECT (json_populate_record(NULL::deployment_requests,$1::json)).*").bind(serde_json::to_string(&request).unwrap()).execute(s.pool()).await.unwrap();
        let event_digest = ContentDigest::sha256(serde_json::to_vec(&request).unwrap());
        sqlx::query("INSERT INTO deployment_request_events VALUES($1,$2,1,'ready',$3,$4,$5,$6)")
            .bind(&request.id)
            .bind(&request.tenant_id)
            .bind(event_digest.as_str())
            .bind(&request.actor_id)
            .bind(&request.audit_correlation_id)
            .bind(i64v(request.updated_unix_ms, "event").unwrap())
            .execute(s.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO environment_concurrency_leases(id,tenant_id,environment_id,deployment_request_id,concurrency_fence,installation_fencing_epoch,state,acquired_unix_ms,expires_unix_ms) VALUES('gate','deployment-tenant','production','request',1,1,'active',40,100)").execute(s.pool()).await.unwrap();
        let replay = s
            .acquire_gate(&AcquireEnvironmentGate {
                tenant_id: "deployment-tenant".into(),
                deployment_request_id: "request".into(),
                installation_fencing_epoch: 1,
                gate_lease_id: "gate".into(),
                gate_expires_unix_ms: 100,
                actor_id: "actor".into(),
                audit_correlation_id: "gate".into(),
                now_unix_ms: 50,
            })
            .await
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.value.concurrency_fence, 1);
        assert_eq!(
            s.request("deployment-tenant", "request").await.unwrap(),
            request
        );
        sqlx::query("INSERT INTO runner_pools(id,tenant_id,name,status,created_unix_ms) VALUES('signing-pool','deployment-tenant','signing','active',35)").execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms) VALUES('signing-runner','signing-pool','online',$1,36,36)").bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES('signing-lease','job','deployment-tenant','signing-runner',1,1,$1,'active',40,45,100,100)").bind(ContentDigest::sha256(b"capsule").as_str()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO approval_requests(id,repository_id,capsule_id,subject_digest,status,request_json,created_unix_ms,expires_unix_ms) VALUES('signing-approval','deployment-repo','capsule',$1,'approved',$2,35,100)").bind(ContentDigest::sha256(b"approval").as_str()).bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        let p = provider();
        let mut reservation = SigningResultReservation {
            request_id: "signing-request".into(),
            tenant_id: request.tenant_id.clone(),
            provider_configuration_id: p.id,
            provider_configuration_digest: p.configuration_digest,
            provider_configuration_version: 1,
            environment_id: request.environment_id.clone(),
            deployment_request_id: request.id.clone(),
            repository_id: request.repository_id.clone(),
            run_id: request.run_id.clone(),
            job_id: request.job_id.clone(),
            job_attempt: request.job_attempt,
            step_id: "sign".into(),
            execution_lease_id: "signing-lease".into(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            policy_epoch: request.policy_epoch,
            environment_version: request.environment_version,
            approval_request_id: "signing-approval".into(),
            approval_subject_digest: ContentDigest::sha256(b"approval"),
            artifact_digest: request.artifact_digest.clone(),
            provenance_digest: request.provenance_digest.clone(),
            purpose: "release-artifact".into(),
            operation: "sign-digest".into(),
            signer_policy_id: "release-policy".into(),
            signer_policy_digest: s
                .signer("deployment-tenant", "release-policy")
                .await
                .unwrap()
                .policy_digest,
            signer_policy_version: 1,
            request_digest: ContentDigest::sha256([]),
            requested_unix_ms: 50,
            expires_unix_ms: 90,
        };
        reservation.request_digest = reservation.expected_request_digest().unwrap();
        let reservation_bytes = serde_json::to_vec(&reservation).unwrap();
        let mut journal_json = serde_json::to_value(&reservation).unwrap();
        let journal = journal_json.as_object_mut().unwrap();
        journal.insert(
            "reservation_json".into(),
            serde_json::Value::String(format!(
                "\\x{}",
                reservation_bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )),
        );
        journal.insert("state".into(), serde_json::json!("reserved"));
        journal.insert("result_json".into(), serde_json::Value::Null);
        journal.insert("result_digest".into(), serde_json::Value::Null);
        journal.insert("retry_attempts".into(), serde_json::json!(0));
        journal.insert("updated_unix_ms".into(), serde_json::json!(50));
        journal.insert("completed_unix_ms".into(), serde_json::Value::Null);
        sqlx::query("INSERT INTO signing_result_journal SELECT (json_populate_record(NULL::signing_result_journal,$1::json)).*")
            .bind(serde_json::to_string(&journal_json).unwrap())
            .execute(s.pool()).await.unwrap();
        assert!(s.reserve_signing(&reservation).await.unwrap().replayed);
        let mut signed = PublicSigningResult {
            signer_key_id: "release-key".into(),
            algorithm: "ed25519".into(),
            signature: b"signature".to_vec(),
            certificate: None,
            attestation: None,
            signed_unix_ms: 60,
            result_digest: ContentDigest::sha256([]),
        };
        signed.result_digest = signed.expected_result_digest().unwrap();
        assert!(
            !s.record_signed(&reservation, &signed)
                .await
                .unwrap()
                .replayed
        );
        assert!(
            s.record_signed(&reservation, &signed)
                .await
                .unwrap()
                .replayed
        );
        assert!(
            !s.complete_signing(
                "deployment-tenant",
                "signing-request",
                &reservation.request_digest,
                70
            )
            .await
            .unwrap()
            .replayed
        );
        assert!(
            s.complete_signing(
                "deployment-tenant",
                "signing-request",
                &reservation.request_digest,
                70
            )
            .await
            .unwrap()
            .replayed
        );
        assert!(matches!(
            s.signing("deployment-tenant", "signing-request")
                .await
                .unwrap()
                .state,
            SigningResultState::Complete(_)
        ));
        assert!(sqlx::query("UPDATE signing_result_journal SET artifact_digest='tampered' WHERE request_id='signing-request'").execute(s.pool()).await.is_err());
        assert!(sqlx::query(
            "DELETE FROM signing_result_journal WHERE request_id='signing-request'"
        )
        .execute(s.pool())
        .await
        .is_err());

        let mut deployment = DeploymentRecord {
            id: "deployment".into(),
            tenant_id: request.tenant_id.clone(),
            environment_id: request.environment_id.clone(),
            deployment_request_id: request.id.clone(),
            rollback_of_deployment_id: None,
            artifact_id: request.artifact_id.clone(),
            promoted_artifact_id: None,
            artifact_digest: request.artifact_digest.clone(),
            manifest_digest: request.manifest_digest.clone(),
            provenance_digest: request.provenance_digest.clone(),
            target_digest: request.target_digest.clone(),
            deployment_capsule_digest: request.deployment_capsule_digest.clone(),
            signing_request_id: None,
            signing_result_digest: None,
            signer_key_id: None,
            signing_algorithm: None,
            signature_digest: None,
            certificate_digest: None,
            attestation_digest: None,
            external_reference: Some("deployment-reference".into()),
            status: "succeeded".into(),
            result_digest: ContentDigest::sha256([]),
            metadata: serde_json::json!({"region":"test"}),
            metadata_digest: ContentDigest::sha256([]),
            started_unix_ms: 60,
            completed_unix_ms: Some(70),
        };
        deployment.metadata_digest = deployment.expected_metadata_digest().unwrap();
        deployment.result_digest = deployment.expected_result_digest().unwrap();
        let metadata_bytes = serde_json::to_vec(&deployment.metadata).unwrap();
        let mut deployment_json = serde_json::to_value(&deployment).unwrap();
        let deployment_object = deployment_json.as_object_mut().unwrap();
        deployment_object.remove("metadata");
        deployment_object.insert(
            "metadata_json".into(),
            serde_json::Value::String(format!(
                "\\x{}",
                metadata_bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )),
        );
        sqlx::query(
            "INSERT INTO deployments SELECT (json_populate_record(NULL::deployments,$1::json)).*",
        )
        .bind(serde_json::to_string(&deployment_json).unwrap())
        .execute(s.pool())
        .await
        .unwrap();
        assert_eq!(
            s.result("deployment-tenant", "deployment").await.unwrap(),
            deployment
        );
        let deployment_audit = R9AuditMetadata {
            actor_id: "deployer".into(),
            correlation_id: "result".into(),
            occurred_unix_ms: 70,
        };
        assert!(
            s.record_result(&deployment, &deployment_audit)
                .await
                .unwrap()
                .replayed
        );
        let mut conflicting = deployment.clone();
        conflicting.external_reference = Some("other-reference".into());
        conflicting.result_digest = conflicting.expected_result_digest().unwrap();
        assert!(matches!(
            s.record_result(&conflicting, &deployment_audit).await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));
        assert!(sqlx::query(
            "UPDATE deployments SET metadata_digest='tampered' WHERE id='deployment'"
        )
        .execute(s.pool())
        .await
        .is_err());
        assert!(sqlx::query("DELETE FROM deployments WHERE id='deployment'")
            .execute(s.pool())
            .await
            .is_err());
        assert!(
            sqlx::query("UPDATE environment_versions SET snapshot_digest='bad'")
                .execute(s.pool())
                .await
                .is_err()
        );
        s.close().await;
        fixture.cleanup().await;
    }
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_artifact_deployment_mutation_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "deployment-mutation").await;
        let s = PostgresInstallationStore::connect(fixture.config(), "deployment-request", 1)
            .await
            .unwrap();
        s.put_tenant_identity(&tenant(), None).await.unwrap();
        contract(&s).await;
        sqlx::query("INSERT INTO repositories(id,tenant_id,owner,name,default_branch,visibility,created_unix_ms) VALUES('deployment-repo','deployment-tenant','owner','repo','main','private',2)").execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO human_users(id,display_name,primary_email,status,created_unix_ms,updated_unix_ms,version) VALUES('policy-author','Policy Author','policy@example.test','active',3,3,1)").execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO policy_bundle_drafts(id,tenant_id,author_id,policy_digest,draft_json,status,audit_correlation_id,created_unix_ms,updated_unix_ms) VALUES('active-policy','deployment-tenant','policy-author',$1,$2,'activated','policy',4,4)").bind(ContentDigest::sha256(b"policy").as_str()).bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO tenant_policy_states(tenant_id,policy_epoch,decision_cache_generation,active_draft_id,active_policy_digest,state_digest,state_json,version,actor_id,audit_correlation_id,updated_unix_ms) VALUES('deployment-tenant',1,1,'active-policy',$1,$2,$3,1,'policy-author','policy',5)").bind(ContentDigest::sha256(b"policy").as_str()).bind(ContentDigest::sha256(b"state").as_str()).bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        let deployment_environment = environment();
        assert!(s
            .put_environment_record(&deployment_environment, None)
            .await
            .unwrap());
        let capsule = deployment_capsule();
        let canonical = capsule.canonical_bytes().unwrap();
        let capsule_digest = capsule.digest().unwrap();
        sqlx::query("INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES('deployment-capsule','deployment-repo',$1,$2,$3,'key',30)")
            .bind(capsule_digest.as_str()).bind(&canonical).bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        for run in ["run", "source-run"] {
            sqlx::query("INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms) VALUES($1,'deployment-repo','deployment-capsule','queued',0,false,31)")
                .bind(run).execute(s.pool()).await.unwrap();
        }
        sqlx::query("INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms) VALUES('job','run','deploy',1,'queued',$1,32),('sign-job','run','sign-deploy',1,'queued',$1,32),('source-job','source-run','source',1,'succeeded',$1,32)")
            .bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO runner_pools(id,tenant_id,name,status,created_unix_ms) VALUES('pool','deployment-tenant','pool','active',33)").execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms) VALUES('runner','pool','online',$1,33,33)").bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES('source-lease','source-job','deployment-tenant','runner',1,1,$1,'active',33,34,200,200)")
            .bind(capsule_digest.as_str()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO runner_data_commits(kind,object_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,output_name,lease_id,fencing_generation,ticket_id,committed_unix_ms) VALUES('artifact','artifact','deployment-tenant','deployment-repo','source-run','source-job',1,'build','bundle','source-lease',1,'ticket',34)").execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO job_result_objects(job_id,job_attempt,kind,object_id,ordinal) VALUES('source-job',1,'artifact','artifact',0)").execute(s.pool()).await.unwrap();
        let mut request = request_fixture();
        request.deployment_capsule_digest = capsule_digest.clone();
        request.request_digest = request.expected_request_digest().unwrap();
        request.approval_subject_digest = request.expected_approval_subject_digest().unwrap();
        sqlx::query("INSERT INTO artifacts_catalog(artifact_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,output_name,content_digest,manifest_digest,provenance_digest,size_bytes,media_type,classification,scan_state,retention_until_unix_seconds,legal_hold,state,created_unix_ms) VALUES('artifact','deployment-tenant','deployment-repo','source-run','source-job',1,'build','bundle',$1,$2,$3,128,'application/octet-stream','release','passed',3600,false,'available',35)")
            .bind(request.artifact_digest.as_str()).bind(request.manifest_digest.as_str()).bind(request.provenance_digest.as_str()).execute(s.pool()).await.unwrap();

        let reserved = s.reserve_request(&request).await.unwrap();
        assert!(!reserved.replayed);
        assert!(s.reserve_request(&request).await.unwrap().replayed);
        let gate_request = AcquireEnvironmentGate {
            tenant_id: request.tenant_id.clone(),
            deployment_request_id: request.id.clone(),
            installation_fencing_epoch: 1,
            gate_lease_id: "gate".into(),
            gate_expires_unix_ms: 150,
            actor_id: "deployer".into(),
            audit_correlation_id: "gate".into(),
            now_unix_ms: 50,
        };
        let gate = s.acquire_gate(&gate_request).await.unwrap();
        assert!(!gate.replayed);
        assert!(s.acquire_gate(&gate_request).await.unwrap().replayed);
        sqlx::query("INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES('lease','job','deployment-tenant','runner',1,1,$1,'active',51,52,140,140)")
            .bind(capsule_digest.as_str()).execute(s.pool()).await.unwrap();
        sqlx::query("UPDATE environment_concurrency_leases SET execution_lease_id='lease',lease_fencing_generation=1 WHERE id='gate'").execute(s.pool()).await.unwrap();
        let mut leased = s.request(&request.tenant_id, &request.id).await.unwrap();
        leased.status = DeploymentRequestStatus::Leased;
        leased.execution_lease_id = Some("lease".into());
        leased.lease_fencing_generation = Some(1);
        leased.updated_unix_ms = 52;
        leased.version += 1;
        sqlx::query("UPDATE deployment_requests SET status='leased',execution_lease_id='lease',lease_fencing_generation=1,updated_unix_ms=52,version=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(&leased.tenant_id).bind(&leased.id).bind(i64v(leased.version,"request version").unwrap()).execute(s.pool()).await.unwrap();
        let event_digest = ContentDigest::sha256(serde_json::to_vec(&leased).unwrap());
        sqlx::query("INSERT INTO deployment_request_events(deployment_request_id,tenant_id,version,status,state_digest,actor_id,audit_correlation_id,occurred_unix_ms) VALUES($1,$2,$3,'leased',$4,$5,$6,52)")
            .bind(&leased.id).bind(&leased.tenant_id).bind(i64v(leased.version,"request version").unwrap()).bind(event_digest.as_str()).bind(&leased.actor_id).bind(&leased.audit_correlation_id).execute(s.pool()).await.unwrap();
        assert!(
            s.bind_gate_lease(&BindDeploymentLease {
                tenant_id: request.tenant_id.clone(),
                deployment_request_id: request.id.clone(),
                execution_lease_id: "lease".into(),
                lease_fencing_generation: 1,
                installation_fencing_epoch: 1,
                now_unix_ms: 53,
            })
            .await
            .unwrap()
            .replayed
        );
        let started = s
            .start_request(
                &request.tenant_id,
                &request.id,
                "lease",
                1,
                1,
                "deployer",
                "start",
                54,
            )
            .await
            .unwrap();
        assert!(!started.replayed);
        assert!(
            s.start_request(
                &request.tenant_id,
                &request.id,
                "lease",
                1,
                1,
                "deployer",
                "start",
                54
            )
            .await
            .unwrap()
            .replayed
        );
        let provider = provider();
        let signer = s
            .signer("deployment-tenant", "release-policy")
            .await
            .unwrap();
        let mut signing_environment = environment();
        signing_environment.id = "signed-production".into();
        signing_environment.name = "signed-production".into();
        signing_environment.deployment_target_reference =
            "deployment-target://signed-production".into();
        signing_environment.deployment_target_digest =
            signing_environment.expected_deployment_target_digest();
        signing_environment.protection_rules.require_signed_artifact = true;
        signing_environment
            .protection_rules
            .allowed_signing_purposes = vec!["release-artifact".into()];
        signing_environment
            .protection_rules
            .allowed_signer_policy_ids = vec!["release-policy".into()];
        signing_environment.protection_rules_digest = signing_environment
            .expected_protection_rules_digest()
            .unwrap();
        signing_environment.signing_provider_configuration_id = Some(provider.id.clone());
        assert!(s
            .put_environment_record(&signing_environment, None)
            .await
            .unwrap());
        let approval_subject = ContentDigest::sha256(b"signing-approval");
        sqlx::query("INSERT INTO approval_requests(id,repository_id,capsule_id,subject_digest,status,request_json,created_unix_ms,expires_unix_ms) VALUES('signing-approval','deployment-repo','deployment-capsule',$1,'approved',$2,40,120)")
            .bind(approval_subject.as_str()).bind(b"{}".as_slice()).execute(s.pool()).await.unwrap();
        sqlx::query("INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES('sign-lease','sign-job','deployment-tenant','runner',1,1,$1,'active',54,55,140,140)")
            .bind(capsule_digest.as_str()).execute(s.pool()).await.unwrap();
        let mut signing_deployment = request_fixture();
        signing_deployment.id = "signing-deployment-request".into();
        signing_deployment.environment_id = signing_environment.id.clone();
        signing_deployment.job_id = "sign-job".into();
        signing_deployment.target_digest = signing_environment.deployment_target_digest.clone();
        signing_deployment.deployment_capsule_digest = capsule_digest.clone();
        signing_deployment.approval_request_id = Some("signing-approval".into());
        signing_deployment.approval_subject_digest = approval_subject.clone();
        signing_deployment.status = DeploymentRequestStatus::InProgress;
        signing_deployment.concurrency_fence = Some(1);
        signing_deployment.execution_lease_id = Some("sign-lease".into());
        signing_deployment.lease_fencing_generation = Some(1);
        signing_deployment.installation_fencing_epoch = Some(1);
        signing_deployment.updated_unix_ms = 55;
        signing_deployment.version = 3;
        signing_deployment.request_digest = signing_deployment.expected_request_digest().unwrap();
        sqlx::query("INSERT INTO deployment_requests SELECT (json_populate_record(NULL::deployment_requests,$1::json)).*")
            .bind(serde_json::to_string(&signing_deployment).unwrap()).execute(s.pool()).await.unwrap();
        let signing_event_digest =
            ContentDigest::sha256(serde_json::to_vec(&signing_deployment).unwrap());
        sqlx::query("INSERT INTO deployment_request_events(deployment_request_id,tenant_id,version,status,state_digest,actor_id,audit_correlation_id,occurred_unix_ms) VALUES($1,$2,$3,'in-progress',$4,$5,$6,$7)")
            .bind(&signing_deployment.id).bind(&signing_deployment.tenant_id)
            .bind(i64v(signing_deployment.version,"request version").unwrap())
            .bind(signing_event_digest.as_str()).bind(&signing_deployment.actor_id)
            .bind(&signing_deployment.audit_correlation_id)
            .bind(i64v(signing_deployment.updated_unix_ms,"request update").unwrap())
            .execute(s.pool()).await.unwrap();
        let mut signing_reservation = SigningResultReservation {
            request_id: "new-signing-request".into(),
            tenant_id: signing_deployment.tenant_id.clone(),
            provider_configuration_id: provider.id,
            provider_configuration_digest: provider.configuration_digest,
            provider_configuration_version: provider.version,
            environment_id: signing_environment.id.clone(),
            deployment_request_id: signing_deployment.id.clone(),
            repository_id: signing_deployment.repository_id.clone(),
            run_id: signing_deployment.run_id.clone(),
            job_id: signing_deployment.job_id.clone(),
            job_attempt: signing_deployment.job_attempt,
            step_id: "sign".into(),
            execution_lease_id: "sign-lease".into(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            policy_epoch: signing_deployment.policy_epoch,
            environment_version: signing_deployment.environment_version,
            approval_request_id: "signing-approval".into(),
            approval_subject_digest: approval_subject,
            artifact_digest: signing_deployment.artifact_digest.clone(),
            provenance_digest: signing_deployment.provenance_digest.clone(),
            purpose: "release-artifact".into(),
            operation: "sign-digest".into(),
            signer_policy_id: signer.id,
            signer_policy_digest: signer.policy_digest,
            signer_policy_version: signer.version,
            request_digest: ContentDigest::sha256([]),
            requested_unix_ms: 56,
            expires_unix_ms: 100,
        };
        signing_reservation.request_digest = signing_reservation.expected_request_digest().unwrap();
        assert!(
            !s.reserve_signing(&signing_reservation)
                .await
                .unwrap()
                .replayed
        );
        assert!(
            s.reserve_signing(&signing_reservation)
                .await
                .unwrap()
                .replayed
        );
        let mut deployment = DeploymentRecord {
            id: "deployment".into(),
            tenant_id: request.tenant_id.clone(),
            environment_id: request.environment_id.clone(),
            deployment_request_id: request.id.clone(),
            rollback_of_deployment_id: None,
            artifact_id: request.artifact_id.clone(),
            promoted_artifact_id: None,
            artifact_digest: request.artifact_digest.clone(),
            manifest_digest: request.manifest_digest.clone(),
            provenance_digest: request.provenance_digest.clone(),
            target_digest: request.target_digest.clone(),
            deployment_capsule_digest: request.deployment_capsule_digest.clone(),
            signing_request_id: None,
            signing_result_digest: None,
            signer_key_id: None,
            signing_algorithm: None,
            signature_digest: None,
            certificate_digest: None,
            attestation_digest: None,
            external_reference: Some("deployment-reference".into()),
            status: "succeeded".into(),
            result_digest: ContentDigest::sha256([]),
            metadata: serde_json::json!({"region":"test"}),
            metadata_digest: ContentDigest::sha256([]),
            started_unix_ms: 54,
            completed_unix_ms: Some(60),
        };
        deployment.metadata_digest = deployment.expected_metadata_digest().unwrap();
        deployment.result_digest = deployment.expected_result_digest().unwrap();
        let audit = R9AuditMetadata {
            actor_id: "deployer".into(),
            correlation_id: "result".into(),
            occurred_unix_ms: 60,
        };
        assert!(!s.record_result(&deployment, &audit).await.unwrap().replayed);
        assert!(s.record_result(&deployment, &audit).await.unwrap().replayed);
        assert_eq!(
            s.result(&request.tenant_id, &deployment.id).await.unwrap(),
            deployment
        );
        assert_eq!(
            s.request(&request.tenant_id, &request.id)
                .await
                .unwrap()
                .status,
            DeploymentRequestStatus::Succeeded
        );
        s.close().await;
        fixture.cleanup().await;
    }
}
