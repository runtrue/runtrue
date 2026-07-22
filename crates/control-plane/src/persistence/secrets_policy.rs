//! Backend contracts for provider-neutral configuration, secret metadata and
//! encrypted vault snapshots, and versioned variables. Policy, workload OIDC,
//! and external-secret release authority intentionally remain outside this
//! boundary.

use super::StoreFuture;
use crate::{
    ConfigurationProjectRecord, ControlPlane, IdempotentResult, PolicyVersionRecord,
    PutConfigurationProject, R9AuditMetadata, SecretMetadataReference, SecretResolutionRecord,
    VariableRecord, VariableSnapshot,
};
use runtrue_oidc::OidcGrant;
use runtrue_policy::{
    ActivatePolicyBundle, ActivePolicyBundleState, PolicyBundleDraft, PolicyShadowReport,
    PolicySimulationReport,
};
use runtrue_secrets::{MasterKey, SecretPlaintext};
use serde_json::Value;
use std::collections::BTreeMap;

#[cfg(feature = "postgres")]
use super::PostgresInstallationStore;
#[cfg(feature = "postgres")]
use crate::{
    ConfigurationProjectTarget, ConfigurationProjectTargetKind, ControlPlaneError,
    SecretResolutionCandidate, SecretScope, SecretScopeKind,
};
#[cfg(feature = "postgres")]
use runtrue_model::ContentDigest;
#[cfg(feature = "postgres")]
use runtrue_policy::{DenyFirstPolicy, PolicyBundleDraftStatus};
#[cfg(feature = "postgres")]
use runtrue_secrets::{SecretIdentity, SecretStatus, SecretVault, SecretVaultSnapshot};
#[cfg(feature = "postgres")]
use serde::Serialize;
#[cfg(feature = "postgres")]
use sqlx::{postgres::PgRow, Postgres, Row as _, Transaction};

#[cfg(feature = "postgres")]
pub(super) const POSTGRES_MIGRATION: &str =
    include_str!("../../migrations/postgres/0008_secrets_variables_policy.sql");

pub trait ConfigurationProjectStore: Send + Sync {
    fn put_project<'a>(
        &'a self,
        input: &'a PutConfigurationProject,
    ) -> StoreFuture<'a, ConfigurationProjectRecord>;
    fn project<'a>(
        &'a self,
        tenant_id: &'a str,
        project_id: &'a str,
    ) -> StoreFuture<'a, ConfigurationProjectRecord>;
    fn projects<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<ConfigurationProjectRecord>>;
}

pub trait SecretConfigurationStore: Send + Sync {
    fn create_secret<'a>(
        &'a self,
        idempotency_key: &'a str,
        metadata: &'a SecretMetadataReference,
        plaintext: Option<&'a SecretPlaintext>,
        master_key: &'a MasterKey,
    ) -> StoreFuture<'a, IdempotentResult<SecretMetadataReference>>;
    #[allow(clippy::too_many_arguments)]
    fn rotate_secret<'a>(
        &'a self,
        idempotency_key: &'a str,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
        plaintext: &'a SecretPlaintext,
        master_key: &'a MasterKey,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, IdempotentResult<SecretMetadataReference>>;
    fn delete_secret_configuration<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
        master_key: &'a MasterKey,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, SecretMetadataReference>;
    fn secret_by_id<'a>(&'a self, id: &'a str) -> StoreFuture<'a, SecretMetadataReference>;
    fn secret_by_name<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, SecretMetadataReference>;
    fn secrets<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> StoreFuture<'a, Vec<SecretMetadataReference>>;
    fn resolve_secret<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        scm_account_id: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, SecretResolutionRecord>;
    fn validate_resolution<'a>(
        &'a self,
        expected: &'a SecretResolutionRecord,
    ) -> StoreFuture<'a, ()>;
}

pub trait VariableConfigurationStore: Send + Sync {
    fn put_variable<'a>(
        &'a self,
        idempotency_key: &'a str,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
        value: Value,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, IdempotentResult<VariableRecord>>;
    fn variable_record<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, VariableRecord>;
    fn variable_records<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> StoreFuture<'a, Vec<VariableRecord>>;
    fn delete_variable_record<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, ()>;
    #[allow(clippy::too_many_arguments)]
    fn create_snapshot<'a>(
        &'a self,
        id: &'a str,
        tenant_id: &'a str,
        scope: &'a str,
        version: u64,
        values: BTreeMap<String, Value>,
        created_unix_ms: u64,
    ) -> StoreFuture<'a, VariableSnapshot>;
    fn latest_snapshot<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> StoreFuture<'a, VariableSnapshot>;
}

pub trait PolicyVersionStore: Send + Sync {
    fn create_policy_version<'a>(
        &'a self,
        idempotency_key: &'a str,
        record: &'a PolicyVersionRecord,
    ) -> StoreFuture<'a, IdempotentResult<PolicyVersionRecord>>;
    fn next_policy_version_number<'a>(&'a self, policy_id: &'a str) -> StoreFuture<'a, u64>;
}

pub trait PolicyLifecycleStore: Send + Sync {
    fn persist_draft<'a>(
        &'a self,
        draft: &'a PolicyBundleDraft,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool>;
    fn persist_simulation<'a>(
        &'a self,
        draft: &'a PolicyBundleDraft,
        report: &'a PolicySimulationReport,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool>;
    fn persist_shadow<'a>(
        &'a self,
        draft: &'a PolicyBundleDraft,
        report: Option<&'a PolicyShadowReport>,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool>;
    fn activate_policy<'a>(
        &'a self,
        draft: &'a PolicyBundleDraft,
        state: &'a ActivePolicyBundleState,
        activation: &'a ActivatePolicyBundle,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool>;
    fn replace_denies<'a>(
        &'a self,
        state: &'a ActivePolicyBundleState,
        expected_cache_generation: u64,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool>;
    fn active_state<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, ActivePolicyBundleState>;
}

pub trait OidcGrantStore: Send + Sync {
    fn store_grant<'a>(&'a self, grant: &'a OidcGrant) -> StoreFuture<'a, ()>;
    #[allow(clippy::too_many_arguments)]
    fn authorize_grant<'a>(
        &'a self,
        grant_id: &'a str,
        execution_lease_id: &'a str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        job_id: &'a str,
        step_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, OidcGrant>;
    fn record_issuance<'a>(
        &'a self,
        grant_id: &'a str,
        audience: &'a str,
        jti: &'a str,
        issued_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> StoreFuture<'a, ()>;
}

impl ConfigurationProjectStore for ControlPlane {
    fn put_project<'a>(
        &'a self,
        input: &'a PutConfigurationProject,
    ) -> StoreFuture<'a, ConfigurationProjectRecord> {
        let value = self.put_configuration_project(input);
        Box::pin(async move { value })
    }
    fn project<'a>(
        &'a self,
        tenant_id: &'a str,
        project_id: &'a str,
    ) -> StoreFuture<'a, ConfigurationProjectRecord> {
        let value = self.configuration_project(tenant_id, project_id);
        Box::pin(async move { value })
    }
    fn projects<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<ConfigurationProjectRecord>> {
        let value = self.list_configuration_projects(tenant_id);
        Box::pin(async move { value })
    }
}

impl SecretConfigurationStore for ControlPlane {
    fn create_secret<'a>(
        &'a self,
        key: &'a str,
        metadata: &'a SecretMetadataReference,
        plaintext: Option<&'a SecretPlaintext>,
        master_key: &'a MasterKey,
    ) -> StoreFuture<'a, IdempotentResult<SecretMetadataReference>> {
        let value = self.create_secret_idempotent(key, metadata, plaintext, master_key);
        Box::pin(async move { value })
    }
    fn rotate_secret<'a>(
        &'a self,
        key: &'a str,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
        plaintext: &'a SecretPlaintext,
        master_key: &'a MasterKey,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<SecretMetadataReference>> {
        let value =
            self.rotate_secret_idempotent(key, tenant_id, scope, name, plaintext, master_key, now);
        Box::pin(async move { value })
    }
    fn delete_secret_configuration<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
        master_key: &'a MasterKey,
        now: u64,
    ) -> StoreFuture<'a, SecretMetadataReference> {
        let value = self.delete_secret(tenant_id, scope, name, master_key, now);
        Box::pin(async move { value })
    }
    fn secret_by_id<'a>(&'a self, id: &'a str) -> StoreFuture<'a, SecretMetadataReference> {
        let value = self.secret_metadata(id);
        Box::pin(async move { value })
    }
    fn secret_by_name<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, SecretMetadataReference> {
        let value = self.secret_metadata_by_name(tenant_id, scope, name);
        Box::pin(async move { value })
    }
    fn secrets<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> StoreFuture<'a, Vec<SecretMetadataReference>> {
        let value = self.list_secret_metadata(tenant_id, scope);
        Box::pin(async move { value })
    }
    fn resolve_secret<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        scm_account_id: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, SecretResolutionRecord> {
        let value = self.resolve_secret_metadata(tenant_id, repository_id, scm_account_id, name);
        Box::pin(async move { value })
    }
    fn validate_resolution<'a>(
        &'a self,
        expected: &'a SecretResolutionRecord,
    ) -> StoreFuture<'a, ()> {
        let value = self.validate_secret_resolution(expected);
        Box::pin(async move { value })
    }
}

impl VariableConfigurationStore for ControlPlane {
    fn put_variable<'a>(
        &'a self,
        key: &'a str,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
        value: Value,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<VariableRecord>> {
        let result = self.put_variable_idempotent(key, tenant_id, scope, name, value, now);
        Box::pin(async move { result })
    }
    fn variable_record<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, VariableRecord> {
        let value = self.variable(tenant_id, scope, name);
        Box::pin(async move { value })
    }
    fn variable_records<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> StoreFuture<'a, Vec<VariableRecord>> {
        let value = self.list_variables(tenant_id, scope);
        Box::pin(async move { value })
    }
    fn delete_variable_record<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, ()> {
        let value = self.delete_variable(tenant_id, scope, name);
        Box::pin(async move { value })
    }
    fn create_snapshot<'a>(
        &'a self,
        id: &'a str,
        tenant_id: &'a str,
        scope: &'a str,
        version: u64,
        values: BTreeMap<String, Value>,
        created: u64,
    ) -> StoreFuture<'a, VariableSnapshot> {
        let value = self.create_variable_snapshot(id, tenant_id, scope, version, values, created);
        Box::pin(async move { value })
    }
    fn latest_snapshot<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> StoreFuture<'a, VariableSnapshot> {
        let value = self.latest_variable_snapshot(tenant_id, scope);
        Box::pin(async move { value })
    }
}

impl PolicyVersionStore for ControlPlane {
    fn create_policy_version<'a>(
        &'a self,
        key: &'a str,
        record: &'a PolicyVersionRecord,
    ) -> StoreFuture<'a, IdempotentResult<PolicyVersionRecord>> {
        let value = self.create_policy_version_idempotent(key, record);
        Box::pin(async move { value })
    }
    fn next_policy_version_number<'a>(&'a self, policy_id: &'a str) -> StoreFuture<'a, u64> {
        let value = self.next_policy_version(policy_id);
        Box::pin(async move { value })
    }
}

impl PolicyLifecycleStore for ControlPlane {
    fn persist_draft<'a>(
        &'a self,
        d: &'a PolicyBundleDraft,
        a: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        let value = self.persist_policy_draft(d, a);
        Box::pin(async move { value })
    }
    fn persist_simulation<'a>(
        &'a self,
        d: &'a PolicyBundleDraft,
        r: &'a PolicySimulationReport,
        a: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        let value = self.persist_policy_simulation(d, r, a);
        Box::pin(async move { value })
    }
    fn persist_shadow<'a>(
        &'a self,
        d: &'a PolicyBundleDraft,
        r: Option<&'a PolicyShadowReport>,
        a: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        let value = self.persist_policy_shadow(d, r, a);
        Box::pin(async move { value })
    }
    fn activate_policy<'a>(
        &'a self,
        d: &'a PolicyBundleDraft,
        s: &'a ActivePolicyBundleState,
        activation: &'a ActivatePolicyBundle,
        a: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        let value = self.activate_policy_bundle(d, s, activation, a);
        Box::pin(async move { value })
    }
    fn replace_denies<'a>(
        &'a self,
        s: &'a ActivePolicyBundleState,
        expected: u64,
        a: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        let value = self.replace_emergency_denies(s, expected, a);
        Box::pin(async move { value })
    }
    fn active_state<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, ActivePolicyBundleState> {
        let value = self.active_policy_state(tenant_id);
        Box::pin(async move { value })
    }
}

impl OidcGrantStore for ControlPlane {
    fn store_grant<'a>(&'a self, grant: &'a OidcGrant) -> StoreFuture<'a, ()> {
        let value = self.store_oidc_grant(grant);
        Box::pin(async move { value })
    }
    fn authorize_grant<'a>(
        &'a self,
        grant_id: &'a str,
        lease_id: &'a str,
        fence: u64,
        epoch: u64,
        job_id: &'a str,
        step_id: &'a str,
        now: u64,
    ) -> StoreFuture<'a, OidcGrant> {
        let value =
            self.authorize_oidc_grant(grant_id, lease_id, fence, epoch, job_id, step_id, now);
        Box::pin(async move { value })
    }
    fn record_issuance<'a>(
        &'a self,
        grant_id: &'a str,
        audience: &'a str,
        jti: &'a str,
        issued: u64,
        expires: u64,
    ) -> StoreFuture<'a, ()> {
        let value = self.record_oidc_issuance(grant_id, audience, jti, issued, expires);
        Box::pin(async move { value })
    }
}

#[cfg(feature = "postgres")]
impl ConfigurationProjectStore for PostgresInstallationStore {
    fn put_project<'a>(
        &'a self,
        input: &'a PutConfigurationProject,
    ) -> StoreFuture<'a, ConfigurationProjectRecord> {
        Box::pin(async move {
            validate_project(input)?;
            let mut tx = self.pool().begin().await?;
            let existing = sqlx::query(
                "SELECT version,created_unix_ms FROM configuration_projects WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            )
            .bind(&input.tenant_id)
            .bind(&input.id)
            .fetch_optional(&mut *tx)
            .await?;
            let (version, created) = match existing {
                None if input.expected_version == 0 => (1, input.updated_unix_ms),
                None => return Err(project_conflict(input, 0)),
                Some(row) => {
                    let actual = pg_u64(row.try_get("version")?, "configuration project version")?;
                    if actual != input.expected_version {
                        return Err(project_conflict(input, actual));
                    }
                    (
                        actual
                            .checked_add(1)
                            .ok_or(ControlPlaneError::IntegerRange {
                                field: "configuration project version",
                            })?,
                        pg_u64(
                            row.try_get("created_unix_ms")?,
                            "configuration project creation",
                        )?,
                    )
                }
            };
            if input.updated_unix_ms < created {
                return Err(ControlPlaneError::InvalidInput(
                    "configuration project update precedes creation",
                ));
            }
            sqlx::query(
                "INSERT INTO configuration_projects(id,tenant_id,name,description,status,version,created_unix_ms,updated_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,status=excluded.status,version=excluded.version,updated_unix_ms=excluded.updated_unix_ms",
            )
            .bind(&input.id)
            .bind(&input.tenant_id)
            .bind(&input.name)
            .bind(&input.description)
            .bind(&input.status)
            .bind(pg_i64(version, "configuration project version")?)
            .bind(pg_i64(created, "configuration project creation")?)
            .bind(pg_i64(input.updated_unix_ms, "configuration project update")?)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "DELETE FROM configuration_project_targets WHERE tenant_id=$1 AND project_id=$2",
            )
            .bind(&input.tenant_id)
            .bind(&input.id)
            .execute(&mut *tx)
            .await?;
            for target in &input.targets {
                sqlx::query("INSERT INTO configuration_project_targets(tenant_id,project_id,target_kind,target_id,created_unix_ms) VALUES($1,$2,$3,$4,$5)")
                    .bind(&input.tenant_id)
                    .bind(&input.id)
                    .bind(target.kind.as_str())
                    .bind(&target.id)
                    .bind(pg_i64(target.created_unix_ms, "configuration target creation")?)
                    .execute(&mut *tx)
                    .await?;
            }
            let value = project_tx(&mut tx, &input.tenant_id, &input.id, false)
                .await?
                .ok_or_else(|| pg_not_found("configuration project", &input.id))?;
            tx.commit().await?;
            Ok(value)
        })
    }

    fn project<'a>(
        &'a self,
        tenant_id: &'a str,
        project_id: &'a str,
    ) -> StoreFuture<'a, ConfigurationProjectRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let value = project_tx(&mut tx, tenant_id, project_id, false)
                .await?
                .ok_or_else(|| pg_not_found("configuration project", project_id))?;
            tx.commit().await?;
            Ok(value)
        })
    }

    fn projects<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<ConfigurationProjectRecord>> {
        Box::pin(async move {
            validate_text_value(tenant_id)?;
            let mut tx = self.pool().begin().await?;
            let ids: Vec<String> = sqlx::query_scalar(
                "SELECT id FROM configuration_projects WHERE tenant_id=$1 ORDER BY name,id",
            )
            .bind(tenant_id)
            .fetch_all(&mut *tx)
            .await?;
            let mut values = Vec::with_capacity(ids.len());
            for id in ids {
                values.push(
                    project_tx(&mut tx, tenant_id, &id, false)
                        .await?
                        .ok_or_else(|| pg_not_found("configuration project", &id))?,
                );
            }
            tx.commit().await?;
            Ok(values)
        })
    }
}

#[cfg(feature = "postgres")]
impl PolicyVersionStore for PostgresInstallationStore {
    fn create_policy_version<'a>(
        &'a self,
        key: &'a str,
        record: &'a PolicyVersionRecord,
    ) -> StoreFuture<'a, IdempotentResult<PolicyVersionRecord>> {
        Box::pin(async move {
            validate_idempotency(key)?;
            for value in [&record.id, &record.policy_id, &record.source, &record.mode] {
                validate_text_value(value)?;
            }
            if record.version == 0
                || !matches!(record.mode.as_str(), "draft" | "shadow" | "enforce")
            {
                return Err(ControlPlaneError::InvalidInput(
                    "policy version or mode is invalid",
                ));
            }
            let actual = ContentDigest::sha256(record.source.as_bytes());
            if actual != record.digest {
                return Err(ControlPlaneError::CapsuleDigestMismatch {
                    expected: record.digest.clone(),
                    actual,
                });
            }
            let request_hash = hash_serializable(&(
                record.policy_id.as_str(),
                record.source.as_str(),
                record.mode.as_str(),
            ))?;
            let operation = format!("policy.version.create:{}", record.policy_id);
            let mut tx = self.pool().begin().await?;
            if let Some((stored, resource)) = idempotency_tx(&mut tx, &operation, key).await? {
                if stored != request_hash {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let value = policy_version_tx(&mut tx, &resource)
                    .await?
                    .ok_or_else(|| pg_not_found("policy version", &resource))?;
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value,
                    replayed: true,
                });
            }
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(&record.policy_id)
                .execute(&mut *tx)
                .await?;
            let next: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(version),0)+1 FROM policy_versions WHERE policy_id=$1",
            )
            .bind(&record.policy_id)
            .fetch_one(&mut *tx)
            .await?;
            if pg_u64(next, "policy version")? != record.version {
                return Err(ControlPlaneError::InvalidInput(
                    "policy version is not the next durable version",
                ));
            }
            sqlx::query("INSERT INTO policy_versions(id,policy_id,version,source,mode,digest,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(&record.id).bind(&record.policy_id).bind(pg_i64(record.version, "policy version")?)
                .bind(&record.source).bind(&record.mode).bind(record.digest.as_str())
                .bind(pg_i64(record.created_unix_ms, "policy version creation")?).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES($1,$2,$3,$4,$5)")
                .bind(operation).bind(key).bind(request_hash.as_str()).bind(&record.id)
                .bind(pg_i64(record.created_unix_ms, "policy version creation")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: record.clone(),
                replayed: false,
            })
        })
    }
    fn next_policy_version_number<'a>(&'a self, policy_id: &'a str) -> StoreFuture<'a, u64> {
        Box::pin(async move {
            validate_text_value(policy_id)?;
            let next: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(version),0)+1 FROM policy_versions WHERE policy_id=$1",
            )
            .bind(policy_id)
            .fetch_one(self.pool())
            .await?;
            pg_u64(next, "policy version")
        })
    }
}

#[cfg(feature = "postgres")]
impl PolicyLifecycleStore for PostgresInstallationStore {
    fn persist_draft<'a>(
        &'a self,
        draft: &'a PolicyBundleDraft,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            draft.verify()?;
            validate_text_value(&audit.actor_id)?;
            validate_text_value(&audit.correlation_id)?;
            if draft.status != PolicyBundleDraftStatus::Draft
                || draft.author_id != audit.actor_id
                || audit.occurred_unix_ms < draft.created_unix_ms
            {
                return Err(ControlPlaneError::InvalidInput(
                    "new policy draft lacks exact author or draft state",
                ));
            }
            let bytes = policy_bytes(draft, 2 * 1024 * 1024)?;
            let mut tx = self.pool().begin().await?;
            require_policy_actor(&mut tx, &draft.tenant_id, &draft.author_id).await?;
            if let Some(old) = policy_draft_tx(&mut tx, &draft.tenant_id, &draft.id, true).await? {
                if old == *draft {
                    tx.commit().await?;
                    return Ok(false);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO policy_bundle_drafts(id,tenant_id,author_id,policy_digest,draft_json,status,simulation_digest,activated_policy_epoch,audit_correlation_id,created_unix_ms,updated_unix_ms) VALUES($1,$2,$3,$4,$5,'draft',NULL,NULL,$6,$7,$8)")
                .bind(&draft.id).bind(&draft.tenant_id).bind(&draft.author_id).bind(draft.digest.as_str()).bind(bytes)
                .bind(&audit.correlation_id).bind(pg_i64(draft.created_unix_ms, "policy draft creation")?)
                .bind(pg_i64(audit.occurred_unix_ms, "policy draft update")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }

    fn persist_simulation<'a>(
        &'a self,
        draft: &'a PolicyBundleDraft,
        report: &'a PolicySimulationReport,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            draft.verify()?;
            report.verify()?;
            if draft.status != PolicyBundleDraftStatus::Simulated
                || draft.simulation_digest.as_ref() != Some(&report.report_digest)
                || draft.digest != report.policy_digest
                || report.results.len()
                    != report
                        .stored_case_count
                        .saturating_add(report.caller_case_count)
                || report.stored_case_count > 1024
                || report.caller_case_count > 128
            {
                return Err(ControlPlaneError::InvalidInput(
                    "policy simulation does not bind the stored draft",
                ));
            }
            let draft_bytes = policy_bytes(draft, 2 * 1024 * 1024)?;
            let report_bytes = policy_bytes(report, 2 * 1024 * 1024)?;
            let mut tx = self.pool().begin().await?;
            require_policy_actor(&mut tx, &draft.tenant_id, &audit.actor_id).await?;
            let old = policy_draft_tx(&mut tx, &draft.tenant_id, &draft.id, true)
                .await?
                .ok_or_else(|| pg_not_found("policy draft", &draft.id))?;
            if old.digest != draft.digest
                || old.author_id != draft.author_id
                || !matches!(
                    old.status,
                    PolicyBundleDraftStatus::Draft | PolicyBundleDraftStatus::Simulated
                )
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if let Some(existing)=sqlx::query_scalar::<_,Vec<u8>>("SELECT report_json FROM policy_simulation_reports WHERE tenant_id=$1 AND draft_id=$2 AND report_digest=$3")
                .bind(&draft.tenant_id).bind(&draft.id).bind(report.report_digest.as_str()).fetch_optional(&mut *tx).await? {
                if existing==report_bytes && old==*draft { tx.commit().await?; return Ok(false); }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO policy_simulation_reports(tenant_id,draft_id,report_digest,corpus_digest,report_json,stored_case_count,caller_case_count,evaluation_error_count,expectation_mismatch_count,actor_id,audit_correlation_id,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
                .bind(&draft.tenant_id).bind(&draft.id).bind(report.report_digest.as_str()).bind(report.corpus_digest.as_str()).bind(report_bytes)
                .bind(i64::try_from(report.stored_case_count).map_err(|_|ControlPlaneError::IntegerRange{field:"stored simulation count"})?)
                .bind(i64::try_from(report.caller_case_count).map_err(|_|ControlPlaneError::IntegerRange{field:"caller simulation count"})?)
                .bind(i64::try_from(report.evaluation_error_count).map_err(|_|ControlPlaneError::IntegerRange{field:"simulation error count"})?)
                .bind(i64::try_from(report.expectation_mismatch_count).map_err(|_|ControlPlaneError::IntegerRange{field:"simulation mismatch count"})?)
                .bind(&audit.actor_id).bind(&audit.correlation_id).bind(pg_i64(audit.occurred_unix_ms,"policy simulation time")?).execute(&mut *tx).await?;
            sqlx::query("UPDATE policy_bundle_drafts SET draft_json=$3,status='simulated',simulation_digest=$4,audit_correlation_id=$5,updated_unix_ms=$6 WHERE tenant_id=$1 AND id=$2")
                .bind(&draft.tenant_id).bind(&draft.id).bind(draft_bytes).bind(report.report_digest.as_str()).bind(&audit.correlation_id)
                .bind(pg_i64(audit.occurred_unix_ms,"policy simulation time")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }

    fn persist_shadow<'a>(
        &'a self,
        draft: &'a PolicyBundleDraft,
        report: Option<&'a PolicyShadowReport>,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            draft.verify()?;
            if draft.status != PolicyBundleDraftStatus::Shadow {
                return Err(ControlPlaneError::InvalidInput(
                    "policy shadow record requires shadow draft state",
                ));
            }
            let draft_bytes = policy_bytes(draft, 2 * 1024 * 1024)?;
            let report_bytes = report
                .map(|r| policy_bytes(r, 2 * 1024 * 1024))
                .transpose()?;
            let report_digest = report_bytes
                .as_ref()
                .map(|b| record_digest(b"runtrue.policy-shadow-report.v1\0", b));
            let mut tx = self.pool().begin().await?;
            require_policy_actor(&mut tx, &draft.tenant_id, &audit.actor_id).await?;
            let old = policy_draft_tx(&mut tx, &draft.tenant_id, &draft.id, true)
                .await?
                .ok_or_else(|| pg_not_found("policy draft", &draft.id))?;
            if old.digest != draft.digest
                || old.author_id != draft.author_id
                || !matches!(
                    old.status,
                    PolicyBundleDraftStatus::Simulated | PolicyBundleDraftStatus::Shadow
                )
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if let Some(report) = report {
                if report.shadow_policy_digest != draft.digest
                    || report.results.is_empty()
                    || report.results.len() > 512
                {
                    return Err(ControlPlaneError::InvalidInput(
                        "policy shadow report does not bind the draft",
                    ));
                }
                let (state, _) = policy_state_tx(&mut tx, &draft.tenant_id, false).await?;
                if report.policy_epoch != state.policy_epoch
                    || report.active_policy_digest
                        != state.active.as_ref().map(|v| v.digest.clone())
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let bytes = report_bytes.as_ref().unwrap();
                let digest = report_digest.as_ref().unwrap();
                if let Some(existing)=sqlx::query_scalar::<_,Vec<u8>>("SELECT report_json FROM policy_shadow_reports WHERE tenant_id=$1 AND draft_id=$2 AND report_digest=$3")
                    .bind(&draft.tenant_id).bind(&draft.id).bind(digest.as_str()).fetch_optional(&mut *tx).await? {
                    if existing==*bytes && old==*draft { tx.commit().await?; return Ok(false); }
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                sqlx::query("INSERT INTO policy_shadow_reports(tenant_id,draft_id,report_digest,policy_epoch,report_json,case_count,actor_id,audit_correlation_id,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                    .bind(&draft.tenant_id).bind(&draft.id).bind(digest.as_str()).bind(pg_i64(report.policy_epoch,"policy epoch")?).bind(bytes)
                    .bind(i64::try_from(report.results.len()).map_err(|_|ControlPlaneError::IntegerRange{field:"shadow case count"})?)
                    .bind(&audit.actor_id).bind(&audit.correlation_id).bind(pg_i64(audit.occurred_unix_ms,"policy shadow time")?).execute(&mut *tx).await?;
            } else if old == *draft {
                tx.commit().await?;
                return Ok(false);
            }
            sqlx::query("UPDATE policy_bundle_drafts SET draft_json=$3,status='shadow',audit_correlation_id=$4,updated_unix_ms=$5 WHERE tenant_id=$1 AND id=$2")
                .bind(&draft.tenant_id).bind(&draft.id).bind(draft_bytes).bind(&audit.correlation_id).bind(pg_i64(audit.occurred_unix_ms,"policy shadow time")?)
                .execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }

    fn activate_policy<'a>(
        &'a self,
        draft: &'a PolicyBundleDraft,
        state: &'a ActivePolicyBundleState,
        activation: &'a ActivatePolicyBundle,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            draft.verify()?;
            drop(state.snapshot()?);
            let Some(active) = &state.active else {
                return Err(ControlPlaneError::InvalidInput(
                    "activated policy state has no active bundle",
                ));
            };
            if draft.status != PolicyBundleDraftStatus::Activated
                || state.tenant_id != draft.tenant_id
                || active.draft_id != draft.id
                || active.digest != draft.digest
                || active.simulation_digest != activation.simulation_digest
                || activation.draft_digest != draft.digest
                || active.approved_by != audit.actor_id
                || activation.approved_by != audit.actor_id
                || draft.author_id == audit.actor_id
                || audit.occurred_unix_ms != activation.approved_unix_ms
            {
                return Err(ControlPlaneError::InvalidInput(
                    "policy activation evidence does not bind state, draft, and actor",
                ));
            }
            let draft_bytes = policy_bytes(draft, 2 * 1024 * 1024)?;
            let activation_bytes = policy_bytes(activation, 256 * 1024)?;
            let activation_digest =
                record_digest(b"runtrue.policy-activation.v1\0", &activation_bytes);
            let mut tx = self.pool().begin().await?;
            require_policy_actor(&mut tx, &draft.tenant_id, &audit.actor_id).await?;
            let old = policy_draft_tx(&mut tx, &draft.tenant_id, &draft.id, true)
                .await?
                .ok_or_else(|| pg_not_found("policy draft", &draft.id))?;
            if let Some(row)=sqlx::query("SELECT activation_digest,activation_json FROM policy_activations WHERE tenant_id=$1 AND draft_id=$2")
                .bind(&draft.tenant_id).bind(&draft.id).fetch_optional(&mut *tx).await? {
                let (stored_state,_)=policy_state_tx(&mut tx,&draft.tenant_id,false).await?;
                if row.try_get::<String,_>("activation_digest")?==activation_digest.as_str()
                    && row.try_get::<Vec<u8>,_>("activation_json")?==activation_bytes && old==*draft && stored_state==*state {
                    tx.commit().await?; return Ok(false);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if old.status != PolicyBundleDraftStatus::Shadow
                || old.digest != draft.digest
                || old.simulation_digest != draft.simulation_digest
                || old.author_id == audit.actor_id
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let simulation_bytes:Vec<u8>=sqlx::query_scalar("SELECT report_json FROM policy_simulation_reports WHERE tenant_id=$1 AND draft_id=$2 AND report_digest=$3")
                .bind(&draft.tenant_id).bind(&draft.id).bind(activation.simulation_digest.as_str()).fetch_optional(&mut *tx).await?
                .ok_or_else(||pg_not_found("eligible policy simulation",&draft.id))?;
            let simulation: PolicySimulationReport = serde_json::from_slice(&simulation_bytes)?;
            simulation.verify()?;
            if !simulation.activation_eligible()
                || simulation.policy_digest != draft.digest
                || simulation.report_digest != activation.simulation_digest
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let (current, version) = policy_state_tx(&mut tx, &draft.tenant_id, true).await?;
            let next_epoch =
                current
                    .policy_epoch
                    .checked_add(1)
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "policy epoch",
                    })?;
            let next_cache = current.decision_cache_generation.checked_add(1).ok_or(
                ControlPlaneError::IntegerRange {
                    field: "policy decision cache generation",
                },
            )?;
            if activation.expected_policy_epoch != current.policy_epoch
                || state.policy_epoch != next_epoch
                || state.decision_cache_generation != next_cache
                || active.policy_epoch != next_epoch
                || state.emergency_denies != current.emergency_denies
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let changed=sqlx::query("UPDATE policy_bundle_drafts SET draft_json=$3,status='activated',activated_policy_epoch=$4,audit_correlation_id=$5,updated_unix_ms=$6 WHERE tenant_id=$1 AND id=$2 AND status='shadow'")
                .bind(&draft.tenant_id).bind(&draft.id).bind(draft_bytes).bind(pg_i64(next_epoch,"policy epoch")?).bind(&audit.correlation_id)
                .bind(pg_i64(audit.occurred_unix_ms,"policy activation time")?).execute(&mut *tx).await?.rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO policy_activations(tenant_id,draft_id,previous_policy_epoch,policy_epoch,activation_digest,policy_digest,simulation_digest,approval_id,approved_by,activation_json,audit_correlation_id,activated_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
                .bind(&draft.tenant_id).bind(&draft.id).bind(pg_i64(current.policy_epoch,"policy epoch")?).bind(pg_i64(next_epoch,"policy epoch")?)
                .bind(activation_digest.as_str()).bind(draft.digest.as_str()).bind(activation.simulation_digest.as_str()).bind(&activation.approval_id)
                .bind(&activation.approved_by).bind(activation_bytes).bind(&audit.correlation_id).bind(pg_i64(audit.occurred_unix_ms,"policy activation time")?)
                .execute(&mut *tx).await?;
            store_policy_state(&mut tx, state, version, audit).await?;
            tx.commit().await?;
            Ok(true)
        })
    }

    fn replace_denies<'a>(
        &'a self,
        state: &'a ActivePolicyBundleState,
        expected: u64,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            drop(state.snapshot()?);
            let denies = policy_bytes(&state.emergency_denies, 2 * 1024 * 1024)?;
            let digest = record_digest(b"runtrue.emergency-denies.v1\0", &denies);
            let mut tx = self.pool().begin().await?;
            require_policy_actor(&mut tx, &state.tenant_id, &audit.actor_id).await?;
            let (current, version) = policy_state_tx(&mut tx, &state.tenant_id, true).await?;
            if current == *state {
                if expected != state.decision_cache_generation {
                    let row=sqlx::query("SELECT previous_cache_generation,deny_digest,denies_json FROM emergency_deny_replacements WHERE tenant_id=$1 AND cache_generation=$2")
                        .bind(&state.tenant_id).bind(pg_i64(state.decision_cache_generation,"policy cache generation")?).fetch_optional(&mut *tx).await?
                        .ok_or(ControlPlaneError::IdempotencyConflict)?;
                    if pg_u64(
                        row.try_get("previous_cache_generation")?,
                        "previous cache generation",
                    )? != expected
                        || row.try_get::<String, _>("deny_digest")? != digest.as_str()
                        || row.try_get::<Vec<u8>, _>("denies_json")? != denies
                    {
                        return Err(ControlPlaneError::IdempotencyConflict);
                    }
                } else if state.decision_cache_generation != 0
                    || state.emergency_denies != DenyFirstPolicy::default()
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(false);
            }
            let next = current.decision_cache_generation.checked_add(1).ok_or(
                ControlPlaneError::IntegerRange {
                    field: "policy decision cache generation",
                },
            )?;
            if expected != current.decision_cache_generation
                || state.decision_cache_generation != next
                || state.policy_epoch != current.policy_epoch
                || state.active != current.active
                || state.emergency_denies == current.emergency_denies
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO emergency_deny_replacements(tenant_id,previous_cache_generation,cache_generation,deny_digest,denies_json,actor_id,audit_correlation_id,replaced_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(&state.tenant_id).bind(pg_i64(current.decision_cache_generation,"policy cache generation")?).bind(pg_i64(next,"policy cache generation")?)
                .bind(digest.as_str()).bind(denies).bind(&audit.actor_id).bind(&audit.correlation_id).bind(pg_i64(audit.occurred_unix_ms,"emergency deny replacement")?)
                .execute(&mut *tx).await?;
            store_policy_state(&mut tx, state, version, audit).await?;
            tx.commit().await?;
            Ok(true)
        })
    }

    fn active_state<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, ActivePolicyBundleState> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let (state, _) = policy_state_tx(&mut tx, tenant_id, false).await?;
            tx.commit().await?;
            Ok(state)
        })
    }
}

#[cfg(feature = "postgres")]
impl OidcGrantStore for PostgresInstallationStore {
    fn store_grant<'a>(&'a self, grant: &'a OidcGrant) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            grant.validate()?;
            let bytes = serde_json::to_vec(grant)?;
            if bytes.len() > 1024 * 1024 {
                return Err(ControlPlaneError::InvalidInput(
                    "OIDC grant exceeds its bound",
                ));
            }
            let mut tx = self.pool().begin().await?;
            super::runner_authority::validate_postgres_oidc_grant_subject(&mut tx, grant).await?;
            sqlx::query("INSERT INTO oidc_grants(id,grant_json) VALUES($1,$2)")
                .bind(&grant.grant_id)
                .bind(bytes)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(())
        })
    }

    fn authorize_grant<'a>(
        &'a self,
        grant_id: &'a str,
        lease_id: &'a str,
        fence: u64,
        epoch: u64,
        job_id: &'a str,
        step_id: &'a str,
        now: u64,
    ) -> StoreFuture<'a, OidcGrant> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let bytes: Vec<u8> = sqlx::query_scalar(
                "SELECT grant_json FROM oidc_grants WHERE id=$1 AND revoked_unix_ms IS NULL",
            )
            .bind(grant_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| pg_not_found("OIDC grant", grant_id))?;
            let grant: OidcGrant = serde_json::from_slice(&bytes)?;
            grant.validate()?;
            if serde_json::to_vec(&grant)? != bytes {
                return Err(ControlPlaneError::CorruptState(
                    "OIDC grant is not canonical".into(),
                ));
            }
            let row=sqlx::query("SELECT job_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,expires_unix_ms,hard_deadline_unix_ms FROM leases WHERE id=$1")
                .bind(lease_id).fetch_optional(&mut *tx).await?.ok_or_else(||pg_not_found("lease",lease_id))?;
            if grant.execution_lease_id != lease_id
                || grant.fencing_generation != fence
                || grant.job_id != job_id
                || grant.step_id != step_id
                || row.try_get::<String, _>("job_id")? != job_id
                || pg_u64(row.try_get("fencing_generation")?, "lease generation")? != fence
                || pg_u64(
                    row.try_get("installation_fencing_epoch")?,
                    "installation epoch",
                )? != epoch
                || row.try_get::<String, _>("capsule_digest")? != grant.capsule_digest.as_str()
                || row.try_get::<String, _>("state")? != "active"
                || now >= pg_u64(row.try_get("expires_unix_ms")?, "lease expiry")?
                || now >= pg_u64(row.try_get("hard_deadline_unix_ms")?, "lease deadline")?
                || now / 1000 >= grant.expires_unix_seconds
            {
                return Err(ControlPlaneError::StaleOidcGrant);
            }
            super::runner_authority::validate_postgres_oidc_grant_subject(&mut tx, &grant).await?;
            tx.commit().await?;
            Ok(grant)
        })
    }

    fn record_issuance<'a>(
        &'a self,
        grant_id: &'a str,
        audience: &'a str,
        jti: &'a str,
        issued: u64,
        expires: u64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            for value in [grant_id, audience, jti] {
                validate_text_value(value)?;
            }
            if expires <= issued {
                return Err(ControlPlaneError::InvalidInput(
                    "OIDC issuance expiry must be in the future",
                ));
            }
            sqlx::query("INSERT INTO oidc_issuances(grant_id,audience,jti,issued_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,$5)")
                .bind(grant_id).bind(audience).bind(jti).bind(pg_i64(issued,"OIDC issue")?).bind(pg_i64(expires,"OIDC expiry")?)
                .execute(self.pool()).await?;
            Ok(())
        })
    }
}

#[cfg(feature = "postgres")]
async fn project_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    project_id: &str,
    lock: bool,
) -> Result<Option<ConfigurationProjectRecord>, ControlPlaneError> {
    let q = format!(
        "SELECT * FROM configuration_projects WHERE tenant_id=$1 AND id=$2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let Some(row) = sqlx::query(&q)
        .bind(tenant_id)
        .bind(project_id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };
    let targets = sqlx::query(
        "SELECT target_kind,target_id,created_unix_ms FROM configuration_project_targets WHERE tenant_id=$1 AND project_id=$2 ORDER BY target_kind,target_id",
    )
    .bind(tenant_id)
    .bind(project_id)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|target| {
        let kind = match target.try_get::<String, _>("target_kind")?.as_str() {
            "scm_account" => ConfigurationProjectTargetKind::ScmAccount,
            "repository" => ConfigurationProjectTargetKind::Repository,
            other => {
                return Err(ControlPlaneError::CorruptState(format!(
                    "unknown configuration project target kind `{other}`"
                )))
            }
        };
        Ok(ConfigurationProjectTarget {
            kind,
            id: target.try_get("target_id")?,
            created_unix_ms: pg_u64(
                target.try_get("created_unix_ms")?,
                "configuration target creation",
            )?,
        })
    })
    .collect::<Result<Vec<_>, ControlPlaneError>>()?;
    Ok(Some(ConfigurationProjectRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        status: row.try_get("status")?,
        version: pg_u64(row.try_get("version")?, "configuration project version")?,
        created_unix_ms: pg_u64(
            row.try_get("created_unix_ms")?,
            "configuration project creation",
        )?,
        updated_unix_ms: pg_u64(
            row.try_get("updated_unix_ms")?,
            "configuration project update",
        )?,
        targets,
    }))
}

#[cfg(feature = "postgres")]
impl VariableConfigurationStore for PostgresInstallationStore {
    fn put_variable<'a>(
        &'a self,
        key: &'a str,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
        value: Value,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<VariableRecord>> {
        Box::pin(async move {
            validate_idempotency(key)?;
            for value in [tenant_id, scope, name] {
                validate_text_value(value)?;
            }
            let canonical = canonicalize_json(value);
            let encoded = serde_json::to_vec(&canonical)?;
            if encoded.len() > 16 * 1024 * 1024 {
                return Err(ControlPlaneError::InvalidInput(
                    "variable value is too large",
                ));
            }
            let request_hash = ContentDigest::sha256(&encoded);
            let operation = format!("variable.put:{tenant_id}:{scope}:{name}");
            let mut tx = self.pool().begin().await?;
            if let Some((stored_hash, resource)) = idempotency_tx(&mut tx, &operation, key).await? {
                if stored_hash != request_hash {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let version = resource.parse::<u64>().map_err(|_| {
                    ControlPlaneError::CorruptState("variable idempotency version".into())
                })?;
                let value = variable_version_tx(&mut tx, tenant_id, scope, name, version)
                    .await?
                    .ok_or_else(|| pg_not_found("variable version", &resource))?;
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value,
                    replayed: true,
                });
            }
            let current: Option<i64> = sqlx::query_scalar(
                "SELECT version FROM variables WHERE tenant_id=$1 AND scope=$2 AND name=$3 FOR UPDATE",
            )
            .bind(tenant_id)
            .bind(scope)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?;
            let version = current
                .map(|v| pg_u64(v, "variable version"))
                .transpose()?
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "variable version",
                })?;
            sqlx::query("INSERT INTO variables(tenant_id,scope,name,value_json,version,updated_unix_ms) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,scope,name) DO UPDATE SET value_json=excluded.value_json,version=excluded.version,updated_unix_ms=excluded.updated_unix_ms")
                .bind(tenant_id).bind(scope).bind(name).bind(&encoded)
                .bind(pg_i64(version, "variable version")?)
                .bind(pg_i64(now, "variable update")?)
                .execute(&mut *tx).await?;
            sqlx::query("INSERT INTO variable_versions(tenant_id,scope,name,version,value_json,updated_unix_ms) VALUES($1,$2,$3,$4,$5,$6)")
                .bind(tenant_id).bind(scope).bind(name)
                .bind(pg_i64(version, "variable version")?).bind(&encoded)
                .bind(pg_i64(now, "variable update")?).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES($1,$2,$3,$4,$5)")
                .bind(&operation).bind(key).bind(request_hash.as_str()).bind(version.to_string())
                .bind(pg_i64(now, "variable update")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: VariableRecord {
                    tenant_id: tenant_id.to_owned(),
                    scope: scope.to_owned(),
                    name: name.to_owned(),
                    value: canonical,
                    version,
                    updated_unix_ms: now,
                },
                replayed: false,
            })
        })
    }

    fn variable_record<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, VariableRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let value = variable_tx(&mut tx, tenant_id, scope, name, false)
                .await?
                .ok_or_else(|| pg_not_found("variable", name))?;
            tx.commit().await?;
            Ok(value)
        })
    }

    fn variable_records<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> StoreFuture<'a, Vec<VariableRecord>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT * FROM variables WHERE tenant_id=$1 AND scope=$2 ORDER BY name",
            )
            .bind(tenant_id)
            .bind(scope)
            .fetch_all(self.pool())
            .await?;
            rows.into_iter().map(variable_row).collect()
        })
    }

    fn delete_variable_record<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let changed =
                sqlx::query("DELETE FROM variables WHERE tenant_id=$1 AND scope=$2 AND name=$3")
                    .bind(tenant_id)
                    .bind(scope)
                    .bind(name)
                    .execute(self.pool())
                    .await?
                    .rows_affected();
            if changed == 0 {
                return Err(pg_not_found("variable", name));
            }
            Ok(())
        })
    }

    fn create_snapshot<'a>(
        &'a self,
        id: &'a str,
        tenant_id: &'a str,
        scope: &'a str,
        version: u64,
        values: BTreeMap<String, Value>,
        created: u64,
    ) -> StoreFuture<'a, VariableSnapshot> {
        Box::pin(async move {
            for value in [id, tenant_id, scope] {
                validate_text_value(value)?;
            }
            if version == 0 {
                return Err(ControlPlaneError::InvalidInput(
                    "variable snapshot version starts at one",
                ));
            }
            for name in values.keys() {
                validate_text_value(name)?;
            }
            let canonical = canonicalize_json(serde_json::to_value(&values)?);
            let encoded = serde_json::to_vec(&canonical)?;
            if encoded.len() > 16 * 1024 * 1024 {
                return Err(ControlPlaneError::InvalidInput(
                    "variable snapshot exceeds its bound",
                ));
            }
            let digest = ContentDigest::sha256(&encoded);
            let values = serde_json::from_value(canonical)?;
            sqlx::query("INSERT INTO variable_snapshots(id,tenant_id,scope,version,values_json,digest,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(id).bind(tenant_id).bind(scope).bind(pg_i64(version, "variable snapshot version")?)
                .bind(encoded).bind(digest.as_str()).bind(pg_i64(created, "variable snapshot creation")?)
                .execute(self.pool()).await?;
            Ok(VariableSnapshot {
                id: id.into(),
                tenant_id: tenant_id.into(),
                scope: scope.into(),
                version,
                values,
                digest,
                created_unix_ms: created,
            })
        })
    }

    fn latest_snapshot<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> StoreFuture<'a, VariableSnapshot> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM variable_snapshots WHERE tenant_id=$1 AND scope=$2 ORDER BY version DESC LIMIT 1")
                .bind(tenant_id).bind(scope).fetch_optional(self.pool()).await?
                .ok_or_else(|| pg_not_found("variable snapshot", scope))?;
            variable_snapshot_row(row)
        })
    }
}

#[cfg(feature = "postgres")]
impl SecretConfigurationStore for PostgresInstallationStore {
    fn create_secret<'a>(
        &'a self,
        key: &'a str,
        metadata: &'a SecretMetadataReference,
        plaintext: Option<&'a SecretPlaintext>,
        master_key: &'a MasterKey,
    ) -> StoreFuture<'a, IdempotentResult<SecretMetadataReference>> {
        Box::pin(async move {
            validate_idempotency(key)?;
            validate_secret_metadata(metadata)?;
            let built_in = metadata.provider == "built-in";
            if built_in != plaintext.is_some()
                || (built_in && metadata.provider_reference.is_some())
                || (!built_in && metadata.provider_reference.is_none())
            {
                return Err(ControlPlaneError::InvalidInput(
                    "built-in secrets require a value; external secrets require only a provider reference",
                ));
            }
            #[derive(Serialize)]
            struct Subject<'a> {
                tenant_id: &'a str,
                scope: &'a str,
                name: &'a str,
                provider: &'a str,
                provider_reference: &'a Option<String>,
                secret_type: &'a str,
                value_digest: Option<ContentDigest>,
            }
            let request_hash = hash_serializable(&Subject {
                tenant_id: &metadata.tenant_id,
                scope: &metadata.scope,
                name: &metadata.name,
                provider: &metadata.provider,
                provider_reference: &metadata.provider_reference,
                secret_type: &metadata.secret_type,
                value_digest: plaintext.map(|value| ContentDigest::sha256(value.as_bytes())),
            })?;
            let operation = format!("secret.create:{}:{}", metadata.tenant_id, metadata.scope);
            let mut tx = self.pool().begin().await?;
            if let Some((stored, resource)) = idempotency_tx(&mut tx, &operation, key).await? {
                if stored != request_hash {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let value = secret_metadata_id_tx(&mut tx, &resource, false)
                    .await?
                    .ok_or_else(|| pg_not_found("secret metadata", &resource))?;
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value,
                    replayed: true,
                });
            }
            if built_in {
                let mut vault = load_vault(
                    &mut tx,
                    &metadata.tenant_id,
                    &metadata.scope,
                    master_key,
                    self.installation_id(),
                )
                .await?;
                let identity = SecretIdentity::new(
                    metadata.tenant_id.clone(),
                    metadata.scope.clone(),
                    metadata.name.clone(),
                )?;
                let created = vault.create_secret(
                    identity,
                    plaintext.expect("built-in plaintext was validated"),
                )?;
                if metadata.current_version != Some(created.current_version)
                    || metadata.status != secret_status_name(created.status)
                {
                    return Err(ControlPlaneError::InvalidInput(
                        "secret metadata does not match encrypted value state",
                    ));
                }
                store_vault(
                    &mut tx,
                    &metadata.tenant_id,
                    &metadata.scope,
                    &vault,
                    metadata.updated_unix_ms,
                )
                .await?;
            }
            insert_secret_metadata(&mut tx, metadata).await?;
            sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES($1,$2,$3,$4,$5)")
                .bind(operation).bind(key).bind(request_hash.as_str()).bind(&metadata.id)
                .bind(pg_i64(metadata.created_unix_ms, "secret creation")?)
                .execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: metadata.clone(),
                replayed: false,
            })
        })
    }

    fn rotate_secret<'a>(
        &'a self,
        key: &'a str,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
        plaintext: &'a SecretPlaintext,
        master_key: &'a MasterKey,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<SecretMetadataReference>> {
        Box::pin(async move {
            validate_idempotency(key)?;
            let request_hash = ContentDigest::sha256(plaintext.as_bytes());
            let operation = format!("secret.rotate:{tenant_id}:{scope}:{name}");
            let mut tx = self.pool().begin().await?;
            if let Some((stored, resource)) = idempotency_tx(&mut tx, &operation, key).await? {
                if stored != request_hash {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let value = secret_metadata_id_tx(&mut tx, &resource, false)
                    .await?
                    .ok_or_else(|| pg_not_found("secret metadata", &resource))?;
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value,
                    replayed: true,
                });
            }
            let mut metadata = secret_metadata_name_tx(&mut tx, tenant_id, scope, name, true)
                .await?
                .ok_or_else(|| pg_not_found("secret", name))?;
            if metadata.provider != "built-in" || metadata.status != "active" {
                return Err(ControlPlaneError::InvalidInput(
                    "only active built-in secrets can rotate values",
                ));
            }
            let mut vault = load_vault(
                &mut tx,
                tenant_id,
                scope,
                master_key,
                self.installation_id(),
            )
            .await?;
            let identity = SecretIdentity::new(tenant_id, scope, name)?;
            let updated = vault.add_version(&identity, plaintext)?;
            metadata.current_version = Some(updated.current_version);
            metadata.updated_unix_ms = now;
            sqlx::query(
                "UPDATE secret_metadata SET current_version=$2,updated_unix_ms=$3 WHERE id=$1",
            )
            .bind(&metadata.id)
            .bind(pg_i64(updated.current_version, "secret version")?)
            .bind(pg_i64(now, "secret update")?)
            .execute(&mut *tx)
            .await?;
            store_vault(&mut tx, tenant_id, scope, &vault, now).await?;
            sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES($1,$2,$3,$4,$5)")
                .bind(operation).bind(key).bind(request_hash.as_str()).bind(&metadata.id)
                .bind(pg_i64(now, "secret update")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: metadata,
                replayed: false,
            })
        })
    }

    fn delete_secret_configuration<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
        master_key: &'a MasterKey,
        now: u64,
    ) -> StoreFuture<'a, SecretMetadataReference> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let mut metadata = secret_metadata_name_tx(&mut tx, tenant_id, scope, name, true)
                .await?
                .ok_or_else(|| pg_not_found("secret", name))?;
            if metadata.status == "tombstoned" {
                tx.commit().await?;
                return Ok(metadata);
            }
            if metadata.provider == "built-in" {
                let mut vault = load_vault(
                    &mut tx,
                    tenant_id,
                    scope,
                    master_key,
                    self.installation_id(),
                )
                .await?;
                vault.tombstone(&SecretIdentity::new(tenant_id, scope, name)?)?;
                store_vault(&mut tx, tenant_id, scope, &vault, now).await?;
            }
            metadata.status = "tombstoned".into();
            metadata.updated_unix_ms = now;
            sqlx::query(
                "UPDATE secret_metadata SET status='tombstoned',updated_unix_ms=$2 WHERE id=$1",
            )
            .bind(&metadata.id)
            .bind(pg_i64(now, "secret update")?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(metadata)
        })
    }

    fn secret_by_id<'a>(&'a self, id: &'a str) -> StoreFuture<'a, SecretMetadataReference> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let value = secret_metadata_id_tx(&mut tx, id, false)
                .await?
                .ok_or_else(|| pg_not_found("secret metadata", id))?;
            tx.commit().await?;
            Ok(value)
        })
    }
    fn secret_by_name<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, SecretMetadataReference> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let value = secret_metadata_name_tx(&mut tx, tenant_id, scope, name, false)
                .await?
                .ok_or_else(|| pg_not_found("secret", name))?;
            tx.commit().await?;
            Ok(value)
        })
    }
    fn secrets<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> StoreFuture<'a, Vec<SecretMetadataReference>> {
        Box::pin(async move {
            sqlx::query(
                "SELECT * FROM secret_metadata WHERE tenant_id=$1 AND scope=$2 ORDER BY name",
            )
            .bind(tenant_id)
            .bind(scope)
            .fetch_all(self.pool())
            .await?
            .into_iter()
            .map(secret_metadata_row)
            .collect()
        })
    }
    fn resolve_secret<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        scm_account_id: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, SecretResolutionRecord> {
        Box::pin(async move {
            resolve_secret(self, tenant_id, repository_id, scm_account_id, name).await
        })
    }
    fn validate_resolution<'a>(
        &'a self,
        expected: &'a SecretResolutionRecord,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let actual = resolve_secret(
                self,
                &expected.tenant_id,
                &expected.repository_id,
                &expected.scm_account_id,
                &expected.name,
            )
            .await?;
            if &actual != expected {
                return Err(ControlPlaneError::StaleSecretResolution {
                    name: expected.name.clone(),
                });
            }
            Ok(())
        })
    }
}

#[cfg(feature = "postgres")]
fn validate_text_value(value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty() || value.len() > 64 * 1024 || value.contains('\0') {
        return Err(ControlPlaneError::InvalidInput(
            "empty, oversized, or NUL text",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_idempotency(value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty() || value.len() > 1024 || value.contains('\0') {
        return Err(ControlPlaneError::InvalidInput("invalid idempotency key"));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_project(input: &PutConfigurationProject) -> Result<(), ControlPlaneError> {
    for value in [&input.id, &input.tenant_id, &input.name] {
        validate_text_value(value)?;
    }
    if input.description.len() > 8 * 1024 || !matches!(input.status.as_str(), "active" | "archived")
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid configuration project",
        ));
    }
    let mut unique = std::collections::BTreeSet::new();
    for target in &input.targets {
        validate_text_value(&target.id)?;
        if target.created_unix_ms > input.updated_unix_ms
            || !unique.insert((target.kind, target.id.as_str()))
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid configuration project targets",
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn project_conflict(input: &PutConfigurationProject, actual: u64) -> ControlPlaneError {
    ControlPlaneError::ConfigurationProjectVersionConflict {
        id: input.id.clone(),
        expected: input.expected_version,
        actual,
    }
}

#[cfg(feature = "postgres")]
fn pg_i64(value: u64, field: &'static str) -> Result<i64, ControlPlaneError> {
    i64::try_from(value).map_err(|_| ControlPlaneError::IntegerRange { field })
}

#[cfg(feature = "postgres")]
fn pg_u64(value: i64, field: &'static str) -> Result<u64, ControlPlaneError> {
    u64::try_from(value).map_err(|_| ControlPlaneError::CorruptState(format!("negative {field}")))
}

#[cfg(feature = "postgres")]
fn pg_not_found(kind: &'static str, id: &str) -> ControlPlaneError {
    ControlPlaneError::NotFound {
        kind,
        id: id.to_owned(),
    }
}

#[cfg(feature = "postgres")]
fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        value => value,
    }
}

#[cfg(feature = "postgres")]
fn hash_serializable(value: &impl Serialize) -> Result<ContentDigest, ControlPlaneError> {
    Ok(ContentDigest::sha256(serde_json::to_vec(value)?))
}

#[cfg(feature = "postgres")]
async fn idempotency_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation: &str,
    key: &str,
) -> Result<Option<(ContentDigest, String)>, ControlPlaneError> {
    sqlx::query("SELECT request_hash,resource_id FROM idempotency_records WHERE operation=$1 AND idempotency_key=$2")
        .bind(operation).bind(key).fetch_optional(&mut **tx).await?
        .map(|row| {
            let raw: String = row.try_get("request_hash")?;
            let digest = ContentDigest::parse(raw)
                .map_err(|e| ControlPlaneError::CorruptState(e.to_string()))?;
            Ok((digest, row.try_get("resource_id")?))
        }).transpose()
}

#[cfg(feature = "postgres")]
fn variable_row(row: PgRow) -> Result<VariableRecord, ControlPlaneError> {
    let bytes: Vec<u8> = row.try_get("value_json")?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&canonicalize_json(value.clone()))? != bytes {
        return Err(ControlPlaneError::CorruptState(
            "variable value is not canonical".into(),
        ));
    }
    Ok(VariableRecord {
        tenant_id: row.try_get("tenant_id")?,
        scope: row.try_get("scope")?,
        name: row.try_get("name")?,
        value,
        version: pg_u64(row.try_get("version")?, "variable version")?,
        updated_unix_ms: pg_u64(row.try_get("updated_unix_ms")?, "variable update")?,
    })
}

#[cfg(feature = "postgres")]
async fn variable_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    scope: &str,
    name: &str,
    lock: bool,
) -> Result<Option<VariableRecord>, ControlPlaneError> {
    let q = format!(
        "SELECT * FROM variables WHERE tenant_id=$1 AND scope=$2 AND name=$3{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    sqlx::query(&q)
        .bind(tenant_id)
        .bind(scope)
        .bind(name)
        .fetch_optional(&mut **tx)
        .await?
        .map(variable_row)
        .transpose()
}

#[cfg(feature = "postgres")]
async fn variable_version_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    scope: &str,
    name: &str,
    version: u64,
) -> Result<Option<VariableRecord>, ControlPlaneError> {
    sqlx::query("SELECT * FROM variable_versions WHERE tenant_id=$1 AND scope=$2 AND name=$3 AND version=$4")
        .bind(tenant_id).bind(scope).bind(name).bind(pg_i64(version, "variable version")?)
        .fetch_optional(&mut **tx).await?.map(variable_row).transpose()
}

#[cfg(feature = "postgres")]
fn variable_snapshot_row(row: PgRow) -> Result<VariableSnapshot, ControlPlaneError> {
    let bytes: Vec<u8> = row.try_get("values_json")?;
    let values: BTreeMap<String, Value> = serde_json::from_slice(&bytes)?;
    let digest_raw: String = row.try_get("digest")?;
    let digest = ContentDigest::parse(digest_raw)
        .map_err(|e| ControlPlaneError::CorruptState(e.to_string()))?;
    if serde_json::to_vec(&canonicalize_json(serde_json::to_value(&values)?))? != bytes
        || ContentDigest::sha256(&bytes) != digest
    {
        return Err(ControlPlaneError::CorruptState(
            "variable snapshot digest changed".into(),
        ));
    }
    Ok(VariableSnapshot {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        scope: row.try_get("scope")?,
        version: pg_u64(row.try_get("version")?, "variable snapshot version")?,
        values,
        digest,
        created_unix_ms: pg_u64(
            row.try_get("created_unix_ms")?,
            "variable snapshot creation",
        )?,
    })
}

#[cfg(feature = "postgres")]
fn validate_secret_metadata(value: &SecretMetadataReference) -> Result<(), ControlPlaneError> {
    for field in [
        &value.id,
        &value.tenant_id,
        &value.scope,
        &value.name,
        &value.provider,
        &value.secret_type,
        &value.status,
    ] {
        validate_text_value(field)?;
    }
    if let Some(reference) = &value.provider_reference {
        validate_text_value(reference)?;
    }
    if value.current_version == Some(0) || value.updated_unix_ms < value.created_unix_ms {
        return Err(ControlPlaneError::InvalidInput("invalid secret metadata"));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn secret_metadata_row(row: PgRow) -> Result<SecretMetadataReference, ControlPlaneError> {
    let value = SecretMetadataReference {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        scope: row.try_get("scope")?,
        name: row.try_get("name")?,
        provider: row.try_get("provider")?,
        provider_reference: row.try_get("provider_reference")?,
        secret_type: row.try_get("secret_type")?,
        status: row.try_get("status")?,
        current_version: row
            .try_get::<Option<i64>, _>("current_version")?
            .map(|v| pg_u64(v, "secret version"))
            .transpose()?,
        created_unix_ms: pg_u64(row.try_get("created_unix_ms")?, "secret creation")?,
        updated_unix_ms: pg_u64(row.try_get("updated_unix_ms")?, "secret update")?,
    };
    validate_secret_metadata(&value)?;
    Ok(value)
}

#[cfg(feature = "postgres")]
pub(super) async fn secret_metadata_id_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    lock: bool,
) -> Result<Option<SecretMetadataReference>, ControlPlaneError> {
    let q = format!(
        "SELECT * FROM secret_metadata WHERE id=$1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    sqlx::query(&q)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(secret_metadata_row)
        .transpose()
}

#[cfg(feature = "postgres")]
async fn secret_metadata_name_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    scope: &str,
    name: &str,
    lock: bool,
) -> Result<Option<SecretMetadataReference>, ControlPlaneError> {
    let q = format!(
        "SELECT * FROM secret_metadata WHERE tenant_id=$1 AND scope=$2 AND name=$3{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    sqlx::query(&q)
        .bind(tenant_id)
        .bind(scope)
        .bind(name)
        .fetch_optional(&mut **tx)
        .await?
        .map(secret_metadata_row)
        .transpose()
}

#[cfg(feature = "postgres")]
async fn insert_secret_metadata(
    tx: &mut Transaction<'_, Postgres>,
    value: &SecretMetadataReference,
) -> Result<(), ControlPlaneError> {
    sqlx::query("INSERT INTO secret_metadata(id,tenant_id,scope,name,provider,provider_reference,secret_type,status,current_version,created_unix_ms,updated_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(&value.id).bind(&value.tenant_id).bind(&value.scope).bind(&value.name)
        .bind(&value.provider).bind(&value.provider_reference).bind(&value.secret_type)
        .bind(&value.status).bind(value.current_version.map(|v| pg_i64(v, "secret version")).transpose()?)
        .bind(pg_i64(value.created_unix_ms, "secret creation")?)
        .bind(pg_i64(value.updated_unix_ms, "secret update")?)
        .execute(&mut **tx).await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub(super) async fn load_vault(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    scope: &str,
    master_key: &MasterKey,
    installation_id: &str,
) -> Result<SecretVault, ControlPlaneError> {
    let bytes: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT snapshot_json FROM secret_vault_snapshots WHERE tenant_id=$1 AND scope=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(scope)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(bytes) = bytes {
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(ControlPlaneError::CorruptState(
                "secret vault snapshot exceeds its durable bound".into(),
            ));
        }
        let snapshot: SecretVaultSnapshot = serde_json::from_slice(&bytes)?;
        if serde_json::to_vec(&snapshot)? != bytes {
            return Err(ControlPlaneError::CorruptState(
                "secret vault snapshot is not canonical".into(),
            ));
        }
        Ok(SecretVault::from_snapshot(
            snapshot,
            master_key.duplicate(),
        )?)
    } else {
        Ok(SecretVault::new(
            format!("control-plane:{installation_id}:v1"),
            master_key.duplicate(),
        )?)
    }
}

#[cfg(feature = "postgres")]
async fn store_vault(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    scope: &str,
    vault: &SecretVault,
    now: u64,
) -> Result<(), ControlPlaneError> {
    let bytes = serde_json::to_vec(&vault.snapshot())?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(ControlPlaneError::InvalidInput(
            "secret vault snapshot exceeds its durable bound",
        ));
    }
    sqlx::query("INSERT INTO secret_vault_snapshots(tenant_id,scope,snapshot_json,updated_unix_ms) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,scope) DO UPDATE SET snapshot_json=excluded.snapshot_json,updated_unix_ms=excluded.updated_unix_ms")
        .bind(tenant_id).bind(scope).bind(bytes).bind(pg_i64(now, "secret vault update")?)
        .execute(&mut **tx).await?;
    Ok(())
}

#[cfg(feature = "postgres")]
const fn secret_status_name(status: SecretStatus) -> &'static str {
    match status {
        SecretStatus::Active => "active",
        SecretStatus::Tombstoned => "tombstoned",
    }
}

#[cfg(feature = "postgres")]
async fn find_secret_candidate(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    scope: SecretScope,
    name: &str,
) -> Result<Option<SecretResolutionCandidate>, ControlPlaneError> {
    let key = scope.durable_key();
    let row = sqlx::query(
        "SELECT id,current_version FROM secret_metadata WHERE tenant_id=$1 AND scope=$2 AND name=$3 AND status='active'",
    )
    .bind(tenant_id)
    .bind(key)
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        Ok(SecretResolutionCandidate {
            scope,
            metadata_id: row.try_get("id")?,
            version: row
                .try_get::<Option<i64>, _>("current_version")?
                .map(|v| pg_u64(v, "secret version"))
                .transpose()?,
        })
    })
    .transpose()
}

#[cfg(feature = "postgres")]
async fn resolve_secret(
    store: &PostgresInstallationStore,
    tenant_id: &str,
    repository_id: &str,
    scm_account_id: &str,
    name: &str,
) -> Result<SecretResolutionRecord, ControlPlaneError> {
    for value in [tenant_id, repository_id, scm_account_id, name] {
        validate_text_value(value)?;
    }
    let mut tx = store.pool().begin().await?;
    let project_versions = sqlx::query(
        "SELECT DISTINCT p.id,p.version FROM configuration_projects p JOIN configuration_project_targets t ON t.tenant_id=p.tenant_id AND t.project_id=p.id WHERE p.tenant_id=$1 AND p.status='active' AND ((t.target_kind='repository' AND t.target_id=$2) OR (t.target_kind='scm_account' AND t.target_id=$3)) ORDER BY p.id",
    )
    .bind(tenant_id)
    .bind(repository_id)
    .bind(scm_account_id)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(|row| {
        Ok((
            row.try_get("id")?,
            pg_u64(row.try_get("version")?, "configuration project version")?,
        ))
    })
    .collect::<Result<Vec<(String, u64)>, ControlPlaneError>>()?;
    let repository = find_secret_candidate(
        &mut tx,
        tenant_id,
        SecretScope {
            kind: SecretScopeKind::Repository,
            id: repository_id.into(),
        },
        name,
    )
    .await?;
    let mut project_candidates = Vec::new();
    for (id, _) in &project_versions {
        if let Some(candidate) = find_secret_candidate(
            &mut tx,
            tenant_id,
            SecretScope {
                kind: SecretScopeKind::Project,
                id: id.clone(),
            },
            name,
        )
        .await?
        {
            project_candidates.push(candidate);
        }
    }
    let scm_account = find_secret_candidate(
        &mut tx,
        tenant_id,
        SecretScope {
            kind: SecretScopeKind::ScmAccount,
            id: scm_account_id.into(),
        },
        name,
    )
    .await?;
    let workspace =
        find_secret_candidate(&mut tx, tenant_id, SecretScope::workspace(tenant_id), name).await?;
    if repository.is_none() && project_candidates.len() > 1 {
        return Err(ControlPlaneError::AmbiguousSecretResolution {
            name: name.into(),
            project_ids: project_candidates
                .iter()
                .map(|candidate| candidate.scope.id.clone())
                .collect(),
        });
    }
    let selected = repository
        .clone()
        .or_else(|| project_candidates.first().cloned())
        .or_else(|| scm_account.clone())
        .or_else(|| workspace.clone())
        .ok_or_else(|| pg_not_found("secret", name))?;
    let mut shadowed = project_candidates;
    shadowed.extend(scm_account);
    shadowed.extend(workspace);
    shadowed.retain(|candidate| candidate != &selected);
    #[derive(Serialize)]
    struct Subject<'a> {
        version: u32,
        tenant_id: &'a str,
        repository_id: &'a str,
        scm_account_id: &'a str,
        name: &'a str,
        selected: &'a SecretResolutionCandidate,
        shadowed: &'a [SecretResolutionCandidate],
        project_versions: &'a [(String, u64)],
    }
    let resolution_digest = hash_serializable(&Subject {
        version: 1,
        tenant_id,
        repository_id,
        scm_account_id,
        name,
        selected: &selected,
        shadowed: &shadowed,
        project_versions: &project_versions,
    })?;
    tx.commit().await?;
    Ok(SecretResolutionRecord {
        tenant_id: tenant_id.into(),
        repository_id: repository_id.into(),
        scm_account_id: scm_account_id.into(),
        name: name.into(),
        selected,
        shadowed,
        project_versions,
        resolution_digest,
    })
}

#[cfg(feature = "postgres")]
fn policy_status(status: PolicyBundleDraftStatus) -> &'static str {
    match status {
        PolicyBundleDraftStatus::Draft => "draft",
        PolicyBundleDraftStatus::Simulated => "simulated",
        PolicyBundleDraftStatus::Shadow => "shadow",
        PolicyBundleDraftStatus::Activated => "activated",
        PolicyBundleDraftStatus::Retired => "retired",
    }
}

#[cfg(feature = "postgres")]
fn policy_bytes(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, ControlPlaneError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > limit {
        return Err(ControlPlaneError::InvalidInput(
            "policy record exceeds its bound",
        ));
    }
    Ok(bytes)
}

#[cfg(feature = "postgres")]
fn record_digest(domain: &[u8], bytes: &[u8]) -> ContentDigest {
    let mut material = Vec::with_capacity(domain.len() + bytes.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(bytes);
    ContentDigest::sha256(material)
}

#[cfg(feature = "postgres")]
async fn policy_version_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<PolicyVersionRecord>, ControlPlaneError> {
    sqlx::query("SELECT * FROM policy_versions WHERE id=$1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(|row| {
            let digest = ContentDigest::parse(row.try_get::<String, _>("digest")?)
                .map_err(|e| ControlPlaneError::CorruptState(e.to_string()))?;
            let value = PolicyVersionRecord {
                id: row.try_get("id")?,
                policy_id: row.try_get("policy_id")?,
                version: pg_u64(row.try_get("version")?, "policy version")?,
                source: row.try_get("source")?,
                mode: row.try_get("mode")?,
                digest,
                created_unix_ms: pg_u64(
                    row.try_get("created_unix_ms")?,
                    "policy version creation",
                )?,
            };
            if ContentDigest::sha256(value.source.as_bytes()) != value.digest {
                return Err(ControlPlaneError::CorruptState(
                    "policy version digest changed".into(),
                ));
            }
            Ok(value)
        })
        .transpose()
}

#[cfg(feature = "postgres")]
async fn policy_draft_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    id: &str,
    lock: bool,
) -> Result<Option<PolicyBundleDraft>, ControlPlaneError> {
    let q = format!(
        "SELECT * FROM policy_bundle_drafts WHERE tenant_id=$1 AND id=$2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let Some(row) = sqlx::query(&q)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };
    let bytes: Vec<u8> = row.try_get("draft_json")?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(ControlPlaneError::CorruptState(
            "policy draft exceeds its durable bound".into(),
        ));
    }
    let draft: PolicyBundleDraft = serde_json::from_slice(&bytes)?;
    draft.verify()?;
    if serde_json::to_vec(&draft)? != bytes
        || draft.tenant_id != tenant_id
        || draft.id != id
        || draft.author_id != row.try_get::<String, _>("author_id")?
        || draft.digest.as_str() != row.try_get::<String, _>("policy_digest")?
        || policy_status(draft.status) != row.try_get::<String, _>("status")?
        || draft.simulation_digest.as_ref().map(ContentDigest::as_str)
            != row
                .try_get::<Option<String>, _>("simulation_digest")?
                .as_deref()
        || draft.activated_policy_epoch
            != row
                .try_get::<Option<i64>, _>("activated_policy_epoch")?
                .map(|v| pg_u64(v, "activated policy epoch"))
                .transpose()?
    {
        return Err(ControlPlaneError::CorruptState(
            "policy draft durable binding changed".into(),
        ));
    }
    Ok(Some(draft))
}

#[cfg(feature = "postgres")]
async fn policy_state_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    lock: bool,
) -> Result<(ActivePolicyBundleState, u64), ControlPlaneError> {
    let q = format!(
        "SELECT * FROM tenant_policy_states WHERE tenant_id=$1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let Some(row) = sqlx::query(&q)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok((ActivePolicyBundleState::new(tenant_id.to_owned())?, 0));
    };
    let bytes: Vec<u8> = row.try_get("state_json")?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(ControlPlaneError::CorruptState(
            "active policy state exceeds its durable bound".into(),
        ));
    }
    let state: ActivePolicyBundleState = serde_json::from_slice(&bytes)?;
    drop(state.snapshot()?);
    let digest = record_digest(b"runtrue.active-policy-state.v1\0", &bytes);
    if serde_json::to_vec(&state)? != bytes
        || state.tenant_id != tenant_id
        || state.policy_epoch != pg_u64(row.try_get("policy_epoch")?, "policy epoch")?
        || state.decision_cache_generation
            != pg_u64(
                row.try_get("decision_cache_generation")?,
                "policy cache generation",
            )?
        || state.active.as_ref().map(|v| v.draft_id.as_str())
            != row
                .try_get::<Option<String>, _>("active_draft_id")?
                .as_deref()
        || state.active.as_ref().map(|v| v.digest.as_str())
            != row
                .try_get::<Option<String>, _>("active_policy_digest")?
                .as_deref()
        || digest.as_str() != row.try_get::<String, _>("state_digest")?
    {
        return Err(ControlPlaneError::CorruptState(
            "active policy state durable binding changed".into(),
        ));
    }
    Ok((
        state,
        pg_u64(row.try_get("version")?, "policy state version")?,
    ))
}

#[cfg(feature = "postgres")]
async fn require_policy_actor(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    actor: &str,
) -> Result<(), ControlPlaneError> {
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenant_memberships m JOIN human_users u ON u.id=m.user_id WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.status='active' AND u.status='active')")
        .bind(tenant).bind(actor).fetch_one(&mut **tx).await?;
    if !active {
        return Err(pg_not_found("active policy actor membership", actor));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn store_policy_state(
    tx: &mut Transaction<'_, Postgres>,
    state: &ActivePolicyBundleState,
    previous: u64,
    audit: &R9AuditMetadata,
) -> Result<(), ControlPlaneError> {
    drop(state.snapshot()?);
    let bytes = policy_bytes(state, 2 * 1024 * 1024)?;
    let digest = record_digest(b"runtrue.active-policy-state.v1\0", &bytes);
    let next = previous
        .checked_add(1)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "policy state version",
        })?;
    let active_id = state.active.as_ref().map(|v| v.draft_id.as_str());
    let active_digest = state.active.as_ref().map(|v| v.digest.as_str());
    let changed = if previous == 0 {
        sqlx::query("INSERT INTO tenant_policy_states(tenant_id,policy_epoch,decision_cache_generation,active_draft_id,active_policy_digest,state_digest,state_json,version,actor_id,audit_correlation_id,updated_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10)")
            .bind(&state.tenant_id).bind(pg_i64(state.policy_epoch, "policy epoch")?).bind(pg_i64(state.decision_cache_generation, "policy cache generation")?)
            .bind(active_id).bind(active_digest).bind(digest.as_str()).bind(bytes).bind(&audit.actor_id).bind(&audit.correlation_id)
            .bind(pg_i64(audit.occurred_unix_ms, "policy update")?).execute(&mut **tx).await?.rows_affected()
    } else {
        sqlx::query("UPDATE tenant_policy_states SET policy_epoch=$2,decision_cache_generation=$3,active_draft_id=$4,active_policy_digest=$5,state_digest=$6,state_json=$7,version=$8,actor_id=$9,audit_correlation_id=$10,updated_unix_ms=$11 WHERE tenant_id=$1 AND version=$12")
            .bind(&state.tenant_id).bind(pg_i64(state.policy_epoch, "policy epoch")?).bind(pg_i64(state.decision_cache_generation, "policy cache generation")?)
            .bind(active_id).bind(active_digest).bind(digest.as_str()).bind(bytes).bind(pg_i64(next, "policy state version")?)
            .bind(&audit.actor_id).bind(&audit.correlation_id).bind(pg_i64(audit.occurred_unix_ms, "policy update")?)
            .bind(pg_i64(previous, "policy state version")?).execute(&mut **tx).await?.rows_affected()
    };
    if changed != 1 {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    Ok(())
}

/// Durable tables owned by the independent portion of migration 8. Kept as a
/// machine-checkable inventory so later transaction contracts cannot silently
/// omit a journal or projection.
#[cfg(test)]
pub(super) const OWNED_TABLES: &[&str] = &[
    "configuration_projects",
    "configuration_project_targets",
    "secret_metadata",
    "secret_vault_snapshots",
    "variables",
    "variable_versions",
    "variable_snapshots",
    "policy_versions",
    "oidc_grants",
    "oidc_issuances",
    "policy_bundle_drafts",
    "policy_simulation_reports",
    "policy_shadow_reports",
    "tenant_policy_states",
    "policy_activations",
    "emergency_deny_replacements",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConfigurationProjectTarget, ConfigurationProjectTargetKind, HumanIdentityStore,
        HumanUserRecord, SecretScope, SecretScopeKind, TenantIdentityRecord, TenantIdentityStore,
        TenantMembershipRecord,
    };
    use runtrue_policy::{
        CedarAction, CedarAuthorizationRequest, CedarPrincipal, CedarPrincipalKind,
        CedarRequestContext, CedarResource, CedarResourceKind, DenyFirstPolicy, EmergencyDeny,
        PolicySimulationCase,
    };
    use std::collections::BTreeSet;

    #[test]
    fn migration_eight_inventory_has_no_duplicates() {
        assert_eq!(
            OWNED_TABLES.len(),
            OWNED_TABLES.iter().copied().collect::<BTreeSet<_>>().len()
        );
        assert!(!OWNED_TABLES.contains(&"external_secret_release_journal"));
    }

    fn tenant() -> TenantIdentityRecord {
        TenantIdentityRecord {
            id: "configuration-tenant".into(),
            slug: "configuration-tenant".into(),
            name: "Configuration tenant".into(),
            status: "active".into(),
            settings: serde_json::json!({}),
            created_unix_ms: 1,
            updated_unix_ms: 1,
            version: 1,
        }
    }

    async fn configuration_contract(
        store: &(impl ConfigurationProjectStore
              + SecretConfigurationStore
              + VariableConfigurationStore
              + TenantIdentityStore),
    ) {
        let _ = store.put_tenant_identity(&tenant(), None).await;
        let mut project = PutConfigurationProject {
            id: "release-project".into(),
            tenant_id: tenant().id,
            name: "Release".into(),
            description: "Release repositories".into(),
            status: "active".into(),
            expected_version: 0,
            targets: vec![ConfigurationProjectTarget {
                kind: ConfigurationProjectTargetKind::Repository,
                id: "release-repository".into(),
                created_unix_ms: 2,
            }],
            updated_unix_ms: 2,
        };
        let created = store.put_project(&project).await.unwrap();
        assert_eq!(created.version, 1);
        assert_eq!(
            store
                .project(&project.tenant_id, &project.id)
                .await
                .unwrap(),
            created
        );
        project.expected_version = 1;
        project.description = "Updated release repositories".into();
        project.updated_unix_ms = 3;
        let updated = store.put_project(&project).await.unwrap();
        assert_eq!(updated.version, 2);
        assert_eq!(
            store.projects(&project.tenant_id).await.unwrap(),
            vec![updated]
        );

        let key = MasterKey::from_bytes([29; 32]);
        let project_scope = SecretScope {
            kind: SecretScopeKind::Project,
            id: project.id.clone(),
        }
        .durable_key();
        let external = SecretMetadataReference {
            id: "project-token".into(),
            tenant_id: project.tenant_id.clone(),
            scope: project_scope.clone(),
            name: "TOKEN".into(),
            provider: "external-test".into(),
            provider_reference: Some("provider://token".into()),
            secret_type: "opaque".into(),
            status: "active".into(),
            current_version: None,
            created_unix_ms: 4,
            updated_unix_ms: 4,
        };
        assert!(
            !store
                .create_secret("external-create", &external, None, &key)
                .await
                .unwrap()
                .replayed
        );
        assert!(
            store
                .create_secret("external-create", &external, None, &key)
                .await
                .unwrap()
                .replayed
        );
        let resolution = store
            .resolve_secret(&project.tenant_id, "release-repository", "account", "TOKEN")
            .await
            .unwrap();
        assert_eq!(resolution.selected.metadata_id, external.id);
        store.validate_resolution(&resolution).await.unwrap();

        let built_in = SecretMetadataReference {
            id: "built-in-token".into(),
            tenant_id: project.tenant_id.clone(),
            scope: SecretScope::workspace(&project.tenant_id).durable_key(),
            name: "BUILT_IN".into(),
            provider: "built-in".into(),
            provider_reference: None,
            secret_type: "opaque".into(),
            status: "active".into(),
            current_version: Some(1),
            created_unix_ms: 5,
            updated_unix_ms: 5,
        };
        let first = SecretPlaintext::new(b"first".to_vec());
        assert!(
            !store
                .create_secret("built-in-create", &built_in, Some(&first), &key)
                .await
                .unwrap()
                .replayed
        );
        let second = SecretPlaintext::new(b"second".to_vec());
        let rotated = store
            .rotate_secret(
                "built-in-rotate",
                &built_in.tenant_id,
                &built_in.scope,
                &built_in.name,
                &second,
                &key,
                6,
            )
            .await
            .unwrap();
        assert_eq!(rotated.value.current_version, Some(2));
        assert!(
            store
                .rotate_secret(
                    "built-in-rotate",
                    &built_in.tenant_id,
                    &built_in.scope,
                    &built_in.name,
                    &second,
                    &key,
                    6
                )
                .await
                .unwrap()
                .replayed
        );
        assert_eq!(
            store
                .secrets(&built_in.tenant_id, &built_in.scope)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .delete_secret_configuration(
                    &built_in.tenant_id,
                    &built_in.scope,
                    &built_in.name,
                    &key,
                    7
                )
                .await
                .unwrap()
                .status,
            "tombstoned"
        );

        let first_variable = store
            .put_variable(
                "variable-one",
                &project.tenant_id,
                "repository:release-repository",
                "CHANNEL",
                serde_json::json!({"b":2,"a":1}),
                8,
            )
            .await
            .unwrap();
        assert_eq!(first_variable.value.version, 1);
        assert!(
            store
                .put_variable(
                    "variable-one",
                    &project.tenant_id,
                    "repository:release-repository",
                    "CHANNEL",
                    serde_json::json!({"a":1,"b":2}),
                    8
                )
                .await
                .unwrap()
                .replayed
        );
        let second_variable = store
            .put_variable(
                "variable-two",
                &project.tenant_id,
                "repository:release-repository",
                "CHANNEL",
                serde_json::json!("stable"),
                9,
            )
            .await
            .unwrap();
        assert_eq!(second_variable.value.version, 2);
        assert_eq!(
            store
                .variable_record(
                    &project.tenant_id,
                    "repository:release-repository",
                    "CHANNEL"
                )
                .await
                .unwrap(),
            second_variable.value
        );
        assert_eq!(
            store
                .variable_records(&project.tenant_id, "repository:release-repository")
                .await
                .unwrap()
                .len(),
            1
        );
        let values = BTreeMap::from([("CHANNEL".into(), serde_json::json!("stable"))]);
        let snapshot = store
            .create_snapshot(
                "snapshot",
                &project.tenant_id,
                "repository:release-repository",
                1,
                values,
                10,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .latest_snapshot(&project.tenant_id, "repository:release-repository")
                .await
                .unwrap(),
            snapshot
        );
        store
            .delete_variable_record(
                &project.tenant_id,
                "repository:release-repository",
                "CHANNEL",
            )
            .await
            .unwrap();
    }

    fn policy_user(id: &str) -> HumanUserRecord {
        HumanUserRecord {
            id: id.into(),
            display_name: id.into(),
            primary_email: format!("{id}@example.test"),
            status: "active".into(),
            created_unix_ms: 20,
            updated_unix_ms: 20,
            last_seen_unix_ms: Some(20),
            version: 1,
        }
    }

    fn policy_membership(user: &str) -> TenantMembershipRecord {
        let mut value = TenantMembershipRecord {
            id: format!("membership-{user}"),
            tenant_id: "policy-tenant".into(),
            user_id: user.into(),
            role_template: "policy-admin".into(),
            attributes: serde_json::json!({"source":"contract"}),
            attributes_digest: runtrue_model::ContentDigest::sha256([]),
            status: "active".into(),
            created_unix_ms: 20,
            updated_unix_ms: 20,
            version: 1,
        };
        value.attributes_digest = value.expected_attributes_digest().unwrap();
        value
    }

    fn policy_case() -> PolicySimulationCase {
        PolicySimulationCase {
            id: "case".into(),
            request: CedarAuthorizationRequest {
                principal: CedarPrincipal {
                    kind: CedarPrincipalKind::User,
                    id: "author".into(),
                    tenant_id: "policy-tenant".into(),
                    groups: BTreeSet::new(),
                },
                action: CedarAction::ViewRepository,
                resource: CedarResource {
                    kind: CedarResourceKind::Repository,
                    id: "repo".into(),
                    tenant_id: "policy-tenant".into(),
                    repository_id: Some("repo".into()),
                    author_id: None,
                    risk_score: 0,
                    privileged: false,
                    untrusted: false,
                },
                context: CedarRequestContext::default(),
            },
            expected_allowed: Some(true),
        }
    }

    fn audit(actor: &str, correlation: &str, time: u64) -> R9AuditMetadata {
        R9AuditMetadata {
            actor_id: actor.into(),
            correlation_id: correlation.into(),
            occurred_unix_ms: time,
        }
    }

    async fn policy_contract(
        store: &(impl PolicyVersionStore
              + PolicyLifecycleStore
              + TenantIdentityStore
              + HumanIdentityStore),
    ) {
        let tenant = TenantIdentityRecord {
            id: "policy-tenant".into(),
            slug: "policy-tenant".into(),
            name: "Policy tenant".into(),
            status: "active".into(),
            settings: serde_json::json!({}),
            created_unix_ms: 20,
            updated_unix_ms: 20,
            version: 1,
        };
        store.put_tenant_identity(&tenant, None).await.unwrap();
        for user in ["author", "reviewer"] {
            store
                .put_human_user(&tenant.id, &policy_user(user), None)
                .await
                .unwrap();
            store
                .put_membership(&policy_membership(user), None)
                .await
                .unwrap();
        }
        let source =
            "permit (principal, action == Action::\"ViewRepository\", resource is Repository);";
        let version = PolicyVersionRecord {
            id: "policy-version".into(),
            policy_id: "main".into(),
            version: 1,
            source: source.into(),
            mode: "draft".into(),
            digest: runtrue_model::ContentDigest::sha256(source.as_bytes()),
            created_unix_ms: 21,
        };
        assert!(
            !store
                .create_policy_version("version", &version)
                .await
                .unwrap()
                .replayed
        );
        assert!(
            store
                .create_policy_version("version", &version)
                .await
                .unwrap()
                .replayed
        );
        assert_eq!(store.next_policy_version_number("main").await.unwrap(), 2);
        let mut state = ActivePolicyBundleState::new(&tenant.id).unwrap();
        let mut draft = PolicyBundleDraft::new("draft", &tenant.id, "author", source, 22).unwrap();
        assert!(store
            .persist_draft(&draft, &audit("author", "draft", 22))
            .await
            .unwrap());
        assert!(!store
            .persist_draft(&draft, &audit("author", "draft", 22))
            .await
            .unwrap());
        let simulation = state.simulate(&mut draft, &[policy_case()], &[]).unwrap();
        assert!(store
            .persist_simulation(&draft, &simulation, &audit("author", "simulation", 23))
            .await
            .unwrap());
        draft.enter_shadow(&simulation.report_digest).unwrap();
        let shadow = state.compare_shadow(&draft, &[policy_case()]).unwrap();
        assert!(store
            .persist_shadow(&draft, Some(&shadow), &audit("author", "shadow", 24))
            .await
            .unwrap());
        let activation = ActivatePolicyBundle {
            draft_digest: draft.digest.clone(),
            simulation_digest: simulation.report_digest.clone(),
            expected_policy_epoch: 0,
            approval_id: "approval".into(),
            approved_by: "reviewer".into(),
            approved_unix_ms: 25,
        };
        state.activate(&mut draft, &activation).unwrap();
        assert!(store
            .activate_policy(
                &draft,
                &state,
                &activation,
                &audit("reviewer", "activation", 25)
            )
            .await
            .unwrap());
        assert!(!store
            .activate_policy(
                &draft,
                &state,
                &activation,
                &audit("reviewer", "activation", 25)
            )
            .await
            .unwrap());
        assert_eq!(store.active_state(&tenant.id).await.unwrap(), state);
        let previous = state.decision_cache_generation;
        state
            .replace_emergency_denies(
                DenyFirstPolicy {
                    emergency_denies: vec![EmergencyDeny {
                        id: "halt".into(),
                        actions: BTreeSet::from(["ViewRepository".into()]),
                        repository_id: Some("repo".into()),
                        minimum_risk_score: None,
                        deny_privileged: false,
                        deny_untrusted: false,
                    }],
                },
                previous,
            )
            .unwrap();
        assert!(store
            .replace_denies(&state, previous, &audit("reviewer", "deny", 26))
            .await
            .unwrap());
        assert!(!store
            .replace_denies(&state, previous, &audit("reviewer", "deny", 26))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn sqlite_configuration_contract() {
        let store = ControlPlane::open_in_memory("configuration-contract", 1).unwrap();
        configuration_contract(&store).await;
    }

    #[tokio::test]
    async fn sqlite_policy_contract() {
        let store = ControlPlane::open_in_memory("policy-contract", 1).unwrap();
        policy_contract(&store).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_configuration_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "configuration").await;
        let store =
            PostgresInstallationStore::connect(fixture.config(), "configuration-contract", 1)
                .await
                .unwrap();
        configuration_contract(&store).await;
        assert!(sqlx::query("UPDATE variable_versions SET value_json=$1")
            .bind(b"null".as_slice())
            .execute(store.pool())
            .await
            .is_err());
        assert!(sqlx::query("DELETE FROM variable_snapshots")
            .execute(store.pool())
            .await
            .is_err());
        store.close().await;
        fixture.cleanup().await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_policy_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "policy").await;
        let store = PostgresInstallationStore::connect(fixture.config(), "policy-contract", 1)
            .await
            .unwrap();
        policy_contract(&store).await;
        assert!(sqlx::query("DELETE FROM policy_activations")
            .execute(store.pool())
            .await
            .is_err());
        assert!(
            sqlx::query("UPDATE policy_simulation_reports SET corpus_digest='bad'")
                .execute(store.pool())
                .await
                .is_err()
        );
        assert!(sqlx::query("DELETE FROM policy_shadow_reports")
            .execute(store.pool())
            .await
            .is_err());
        assert!(
            sqlx::query("UPDATE emergency_deny_replacements SET deny_digest='bad'")
                .execute(store.pool())
                .await
                .is_err()
        );
        sqlx::query(
            "UPDATE tenant_policy_states SET state_digest='bad' WHERE tenant_id='policy-tenant'",
        )
        .execute(store.pool())
        .await
        .unwrap();
        assert!(matches!(
            store.active_state("policy-tenant").await,
            Err(ControlPlaneError::CorruptState(_))
        ));
        store.close().await;
        fixture.cleanup().await;
    }
}
