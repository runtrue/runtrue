use super::StoreFuture;
#[cfg(feature = "postgres")]
use crate::ControlPlaneError;
use crate::{ControlPlane, R9AuditMetadata};
#[cfg(feature = "postgres")]
use runtrue_auth::OidcTransactionStatus;
use runtrue_auth::{OidcAuthorizationTransaction, SessionRecord};

#[cfg(feature = "postgres")]
use super::PostgresInstallationStore;
#[cfg(any(feature = "postgres", test))]
use runtrue_model::ContentDigest;
#[cfg(feature = "postgres")]
use sqlx::{Postgres, Row as _, Transaction};

#[cfg(feature = "postgres")]
pub(super) const POSTGRES_MIGRATION: &str =
    include_str!("../../migrations/postgres/0007_browser_sessions.sql");

/// One-use OIDC transactions and browser session refresh families are one
/// boundary because every state mutation must append its immutable journal
/// event in the same database transaction.
pub trait BrowserSessionStore: Send + Sync {
    fn persist_oidc_transaction<'a>(
        &'a self,
        record: &'a OidcAuthorizationTransaction,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool>;
    fn oidc_transaction<'a>(
        &'a self,
        tenant_id: &'a str,
        transaction_id: &'a str,
    ) -> StoreFuture<'a, OidcAuthorizationTransaction>;
    fn persist_session<'a>(
        &'a self,
        record: &'a SessionRecord,
        expected_generation: Option<u64>,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool>;
    fn session<'a>(
        &'a self,
        tenant_id: &'a str,
        session_id: &'a str,
    ) -> StoreFuture<'a, SessionRecord>;
}

impl BrowserSessionStore for ControlPlane {
    fn persist_oidc_transaction<'a>(
        &'a self,
        record: &'a OidcAuthorizationTransaction,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        let result = self.persist_oidc_browser_transaction(record, audit);
        Box::pin(async move { result })
    }

    fn oidc_transaction<'a>(
        &'a self,
        tenant_id: &'a str,
        transaction_id: &'a str,
    ) -> StoreFuture<'a, OidcAuthorizationTransaction> {
        let result = self.oidc_browser_transaction(tenant_id, transaction_id);
        Box::pin(async move { result })
    }

    fn persist_session<'a>(
        &'a self,
        record: &'a SessionRecord,
        expected_generation: Option<u64>,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        let result = self.persist_browser_session(record, expected_generation, audit);
        Box::pin(async move { result })
    }

    fn session<'a>(
        &'a self,
        tenant_id: &'a str,
        session_id: &'a str,
    ) -> StoreFuture<'a, SessionRecord> {
        let result = self.browser_session(tenant_id, session_id);
        Box::pin(async move { result })
    }
}

#[cfg(feature = "postgres")]
impl BrowserSessionStore for PostgresInstallationStore {
    fn persist_oidc_transaction<'a>(
        &'a self,
        record: &'a OidcAuthorizationTransaction,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            record.validate()?;
            validate_audit(audit, record.created_unix_ms)?;
            if audit.occurred_unix_ms >= record.expires_unix_ms
                && record.status != OidcTransactionStatus::Expired
            {
                return Err(ControlPlaneError::InvalidInput(
                    "non-expired OIDC transaction recorded after expiry",
                ));
            }
            let bytes = bounded_json(record, 262_144, "OIDC browser transaction")?;
            let digest = record_digest(b"runtrue.oidc-browser-transaction.v1\0", &bytes);
            let mut tx = self.pool().begin().await?;
            let provider = sqlx::query(
                "SELECT issuer,client_id,redirect_uri,status,configuration_digest,version
                 FROM tenant_oidc_provider_configs
                 WHERE tenant_id=$1 AND id=$2 FOR SHARE",
            )
            .bind(&record.tenant_id)
            .bind(&record.provider_configuration_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                not_found(
                    "OIDC provider configuration",
                    &record.provider_configuration_id,
                )
            })?;
            if provider.try_get::<String, _>("issuer")? != record.issuer
                || provider.try_get::<String, _>("client_id")? != record.client_id
                || provider.try_get::<String, _>("redirect_uri")? != record.redirect_uri
                || provider.try_get::<String, _>("status")? != "active"
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let provider_digest: String = provider.try_get("configuration_digest")?;
            let provider_version: i64 = provider.try_get("version")?;
            if let Some(existing) = load_oidc(&mut tx, &record.tenant_id, &record.id, true).await? {
                if existing == *record {
                    tx.commit().await?;
                    return Ok(false);
                }
                if !same_oidc_binding(&existing, record)
                    || !valid_oidc_transition(existing.status, record.status)
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let changed = sqlx::query(
                    "UPDATE oidc_browser_transactions SET record_digest=$3,record_json=$4,
                     status=$5,updated_unix_ms=$6,audit_correlation_id=$7
                     WHERE tenant_id=$1 AND id=$2 AND provider_configuration_digest=$8
                       AND provider_configuration_version=$9",
                )
                .bind(&record.tenant_id)
                .bind(&record.id)
                .bind(digest.as_str())
                .bind(&bytes)
                .bind(status_name(record.status))
                .bind(i64v(audit.occurred_unix_ms, "OIDC audit time")?)
                .bind(&audit.correlation_id)
                .bind(&provider_digest)
                .bind(provider_version)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            } else {
                if record.status != OidcTransactionStatus::Pending {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                sqlx::query(
                    "INSERT INTO oidc_browser_transactions
                     (id,tenant_id,provider_configuration_id,provider_configuration_digest,
                      provider_configuration_version,state_digest,nonce_digest,pkce_verifier_digest,
                      record_digest,record_json,status,expires_unix_ms,audit_correlation_id,
                      created_unix_ms,updated_unix_ms)
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending',$11,$12,$13,$14)",
                )
                .bind(&record.id)
                .bind(&record.tenant_id)
                .bind(&record.provider_configuration_id)
                .bind(&provider_digest)
                .bind(provider_version)
                .bind(record.state_digest.storage_key())
                .bind(record.nonce_digest.storage_key())
                .bind(record.pkce_verifier_digest.storage_key())
                .bind(digest.as_str())
                .bind(&bytes)
                .bind(i64v(record.expires_unix_ms, "OIDC expiry")?)
                .bind(&audit.correlation_id)
                .bind(i64v(record.created_unix_ms, "OIDC creation")?)
                .bind(i64v(audit.occurred_unix_ms, "OIDC audit time")?)
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query(
                "INSERT INTO oidc_browser_transaction_events
                 (transaction_id,tenant_id,status,record_digest,audit_correlation_id,occurred_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6)",
            )
            .bind(&record.id).bind(&record.tenant_id).bind(status_name(record.status))
            .bind(digest.as_str()).bind(&audit.correlation_id)
            .bind(i64v(audit.occurred_unix_ms, "OIDC event time")?)
            .execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }

    fn oidc_transaction<'a>(
        &'a self,
        tenant_id: &'a str,
        transaction_id: &'a str,
    ) -> StoreFuture<'a, OidcAuthorizationTransaction> {
        Box::pin(async move {
            validate_text(tenant_id)?;
            validate_text(transaction_id)?;
            let mut tx = self.pool().begin().await?;
            let record = load_oidc(&mut tx, tenant_id, transaction_id, false)
                .await?
                .ok_or_else(|| not_found("OIDC browser transaction", transaction_id))?;
            tx.commit().await?;
            Ok(record)
        })
    }

    fn persist_session<'a>(
        &'a self,
        record: &'a SessionRecord,
        expected_generation: Option<u64>,
        audit: &'a R9AuditMetadata,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            record.validate()?;
            validate_audit(audit, record.created_unix_ms)?;
            let bytes = bounded_json(record, 2 * 1024 * 1024, "browser session")?;
            let digest = record_digest(b"runtrue.browser-session-record.v1\0", &bytes);
            let mut tx = self.pool().begin().await?;
            require_active_principal(&mut tx, &record.tenant_id, &record.principal_id).await?;
            let existing = load_session(&mut tx, &record.tenant_id, &record.id, true).await?;
            let event_kind;
            if let Some(existing) = existing {
                if existing == *record {
                    tx.commit().await?;
                    return Ok(false);
                }
                if expected_generation != Some(existing.access_generation) {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                event_kind = valid_session_transition(&existing, record)
                    .ok_or(ControlPlaneError::IdempotencyConflict)?;
                if event_kind == "rotated" {
                    let changed = sqlx::query(
                        "UPDATE browser_refresh_family_tokens SET status='consumed',consumed_unix_ms=$3
                         WHERE tenant_id=$1 AND session_id=$2 AND status='active'
                           AND generation=$4 AND refresh_digest=$5",
                    ).bind(&record.tenant_id).bind(&record.id)
                    .bind(i64v(audit.occurred_unix_ms, "refresh consumption")?)
                    .bind(i64v(existing.access_generation, "access generation")?)
                    .bind(existing.refresh_digest.storage_key()).execute(&mut *tx).await?.rows_affected();
                    if changed != 1 {
                        return Err(ControlPlaneError::IdempotencyConflict);
                    }
                    sqlx::query(
                        "INSERT INTO browser_refresh_family_tokens
                         (session_id,tenant_id,generation,refresh_digest,status,created_unix_ms)
                         VALUES($1,$2,$3,$4,'active',$5)",
                    )
                    .bind(&record.id)
                    .bind(&record.tenant_id)
                    .bind(i64v(record.access_generation, "access generation")?)
                    .bind(record.refresh_digest.storage_key())
                    .bind(i64v(audit.occurred_unix_ms, "refresh creation")?)
                    .execute(&mut *tx)
                    .await?;
                } else if event_kind == "revoked" {
                    sqlx::query(
                        "UPDATE browser_refresh_family_tokens SET status='revoked',consumed_unix_ms=$3
                         WHERE tenant_id=$1 AND session_id=$2 AND status='active'",
                    ).bind(&record.tenant_id).bind(&record.id)
                    .bind(i64v(record.revoked_unix_ms.unwrap_or(audit.occurred_unix_ms), "session revocation")?)
                    .execute(&mut *tx).await?;
                }
                let changed = sqlx::query(
                    "UPDATE browser_sessions SET access_generation=$3,access_digest=$4,
                     refresh_digest=$5,csrf_digest=$6,record_digest=$7,record_json=$8,
                     access_expires_unix_ms=$9,refresh_expires_unix_ms=$10,revoked_unix_ms=$11,
                     audit_correlation_id=$12,updated_unix_ms=$13
                     WHERE tenant_id=$1 AND id=$2 AND access_generation=$14",
                )
                .bind(&record.tenant_id)
                .bind(&record.id)
                .bind(i64v(record.access_generation, "access generation")?)
                .bind(record.access_digest.storage_key())
                .bind(record.refresh_digest.storage_key())
                .bind(record.csrf_digest.storage_key())
                .bind(digest.as_str())
                .bind(&bytes)
                .bind(i64v(record.access_expires_unix_ms, "access expiry")?)
                .bind(i64v(record.refresh_expires_unix_ms, "refresh expiry")?)
                .bind(opt_i64(record.revoked_unix_ms, "session revocation")?)
                .bind(&audit.correlation_id)
                .bind(i64v(audit.occurred_unix_ms, "session update")?)
                .bind(i64v(existing.access_generation, "expected generation")?)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            } else {
                if expected_generation.is_some() || record.access_generation != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                event_kind = "created";
                sqlx::query(
                    "INSERT INTO browser_sessions
                     (id,tenant_id,user_id,device_id,access_generation,access_digest,refresh_digest,
                      csrf_digest,record_digest,record_json,access_expires_unix_ms,
                      refresh_expires_unix_ms,absolute_expires_unix_ms,revoked_unix_ms,
                      audit_correlation_id,created_unix_ms,updated_unix_ms)
                     VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
                )
                .bind(&record.id)
                .bind(&record.tenant_id)
                .bind(&record.principal_id)
                .bind(&record.device_id)
                .bind(record.access_digest.storage_key())
                .bind(record.refresh_digest.storage_key())
                .bind(record.csrf_digest.storage_key())
                .bind(digest.as_str())
                .bind(&bytes)
                .bind(i64v(record.access_expires_unix_ms, "access expiry")?)
                .bind(i64v(record.refresh_expires_unix_ms, "refresh expiry")?)
                .bind(i64v(record.absolute_expires_unix_ms, "absolute expiry")?)
                .bind(opt_i64(record.revoked_unix_ms, "session revocation")?)
                .bind(&audit.correlation_id)
                .bind(i64v(record.created_unix_ms, "session creation")?)
                .bind(i64v(audit.occurred_unix_ms, "session update")?)
                .execute(&mut *tx)
                .await?;
                let status = if record.revoked_unix_ms.is_some() {
                    "revoked"
                } else {
                    "active"
                };
                sqlx::query(
                    "INSERT INTO browser_refresh_family_tokens
                     (session_id,tenant_id,generation,refresh_digest,status,created_unix_ms,consumed_unix_ms)
                     VALUES($1,$2,1,$3,$4,$5,$6)",
                ).bind(&record.id).bind(&record.tenant_id).bind(record.refresh_digest.storage_key())
                .bind(status).bind(i64v(record.created_unix_ms, "refresh creation")?)
                .bind(opt_i64(record.revoked_unix_ms, "session revocation")?)
                .execute(&mut *tx).await?;
            }
            let event_bytes = bounded_json(
                &(
                    &record.tenant_id,
                    &record.id,
                    event_kind,
                    record.access_generation,
                    &digest,
                    &audit.correlation_id,
                    audit.occurred_unix_ms,
                ),
                65_536,
                "browser session event",
            )?;
            let event_digest = record_digest(b"runtrue.browser-session-event.v1\0", &event_bytes);
            sqlx::query(
                "INSERT INTO browser_session_events
                 (session_id,tenant_id,event_digest,event_kind,access_generation,
                  audit_correlation_id,occurred_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(&record.id)
            .bind(&record.tenant_id)
            .bind(event_digest.as_str())
            .bind(event_kind)
            .bind(i64v(record.access_generation, "event generation")?)
            .bind(&audit.correlation_id)
            .bind(i64v(audit.occurred_unix_ms, "event time")?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(true)
        })
    }

    fn session<'a>(
        &'a self,
        tenant_id: &'a str,
        session_id: &'a str,
    ) -> StoreFuture<'a, SessionRecord> {
        Box::pin(async move {
            validate_text(tenant_id)?;
            validate_text(session_id)?;
            let mut tx = self.pool().begin().await?;
            let record = load_session(&mut tx, tenant_id, session_id, false)
                .await?
                .ok_or_else(|| not_found("browser session", session_id))?;
            require_active_principal(&mut tx, tenant_id, &record.principal_id).await?;
            tx.commit().await?;
            Ok(record)
        })
    }
}

#[cfg(feature = "postgres")]
fn status_name(status: OidcTransactionStatus) -> &'static str {
    match status {
        OidcTransactionStatus::Pending => "pending",
        OidcTransactionStatus::Exchanging => "exchanging",
        OidcTransactionStatus::Consumed => "consumed",
        OidcTransactionStatus::Rejected => "rejected",
        OidcTransactionStatus::Expired => "expired",
    }
}

#[cfg(feature = "postgres")]
fn valid_oidc_transition(old: OidcTransactionStatus, new: OidcTransactionStatus) -> bool {
    matches!(
        (old, new),
        (
            OidcTransactionStatus::Pending,
            OidcTransactionStatus::Exchanging
                | OidcTransactionStatus::Rejected
                | OidcTransactionStatus::Expired
        ) | (
            OidcTransactionStatus::Exchanging,
            OidcTransactionStatus::Consumed
                | OidcTransactionStatus::Rejected
                | OidcTransactionStatus::Expired
        )
    )
}

#[cfg(feature = "postgres")]
fn same_oidc_binding(
    old: &OidcAuthorizationTransaction,
    new: &OidcAuthorizationTransaction,
) -> bool {
    old.id == new.id
        && old.tenant_id == new.tenant_id
        && old.provider_configuration_id == new.provider_configuration_id
        && old.issuer == new.issuer
        && old.client_id == new.client_id
        && old.redirect_uri == new.redirect_uri
        && old.state_digest == new.state_digest
        && old.nonce_digest == new.nonce_digest
        && old.pkce_verifier_digest == new.pkce_verifier_digest
        && old.pkce_challenge == new.pkce_challenge
        && old.created_unix_ms == new.created_unix_ms
        && old.expires_unix_ms == new.expires_unix_ms
}

#[cfg(feature = "postgres")]
fn valid_session_transition(old: &SessionRecord, new: &SessionRecord) -> Option<&'static str> {
    fn monotonic(old: Option<u64>, new: Option<u64>) -> bool {
        !matches!((old, new), (Some(_), None)) && old.zip(new).is_none_or(|(a, b)| b >= a)
    }
    if old.id != new.id
        || old.tenant_id != new.tenant_id
        || old.principal_id != new.principal_id
        || old.device_id != new.device_id
        || old.scopes != new.scopes
        || old.created_unix_ms != new.created_unix_ms
        || old.absolute_expires_unix_ms != new.absolute_expires_unix_ms
        || old.revoked_unix_ms.is_some()
        || !monotonic(old.mfa_authenticated_unix_ms, new.mfa_authenticated_unix_ms)
        || !monotonic(old.reauthenticated_unix_ms, new.reauthenticated_unix_ms)
    {
        return None;
    }
    if new.access_generation == old.access_generation.checked_add(1)?
        && new.revoked_unix_ms.is_none()
        && new.used_refresh_digests.len() == old.used_refresh_digests.len().checked_add(1)?
        && new
            .used_refresh_digests
            .starts_with(&old.used_refresh_digests)
        && new.used_refresh_digests.last() == Some(&old.refresh_digest)
    {
        return Some("rotated");
    }
    if new.access_generation == old.access_generation
        && new.access_digest == old.access_digest
        && new.refresh_digest == old.refresh_digest
        && new.csrf_digest == old.csrf_digest
        && new.access_expires_unix_ms == old.access_expires_unix_ms
        && new.refresh_expires_unix_ms == old.refresh_expires_unix_ms
        && new.used_refresh_digests == old.used_refresh_digests
    {
        return new
            .revoked_unix_ms
            .map_or(Some("reauthenticated"), |_| Some("revoked"));
    }
    None
}

#[cfg(feature = "postgres")]
async fn load_oidc(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: &str,
    locked: bool,
) -> Result<Option<OidcAuthorizationTransaction>, ControlPlaneError> {
    let suffix = if locked { " FOR UPDATE" } else { "" };
    let query = format!(
        "SELECT provider_configuration_id,provider_configuration_digest,
        provider_configuration_version,state_digest,nonce_digest,pkce_verifier_digest,
        record_digest,record_json,status,expires_unix_ms FROM oidc_browser_transactions
        WHERE tenant_id=$1 AND id=$2{suffix}"
    );
    let Some(row) = sqlx::query(&query)
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };
    let bytes: Vec<u8> = row.try_get("record_json")?;
    if bytes.len() > 262_144 {
        return Err(corrupt(
            "OIDC browser transaction exceeds its durable bound",
        ));
    }
    let record: OidcAuthorizationTransaction = serde_json::from_slice(&bytes)?;
    record.validate()?;
    let digest = record_digest(b"runtrue.oidc-browser-transaction.v1\0", &bytes);
    if record.tenant_id != tenant
        || record.id != id
        || record.provider_configuration_id
            != row.try_get::<String, _>("provider_configuration_id")?
        || ContentDigest::parse(row.try_get::<String, _>("provider_configuration_digest")?).is_err()
        || row.try_get::<i64, _>("provider_configuration_version")? < 1
        || record.state_digest.storage_key() != row.try_get::<String, _>("state_digest")?
        || record.nonce_digest.storage_key() != row.try_get::<String, _>("nonce_digest")?
        || record.pkce_verifier_digest.storage_key()
            != row.try_get::<String, _>("pkce_verifier_digest")?
        || digest.as_str() != row.try_get::<String, _>("record_digest")?
        || status_name(record.status) != row.try_get::<String, _>("status")?
        || i64v(record.expires_unix_ms, "OIDC expiry")?
            != row.try_get::<i64, _>("expires_unix_ms")?
    {
        return Err(corrupt("OIDC browser transaction durable binding changed"));
    }
    Ok(Some(record))
}

#[cfg(feature = "postgres")]
async fn load_session(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: &str,
    locked: bool,
) -> Result<Option<SessionRecord>, ControlPlaneError> {
    let suffix = if locked { " FOR UPDATE" } else { "" };
    let query = format!(
        "SELECT user_id,device_id,access_generation,access_digest,refresh_digest,
        csrf_digest,record_digest,record_json,access_expires_unix_ms,refresh_expires_unix_ms,
        absolute_expires_unix_ms,revoked_unix_ms FROM browser_sessions
        WHERE tenant_id=$1 AND id=$2{suffix}"
    );
    let Some(row) = sqlx::query(&query)
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };
    let bytes: Vec<u8> = row.try_get("record_json")?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(corrupt("browser session exceeds its durable bound"));
    }
    let record: SessionRecord = serde_json::from_slice(&bytes)?;
    record.validate()?;
    let digest = record_digest(b"runtrue.browser-session-record.v1\0", &bytes);
    if record.tenant_id != tenant
        || record.id != id
        || record.principal_id != row.try_get::<String, _>("user_id")?
        || record.device_id != row.try_get::<String, _>("device_id")?
        || i64v(record.access_generation, "access generation")?
            != row.try_get::<i64, _>("access_generation")?
        || record.access_digest.storage_key() != row.try_get::<String, _>("access_digest")?
        || record.refresh_digest.storage_key() != row.try_get::<String, _>("refresh_digest")?
        || record.csrf_digest.storage_key() != row.try_get::<String, _>("csrf_digest")?
        || digest.as_str() != row.try_get::<String, _>("record_digest")?
        || i64v(record.access_expires_unix_ms, "access expiry")?
            != row.try_get::<i64, _>("access_expires_unix_ms")?
        || i64v(record.refresh_expires_unix_ms, "refresh expiry")?
            != row.try_get::<i64, _>("refresh_expires_unix_ms")?
        || i64v(record.absolute_expires_unix_ms, "absolute expiry")?
            != row.try_get::<i64, _>("absolute_expires_unix_ms")?
        || opt_i64(record.revoked_unix_ms, "revocation")?
            != row.try_get::<Option<i64>, _>("revoked_unix_ms")?
    {
        return Err(corrupt("browser session durable binding changed"));
    }
    Ok(Some(record))
}

#[cfg(feature = "postgres")]
async fn require_active_principal(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    user: &str,
) -> Result<(), ControlPlaneError> {
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(
        SELECT 1 FROM human_users u
        JOIN human_user_tenant_bindings b ON b.user_id=u.id AND b.tenant_id=$1
        JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=b.tenant_id
        WHERE u.id=$2 AND u.status='active' AND m.status='active')",
    )
    .bind(tenant)
    .bind(user)
    .fetch_one(&mut **tx)
    .await?;
    if !active {
        return Err(not_found("active browser principal", user));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_audit(audit: &R9AuditMetadata, created: u64) -> Result<(), ControlPlaneError> {
    validate_text(&audit.actor_id)?;
    validate_text(&audit.correlation_id)?;
    if audit.occurred_unix_ms < created {
        return Err(ControlPlaneError::InvalidInput(
            "browser audit time precedes creation",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_text(value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        return Err(ControlPlaneError::InvalidInput("browser persistence text"));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn bounded_json<T: serde::Serialize>(
    value: &T,
    max: usize,
    field: &'static str,
) -> Result<Vec<u8>, ControlPlaneError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > max {
        return Err(ControlPlaneError::InvalidInput(field));
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
fn i64v(value: u64, field: &'static str) -> Result<i64, ControlPlaneError> {
    i64::try_from(value).map_err(|_| ControlPlaneError::IntegerRange { field })
}

#[cfg(feature = "postgres")]
fn opt_i64(value: Option<u64>, field: &'static str) -> Result<Option<i64>, ControlPlaneError> {
    value.map(|value| i64v(value, field)).transpose()
}

#[cfg(feature = "postgres")]
fn not_found(kind: &'static str, id: &str) -> ControlPlaneError {
    ControlPlaneError::NotFound {
        kind,
        id: id.to_owned(),
    }
}

#[cfg(feature = "postgres")]
fn corrupt(message: &str) -> ControlPlaneError {
    ControlPlaneError::CorruptState(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HumanIdentityStore, HumanUserRecord, TenantIdentityRecord, TenantIdentityStore,
        TenantMembershipRecord, TenantOidcProviderConfiguration,
    };
    use runtrue_auth::{
        BeginOidcExchange, IssueOidcAuthorization, IssueSession, RotateSessionRequest,
        SessionPolicy, TokenHasher,
    };
    use std::collections::BTreeSet;

    fn tenant() -> TenantIdentityRecord {
        TenantIdentityRecord {
            id: "browser-tenant".to_owned(),
            slug: "browser-tenant".to_owned(),
            name: "Browser tenant".to_owned(),
            status: "active".to_owned(),
            settings: serde_json::json!({}),
            created_unix_ms: 1,
            updated_unix_ms: 1,
            version: 1,
        }
    }

    fn provider() -> TenantOidcProviderConfiguration {
        let mut record = TenantOidcProviderConfiguration {
            id: "browser-provider".to_owned(),
            tenant_id: "browser-tenant".to_owned(),
            issuer: "https://id.browser.test".to_owned(),
            client_id: "browser-client".to_owned(),
            authorization_endpoint: "https://id.browser.test/authorize".to_owned(),
            token_endpoint: "https://id.browser.test/token".to_owned(),
            jwks_uri: "https://id.browser.test/keys".to_owned(),
            redirect_uri: "https://runtrue.browser.test/callback".to_owned(),
            scopes: vec!["openid".to_owned()],
            mfa_claim: serde_json::json!({}),
            status: "active".to_owned(),
            configuration_digest: ContentDigest::sha256([]),
            created_unix_ms: 10,
            updated_unix_ms: 10,
            version: 1,
        };
        record.configuration_digest = record.expected_configuration_digest().unwrap();
        record
    }

    fn audit(correlation_id: &str, occurred_unix_ms: u64) -> R9AuditMetadata {
        R9AuditMetadata {
            actor_id: "browser-user".to_owned(),
            correlation_id: correlation_id.to_owned(),
            occurred_unix_ms,
        }
    }

    async fn contract(
        store: &(impl BrowserSessionStore + TenantIdentityStore + HumanIdentityStore),
    ) {
        let _ = store.put_tenant_identity(&tenant(), None).await;
        let provider = provider();
        assert!(store.put_oidc_provider(&provider, None).await.unwrap());
        let user = HumanUserRecord {
            id: "browser-user".to_owned(),
            display_name: "Browser User".to_owned(),
            primary_email: "browser@example.test".to_owned(),
            status: "active".to_owned(),
            created_unix_ms: 20,
            updated_unix_ms: 20,
            last_seen_unix_ms: None,
            version: 1,
        };
        assert!(store
            .put_human_user("browser-tenant", &user, None)
            .await
            .unwrap());
        let mut membership = TenantMembershipRecord {
            id: "browser-membership".to_owned(),
            tenant_id: "browser-tenant".to_owned(),
            user_id: user.id.clone(),
            role_template: "viewer".to_owned(),
            attributes: serde_json::json!({}),
            attributes_digest: ContentDigest::sha256([]),
            status: "active".to_owned(),
            created_unix_ms: 21,
            updated_unix_ms: 21,
            version: 1,
        };
        membership.attributes_digest = membership.expected_attributes_digest().unwrap();
        assert!(store.put_membership(&membership, None).await.unwrap());

        let hasher = TokenHasher::from_key([17; 32]);
        let issued = OidcAuthorizationTransaction::issue(
            &hasher,
            IssueOidcAuthorization {
                id: "browser-login".to_owned(),
                tenant_id: "browser-tenant".to_owned(),
                provider_configuration_id: provider.id.clone(),
                issuer: provider.issuer.clone(),
                client_id: provider.client_id.clone(),
                redirect_uri: provider.redirect_uri.clone(),
                created_unix_ms: 100,
                expires_unix_ms: 200,
            },
        )
        .unwrap();
        let state = issued.state.expose().to_owned();
        let verifier = issued.pkce_verifier.expose().to_owned();
        let mut login = issued.record;
        assert!(store
            .persist_oidc_transaction(&login, &audit("login-created", 100))
            .await
            .unwrap());
        assert!(!store
            .persist_oidc_transaction(&login, &audit("login-created", 100))
            .await
            .unwrap());
        login
            .begin_exchange(
                &hasher,
                BeginOidcExchange {
                    tenant_id: "browser-tenant",
                    provider_configuration_id: &provider.id,
                    issuer: &provider.issuer,
                    client_id: &provider.client_id,
                    redirect_uri: &provider.redirect_uri,
                    state: &state,
                    pkce_verifier: &verifier,
                    now_unix_ms: 101,
                },
            )
            .unwrap();
        assert!(store
            .persist_oidc_transaction(&login, &audit("login-exchange", 101))
            .await
            .unwrap());
        assert_eq!(
            store
                .oidc_transaction("browser-tenant", "browser-login")
                .await
                .unwrap(),
            login
        );

        let issued_session = SessionRecord::issue(
            &hasher,
            SessionPolicy::default(),
            IssueSession {
                id: "browser-session".to_owned(),
                principal_id: user.id,
                tenant_id: "browser-tenant".to_owned(),
                device_id: "browser-device".to_owned(),
                scopes: BTreeSet::from(["runs:read".to_owned()]),
                now_unix_ms: 100,
                mfa_authenticated_unix_ms: Some(100),
            },
        )
        .unwrap();
        let refresh = issued_session.refresh_token.expose().to_owned();
        let csrf = issued_session.csrf_token.expose().to_owned();
        let mut session = issued_session.record;
        assert!(store
            .persist_session(&session, None, &audit("session-created", 100))
            .await
            .unwrap());
        session
            .rotate(
                &hasher,
                SessionPolicy::default(),
                RotateSessionRequest {
                    refresh_token: &refresh,
                    csrf_token: &csrf,
                    require_mfa_within_ms: None,
                    now_unix_ms: 101,
                },
            )
            .unwrap();
        assert!(store
            .persist_session(&session, Some(1), &audit("session-rotated", 101))
            .await
            .unwrap());
        assert_eq!(
            store
                .session("browser-tenant", "browser-session")
                .await
                .unwrap(),
            session
        );
    }

    #[tokio::test]
    async fn sqlite_browser_session_contract() {
        let store = ControlPlane::open_in_memory("browser-contract", 1).unwrap();
        contract(&store).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_browser_session_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "browser-session").await;
        let store = PostgresInstallationStore::connect(fixture.config(), "pg-browser-contract", 1)
            .await
            .unwrap();
        contract(&store).await;

        assert!(
            sqlx::query("UPDATE browser_session_events SET event_kind='revoked'")
                .execute(store.pool())
                .await
                .is_err()
        );
        assert!(sqlx::query("DELETE FROM browser_refresh_family_tokens")
            .execute(store.pool())
            .await
            .is_err());
        store.close().await;
        fixture.cleanup().await;
    }
}
