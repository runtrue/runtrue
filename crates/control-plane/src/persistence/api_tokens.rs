#[cfg(feature = "postgres")]
use super::PostgresInstallationStore;
use super::StoreFuture;
use crate::ControlPlane;
#[cfg(feature = "postgres")]
use crate::ControlPlaneError;
#[cfg(any(feature = "postgres", test))]
use runtrue_audit::verify_chain;
use runtrue_audit::{AuditEvent, AuditEventData, AuditPrincipal};
#[cfg(feature = "postgres")]
use runtrue_audit::{AuditResource, AuditValue};
#[cfg(feature = "postgres")]
use runtrue_auth::AuthError;
use runtrue_auth::{ApiTokenRecord, AuthContext, TokenHasher};
#[cfg(feature = "postgres")]
use runtrue_model::ContentDigest;
#[cfg(feature = "postgres")]
use std::collections::BTreeMap;
#[cfg(any(feature = "postgres", test))]
use std::collections::BTreeSet;

#[cfg(feature = "postgres")]
use sqlx::Row as _;

#[cfg(feature = "postgres")]
pub(super) const POSTGRES_MIGRATION: &str =
    include_str!("../../migrations/postgres/0004_api_tokens_audit.sql");
#[cfg(feature = "postgres")]
const AUDIT_LOCK: i64 = 0x5275_6e54_6175_6401;
#[cfg(feature = "postgres")]
const MAX_ANCESTRY: usize = 32;

pub trait ApiTokenAuditStore: Send + Sync {
    fn create_token<'a>(
        &'a self,
        record: &'a ApiTokenRecord,
        parent: Option<&'a str>,
        actor: AuditPrincipal,
        request_id: &'a str,
    ) -> StoreFuture<'a, ()>;
    fn token<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ApiTokenRecord>;
    fn tokens<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, Vec<ApiTokenRecord>>;
    fn tokens_page<'a>(
        &'a self,
        tenant_id: &'a str,
        after_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ApiTokenRecord>>;
    fn authenticate_token<'a>(
        &'a self,
        hasher: &'a TokenHasher,
        token: &'a str,
        scope: &'a str,
        now: u64,
    ) -> StoreFuture<'a, AuthContext>;
    fn revoke_token<'a>(
        &'a self,
        id: &'a str,
        actor: AuditPrincipal,
        actor_credential: Option<&'a str>,
        request_id: &'a str,
        now: u64,
    ) -> StoreFuture<'a, ApiTokenRecord>;
    fn append_event<'a>(&'a self, data: AuditEventData) -> StoreFuture<'a, AuditEvent>;
    fn events(&self) -> StoreFuture<'_, Vec<AuditEvent>>;
    fn events_page<'a>(
        &'a self,
        action: Option<&'a str>,
        before_sequence: Option<u64>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<AuditEvent>>;
    fn events_page_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        action: Option<&'a str>,
        before_sequence: Option<u64>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<AuditEvent>>;
}

impl ApiTokenAuditStore for ControlPlane {
    fn create_token<'a>(
        &'a self,
        record: &'a ApiTokenRecord,
        parent: Option<&'a str>,
        actor: AuditPrincipal,
        request: &'a str,
    ) -> StoreFuture<'a, ()> {
        let r = match parent {
            Some(p) => self.create_delegated_api_token(record, p, actor, request),
            None => self.create_api_token(record, actor, request),
        };
        Box::pin(async move { r })
    }
    fn token<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ApiTokenRecord> {
        let r = self.api_token(id);
        Box::pin(async move { r })
    }
    fn tokens<'a>(&'a self, tenant: &'a str) -> StoreFuture<'a, Vec<ApiTokenRecord>> {
        let r = self.list_api_tokens(tenant);
        Box::pin(async move { r })
    }
    fn tokens_page<'a>(
        &'a self,
        tenant: &'a str,
        after: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ApiTokenRecord>> {
        let r = self.list_api_tokens_page(tenant, after, limit);
        Box::pin(async move { r })
    }
    fn authenticate_token<'a>(
        &'a self,
        h: &'a TokenHasher,
        t: &'a str,
        s: &'a str,
        n: u64,
    ) -> StoreFuture<'a, AuthContext> {
        let r = self.authenticate_api_token(h, t, s, n);
        Box::pin(async move { r })
    }
    fn revoke_token<'a>(
        &'a self,
        id: &'a str,
        a: AuditPrincipal,
        c: Option<&'a str>,
        r: &'a str,
        n: u64,
    ) -> StoreFuture<'a, ApiTokenRecord> {
        let v = self.revoke_api_token_authenticated(id, a, c, r, n);
        Box::pin(async move { v })
    }
    fn append_event<'a>(&'a self, data: AuditEventData) -> StoreFuture<'a, AuditEvent> {
        let r = self.append_audit_event(data);
        Box::pin(async move { r })
    }
    fn events(&self) -> StoreFuture<'_, Vec<AuditEvent>> {
        let r = self.audit_events();
        Box::pin(async move { r })
    }
    fn events_page<'a>(
        &'a self,
        action: Option<&'a str>,
        before: Option<u64>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<AuditEvent>> {
        let r = self.audit_events_page(action, before, limit);
        Box::pin(async move { r })
    }
    fn events_page_for_tenant<'a>(
        &'a self,
        tenant: &'a str,
        action: Option<&'a str>,
        before: Option<u64>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<AuditEvent>> {
        let r = self.audit_events_page_for_tenant(tenant, action, before, limit);
        Box::pin(async move { r })
    }
}

#[cfg(feature = "postgres")]
impl ApiTokenAuditStore for PostgresInstallationStore {
    fn create_token<'a>(
        &'a self,
        r: &'a ApiTokenRecord,
        parent: Option<&'a str>,
        actor: AuditPrincipal,
        request: &'a str,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            validate_record(r)?;
            validate_text(request)?;
            let scopes = serde_json::to_vec(&r.scopes)?;
            if scopes.len() > 8192 {
                return Err(ControlPlaneError::InvalidInput(
                    "API token scope encoding exceeds its durable bound",
                ));
            }
            let mut tx = self.pool().begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5932164))")
                .bind(&r.tenant_id)
                .execute(&mut *tx)
                .await?;
            if let Some(p) = parent {
                validate_text(p)?;
                validate_ancestry(&mut tx, p, r.created_unix_ms).await?;
                let pr = token_by_id(&mut tx, p).await?;
                if pr.principal_id != r.principal_id
                    || pr.tenant_id != r.tenant_id
                    || !r.scopes.is_subset(&pr.scopes)
                    || r.expires_unix_ms > pr.expires_unix_ms
                {
                    return Err(ControlPlaneError::InvalidInput("delegated API token exceeds its parent identity, tenant, scopes, or expiry"));
                }
            }
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE tenant_id=$1")
                    .bind(&r.tenant_id)
                    .fetch_one(&mut *tx)
                    .await?;
            if count >= 10000 {
                return Err(ControlPlaneError::InvalidInput(
                    "API token limit reached for tenant",
                ));
            }
            sqlx::query("INSERT INTO api_tokens(id,principal_id,tenant_id,name,digest,scopes_json,created_unix_ms,expires_unix_ms,last_used_unix_ms,revoked_unix_ms,parent_token_id)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)").bind(&r.id).bind(&r.principal_id).bind(&r.tenant_id).bind(&r.name).bind(r.digest.storage_key()).bind(scopes).bind(i64v(r.created_unix_ms,"API token creation")?).bind(i64v(r.expires_unix_ms,"API token expiry")?).bind(opt_i64(r.last_used_unix_ms,"API token last use")?).bind(opt_i64(r.revoked_unix_ms,"API token revocation")?).bind(parent).execute(&mut *tx).await?;
            let mut metadata = BTreeMap::from([
                (
                    "principal_id".to_owned(),
                    AuditValue::String(r.principal_id.clone()),
                ),
                (
                    "scope_count".to_owned(),
                    AuditValue::Integer(i64::try_from(r.scopes.len()).map_err(|_| {
                        ControlPlaneError::IntegerRange {
                            field: "API token scope count",
                        }
                    })?),
                ),
            ]);
            if let Some(p) = parent {
                metadata.insert(
                    "parent_token_id".to_owned(),
                    AuditValue::String(p.to_owned()),
                );
                metadata.insert(
                    "actor_credential_id".to_owned(),
                    AuditValue::String(p.to_owned()),
                );
            }
            append(
                &mut tx,
                &self.installation_id,
                AuditEventData {
                    observed_unix_ms: r.created_unix_ms,
                    tenant_id: r.tenant_id.clone(),
                    actor,
                    action: "api_token.create".to_owned(),
                    resource: AuditResource {
                        kind: "api_token".to_owned(),
                        id: r.id.clone(),
                    },
                    result: "success".to_owned(),
                    request_id: request.to_owned(),
                    decision_id: None,
                    metadata,
                },
            )
            .await?;
            tx.commit().await?;
            Ok(())
        })
    }
    fn token<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ApiTokenRecord> {
        Box::pin(async move {
            validate_text(id)?;
            let mut c = self.pool().acquire().await?;
            token_by_id(&mut c, id).await
        })
    }
    fn tokens<'a>(&'a self, tenant: &'a str) -> StoreFuture<'a, Vec<ApiTokenRecord>> {
        Box::pin(async move {
            validate_text(tenant)?;
            let rows=sqlx::query("SELECT * FROM api_tokens WHERE tenant_id=$1 ORDER BY created_unix_ms,id LIMIT 10000").bind(tenant).fetch_all(self.pool()).await?;
            rows.into_iter().map(token_row).collect()
        })
    }
    fn tokens_page<'a>(
        &'a self,
        tenant: &'a str,
        after: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ApiTokenRecord>> {
        Box::pin(async move {
            validate_text(tenant)?;
            if limit == 0 || limit > 1000 {
                return Err(ControlPlaneError::InvalidInput(
                    "page limit is out of range",
                ));
            }
            if let Some(after) = after {
                validate_text(after)?;
            }
            let rows = sqlx::query(
                "SELECT * FROM api_tokens WHERE tenant_id=$1 AND ($2='' OR id>$2) ORDER BY id LIMIT $3",
            )
            .bind(tenant)
            .bind(after.unwrap_or(""))
            .bind(i64::try_from(limit).map_err(|_| ControlPlaneError::IntegerRange {
                field: "API token page limit",
            })?)
            .fetch_all(self.pool())
            .await?;
            rows.into_iter().map(token_row).collect()
        })
    }
    fn authenticate_token<'a>(
        &'a self,
        h: &'a TokenHasher,
        token: &'a str,
        scope: &'a str,
        now: u64,
    ) -> StoreFuture<'a, AuthContext> {
        Box::pin(async move {
            if token.len() != 64
                || !token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(AuthError::InvalidCredential.into());
            }
            let digest = h.api_token_digest(token).storage_key();
            let mut tx = self.pool().begin().await?;
            let row = sqlx::query("SELECT * FROM api_tokens WHERE digest=$1 FOR UPDATE")
                .bind(&digest)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(AuthError::InvalidCredential)?;
            let mut r = token_row(row)?;
            validate_ancestry(&mut tx, &r.id, now).await?;
            let context = r.authenticate(h, token, scope, now)?;
            sqlx::query("UPDATE api_tokens SET last_used_unix_ms=$1 WHERE id=$2 AND digest=$3")
                .bind(i64v(now, "API token last use")?)
                .bind(&r.id)
                .bind(digest)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(context)
        })
    }
    fn revoke_token<'a>(
        &'a self,
        id: &'a str,
        actor: AuditPrincipal,
        credential: Option<&'a str>,
        request: &'a str,
        now: u64,
    ) -> StoreFuture<'a, ApiTokenRecord> {
        Box::pin(async move {
            validate_text(id)?;
            validate_text(request)?;
            if let Some(c) = credential {
                validate_text(c)?
            }
            let mut tx = self.pool().begin().await?;
            let mut r = token_by_id_locked(&mut tx, id).await?;
            if now < r.created_unix_ms {
                return Err(ControlPlaneError::InvalidInput(
                    "API token revocation cannot precede creation",
                ));
            }
            if r.revoke(now) {
                sqlx::query("UPDATE api_tokens SET revoked_unix_ms=$1 WHERE id=$2")
                    .bind(i64v(now, "API token revocation")?)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                let metadata = credential.map_or_else(BTreeMap::new, |c| {
                    BTreeMap::from([(
                        "actor_credential_id".to_owned(),
                        AuditValue::String(c.to_owned()),
                    )])
                });
                append(
                    &mut tx,
                    &self.installation_id,
                    AuditEventData {
                        observed_unix_ms: now,
                        tenant_id: r.tenant_id.clone(),
                        actor,
                        action: "api_token.revoke".to_owned(),
                        resource: AuditResource {
                            kind: "api_token".to_owned(),
                            id: r.id.clone(),
                        },
                        result: "success".to_owned(),
                        request_id: request.to_owned(),
                        decision_id: None,
                        metadata,
                    },
                )
                .await?;
            }
            tx.commit().await?;
            Ok(r)
        })
    }
    fn append_event<'a>(&'a self, data: AuditEventData) -> StoreFuture<'a, AuditEvent> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let e = append(&mut tx, &self.installation_id, data).await?;
            tx.commit().await?;
            Ok(e)
        })
    }
    fn events(&self) -> StoreFuture<'_, Vec<AuditEvent>> {
        Box::pin(async move {
            let rows: Vec<Vec<u8>> =
                sqlx::query_scalar("SELECT event_json FROM audit_events ORDER BY sequence")
                    .fetch_all(self.pool())
                    .await?;
            let events = rows
                .into_iter()
                .map(|b| serde_json::from_slice(&b))
                .collect::<Result<Vec<AuditEvent>, _>>()?;
            verify_chain(&events)?;
            Ok(events)
        })
    }
    fn events_page<'a>(
        &'a self,
        action: Option<&'a str>,
        before: Option<u64>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<AuditEvent>> {
        Box::pin(async move {
            validate_page_arguments(action, limit)?;
            Ok(self
                .events()
                .await?
                .into_iter()
                .rev()
                .filter(|event| before.is_none_or(|cursor| event.sequence < cursor))
                .filter(|event| action.is_none_or(|wanted| event.data.action == wanted))
                .take(limit)
                .collect())
        })
    }
    fn events_page_for_tenant<'a>(
        &'a self,
        tenant: &'a str,
        action: Option<&'a str>,
        before: Option<u64>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<AuditEvent>> {
        Box::pin(async move {
            validate_text(tenant)?;
            validate_page_arguments(action, limit)?;
            Ok(self
                .events()
                .await?
                .into_iter()
                .rev()
                .filter(|event| event.data.tenant_id == tenant)
                .filter(|event| before.is_none_or(|cursor| event.sequence < cursor))
                .filter(|event| action.is_none_or(|wanted| event.data.action == wanted))
                .take(limit)
                .collect())
        })
    }
}

#[cfg(feature = "postgres")]
fn validate_page_arguments(action: Option<&str>, limit: usize) -> Result<(), ControlPlaneError> {
    if limit == 0 || limit > 1000 {
        return Err(ControlPlaneError::InvalidInput(
            "page limit is out of range",
        ));
    }
    if let Some(action) = action {
        validate_text(action)?;
    }
    Ok(())
}

#[cfg(feature = "postgres")]
pub(super) async fn append(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    installation: &str,
    data: AuditEventData,
) -> Result<AuditEvent, ControlPlaneError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_LOCK)
        .execute(&mut **tx)
        .await?;
    let previous: Option<(i64, String)> = sqlx::query_as(
        "SELECT sequence,event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut **tx)
    .await?;
    let (sequence, hash) = match previous {
        Some((s, h)) => (
            u64::try_from(s)
                .map_err(|_| ControlPlaneError::IntegerRange {
                    field: "audit sequence",
                })?
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "audit sequence",
                })?,
            Some(ContentDigest::parse(h)?),
        ),
        None => (1, None),
    };
    let event = AuditEvent::create(sequence, installation.to_owned(), hash, data)?;
    sqlx::query("INSERT INTO audit_events(sequence,installation_id,previous_hash,event_hash,event_json)VALUES($1,$2,$3,$4,$5)").bind(i64v(sequence,"audit sequence")?).bind(&event.installation_id).bind(event.previous_hash.as_ref().map(ContentDigest::as_str)).bind(event.event_hash.as_str()).bind(serde_json::to_vec(&event)?).execute(&mut **tx).await?;
    Ok(event)
}
#[cfg(feature = "postgres")]
async fn token_by_id(
    e: &mut sqlx::PgConnection,
    id: &str,
) -> Result<ApiTokenRecord, ControlPlaneError> {
    sqlx::query("SELECT * FROM api_tokens WHERE id=$1")
        .bind(id)
        .fetch_optional(e)
        .await?
        .map(token_row)
        .transpose()?
        .ok_or_else(|| ControlPlaneError::NotFound {
            kind: "API token",
            id: id.to_owned(),
        })
}
#[cfg(feature = "postgres")]
async fn token_by_id_locked(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
) -> Result<ApiTokenRecord, ControlPlaneError> {
    sqlx::query("SELECT * FROM api_tokens WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(token_row)
        .transpose()?
        .ok_or_else(|| ControlPlaneError::NotFound {
            kind: "API token",
            id: id.to_owned(),
        })
}
#[cfg(feature = "postgres")]
fn token_row(row: sqlx::postgres::PgRow) -> Result<ApiTokenRecord, ControlPlaneError> {
    let scopes: Vec<u8> = row.try_get("scopes_json")?;
    let r = ApiTokenRecord {
        id: row.try_get("id")?,
        principal_id: row.try_get("principal_id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        digest: serde_json::from_value(serde_json::Value::String(row.try_get("digest")?))?,
        scopes: serde_json::from_slice(&scopes)?,
        created_unix_ms: u64v(row.try_get("created_unix_ms")?, "API token creation")?,
        expires_unix_ms: u64v(row.try_get("expires_unix_ms")?, "API token expiry")?,
        last_used_unix_ms: row
            .try_get::<Option<i64>, _>("last_used_unix_ms")?
            .map(|v| u64v(v, "API token last use"))
            .transpose()?,
        revoked_unix_ms: row
            .try_get::<Option<i64>, _>("revoked_unix_ms")?
            .map(|v| u64v(v, "API token revocation"))
            .transpose()?,
    };
    validate_record(&r)?;
    Ok(r)
}
#[cfg(feature = "postgres")]
async fn validate_ancestry(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
    now: u64,
) -> Result<(), ControlPlaneError> {
    let mut current = Some(id.to_owned());
    let mut child: Option<(String, String, BTreeSet<String>, u64, u64)> = None;
    let mut seen = BTreeSet::new();
    for _ in 0..MAX_ANCESTRY {
        let Some(id) = current.take() else {
            return Ok(());
        };
        if !seen.insert(id.clone()) {
            return Err(ControlPlaneError::CorruptState(
                "API token delegation ancestry contains a cycle".to_owned(),
            ));
        }
        let row=sqlx::query("SELECT principal_id,tenant_id,scopes_json,created_unix_ms,expires_unix_ms,revoked_unix_ms,parent_token_id FROM api_tokens WHERE id=$1 FOR UPDATE").bind(&id).fetch_optional(&mut **tx).await?.ok_or(AuthError::InvalidCredential)?;
        let scopes: Vec<u8> = row.try_get("scopes_json")?;
        let scopes: BTreeSet<String> = serde_json::from_slice(&scopes)?;
        let created = u64v(row.try_get("created_unix_ms")?, "API token creation")?;
        let expires = u64v(row.try_get("expires_unix_ms")?, "API token expiry")?;
        if row.try_get::<Option<i64>, _>("revoked_unix_ms")?.is_some() {
            return Err(AuthError::Revoked.into());
        }
        if now < created || now >= expires {
            return Err(AuthError::Expired.into());
        }
        if let Some((p, t, s, c, e)) = child.take() {
            if p != row.try_get::<String, _>("principal_id")?
                || t != row.try_get::<String, _>("tenant_id")?
                || !s.is_subset(&scopes)
                || c < created
                || e > expires
            {
                return Err(ControlPlaneError::CorruptState(
                    "delegated API token ancestry broadens identity or expiry".to_owned(),
                ));
            }
        }
        child = Some((
            row.try_get("principal_id")?,
            row.try_get("tenant_id")?,
            scopes,
            created,
            expires,
        ));
        current = row.try_get("parent_token_id")?
    }
    Err(ControlPlaneError::CorruptState(
        "API token delegation ancestry exceeds its bound".to_owned(),
    ))
}
#[cfg(feature = "postgres")]
fn validate_text(v: &str) -> Result<(), ControlPlaneError> {
    if v.is_empty() || v.len() > 8192 || v.bytes().any(|b| b.is_ascii_control()) {
        Err(ControlPlaneError::InvalidInput("invalid persistence text"))
    } else {
        Ok(())
    }
}
#[cfg(feature = "postgres")]
fn validate_record(r: &ApiTokenRecord) -> Result<(), ControlPlaneError> {
    r.validate().map_err(Into::into)
}
#[cfg(feature = "postgres")]
fn i64v(v: u64, field: &'static str) -> Result<i64, ControlPlaneError> {
    i64::try_from(v).map_err(|_| ControlPlaneError::IntegerRange { field })
}
#[cfg(feature = "postgres")]
fn u64v(v: i64, field: &'static str) -> Result<u64, ControlPlaneError> {
    u64::try_from(v)
        .map_err(|_| ControlPlaneError::CorruptState(format!("PostgreSQL {field} is negative")))
}
#[cfg(feature = "postgres")]
fn opt_i64(v: Option<u64>, field: &'static str) -> Result<Option<i64>, ControlPlaneError> {
    v.map(|v| i64v(v, field)).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ControlPlaneError, TenantIdentityRecord, TenantIdentityStore};
    use runtrue_auth::{AuthError, IssueApiToken};

    fn tenant() -> TenantIdentityRecord {
        TenantIdentityRecord {
            id: "token-tenant".to_owned(),
            slug: "token-tenant".to_owned(),
            name: "Token tenant".to_owned(),
            status: "active".to_owned(),
            settings: serde_json::json!({}),
            created_unix_ms: 1,
            updated_unix_ms: 1,
            version: 1,
        }
    }
    fn actor() -> AuditPrincipal {
        AuditPrincipal {
            kind: "human".to_owned(),
            id: "operator".to_owned(),
        }
    }

    async fn contract(store: &(impl ApiTokenAuditStore + TenantIdentityStore)) {
        let _ = store.put_tenant_identity(&tenant(), None).await;
        let hasher = TokenHasher::generate().unwrap();
        let parent = ApiTokenRecord::issue(
            &hasher,
            IssueApiToken {
                id: "token-parent".to_owned(),
                principal_id: "principal".to_owned(),
                tenant_id: "token-tenant".to_owned(),
                name: "parent".to_owned(),
                scopes: BTreeSet::from(["read".to_owned(), "write".to_owned()]),
                created_unix_ms: 100,
                expires_unix_ms: 1000,
            },
        )
        .unwrap();
        store
            .create_token(&parent.record, None, actor(), "request-parent")
            .await
            .unwrap();
        assert_eq!(store.token("token-parent").await.unwrap(), parent.record);
        assert_eq!(store.tokens("token-tenant").await.unwrap().len(), 1);
        let auth = store
            .authenticate_token(&hasher, parent.token.expose(), "read", 150)
            .await
            .unwrap();
        assert_eq!(auth.principal_id, "principal");
        let child = ApiTokenRecord::issue(
            &hasher,
            IssueApiToken {
                id: "token-child".to_owned(),
                principal_id: "principal".to_owned(),
                tenant_id: "token-tenant".to_owned(),
                name: "child".to_owned(),
                scopes: BTreeSet::from(["read".to_owned()]),
                created_unix_ms: 160,
                expires_unix_ms: 900,
            },
        )
        .unwrap();
        store
            .create_token(
                &child.record,
                Some("token-parent"),
                actor(),
                "request-child",
            )
            .await
            .unwrap();
        assert_eq!(store.tokens("token-tenant").await.unwrap().len(), 2);
        let revoked = store
            .revoke_token("token-parent", actor(), None, "request-revoke", 200)
            .await
            .unwrap();
        assert_eq!(revoked.revoked_unix_ms, Some(200));
        assert!(matches!(
            store
                .authenticate_token(&hasher, child.token.expose(), "read", 250)
                .await,
            Err(ControlPlaneError::Auth(AuthError::Revoked))
        ));
        let events = store.events().await.unwrap();
        verify_chain(&events).unwrap();
        assert!(events
            .iter()
            .any(|e| e.data.action == "api_token.create" && e.data.resource.id == "token-child"));
        assert!(events.iter().any(|e| e.data.action == "api_token.revoke"));
    }

    #[tokio::test]
    async fn sqlite_api_token_audit_contract() {
        let store = ControlPlane::open_in_memory("token-contract", 1).unwrap();
        contract(&store).await
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_api_token_audit_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "api-token-audit").await;
        let store = PostgresInstallationStore::connect(fixture.config(), "pg-contract", 1)
            .await
            .unwrap();
        contract(&store).await;
        store.close().await;
        fixture.cleanup().await;
    }
}
