use super::StoreFuture;
#[cfg(feature = "postgres")]
use super::{pg_i64, pg_require_tenant, postgres_u64, PostgresInstallationStore};
use crate::{
    ControlPlane, EffectiveRepositoryAccess, HumanUserRecord, RepositoryAccessGrantRecord,
    TeamMembershipRecord, TeamRecord,
};
#[cfg(feature = "postgres")]
use crate::{ControlPlaneError, RepositoryAccessSubject};
#[cfg(feature = "postgres")]
use sqlx::Row as _;
#[cfg(feature = "postgres")]
use std::collections::{BTreeMap, BTreeSet};

pub trait UserManagementStore: Send + Sync {
    fn users_for_tenant<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, Vec<HumanUserRecord>>;
    fn put_team<'a>(
        &'a self,
        record: &'a TeamRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool>;
    fn team<'a>(&'a self, tenant_id: &'a str, team_id: &'a str) -> StoreFuture<'a, TeamRecord>;
    fn teams_for_tenant<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, Vec<TeamRecord>>;
    fn put_team_membership<'a>(&'a self, record: &'a TeamMembershipRecord)
        -> StoreFuture<'a, bool>;
    fn remove_team_membership<'a>(
        &'a self,
        tenant_id: &'a str,
        team_id: &'a str,
        user_id: &'a str,
    ) -> StoreFuture<'a, bool>;
    fn team_memberships<'a>(
        &'a self,
        tenant_id: &'a str,
        team_id: &'a str,
    ) -> StoreFuture<'a, Vec<TeamMembershipRecord>>;
    fn put_repository_access_grant<'a>(
        &'a self,
        record: &'a RepositoryAccessGrantRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool>;
    fn repository_access_grants<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
    ) -> StoreFuture<'a, Vec<RepositoryAccessGrantRecord>>;
    fn revoke_repository_access_grant<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        grant_id: &'a str,
    ) -> StoreFuture<'a, bool>;
    fn effective_repository_access_for_user<'a>(
        &'a self,
        tenant_id: &'a str,
        user_id: &'a str,
    ) -> StoreFuture<'a, Vec<EffectiveRepositoryAccess>>;
}

impl UserManagementStore for ControlPlane {
    fn users_for_tenant<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, Vec<HumanUserRecord>> {
        let result = self.list_human_users_for_tenant(tenant_id);
        Box::pin(async move { result })
    }

    fn put_team<'a>(
        &'a self,
        record: &'a TeamRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::put_team(self, record, expected_version);
        Box::pin(async move { result })
    }

    fn team<'a>(&'a self, tenant_id: &'a str, team_id: &'a str) -> StoreFuture<'a, TeamRecord> {
        let result = self.team_for_tenant(tenant_id, team_id);
        Box::pin(async move { result })
    }

    fn teams_for_tenant<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, Vec<TeamRecord>> {
        let result = ControlPlane::teams_for_tenant(self, tenant_id);
        Box::pin(async move { result })
    }

    fn put_team_membership<'a>(
        &'a self,
        record: &'a TeamMembershipRecord,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::put_team_membership(self, record);
        Box::pin(async move { result })
    }

    fn remove_team_membership<'a>(
        &'a self,
        tenant_id: &'a str,
        team_id: &'a str,
        user_id: &'a str,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::remove_team_membership(self, tenant_id, team_id, user_id);
        Box::pin(async move { result })
    }

    fn team_memberships<'a>(
        &'a self,
        tenant_id: &'a str,
        team_id: &'a str,
    ) -> StoreFuture<'a, Vec<TeamMembershipRecord>> {
        let result = ControlPlane::team_memberships(self, tenant_id, team_id);
        Box::pin(async move { result })
    }

    fn put_repository_access_grant<'a>(
        &'a self,
        record: &'a RepositoryAccessGrantRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::put_repository_access_grant(self, record, expected_version);
        Box::pin(async move { result })
    }

    fn repository_access_grants<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
    ) -> StoreFuture<'a, Vec<RepositoryAccessGrantRecord>> {
        let result = ControlPlane::repository_access_grants(self, tenant_id, repository_id);
        Box::pin(async move { result })
    }

    fn revoke_repository_access_grant<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        grant_id: &'a str,
    ) -> StoreFuture<'a, bool> {
        let result =
            ControlPlane::revoke_repository_access_grant(self, tenant_id, repository_id, grant_id);
        Box::pin(async move { result })
    }

    fn effective_repository_access_for_user<'a>(
        &'a self,
        tenant_id: &'a str,
        user_id: &'a str,
    ) -> StoreFuture<'a, Vec<EffectiveRepositoryAccess>> {
        let result = ControlPlane::effective_repository_access_for_user(self, tenant_id, user_id);
        Box::pin(async move { result })
    }
}

#[cfg(feature = "postgres")]
fn pg_team(row: sqlx::postgres::PgRow) -> Result<TeamRecord, ControlPlaneError> {
    Ok(TeamRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        status: row.try_get("status")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "team creation")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "team update")?,
        version: postgres_u64(row.try_get("version")?, "team version")?,
    })
}

#[cfg(feature = "postgres")]
fn pg_team_membership(
    row: sqlx::postgres::PgRow,
) -> Result<TeamMembershipRecord, ControlPlaneError> {
    Ok(TeamMembershipRecord {
        tenant_id: row.try_get("tenant_id")?,
        team_id: row.try_get("team_id")?,
        user_id: row.try_get("user_id")?,
        role: row.try_get("role")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "team membership creation")?,
    })
}

#[cfg(feature = "postgres")]
fn pg_access_grant(
    row: sqlx::postgres::PgRow,
) -> Result<RepositoryAccessGrantRecord, ControlPlaneError> {
    let user_id: Option<String> = row.try_get("user_id")?;
    let team_id: Option<String> = row.try_get("team_id")?;
    let subject = match (user_id, team_id) {
        (Some(id), None) => RepositoryAccessSubject::User(id),
        (None, Some(id)) => RepositoryAccessSubject::Team(id),
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "repository access grant has an invalid subject".to_owned(),
            ))
        }
    };
    Ok(RepositoryAccessGrantRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        subject,
        permission: row.try_get("permission")?,
        created_unix_ms: postgres_u64(
            row.try_get("created_unix_ms")?,
            "repository access grant creation",
        )?,
        updated_unix_ms: postgres_u64(
            row.try_get("updated_unix_ms")?,
            "repository access grant update",
        )?,
        version: postgres_u64(row.try_get("version")?, "repository access grant version")?,
    })
}

#[cfg(feature = "postgres")]
fn validate_id(value: &str) -> Result<(), ControlPlaneError> {
    crate::store::validate_persistence_identity_identifier(value)
}

#[cfg(feature = "postgres")]
fn validate_team(record: &TeamRecord) -> Result<(), ControlPlaneError> {
    for value in [&record.id, &record.tenant_id, &record.name] {
        validate_id(value)?;
    }
    if record.description.len() > 8192
        || record.description.contains('\0')
        || !matches!(record.status.as_str(), "active" | "disabled")
        || record.version == 0
        || record.updated_unix_ms < record.created_unix_ms
    {
        return Err(ControlPlaneError::InvalidInput("invalid team"));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_membership(record: &TeamMembershipRecord) -> Result<(), ControlPlaneError> {
    for value in [&record.tenant_id, &record.team_id, &record.user_id] {
        validate_id(value)?;
    }
    if !matches!(record.role.as_str(), "member" | "maintainer") {
        return Err(ControlPlaneError::InvalidInput("invalid team membership"));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_grant(record: &RepositoryAccessGrantRecord) -> Result<(), ControlPlaneError> {
    for value in [&record.id, &record.tenant_id, &record.repository_id] {
        validate_id(value)?;
    }
    match &record.subject {
        RepositoryAccessSubject::User(id) | RepositoryAccessSubject::Team(id) => validate_id(id)?,
    }
    if !matches!(record.permission.as_str(), "read" | "write" | "admin")
        || record.version == 0
        || record.updated_unix_ms < record.created_unix_ms
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid repository access grant",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
impl UserManagementStore for PostgresInstallationStore {
    fn users_for_tenant<'a>(&'a self, tenant: &'a str) -> StoreFuture<'a, Vec<HumanUserRecord>> {
        Box::pin(async move {
            validate_id(tenant)?;
            let rows = sqlx::query(
                "SELECT u.* FROM human_users u JOIN human_user_tenant_bindings b ON b.user_id=u.id
                 WHERE b.tenant_id=$1 ORDER BY u.id",
            )
            .bind(tenant)
            .fetch_all(&self.pool)
            .await?;
            rows.into_iter().map(super::pg_user).collect()
        })
    }

    fn put_team<'a>(
        &'a self,
        record: &'a TeamRecord,
        expected: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_team(record)?;
            let mut tx = self.pool.begin().await?;
            pg_require_tenant(&mut tx, &record.tenant_id).await?;
            let old = sqlx::query("SELECT * FROM teams WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(&record.tenant_id)
                .bind(&record.id)
                .fetch_optional(&mut *tx)
                .await?
                .map(pg_team)
                .transpose()?;
            if let Some(old) = old {
                if old == *record {
                    tx.commit().await?;
                    return Ok(false);
                }
                if expected != Some(old.version)
                    || record.version
                        != old
                            .version
                            .checked_add(1)
                            .ok_or(ControlPlaneError::IntegerRange {
                                field: "team version",
                            })?
                    || record.created_unix_ms != old.created_unix_ms
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let changed = sqlx::query(
                    "UPDATE teams SET name=$3,description=$4,status=$5,updated_unix_ms=$6,version=$7
                     WHERE tenant_id=$1 AND id=$2 AND version=$8",
                )
                .bind(&record.tenant_id).bind(&record.id).bind(&record.name)
                .bind(&record.description).bind(&record.status)
                .bind(pg_i64(record.updated_unix_ms, "team update")?)
                .bind(pg_i64(record.version, "team version")?)
                .bind(pg_i64(old.version, "team version")?)
                .execute(&mut *tx).await?.rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(true);
            }
            if expected.is_some() || record.version != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query(
                "INSERT INTO teams(id,tenant_id,name,description,status,created_unix_ms,updated_unix_ms,version)
                 VALUES($1,$2,$3,$4,$5,$6,$7,1)",
            )
            .bind(&record.id).bind(&record.tenant_id).bind(&record.name)
            .bind(&record.description).bind(&record.status)
            .bind(pg_i64(record.created_unix_ms, "team creation")?)
            .bind(pg_i64(record.updated_unix_ms, "team update")?)
            .execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }

    fn team<'a>(&'a self, tenant: &'a str, id: &'a str) -> StoreFuture<'a, TeamRecord> {
        Box::pin(async move {
            validate_id(tenant)?;
            validate_id(id)?;
            sqlx::query("SELECT * FROM teams WHERE tenant_id=$1 AND id=$2")
                .bind(tenant)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| ControlPlaneError::NotFound {
                    kind: "team",
                    id: id.to_owned(),
                })
                .and_then(pg_team)
        })
    }

    fn teams_for_tenant<'a>(&'a self, tenant: &'a str) -> StoreFuture<'a, Vec<TeamRecord>> {
        Box::pin(async move {
            validate_id(tenant)?;
            sqlx::query("SELECT * FROM teams WHERE tenant_id=$1 ORDER BY id")
                .bind(tenant)
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(pg_team)
                .collect()
        })
    }

    fn put_team_membership<'a>(
        &'a self,
        record: &'a TeamMembershipRecord,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_membership(record)?;
            let changed = sqlx::query(
                "INSERT INTO team_memberships(tenant_id,team_id,user_id,role,created_unix_ms)
                 SELECT $1,$2,$3,$4,$5
                 WHERE EXISTS(SELECT 1 FROM teams WHERE tenant_id=$1 AND id=$2 AND status='active')
                   AND EXISTS(SELECT 1 FROM human_user_tenant_bindings b JOIN human_users u ON u.id=b.user_id WHERE b.tenant_id=$1 AND b.user_id=$3 AND u.status='active')
                 ON CONFLICT(tenant_id,team_id,user_id) DO UPDATE SET role=excluded.role
                 WHERE team_memberships.role<>excluded.role",
            )
            .bind(&record.tenant_id).bind(&record.team_id).bind(&record.user_id).bind(&record.role)
            .bind(pg_i64(record.created_unix_ms, "team membership creation")?)
            .execute(&self.pool).await?.rows_affected();
            if changed == 1 {
                return Ok(true);
            }
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT role FROM team_memberships WHERE tenant_id=$1 AND team_id=$2 AND user_id=$3",
            ).bind(&record.tenant_id).bind(&record.team_id).bind(&record.user_id)
                .fetch_optional(&self.pool).await?;
            if existing.as_deref() == Some(record.role.as_str()) {
                Ok(false)
            } else {
                Err(ControlPlaneError::NotFound {
                    kind: "team or human user",
                    id: record.team_id.clone(),
                })
            }
        })
    }

    fn remove_team_membership<'a>(
        &'a self,
        tenant: &'a str,
        team: &'a str,
        user: &'a str,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            for value in [tenant, team, user] {
                validate_id(value)?;
            }
            Ok(sqlx::query(
                "DELETE FROM team_memberships WHERE tenant_id=$1 AND team_id=$2 AND user_id=$3",
            )
            .bind(tenant)
            .bind(team)
            .bind(user)
            .execute(&self.pool)
            .await?
            .rows_affected()
                == 1)
        })
    }

    fn team_memberships<'a>(
        &'a self,
        tenant: &'a str,
        team: &'a str,
    ) -> StoreFuture<'a, Vec<TeamMembershipRecord>> {
        Box::pin(async move {
            validate_id(tenant)?;
            validate_id(team)?;
            sqlx::query(
                "SELECT * FROM team_memberships WHERE tenant_id=$1 AND team_id=$2 ORDER BY user_id",
            )
            .bind(tenant)
            .bind(team)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(pg_team_membership)
            .collect()
        })
    }

    fn put_repository_access_grant<'a>(
        &'a self,
        record: &'a RepositoryAccessGrantRecord,
        expected: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_grant(record)?;
            let (user_id, team_id) = match &record.subject {
                RepositoryAccessSubject::User(id) => (Some(id.as_str()), None),
                RepositoryAccessSubject::Team(id) => (None, Some(id.as_str())),
            };
            let mut tx = self.pool.begin().await?;
            pg_require_tenant(&mut tx, &record.tenant_id).await?;
            let repository_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM repositories WHERE tenant_id=$1 AND id=$2)",
            )
            .bind(&record.tenant_id)
            .bind(&record.repository_id)
            .fetch_one(&mut *tx)
            .await?;
            let subject_exists: bool = if let Some(id) = user_id {
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM human_user_tenant_bindings b JOIN human_users u ON u.id=b.user_id WHERE b.tenant_id=$1 AND b.user_id=$2 AND u.status='active')")
                    .bind(&record.tenant_id).bind(id).fetch_one(&mut *tx).await?
            } else if let Some(id) = team_id {
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM teams WHERE tenant_id=$1 AND id=$2 AND status='active')")
                    .bind(&record.tenant_id).bind(id).fetch_one(&mut *tx).await?
            } else {
                false
            };
            if !repository_exists || !subject_exists {
                return Err(ControlPlaneError::NotFound {
                    kind: "repository or access subject",
                    id: record.repository_id.clone(),
                });
            }
            let old = sqlx::query(
                "SELECT * FROM repository_access_grants WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            )
            .bind(&record.tenant_id)
            .bind(&record.id)
            .fetch_optional(&mut *tx)
            .await?
            .map(pg_access_grant)
            .transpose()?;
            if let Some(old) = old {
                if old == *record {
                    tx.commit().await?;
                    return Ok(false);
                }
                if expected != Some(old.version)
                    || record.version
                        != old
                            .version
                            .checked_add(1)
                            .ok_or(ControlPlaneError::IntegerRange {
                                field: "repository access grant version",
                            })?
                    || record.created_unix_ms != old.created_unix_ms
                    || record.repository_id != old.repository_id
                    || record.subject != old.subject
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let changed = sqlx::query("UPDATE repository_access_grants SET permission=$3,updated_unix_ms=$4,version=$5 WHERE tenant_id=$1 AND id=$2 AND version=$6")
                    .bind(&record.tenant_id).bind(&record.id).bind(&record.permission)
                    .bind(pg_i64(record.updated_unix_ms,"repository access grant update")?)
                    .bind(pg_i64(record.version,"repository access grant version")?)
                    .bind(pg_i64(old.version,"repository access grant version")?)
                    .execute(&mut *tx).await?.rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(true);
            }
            if expected.is_some() || record.version != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let duplicate: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM repository_access_grants WHERE tenant_id=$1 AND repository_id=$2 AND ((user_id=$3 AND $3 IS NOT NULL) OR (team_id=$4 AND $4 IS NOT NULL)))")
                .bind(&record.tenant_id).bind(&record.repository_id).bind(user_id).bind(team_id)
                .fetch_one(&mut *tx).await?;
            if duplicate {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO repository_access_grants(id,tenant_id,repository_id,user_id,team_id,permission,created_unix_ms,updated_unix_ms,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1)")
                .bind(&record.id).bind(&record.tenant_id).bind(&record.repository_id).bind(user_id).bind(team_id)
                .bind(&record.permission).bind(pg_i64(record.created_unix_ms,"repository access grant creation")?)
                .bind(pg_i64(record.updated_unix_ms,"repository access grant update")?)
                .execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }

    fn repository_access_grants<'a>(
        &'a self,
        tenant: &'a str,
        repository: &'a str,
    ) -> StoreFuture<'a, Vec<RepositoryAccessGrantRecord>> {
        Box::pin(async move {
            validate_id(tenant)?;
            validate_id(repository)?;
            sqlx::query("SELECT * FROM repository_access_grants WHERE tenant_id=$1 AND repository_id=$2 ORDER BY id")
                .bind(tenant).bind(repository).fetch_all(&self.pool).await?
                .into_iter().map(pg_access_grant).collect()
        })
    }

    fn revoke_repository_access_grant<'a>(
        &'a self,
        tenant: &'a str,
        repository: &'a str,
        grant: &'a str,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            for value in [tenant, repository, grant] {
                validate_id(value)?;
            }
            Ok(sqlx::query("DELETE FROM repository_access_grants WHERE tenant_id=$1 AND repository_id=$2 AND id=$3")
                .bind(tenant).bind(repository).bind(grant).execute(&self.pool).await?.rows_affected() == 1)
        })
    }

    fn effective_repository_access_for_user<'a>(
        &'a self,
        tenant: &'a str,
        user: &'a str,
    ) -> StoreFuture<'a, Vec<EffectiveRepositoryAccess>> {
        Box::pin(async move {
            validate_id(tenant)?;
            validate_id(user)?;
            let rows = sqlx::query("SELECT g.repository_id,g.permission,g.user_id,g.team_id FROM repository_access_grants g WHERE g.tenant_id=$1 AND EXISTS(SELECT 1 FROM human_user_tenant_bindings b JOIN human_users u ON u.id=b.user_id WHERE b.tenant_id=$1 AND b.user_id=$2 AND u.status='active') AND (g.user_id=$2 OR g.team_id IN (SELECT m.team_id FROM team_memberships m JOIN teams t ON t.tenant_id=m.tenant_id AND t.id=m.team_id WHERE m.tenant_id=$1 AND m.user_id=$2 AND t.status='active')) ORDER BY g.repository_id,g.id")
                .bind(tenant).bind(user).fetch_all(&self.pool).await?;
            let mut access = BTreeMap::<String, (u8, bool, BTreeSet<String>)>::new();
            for row in rows {
                let repository_id: String = row.try_get("repository_id")?;
                let permission: String = row.try_get("permission")?;
                let rank = match permission.as_str() {
                    "read" => 1,
                    "write" => 2,
                    "admin" => 3,
                    _ => {
                        return Err(ControlPlaneError::CorruptState(
                            "invalid repository permission".to_owned(),
                        ))
                    }
                };
                let direct: Option<String> = row.try_get("user_id")?;
                let team: Option<String> = row.try_get("team_id")?;
                let entry = access.entry(repository_id).or_default();
                entry.0 = entry.0.max(rank);
                entry.1 |= direct.is_some();
                if let Some(team) = team {
                    entry.2.insert(team);
                }
            }
            Ok(access
                .into_iter()
                .map(
                    |(repository_id, (rank, direct, teams))| EffectiveRepositoryAccess {
                        repository_id,
                        permission: match rank {
                            3 => "admin",
                            2 => "write",
                            _ => "read",
                        }
                        .to_owned(),
                        direct,
                        team_ids: teams.into_iter().collect(),
                    },
                )
                .collect())
        })
    }
}
