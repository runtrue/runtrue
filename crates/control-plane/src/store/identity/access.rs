use super::users::human_user_row;
use super::*;

fn team_row(row: &Row<'_>) -> rusqlite::Result<TeamRecord> {
    Ok(TeamRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        name: row.get(2)?,
        description: row.get(3)?,
        status: row.get(4)?,
        created_unix_ms: u64_column(row, 5, "team creation")?,
        updated_unix_ms: u64_column(row, 6, "team update")?,
        version: u64_column(row, 7, "team version")?,
    })
}

fn team_membership_row(row: &Row<'_>) -> rusqlite::Result<TeamMembershipRecord> {
    Ok(TeamMembershipRecord {
        tenant_id: row.get(0)?,
        team_id: row.get(1)?,
        user_id: row.get(2)?,
        role: row.get(3)?,
        created_unix_ms: u64_column(row, 4, "team membership creation")?,
    })
}

fn access_grant_row(row: &Row<'_>) -> rusqlite::Result<RepositoryAccessGrantRecord> {
    let user_id: Option<String> = row.get(3)?;
    let team_id: Option<String> = row.get(4)?;
    let subject = match (user_id, team_id) {
        (Some(user_id), None) => RepositoryAccessSubject::User(user_id),
        (None, Some(team_id)) => RepositoryAccessSubject::Team(team_id),
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(RepositoryAccessGrantRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        repository_id: row.get(2)?,
        subject,
        permission: row.get(5)?,
        created_unix_ms: u64_column(row, 6, "repository grant creation")?,
        updated_unix_ms: u64_column(row, 7, "repository grant update")?,
        version: u64_column(row, 8, "repository grant version")?,
    })
}

fn validate_team(record: &TeamRecord) -> Result<(), ControlPlaneError> {
    validate_r9_identifier(&record.id)?;
    validate_r9_identifier(&record.tenant_id)?;
    validate_r9_identifier(&record.name)?;
    if record.description.len() > MAX_TEXT_BYTES
        || record.description.contains('\0')
        || !matches!(record.status.as_str(), "active" | "disabled")
        || record.version == 0
        || record.updated_unix_ms < record.created_unix_ms
    {
        return Err(ControlPlaneError::InvalidInput("invalid team"));
    }
    Ok(())
}

fn validate_team_membership(record: &TeamMembershipRecord) -> Result<(), ControlPlaneError> {
    validate_r9_identifier(&record.tenant_id)?;
    validate_r9_identifier(&record.team_id)?;
    validate_r9_identifier(&record.user_id)?;
    if !matches!(record.role.as_str(), "member" | "maintainer") {
        return Err(ControlPlaneError::InvalidInput("invalid team membership"));
    }
    Ok(())
}

fn validate_access_grant(record: &RepositoryAccessGrantRecord) -> Result<(), ControlPlaneError> {
    for value in [&record.id, &record.tenant_id, &record.repository_id] {
        validate_r9_identifier(value)?;
    }
    match &record.subject {
        RepositoryAccessSubject::User(id) | RepositoryAccessSubject::Team(id) => {
            validate_r9_identifier(id)?;
        }
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

impl ControlPlane {
    pub fn list_human_users_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<HumanUserRecord>, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let users = transaction
            .prepare(
                "SELECT u.id,u.display_name,u.primary_email,u.status,u.created_unix_ms,
                        u.updated_unix_ms,u.last_seen_unix_ms,u.version
                 FROM human_users u JOIN human_user_tenant_bindings b ON b.user_id=u.id
                 WHERE b.tenant_id=?1 ORDER BY u.id",
            )?
            .query_map([tenant_id], human_user_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        transaction.commit()?;
        Ok(users)
    }

    pub fn put_team(
        &self,
        record: &TeamRecord,
        expected_version: Option<u64>,
    ) -> Result<bool, ControlPlaneError> {
        validate_team(record)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        let existing = transaction
            .query_row(
                "SELECT id,tenant_id,name,description,status,created_unix_ms,updated_unix_ms,version
                 FROM teams WHERE tenant_id=?1 AND id=?2",
                params![record.tenant_id, record.id],
                team_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == *record {
                transaction.commit()?;
                return Ok(false);
            }
            if expected_version != Some(existing.version)
                || record.version
                    != existing
                        .version
                        .checked_add(1)
                        .ok_or(ControlPlaneError::IntegerRange {
                            field: "team version",
                        })?
                || record.created_unix_ms != existing.created_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let changed = transaction.execute(
                "UPDATE teams SET name=?3,description=?4,status=?5,updated_unix_ms=?6,version=?7
                 WHERE tenant_id=?1 AND id=?2 AND version=?8",
                params![
                    record.tenant_id,
                    record.id,
                    record.name,
                    record.description,
                    record.status,
                    to_i64(record.updated_unix_ms)?,
                    to_i64(record.version)?,
                    to_i64(existing.version)?
                ],
            )?;
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(true);
        }
        if expected_version.is_some() || record.version != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO teams(id,tenant_id,name,description,status,created_unix_ms,updated_unix_ms,version)
             VALUES(?1,?2,?3,?4,?5,?6,?7,1)",
            params![record.id, record.tenant_id, record.name, record.description, record.status,
                to_i64(record.created_unix_ms)?, to_i64(record.updated_unix_ms)?],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn team_for_tenant(
        &self,
        tenant_id: &str,
        team_id: &str,
    ) -> Result<TeamRecord, ControlPlaneError> {
        validate_r9_identifier(tenant_id)?;
        validate_r9_identifier(team_id)?;
        self.connection()?
            .query_row(
                "SELECT id,tenant_id,name,description,status,created_unix_ms,updated_unix_ms,version
                 FROM teams WHERE tenant_id=?1 AND id=?2",
                params![tenant_id, team_id],
                team_row,
            )
            .optional()?
            .ok_or_else(|| not_found("team", team_id))
    }

    pub fn teams_for_tenant(&self, tenant_id: &str) -> Result<Vec<TeamRecord>, ControlPlaneError> {
        validate_r9_identifier(tenant_id)?;
        let connection = self.connection()?;
        let teams = connection
            .prepare(
                "SELECT id,tenant_id,name,description,status,created_unix_ms,updated_unix_ms,version
                 FROM teams WHERE tenant_id=?1 ORDER BY id",
            )?
            .query_map([tenant_id], team_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(teams)
    }

    pub fn put_team_membership(
        &self,
        record: &TeamMembershipRecord,
    ) -> Result<bool, ControlPlaneError> {
        validate_team_membership(record)?;
        let connection = self.connection()?;
        let changed = connection.execute(
            "INSERT INTO team_memberships(tenant_id,team_id,user_id,role,created_unix_ms)
             SELECT ?1,?2,?3,?4,?5
             WHERE EXISTS(SELECT 1 FROM teams WHERE tenant_id=?1 AND id=?2 AND status='active')
               AND EXISTS(SELECT 1 FROM human_user_tenant_bindings b JOIN human_users u
                            ON u.id=b.user_id
                          WHERE b.tenant_id=?1 AND b.user_id=?3 AND u.status='active')
             ON CONFLICT(tenant_id,team_id,user_id) DO UPDATE SET role=excluded.role
             WHERE team_memberships.role<>excluded.role",
            params![
                record.tenant_id,
                record.team_id,
                record.user_id,
                record.role,
                to_i64(record.created_unix_ms)?
            ],
        )?;
        if changed == 0 {
            let existing: Option<String> = connection
                .query_row(
                    "SELECT role FROM team_memberships WHERE tenant_id=?1 AND team_id=?2 AND user_id=?3",
                    params![record.tenant_id, record.team_id, record.user_id],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.as_deref() == Some(record.role.as_str()) {
                return Ok(false);
            }
            return Err(not_found("team or human user", &record.team_id));
        }
        Ok(true)
    }

    pub fn remove_team_membership(
        &self,
        tenant_id: &str,
        team_id: &str,
        user_id: &str,
    ) -> Result<bool, ControlPlaneError> {
        for value in [tenant_id, team_id, user_id] {
            validate_r9_identifier(value)?;
        }
        Ok(self.connection()?.execute(
            "DELETE FROM team_memberships WHERE tenant_id=?1 AND team_id=?2 AND user_id=?3",
            params![tenant_id, team_id, user_id],
        )? == 1)
    }

    pub fn team_memberships(
        &self,
        tenant_id: &str,
        team_id: &str,
    ) -> Result<Vec<TeamMembershipRecord>, ControlPlaneError> {
        for value in [tenant_id, team_id] {
            validate_r9_identifier(value)?;
        }
        let connection = self.connection()?;
        let rows = connection
            .prepare(
                "SELECT tenant_id,team_id,user_id,role,created_unix_ms FROM team_memberships
                 WHERE tenant_id=?1 AND team_id=?2 ORDER BY user_id",
            )?
            .query_map(params![tenant_id, team_id], team_membership_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn put_repository_access_grant(
        &self,
        record: &RepositoryAccessGrantRecord,
        expected_version: Option<u64>,
    ) -> Result<bool, ControlPlaneError> {
        validate_access_grant(record)?;
        let (user_id, team_id) = match &record.subject {
            RepositoryAccessSubject::User(id) => (Some(id.as_str()), None),
            RepositoryAccessSubject::Team(id) => (None, Some(id.as_str())),
        };
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        let repository_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM repositories WHERE tenant_id=?1 AND id=?2)",
            params![record.tenant_id, record.repository_id],
            |row| row.get(0),
        )?;
        let subject_exists: bool = match (&record.subject, user_id, team_id) {
            (RepositoryAccessSubject::User(_), Some(id), _) => transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM human_user_tenant_bindings b JOIN human_users u
                  ON u.id=b.user_id WHERE b.tenant_id=?1 AND b.user_id=?2 AND u.status='active')",
                params![record.tenant_id, id], |row| row.get(0))?,
            (RepositoryAccessSubject::Team(_), _, Some(id)) => transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM teams WHERE tenant_id=?1 AND id=?2 AND status='active')",
                params![record.tenant_id, id], |row| row.get(0))?,
            _ => false,
        };
        if !repository_exists || !subject_exists {
            return Err(not_found(
                "repository or access subject",
                &record.repository_id,
            ));
        }
        let existing = transaction
            .query_row(
                "SELECT id,tenant_id,repository_id,user_id,team_id,permission,created_unix_ms,updated_unix_ms,version
                 FROM repository_access_grants WHERE tenant_id=?1 AND id=?2",
                params![record.tenant_id, record.id], access_grant_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == *record {
                transaction.commit()?;
                return Ok(false);
            }
            if expected_version != Some(existing.version)
                || record.version
                    != existing
                        .version
                        .checked_add(1)
                        .ok_or(ControlPlaneError::IntegerRange {
                            field: "repository access grant version",
                        })?
                || record.created_unix_ms != existing.created_unix_ms
                || record.tenant_id != existing.tenant_id
                || record.repository_id != existing.repository_id
                || record.subject != existing.subject
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.execute(
                "UPDATE repository_access_grants SET permission=?3,updated_unix_ms=?4,version=?5
                 WHERE tenant_id=?1 AND id=?2 AND version=?6",
                params![
                    record.tenant_id,
                    record.id,
                    record.permission,
                    to_i64(record.updated_unix_ms)?,
                    to_i64(record.version)?,
                    to_i64(existing.version)?
                ],
            )?;
            transaction.commit()?;
            return Ok(true);
        }
        if expected_version.is_some() || record.version != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let duplicate: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM repository_access_grants
             WHERE tenant_id=?1 AND repository_id=?2
               AND ((user_id=?3 AND ?3 IS NOT NULL) OR (team_id=?4 AND ?4 IS NOT NULL)))",
            params![record.tenant_id, record.repository_id, user_id, team_id],
            |row| row.get(0),
        )?;
        if duplicate {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO repository_access_grants
             (id,tenant_id,repository_id,user_id,team_id,permission,created_unix_ms,updated_unix_ms,version)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1)",
            params![record.id, record.tenant_id, record.repository_id, user_id, team_id,
                record.permission, to_i64(record.created_unix_ms)?, to_i64(record.updated_unix_ms)?],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn repository_access_grants(
        &self,
        tenant_id: &str,
        repository_id: &str,
    ) -> Result<Vec<RepositoryAccessGrantRecord>, ControlPlaneError> {
        for value in [tenant_id, repository_id] {
            validate_r9_identifier(value)?;
        }
        let connection = self.connection()?;
        let rows = connection.prepare(
            "SELECT id,tenant_id,repository_id,user_id,team_id,permission,created_unix_ms,updated_unix_ms,version
             FROM repository_access_grants WHERE tenant_id=?1 AND repository_id=?2 ORDER BY id")?
            .query_map(params![tenant_id, repository_id], access_grant_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn revoke_repository_access_grant(
        &self,
        tenant_id: &str,
        repository_id: &str,
        grant_id: &str,
    ) -> Result<bool, ControlPlaneError> {
        for value in [tenant_id, repository_id, grant_id] {
            validate_r9_identifier(value)?;
        }
        Ok(self.connection()?.execute(
            "DELETE FROM repository_access_grants WHERE tenant_id=?1 AND repository_id=?2 AND id=?3",
            params![tenant_id, repository_id, grant_id],
        )? == 1)
    }

    pub fn effective_repository_access_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<EffectiveRepositoryAccess>, ControlPlaneError> {
        for value in [tenant_id, user_id] {
            validate_r9_identifier(value)?;
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT g.repository_id,g.permission,g.user_id,g.team_id
             FROM repository_access_grants g
             WHERE g.tenant_id=?1
               AND EXISTS(SELECT 1 FROM human_user_tenant_bindings b JOIN human_users u
                            ON u.id=b.user_id
                          WHERE b.tenant_id=?1 AND b.user_id=?2 AND u.status='active')
               AND (g.user_id=?2 OR g.team_id IN (
                 SELECT m.team_id FROM team_memberships m JOIN teams t
                   ON t.tenant_id=m.tenant_id AND t.id=m.team_id
                 WHERE m.tenant_id=?1 AND m.user_id=?2 AND t.status='active'))
             ORDER BY g.repository_id,g.id",
        )?;
        let mut access = BTreeMap::<String, (u8, bool, BTreeSet<String>)>::new();
        let rows = statement.query_map(params![tenant_id, user_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        for row in rows {
            let (repository_id, permission, direct_user, team_id) = row?;
            let rank = permission_rank(&permission).ok_or_else(|| {
                ControlPlaneError::CorruptState("invalid repository permission".to_owned())
            })?;
            let entry = access.entry(repository_id).or_default();
            entry.0 = entry.0.max(rank);
            entry.1 |= direct_user.is_some();
            if let Some(team_id) = team_id {
                entry.2.insert(team_id);
            }
        }
        Ok(access
            .into_iter()
            .map(
                |(repository_id, (rank, direct, teams))| EffectiveRepositoryAccess {
                    repository_id,
                    permission: permission_name(rank).to_owned(),
                    direct,
                    team_ids: teams.into_iter().collect(),
                },
            )
            .collect())
    }
}

fn permission_rank(permission: &str) -> Option<u8> {
    match permission {
        "read" => Some(1),
        "write" => Some(2),
        "admin" => Some(3),
        _ => None,
    }
}

fn permission_name(rank: u8) -> &'static str {
    match rank {
        1 => "read",
        2 => "write",
        3 => "admin",
        _ => "read",
    }
}
