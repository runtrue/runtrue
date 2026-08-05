use super::*;
use rusqlite::params;

pub(super) fn validate_repository(repository: &RepositoryRecord) -> Result<(), ControlPlaneError> {
    validate_text("repository.id", &repository.id)?;
    validate_text("repository.tenant_id", &repository.tenant_id)?;
    validate_text("repository.owner", &repository.owner)?;
    validate_text("repository.name", &repository.name)?;
    validate_text("repository.default_branch", &repository.default_branch)?;
    validate_text("repository.visibility", &repository.visibility)
}

pub(super) fn repository_conn(
    connection: &Connection,
    id: &str,
) -> Result<RepositoryRecord, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, tenant_id, owner, name, default_branch, visibility, created_unix_ms
             FROM repositories WHERE id = ?1",
            [id],
            repository_row,
        )
        .optional()?
        .ok_or_else(|| not_found("repository", id))
}

pub(super) fn repository_row(row: &Row<'_>) -> rusqlite::Result<RepositoryRecord> {
    Ok(RepositoryRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        owner: row.get(2)?,
        name: row.get(3)?,
        default_branch: row.get(4)?,
        visibility: row.get(5)?,
        created_unix_ms: u64_column(row, 6, "created_unix_ms")?,
    })
}

pub(super) fn scm_installation_conn(
    connection: &Connection,
    id: &str,
) -> Result<ScmInstallationRecord, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, tenant_id, provider, external_id, credential_reference,
                    permissions_json, status, created_unix_ms, updated_unix_ms
             FROM scm_installations WHERE id = ?1",
            [id],
            |row| scm_installation_row_at(row, 0),
        )
        .optional()?
        .ok_or_else(|| not_found("SCM installation", id))
}

pub(super) fn scm_installation_row_at(
    row: &Row<'_>,
    offset: usize,
) -> rusqlite::Result<ScmInstallationRecord> {
    let permissions: String = row.get(offset + 5)?;
    Ok(ScmInstallationRecord {
        id: row.get(offset)?,
        tenant_id: row.get(offset + 1)?,
        provider: row.get(offset + 2)?,
        external_id: row.get(offset + 3)?,
        credential_reference: row.get(offset + 4)?,
        permissions: serde_json::from_str(&permissions)
            .map_err(|error| conversion(offset + 5, error))?,
        status: row.get(offset + 6)?,
        created_unix_ms: u64_column(row, offset + 7, "SCM installation created_unix_ms")?,
        updated_unix_ms: u64_column(row, offset + 8, "SCM installation updated_unix_ms")?,
    })
}

pub(super) fn scm_repository_link_conn(
    connection: &Connection,
    repository_id: &str,
) -> Result<ScmRepositoryLinkRecord, ControlPlaneError> {
    connection
        .query_row(
            "SELECT repository_id, tenant_id, installation_id, external_repository_id,
                    clone_url, status, created_unix_ms, updated_unix_ms
             FROM scm_repository_links WHERE repository_id = ?1",
            [repository_id],
            |row| scm_repository_link_row_at(row, 0),
        )
        .optional()?
        .ok_or_else(|| not_found("SCM repository link", repository_id))
}

pub(super) fn scm_repository_link_row_at(
    row: &Row<'_>,
    offset: usize,
) -> rusqlite::Result<ScmRepositoryLinkRecord> {
    Ok(ScmRepositoryLinkRecord {
        repository_id: row.get(offset)?,
        tenant_id: row.get(offset + 1)?,
        installation_id: row.get(offset + 2)?,
        external_repository_id: row.get(offset + 3)?,
        clone_url: row.get(offset + 4)?,
        status: row.get(offset + 5)?,
        created_unix_ms: u64_column(row, offset + 6, "SCM repository link created_unix_ms")?,
        updated_unix_ms: u64_column(row, offset + 7, "SCM repository link updated_unix_ms")?,
    })
}

pub(in crate::store) const GITHUB_SETUP_COLUMNS: &str =
    "id, tenant_id, principal_id, idempotency_key, request_digest, state_digest,
     github_web_origin, github_api_origin, return_path, status, attempts,
     expires_unix_ms, installation_id,
     installation_external_id, completion_digest, last_error_code,
     created_unix_ms, updated_unix_ms, completed_unix_ms";

impl ControlPlane {
    pub fn create_repository(
        &self,
        repository: &RepositoryRecord,
    ) -> Result<(), ControlPlaneError> {
        validate_repository(repository)?;
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO repositories
             (id, tenant_id, owner, name, default_branch, visibility, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                repository.id,
                repository.tenant_id,
                repository.owner,
                repository.name,
                repository.default_branch,
                repository.visibility,
                to_i64(repository.created_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    pub fn repository(&self, id: &str) -> Result<RepositoryRecord, ControlPlaneError> {
        let connection = self.connection()?;
        repository_conn(&connection, id)
    }

    /// Resolve one provider repository by its exact, case-sensitive normalized
    /// owner/name identity. Multiple tenant registrations are rejected instead
    /// of selecting an arbitrary trust configuration.
    pub fn repository_by_owner_name(
        &self,
        owner: &str,
        name: &str,
    ) -> Result<RepositoryRecord, ControlPlaneError> {
        validate_text("repository.owner", owner)?;
        validate_text("repository.name", name)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, owner, name, default_branch, visibility, created_unix_ms
             FROM repositories WHERE owner = ?1 AND name = ?2 ORDER BY tenant_id, id LIMIT 2",
        )?;
        let repositories = statement
            .query_map(params![owner, name], repository_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        match repositories.as_slice() {
            [repository] => Ok(repository.clone()),
            [] => Err(not_found("repository", &format!("{owner}/{name}"))),
            _ => Err(ControlPlaneError::AmbiguousRepositoryIdentity {
                owner: owner.to_owned(),
                name: name.to_owned(),
            }),
        }
    }

    pub fn list_repositories(&self) -> Result<Vec<RepositoryRecord>, ControlPlaneError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, owner, name, default_branch, visibility, created_unix_ms
             FROM repositories ORDER BY id",
        )?;
        let rows = statement
            .query_map([], repository_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn list_repositories_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<RepositoryRecord>, ControlPlaneError> {
        validate_text("repository tenant", tenant_id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, owner, name, default_branch, visibility, created_unix_ms
             FROM repositories WHERE tenant_id = ?1 ORDER BY id",
        )?;
        let rows = statement
            .query_map([tenant_id], repository_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Return the repository-specific workflow directory, if one overrides the
    /// server-wide default.
    pub fn repository_workflow_directory(
        &self,
        tenant_id: &str,
        repository_id: &str,
    ) -> Result<Option<String>, ControlPlaneError> {
        validate_text("repository workflow tenant", tenant_id)?;
        validate_text("repository workflow repository", repository_id)?;
        let connection = self.connection()?;
        let workflow_directory: Option<String> = connection
            .query_row(
                "SELECT workflow_directory FROM repository_workflow_settings
                 WHERE tenant_id = ?1 AND repository_id = ?2",
                params![tenant_id, repository_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControlPlaneError::from)?;
        match workflow_directory {
            Some(directory)
                if directory.len() <= 1024
                    && normalize_relative_path(&directory).ok().as_deref()
                        == Some(directory.as_str()) =>
            {
                Ok(Some(directory))
            }
            Some(_) => Err(ControlPlaneError::CorruptState(
                "repository workflow directory".to_owned(),
            )),
            None => Ok(None),
        }
    }

    /// Set the repository-relative directory containing workflow files.
    /// Paths are stored in canonical form so equivalent spellings cannot
    /// create different task identities.
    pub fn set_repository_workflow_directory(
        &self,
        tenant_id: &str,
        repository_id: &str,
        workflow_directory: &str,
        now_unix_ms: u64,
    ) -> Result<String, ControlPlaneError> {
        validate_text("repository workflow tenant", tenant_id)?;
        validate_text("repository workflow repository", repository_id)?;
        let normalized = normalize_relative_path(workflow_directory).map_err(|_| {
            ControlPlaneError::InvalidInput("workflow directory must be repository-relative")
        })?;
        if normalized != workflow_directory || normalized.len() > 1024 {
            return Err(ControlPlaneError::InvalidInput(
                "workflow directory must be a normalized repository-relative path",
            ));
        }
        let connection = self.connection()?;
        let changed = connection.execute(
            "INSERT INTO repository_workflow_settings
             (repository_id, tenant_id, workflow_directory, updated_unix_ms)
             SELECT id, tenant_id, ?3, ?4 FROM repositories
             WHERE tenant_id = ?1 AND id = ?2
             ON CONFLICT(repository_id) DO UPDATE SET
                 workflow_directory = excluded.workflow_directory,
                 updated_unix_ms = excluded.updated_unix_ms
             WHERE repository_workflow_settings.tenant_id = excluded.tenant_id",
            params![tenant_id, repository_id, normalized, to_i64(now_unix_ms)?,],
        )?;
        if changed != 1 {
            return Err(not_found("repository", repository_id));
        }
        Ok(normalized)
    }

    pub fn repository_auto_approve_writers(
        &self,
        tenant_id: &str,
        repository_id: &str,
    ) -> Result<bool, ControlPlaneError> {
        validate_text("repository approval tenant", tenant_id)?;
        validate_text("repository approval repository", repository_id)?;
        let connection = self.connection()?;
        let enabled: Option<i64> = connection
            .query_row(
                "SELECT enabled FROM repository_auto_approval_policies
                 WHERE tenant_id = ?1 AND repository_id = ?2",
                params![tenant_id, repository_id],
                |row| row.get(0),
            )
            .optional()?;
        match enabled {
            None | Some(0) => Ok(false),
            Some(1) => Ok(true),
            Some(_) => Err(ControlPlaneError::CorruptState(
                "repository auto-approval policy".to_owned(),
            )),
        }
    }

    pub fn set_repository_auto_approve_writers(
        &self,
        tenant_id: &str,
        repository_id: &str,
        enabled: bool,
        now_unix_ms: u64,
    ) -> Result<bool, ControlPlaneError> {
        validate_text("repository approval tenant", tenant_id)?;
        validate_text("repository approval repository", repository_id)?;
        let connection = self.connection()?;
        let changed = connection.execute(
            "INSERT INTO repository_auto_approval_policies
             (repository_id, tenant_id, enabled, updated_unix_ms)
             SELECT id, tenant_id, ?3, ?4 FROM repositories
             WHERE tenant_id = ?1 AND id = ?2
             ON CONFLICT(repository_id) DO UPDATE SET
                 enabled = excluded.enabled,
                 updated_unix_ms = excluded.updated_unix_ms
             WHERE repository_auto_approval_policies.tenant_id = excluded.tenant_id",
            params![
                tenant_id,
                repository_id,
                i64::from(enabled),
                to_i64(now_unix_ms)?,
            ],
        )?;
        if changed != 1 {
            return Err(not_found("repository", repository_id));
        }
        Ok(enabled)
    }

    pub fn create_scm_installation(
        &self,
        record: &ScmInstallationRecord,
    ) -> Result<IdempotentResult<ScmInstallationRecord>, ControlPlaneError> {
        for (field, value) in [
            ("SCM installation id", record.id.as_str()),
            ("SCM installation tenant", record.tenant_id.as_str()),
            ("SCM installation external id", record.external_id.as_str()),
            (
                "SCM credential reference",
                record.credential_reference.as_str(),
            ),
        ] {
            validate_text(field, value)?;
        }
        if record.provider != "github"
            || !matches!(record.status.as_str(), "active" | "suspended" | "revoked")
            || record.updated_unix_ms < record.created_unix_ms
            || record
                .external_id
                .parse::<u64>()
                .ok()
                .filter(|id| *id > 0)
                .is_none()
            || !valid_github_installation_permissions(&record.permissions)
            || (record.status == "active"
                && !github_installation_permissions_ready(&record.permissions))
        {
            return Err(ControlPlaneError::InvalidInput("invalid SCM installation"));
        }
        let permissions = serde_json::to_string(&canonicalize_json(record.permissions.clone()))?;
        let connection = self.connection()?;
        let inserted = connection.execute(
            "INSERT OR IGNORE INTO scm_installations
             (id, tenant_id, provider, external_id, credential_reference, permissions_json,
              status, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, 'github', ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.id,
                record.tenant_id,
                record.external_id,
                record.credential_reference,
                permissions,
                record.status,
                to_i64(record.created_unix_ms)?,
                to_i64(record.updated_unix_ms)?,
            ],
        )?;
        let existing = scm_installation_conn(&connection, &record.id)?;
        if existing != *record {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        Ok(IdempotentResult {
            value: existing,
            replayed: inserted == 0,
        })
    }

    pub fn scm_installation_for_tenant(
        &self,
        tenant_id: &str,
        installation_id: &str,
    ) -> Result<ScmInstallationRecord, ControlPlaneError> {
        validate_text("SCM installation tenant", tenant_id)?;
        validate_text("SCM installation id", installation_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, tenant_id, provider, external_id, credential_reference,
                        permissions_json, status, created_unix_ms, updated_unix_ms
                 FROM scm_installations WHERE tenant_id = ?1 AND id = ?2",
                params![tenant_id, installation_id],
                |row| scm_installation_row_at(row, 0),
            )
            .optional()?
            .ok_or_else(|| not_found("SCM installation", installation_id))
    }

    pub fn link_scm_repository(
        &self,
        record: &ScmRepositoryLinkRecord,
    ) -> Result<IdempotentResult<ScmRepositoryLinkRecord>, ControlPlaneError> {
        for (field, value) in [
            ("SCM repository id", record.repository_id.as_str()),
            ("SCM repository tenant", record.tenant_id.as_str()),
            ("SCM installation id", record.installation_id.as_str()),
            (
                "SCM external repository id",
                record.external_repository_id.as_str(),
            ),
            ("SCM clone URL", record.clone_url.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if !matches!(record.status.as_str(), "active" | "suspended" | "revoked")
            || record.updated_unix_ms < record.created_unix_ms
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid SCM repository link",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM repositories r
                JOIN scm_installations i ON i.id = ?2
                WHERE r.id = ?1 AND r.tenant_id = ?3 AND i.tenant_id = ?3
                  AND i.provider = 'github' AND i.status = 'active'
             )",
            params![
                record.repository_id,
                record.installation_id,
                record.tenant_id
            ],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(ControlPlaneError::NotFound {
                kind: "SCM repository authorization",
                id: record.repository_id.clone(),
            });
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO scm_repository_links
             (repository_id, tenant_id, installation_id, external_repository_id, clone_url,
              status, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.repository_id,
                record.tenant_id,
                record.installation_id,
                record.external_repository_id,
                record.clone_url,
                record.status,
                to_i64(record.created_unix_ms)?,
                to_i64(record.updated_unix_ms)?,
            ],
        )?;
        let existing = scm_repository_link_conn(&transaction, &record.repository_id)?;
        if existing != *record {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let result = IdempotentResult {
            value: existing,
            replayed: inserted == 0,
        };
        transaction.commit()?;
        Ok(result)
    }
}
