use super::*;

impl ControlPlane {
    pub fn list_github_repository_catalog_for_tenant(
        &self,
        tenant_id: &str,
        installation_id: &str,
        include_removed: bool,
        after_external_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<GitHubRepositoryCatalogRecord>, ControlPlaneError> {
        validate_text("GitHub repository catalog tenant", tenant_id)?;
        validate_text("GitHub installation id", installation_id)?;
        validate_page(limit, after_external_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        if github_installation_tx(&transaction, tenant_id, installation_id)?.is_none() {
            return Err(not_found("GitHub installation", installation_id));
        }
        let mut statement = transaction.prepare(
            "SELECT installation_id, external_repository_id, tenant_id,
                    web_origin, api_origin, owner, name, full_name, clone_url,
                    visibility, default_branch, status, selection_generation,
                    first_seen_unix_ms, last_seen_unix_ms, removed_unix_ms, version
             FROM github_repository_catalog
             WHERE tenant_id = ?1 AND installation_id = ?2
               AND (?3 OR status = 'selected') AND external_repository_id > ?4
             ORDER BY external_repository_id LIMIT ?5",
        )?;
        let records = statement
            .query_map(
                params![
                    tenant_id,
                    installation_id,
                    include_removed,
                    after_external_id.unwrap_or(""),
                    i64::try_from(limit).map_err(|_| ControlPlaneError::InvalidInput(
                        "page limit is out of range"
                    ))?,
                ],
                github_repository_catalog_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        transaction.commit()?;
        Ok(records)
    }

    /// Link or provision one local repository only after the provider-selected
    /// catalog and exact tenant/owner/name identities have been resolved.
    pub fn link_selected_github_repository(
        &self,
        request: &LinkSelectedGitHubRepository,
    ) -> Result<IdempotentResult<ScmRepositoryLinkRecord>, ControlPlaneError> {
        validate_github_repository_record(&request.repository)?;
        for value in [
            request.tenant_id.as_str(),
            request.installation_id.as_str(),
            request.external_repository_id.as_str(),
        ] {
            validate_text("GitHub repository link binding", value)?;
        }
        if request.repository.tenant_id != request.tenant_id {
            return Err(ControlPlaneError::InvalidInput(
                "GitHub repository tenant binding differs",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &request.tenant_id)?;
        let installation =
            github_installation_tx(&transaction, &request.tenant_id, &request.installation_id)?
                .filter(|installation| installation.installation.status == "active")
                .ok_or_else(|| {
                    not_found("GitHub repository authorization", &request.repository.id)
                })?;
        let catalog = github_repository_catalog_tx(
            &transaction,
            &request.tenant_id,
            &request.installation_id,
            &request.external_repository_id,
        )?
        .filter(|record| record.status == "selected")
        .ok_or_else(|| not_found("GitHub repository authorization", &request.repository.id))?;
        if installation.installation.id != request.installation_id
            || installation.web_origin != catalog.web_origin
            || installation.api_origin != catalog.api_origin
            || request.repository.owner != catalog.owner
            || request.repository.name != catalog.name
            || request.repository.default_branch != catalog.default_branch
            || request.repository.visibility != catalog.visibility
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        provision_exact_repository_tx(&transaction, &request.repository)?;
        let existing = scm_repository_link_for_tenant_tx(
            &transaction,
            &request.tenant_id,
            &request.repository.id,
        )?;
        if let Some(existing) = existing {
            if existing.installation_id != request.installation_id
                || existing.external_repository_id != request.external_repository_id
                || existing.clone_url != catalog.clone_url
                || existing.status == "revoked"
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if existing.status == "active" {
                transaction.commit()?;
                return Ok(IdempotentResult {
                    value: existing,
                    replayed: true,
                });
            }
            transaction.execute(
                "UPDATE scm_repository_links SET status = 'active', updated_unix_ms = ?3
                 WHERE tenant_id = ?1 AND repository_id = ?2 AND status = 'suspended'",
                params![
                    request.tenant_id,
                    request.repository.id,
                    to_i64(request.now_unix_ms)?,
                ],
            )?;
            let updated = scm_repository_link_for_tenant_tx(
                &transaction,
                &request.tenant_id,
                &request.repository.id,
            )?
            .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "reactivated GitHub link was not readable".to_owned(),
                )
            })?;
            append_github_audit_tx(
                &transaction,
                &self.installation_id,
                request.now_unix_ms,
                &request.tenant_id,
                "github-installation-reconciler",
                "github.repository.link",
                "repository",
                &request.repository.id,
                &format!(
                    "{}:{}",
                    request.installation_id, request.external_repository_id
                ),
                BTreeMap::from([
                    (
                        "external_repository_id".to_owned(),
                        AuditValue::String(request.external_repository_id.clone()),
                    ),
                    (
                        "github_origin_digest".to_owned(),
                        AuditValue::Digest(github_origin_digest(
                            &catalog.web_origin,
                            &catalog.api_origin,
                        )?),
                    ),
                ]),
            )?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: updated,
                replayed: false,
            });
        }
        let conflicting: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM scm_repository_links
             WHERE installation_id = ?1 AND external_repository_id = ?2)",
            params![request.installation_id, request.external_repository_id],
            |row| row.get(0),
        )?;
        if conflicting {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO scm_repository_links
             (repository_id, tenant_id, installation_id, external_repository_id,
              clone_url, status, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?6)",
            params![
                request.repository.id,
                request.tenant_id,
                request.installation_id,
                request.external_repository_id,
                catalog.clone_url,
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let link = scm_repository_link_for_tenant_tx(
            &transaction,
            &request.tenant_id,
            &request.repository.id,
        )?
        .ok_or_else(|| {
            ControlPlaneError::CorruptState("created GitHub link was not readable".to_owned())
        })?;
        append_github_audit_tx(
            &transaction,
            &self.installation_id,
            request.now_unix_ms,
            &request.tenant_id,
            "github-installation-reconciler",
            "github.repository.link",
            "repository",
            &request.repository.id,
            &format!(
                "{}:{}",
                request.installation_id, request.external_repository_id
            ),
            BTreeMap::from([
                (
                    "external_repository_id".to_owned(),
                    AuditValue::String(request.external_repository_id.clone()),
                ),
                (
                    "github_origin_digest".to_owned(),
                    AuditValue::Digest(github_origin_digest(
                        &catalog.web_origin,
                        &catalog.api_origin,
                    )?),
                ),
            ]),
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: link,
            replayed: false,
        })
    }

    pub fn list_github_repository_links_for_tenant(
        &self,
        tenant_id: &str,
        installation_id: &str,
        after_repository_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ScmRepositoryLinkRecord>, ControlPlaneError> {
        validate_text("GitHub repository link tenant", tenant_id)?;
        validate_text("GitHub installation id", installation_id)?;
        validate_page(limit, after_repository_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        if github_installation_tx(&transaction, tenant_id, installation_id)?.is_none() {
            return Err(not_found("GitHub installation", installation_id));
        }
        let mut statement = transaction.prepare(
            "SELECT repository_id, tenant_id, installation_id,
                    external_repository_id, clone_url, status,
                    created_unix_ms, updated_unix_ms
             FROM scm_repository_links
             WHERE tenant_id = ?1 AND installation_id = ?2 AND repository_id > ?3
             ORDER BY repository_id LIMIT ?4",
        )?;
        let links = statement
            .query_map(
                params![
                    tenant_id,
                    installation_id,
                    after_repository_id.unwrap_or(""),
                    i64::try_from(limit).map_err(|_| ControlPlaneError::InvalidInput(
                        "page limit is out of range"
                    ))?,
                ],
                |row| scm_repository_link_row_at(row, 0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        transaction.commit()?;
        Ok(links)
    }

    /// Suspend one repository link without deleting repository-scoped history.
    /// The normal repository-link flow can reactivate the suspended link later.
    pub fn suspend_github_repository_link(
        &self,
        tenant_id: &str,
        repository_id: &str,
        actor_id: &str,
        request_id: &str,
        now_unix_ms: u64,
    ) -> Result<IdempotentResult<ScmRepositoryLinkRecord>, ControlPlaneError> {
        for (field, value) in [
            ("GitHub repository link tenant", tenant_id),
            ("GitHub repository link repository", repository_id),
            ("GitHub repository link actor", actor_id),
            ("GitHub repository link request", request_id),
        ] {
            validate_text(field, value)?;
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let existing = scm_repository_link_for_tenant_tx(&transaction, tenant_id, repository_id)?
            .ok_or_else(|| not_found("GitHub repository link", repository_id))?;
        if existing.status == "revoked" {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if existing.status == "suspended" {
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: existing,
                replayed: true,
            });
        }
        transaction.execute(
            "UPDATE scm_repository_links SET status = 'suspended', updated_unix_ms = ?3
             WHERE tenant_id = ?1 AND repository_id = ?2 AND status = 'active'",
            params![tenant_id, repository_id, to_i64(now_unix_ms)?],
        )?;
        let updated = scm_repository_link_for_tenant_tx(&transaction, tenant_id, repository_id)?
            .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "suspended GitHub repository link was not readable".to_owned(),
                )
            })?;
        append_github_audit_tx(
            &transaction,
            &self.installation_id,
            now_unix_ms,
            tenant_id,
            actor_id,
            "github.repository.unlink",
            "repository",
            repository_id,
            request_id,
            BTreeMap::from([
                (
                    "external_repository_id".to_owned(),
                    AuditValue::String(updated.external_repository_id.clone()),
                ),
                (
                    "installation_id".to_owned(),
                    AuditValue::String(updated.installation_id.clone()),
                ),
            ]),
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: updated,
            replayed: false,
        })
    }
}

use rusqlite::params;

pub(in crate::store) fn github_catalog_matches_selected(
    current: &GitHubRepositoryCatalogRecord,
    selected: &GitHubSelectedRepository,
) -> bool {
    current.external_repository_id == selected.external_repository_id
        && current.owner == selected.owner
        && current.name == selected.name
        && current.full_name == selected.full_name
        && current.clone_url == selected.clone_url
        && current.visibility == selected.visibility
        && current.default_branch == selected.default_branch
}

pub(in crate::store) fn valid_github_status_transition(current: &str, next: &str) -> bool {
    matches!(
        (current, next),
        ("active", "active" | "suspended" | "revoked")
            | ("suspended", "active" | "suspended" | "revoked")
            | ("revoked", "revoked")
    )
}

pub(in crate::store) const fn github_account_kind_name(kind: GitHubAccountKind) -> &'static str {
    match kind {
        GitHubAccountKind::Organization => "organization",
        GitHubAccountKind::User => "user",
    }
}

pub(in crate::store) const fn github_repository_selection_name(
    selection: GitHubRepositorySelection,
) -> &'static str {
    match selection {
        GitHubRepositorySelection::All => "all",
        GitHubRepositorySelection::Selected => "selected",
    }
}

pub(in crate::store) fn reconcile_link_status_for_installation_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    installation_id: &str,
    installation_status: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    match installation_status {
        "active" => {
            transaction.execute(
                "UPDATE scm_repository_links AS l SET status = 'active', updated_unix_ms = ?3
                 WHERE l.tenant_id = ?1 AND l.installation_id = ?2
                   AND l.status = 'suspended' AND EXISTS(
                       SELECT 1 FROM github_repository_catalog c
                       WHERE c.tenant_id = l.tenant_id
                         AND c.installation_id = l.installation_id
                         AND c.external_repository_id = l.external_repository_id
                         AND c.status = 'selected'
                   )",
                params![tenant_id, installation_id, to_i64(now_unix_ms)?],
            )?;
            transaction.execute(
                "UPDATE scm_repository_links AS l SET status = 'suspended', updated_unix_ms = ?3
                 WHERE l.tenant_id = ?1 AND l.installation_id = ?2
                   AND l.status = 'active' AND NOT EXISTS(
                       SELECT 1 FROM github_repository_catalog c
                       WHERE c.tenant_id = l.tenant_id
                         AND c.installation_id = l.installation_id
                         AND c.external_repository_id = l.external_repository_id
                         AND c.status = 'selected'
                   )",
                params![tenant_id, installation_id, to_i64(now_unix_ms)?],
            )?;
        }
        "suspended" => {
            transaction.execute(
                "UPDATE scm_repository_links SET status = 'suspended', updated_unix_ms = ?3
                 WHERE tenant_id = ?1 AND installation_id = ?2 AND status = 'active'",
                params![tenant_id, installation_id, to_i64(now_unix_ms)?],
            )?;
        }
        "revoked" => {
            transaction.execute(
                "UPDATE scm_repository_links SET status = 'revoked', updated_unix_ms = ?3
                 WHERE tenant_id = ?1 AND installation_id = ?2 AND status <> 'revoked'",
                params![tenant_id, installation_id, to_i64(now_unix_ms)?],
            )?;
        }
        _ => {
            return Err(ControlPlaneError::InvalidInput(
                "invalid GitHub installation status",
            ))
        }
    }
    Ok(())
}

pub(in crate::store) fn validate_github_repository_record(
    repository: &RepositoryRecord,
) -> Result<(), ControlPlaneError> {
    validate_repository(repository)?;
    if repository.owner.contains('/')
        || repository.name.contains('/')
        || !matches!(
            repository.visibility.as_str(),
            "public" | "private" | "internal"
        )
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid GitHub repository record",
        ));
    }
    Ok(())
}

pub(in crate::store) fn provision_exact_repository_tx(
    transaction: &Transaction<'_>,
    repository: &RepositoryRecord,
) -> Result<(), ControlPlaneError> {
    let by_id = transaction
        .query_row(
            "SELECT id, tenant_id, owner, name, default_branch, visibility, created_unix_ms
             FROM repositories WHERE id = ?1",
            [&repository.id],
            repository_row,
        )
        .optional()?;
    if let Some(existing) = by_id {
        if existing.tenant_id != repository.tenant_id {
            return Err(not_found("GitHub repository authorization", &repository.id));
        }
        if existing != *repository {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        return Ok(());
    }
    let matching_ids = {
        let mut statement = transaction.prepare(
            "SELECT id FROM repositories
             WHERE tenant_id = ?1 AND owner = ?2 AND name = ?3 ORDER BY id LIMIT 2",
        )?;
        let values = statement
            .query_map(
                params![repository.tenant_id, repository.owner, repository.name],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        values
    };
    if !matching_ids.is_empty() {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let inserted = transaction.execute(
        "INSERT OR IGNORE INTO repositories
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
    if inserted != 1 {
        return Err(not_found("GitHub repository authorization", &repository.id));
    }
    Ok(())
}

pub(in crate::store) fn scm_repository_link_for_tenant_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    repository_id: &str,
) -> Result<Option<ScmRepositoryLinkRecord>, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT repository_id, tenant_id, installation_id,
                    external_repository_id, clone_url, status,
                    created_unix_ms, updated_unix_ms
             FROM scm_repository_links WHERE tenant_id = ?1 AND repository_id = ?2",
            params![tenant_id, repository_id],
            |row| scm_repository_link_row_at(row, 0),
        )
        .optional()
        .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
pub(in crate::store) fn append_github_audit_tx(
    transaction: &Transaction<'_>,
    installation_id: &str,
    observed_unix_ms: u64,
    tenant_id: &str,
    actor_id: &str,
    action: &str,
    resource_kind: &str,
    resource_id: &str,
    request_id: &str,
    metadata: BTreeMap<String, AuditValue>,
) -> Result<(), ControlPlaneError> {
    append_audit_event_tx(
        transaction,
        installation_id,
        AuditEventData {
            observed_unix_ms,
            tenant_id: tenant_id.to_owned(),
            actor: AuditPrincipal {
                kind: "github-app-administrator".to_owned(),
                id: actor_id.to_owned(),
            },
            action: action.to_owned(),
            resource: AuditResource {
                kind: resource_kind.to_owned(),
                id: resource_id.to_owned(),
            },
            result: "success".to_owned(),
            request_id: request_id.to_owned(),
            decision_id: None,
            metadata,
        },
    )?;
    Ok(())
}

pub(in crate::store) const GITHUB_LIFECYCLE_COLUMNS: &str =
    "delivery_id, tenant_id, installation_id, installation_external_id,
     event_name, action, payload_digest, state, attempts, available_unix_ms,
     lease_owner, lease_generation, lease_expires_unix_ms, completion_digest,
     completed_lease_owner, completed_lease_generation, last_failure_generation,
     last_failure_lease_owner, last_error_digest, last_retry_unix_ms,
     created_unix_ms, updated_unix_ms, completed_unix_ms";
