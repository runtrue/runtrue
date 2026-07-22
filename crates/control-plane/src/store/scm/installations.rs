use super::*;
use rusqlite::params;
use serde::Serialize;

pub(in crate::store) fn valid_github_installation_permissions(value: &Value) -> bool {
    let Some(permissions) = value.as_object() else {
        return false;
    };
    if permissions.get("metadata").and_then(Value::as_str) != Some("read") {
        return false;
    }
    permissions.iter().all(|(name, level)| {
        let Some(level) = level.as_str() else {
            return false;
        };
        match name.as_str() {
            "metadata" => level == "read",
            // Persist verified over-broad posture so operators can fix it;
            // activation still requires exact read/write levels below.
            "contents" | "pull_requests" | "actions" | "merge_queues" | "checks" | "statuses"
            | "issues" => matches!(level, "read" | "write"),
            _ => false,
        }
    })
}

pub(in crate::store) fn github_installation_permissions_ready(value: &Value) -> bool {
    let Some(permissions) = value.as_object() else {
        return false;
    };
    permissions.get("metadata").and_then(Value::as_str) == Some("read")
        && matches!(
            permissions.get("contents").and_then(Value::as_str),
            Some("read" | "write")
        )
        && matches!(
            permissions.get("pull_requests").and_then(Value::as_str),
            Some("read" | "write")
        )
        && permissions.get("checks").and_then(Value::as_str) == Some("write")
}

pub(in crate::store) fn github_installation_row(
    row: &Row<'_>,
) -> rusqlite::Result<GitHubInstallationRecord> {
    let account_kind: String = row.get(13)?;
    let account_kind = match account_kind.as_str() {
        "organization" => GitHubAccountKind::Organization,
        "user" => GitHubAccountKind::User,
        other => {
            return Err(conversion(
                13,
                DecodeError(format!("unknown GitHub account kind `{other}`")),
            ))
        }
    };
    let repository_selection: String = row.get(14)?;
    let repository_selection = match repository_selection.as_str() {
        "all" => GitHubRepositorySelection::All,
        "selected" => GitHubRepositorySelection::Selected,
        other => {
            return Err(conversion(
                14,
                DecodeError(format!("unknown GitHub repository selection `{other}`")),
            ))
        }
    };
    Ok(GitHubInstallationRecord {
        installation: scm_installation_row_at(row, 0)?,
        web_origin: row.get(9)?,
        api_origin: row.get(10)?,
        account_external_id: row.get(11)?,
        account_login: row.get(12)?,
        account_kind,
        repository_selection,
        lifecycle_generation: u64_column(row, 15, "GitHub lifecycle generation")?,
        synchronized_unix_ms: u64_column(row, 16, "GitHub synchronization")?,
        suspended_unix_ms: optional_u64_column(row, 17, "GitHub suspension")?,
        revoked_unix_ms: optional_u64_column(row, 18, "GitHub revocation")?,
        version: u64_column(row, 19, "GitHub installation version")?,
    })
}

pub(in crate::store) fn github_installation_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    installation_id: &str,
) -> Result<Option<GitHubInstallationRecord>, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT i.id, i.tenant_id, i.provider, i.external_id,
                    i.credential_reference, i.permissions_json, i.status,
                    i.created_unix_ms, i.updated_unix_ms,
                    p.web_origin, p.api_origin, p.account_external_id,
                    p.account_login, p.account_kind, p.repository_selection,
                    p.lifecycle_generation, p.synchronized_unix_ms,
                    p.suspended_unix_ms, p.revoked_unix_ms, p.version
             FROM scm_installations i
             JOIN github_installation_profiles p ON p.installation_id = i.id
                  AND p.tenant_id = i.tenant_id
             WHERE i.tenant_id = ?1 AND i.id = ?2",
            params![tenant_id, installation_id],
            github_installation_row,
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::store) fn github_repository_catalog_row(
    row: &Row<'_>,
) -> rusqlite::Result<GitHubRepositoryCatalogRecord> {
    Ok(GitHubRepositoryCatalogRecord {
        installation_id: row.get(0)?,
        external_repository_id: row.get(1)?,
        tenant_id: row.get(2)?,
        web_origin: row.get(3)?,
        api_origin: row.get(4)?,
        owner: row.get(5)?,
        name: row.get(6)?,
        full_name: row.get(7)?,
        clone_url: row.get(8)?,
        visibility: row.get(9)?,
        default_branch: row.get(10)?,
        status: row.get(11)?,
        selection_generation: u64_column(row, 12, "GitHub catalog generation")?,
        first_seen_unix_ms: u64_column(row, 13, "GitHub catalog first seen")?,
        last_seen_unix_ms: u64_column(row, 14, "GitHub catalog last seen")?,
        removed_unix_ms: optional_u64_column(row, 15, "GitHub catalog removal")?,
        version: u64_column(row, 16, "GitHub catalog version")?,
    })
}

pub(in crate::store) fn github_repository_catalog_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    installation_id: &str,
    external_repository_id: &str,
) -> Result<Option<GitHubRepositoryCatalogRecord>, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT installation_id, external_repository_id, tenant_id,
                    web_origin, api_origin, owner, name, full_name, clone_url,
                    visibility, default_branch, status, selection_generation,
                    first_seen_unix_ms, last_seen_unix_ms, removed_unix_ms, version
             FROM github_repository_catalog
             WHERE tenant_id = ?1 AND installation_id = ?2
               AND external_repository_id = ?3",
            params![tenant_id, installation_id, external_repository_id],
            github_repository_catalog_row,
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::store) fn validate_github_reconciliation(
    request: &ReconcileGitHubInstallation,
) -> Result<(), ControlPlaneError> {
    let record = &request.installation;
    let installation = &record.installation;
    for value in [
        installation.id.as_str(),
        installation.tenant_id.as_str(),
        installation.external_id.as_str(),
        installation.credential_reference.as_str(),
        record.web_origin.as_str(),
        record.api_origin.as_str(),
        record.account_external_id.as_str(),
        record.account_login.as_str(),
    ] {
        validate_text("GitHub installation identity", value)?;
    }
    validate_github_origins(&record.web_origin, &record.api_origin)?;
    let status_timestamps_valid = match installation.status.as_str() {
        "active" => record.suspended_unix_ms.is_none() && record.revoked_unix_ms.is_none(),
        "suspended" => record.suspended_unix_ms.is_some() && record.revoked_unix_ms.is_none(),
        "revoked" => record.revoked_unix_ms.is_some(),
        _ => false,
    };
    let permissions = serde_json::to_vec(&canonicalize_json(installation.permissions.clone()))?;
    if installation.provider != "github"
        || installation
            .external_id
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
        || record
            .account_external_id
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
        || record.account_login.contains('/')
        || record
            .account_login
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || !valid_github_installation_permissions(&installation.permissions)
        || permissions.len() > MAX_TEXT_BYTES
        || !status_timestamps_valid
        || record.lifecycle_generation == 0
        || record.version == 0
        || installation.updated_unix_ms != record.synchronized_unix_ms
        || request.now_unix_ms != record.synchronized_unix_ms
        || record.synchronized_unix_ms < installation.created_unix_ms
        || record
            .suspended_unix_ms
            .is_some_and(|value| value > record.synchronized_unix_ms)
        || record
            .revoked_unix_ms
            .is_some_and(|value| value > record.synchronized_unix_ms)
        || request.selected_repositories.len() > MAX_GITHUB_SELECTED_REPOSITORIES
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid GitHub installation reconciliation",
        ));
    }
    let mut external_ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for repository in &request.selected_repositories {
        validate_github_selected_repository(repository, &record.web_origin)?;
        if !external_ids.insert(repository.external_repository_id.as_str())
            || !names.insert((repository.owner.as_str(), repository.name.as_str()))
        {
            return Err(ControlPlaneError::InvalidInput(
                "duplicate GitHub repository selection",
            ));
        }
    }
    Ok(())
}

pub(in crate::store) fn validate_github_selected_repository(
    repository: &GitHubSelectedRepository,
    web_origin: &str,
) -> Result<(), ControlPlaneError> {
    for value in [
        repository.external_repository_id.as_str(),
        repository.owner.as_str(),
        repository.name.as_str(),
        repository.full_name.as_str(),
        repository.default_branch.as_str(),
    ] {
        validate_text("GitHub selected repository", value)?;
    }
    if repository
        .external_repository_id
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .is_none()
        || repository.owner.contains('/')
        || repository.name.contains('/')
        || repository.full_name != format!("{}/{}", repository.owner, repository.name)
        || !matches!(
            repository.visibility.as_str(),
            "public" | "private" | "internal"
        )
        || !valid_github_clone_url(repository, web_origin)
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid GitHub selected repository",
        ));
    }
    Ok(())
}

pub(in crate::store) fn valid_github_clone_url(
    repository: &GitHubSelectedRepository,
    web_origin: &str,
) -> bool {
    repository.clone_url == format!("{web_origin}/{}/{}.git", repository.owner, repository.name)
}

pub(in crate::store) fn validate_github_origins(
    web_origin: &str,
    api_origin: &str,
) -> Result<(), ControlPlaneError> {
    if !valid_canonical_github_https_origin(web_origin, false)
        || !valid_canonical_github_https_origin(api_origin, true)
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid canonical GitHub origin",
        ));
    }
    Ok(())
}

pub(in crate::store) fn valid_canonical_github_https_origin(value: &str, allow_path: bool) -> bool {
    let Some(authority_and_path) = value.strip_prefix("https://") else {
        return false;
    };
    if value.len() > MAX_TEXT_BYTES
        || value.ends_with('/')
        || authority_and_path.is_empty()
        || authority_and_path.contains(['?', '#', '@', '\\'])
        || authority_and_path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }
    let (authority, path) = authority_and_path
        .split_once('/')
        .map_or((authority_and_path, None), |(authority, path)| {
            (authority, Some(path))
        });
    if authority.is_empty()
        || authority.starts_with('.')
        || authority.ends_with('.')
        || authority.ends_with(":443")
        || authority.bytes().any(|byte| byte.is_ascii_uppercase())
        || !authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
    {
        return false;
    }
    match path {
        None => true,
        Some(_) if !allow_path => false,
        Some(path) => path.split('/').all(|segment| {
            !segment.is_empty()
                && !matches!(segment, "." | "..")
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~')
                })
        }),
    }
}

pub(in crate::store) fn github_origin_digest(
    web_origin: &str,
    api_origin: &str,
) -> Result<ContentDigest, ControlPlaneError> {
    #[derive(Serialize)]
    struct Material<'a> {
        version: u32,
        web_origin: &'a str,
        api_origin: &'a str,
    }
    let mut bytes = b"runtrue.github-app.origin.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&Material {
        version: 1,
        web_origin,
        api_origin,
    })?);
    Ok(ContentDigest::sha256(bytes))
}

pub(in crate::store) fn github_reconciliation_digest(
    request: &ReconcileGitHubInstallation,
) -> Result<ContentDigest, ControlPlaneError> {
    #[derive(Serialize)]
    struct Material<'a> {
        version: u32,
        installation: &'a GitHubInstallationRecord,
        selected_repositories: Vec<&'a GitHubSelectedRepository>,
    }
    let mut selected_repositories = request.selected_repositories.iter().collect::<Vec<_>>();
    selected_repositories.sort_by(|left, right| {
        left.external_repository_id
            .cmp(&right.external_repository_id)
    });
    let mut bytes = b"runtrue.github-app.reconciliation.v2\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&Material {
        version: 2,
        installation: &request.installation,
        selected_repositories,
    })?);
    Ok(ContentDigest::sha256(bytes))
}

pub(in crate::store) fn scm_installation_for_tenant_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    installation_id: &str,
) -> Result<Option<ScmInstallationRecord>, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, tenant_id, provider, external_id, credential_reference,
                    permissions_json, status, created_unix_ms, updated_unix_ms
             FROM scm_installations WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id, installation_id],
            |row| scm_installation_row_at(row, 0),
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::store) fn reconcile_github_installation_tx(
    transaction: &Transaction<'_>,
    request: &ReconcileGitHubInstallation,
) -> Result<IdempotentResult<GitHubInstallationReconciliationResult>, ControlPlaneError> {
    let incoming = &request.installation;
    let installation = &incoming.installation;
    let current = github_installation_tx(transaction, &installation.tenant_id, &installation.id)?;
    let base =
        scm_installation_for_tenant_tx(transaction, &installation.tenant_id, &installation.id)?;
    let permissions = serde_json::to_string(&canonicalize_json(installation.permissions.clone()))?;
    let installation_replayed = if let Some(current) = current {
        if current == *incoming {
            true
        } else {
            if request.expected_version != Some(current.version)
                || incoming.version
                    != current
                        .version
                        .checked_add(1)
                        .ok_or(ControlPlaneError::IntegerRange {
                            field: "GitHub installation version",
                        })?
                || incoming.lifecycle_generation
                    != current.lifecycle_generation.checked_add(1).ok_or(
                        ControlPlaneError::IntegerRange {
                            field: "GitHub installation lifecycle generation",
                        },
                    )?
                || installation.id != current.installation.id
                || installation.tenant_id != current.installation.tenant_id
                || installation.provider != current.installation.provider
                || installation.external_id != current.installation.external_id
                || installation.credential_reference != current.installation.credential_reference
                || installation.created_unix_ms != current.installation.created_unix_ms
                || incoming.web_origin != current.web_origin
                || incoming.api_origin != current.api_origin
                || incoming.account_external_id != current.account_external_id
                || incoming.account_kind != current.account_kind
                || !valid_github_status_transition(
                    &current.installation.status,
                    &installation.status,
                )
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.execute(
                "UPDATE scm_installations SET permissions_json = ?3, status = ?4,
                     updated_unix_ms = ?5 WHERE tenant_id = ?1 AND id = ?2",
                params![
                    installation.tenant_id,
                    installation.id,
                    permissions,
                    installation.status,
                    to_i64(installation.updated_unix_ms)?,
                ],
            )?;
            transaction.execute(
                "UPDATE github_installation_profiles SET account_login = ?3,
                     repository_selection = ?4, lifecycle_generation = ?5,
                     synchronized_unix_ms = ?6, suspended_unix_ms = ?7,
                     revoked_unix_ms = ?8, version = ?9
                 WHERE tenant_id = ?1 AND installation_id = ?2 AND version = ?10",
                params![
                    installation.tenant_id,
                    installation.id,
                    incoming.account_login,
                    github_repository_selection_name(incoming.repository_selection),
                    to_i64(incoming.lifecycle_generation)?,
                    to_i64(incoming.synchronized_unix_ms)?,
                    incoming.suspended_unix_ms.map(to_i64).transpose()?,
                    incoming.revoked_unix_ms.map(to_i64).transpose()?,
                    to_i64(incoming.version)?,
                    to_i64(current.version)?,
                ],
            )?;
            false
        }
    } else if let Some(base) = base {
        if request.expected_version.is_some()
            || incoming.version != 1
            || incoming.lifecycle_generation != 1
            || installation.id != base.id
            || installation.tenant_id != base.tenant_id
            || installation.provider != base.provider
            || installation.external_id != base.external_id
            || installation.credential_reference != base.credential_reference
            || installation.created_unix_ms != base.created_unix_ms
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE scm_installations SET permissions_json = ?3, status = ?4,
                 updated_unix_ms = ?5 WHERE tenant_id = ?1 AND id = ?2",
            params![
                installation.tenant_id,
                installation.id,
                permissions,
                installation.status,
                to_i64(installation.updated_unix_ms)?,
            ],
        )?;
        insert_github_installation_profile_tx(transaction, incoming)?;
        false
    } else {
        if request.expected_version.is_some()
            || incoming.version != 1
            || incoming.lifecycle_generation != 1
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO scm_installations
             (id, tenant_id, provider, external_id, credential_reference,
              permissions_json, status, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, 'github', ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                installation.id,
                installation.tenant_id,
                installation.external_id,
                installation.credential_reference,
                permissions,
                installation.status,
                to_i64(installation.created_unix_ms)?,
                to_i64(installation.updated_unix_ms)?,
            ],
        )?;
        if inserted != 1 {
            return Err(ControlPlaneError::NotFound {
                kind: "GitHub installation authorization",
                id: installation.id.clone(),
            });
        }
        insert_github_installation_profile_tx(transaction, incoming)?;
        false
    };

    let mut selected = request.selected_repositories.iter().collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        left.external_repository_id
            .cmp(&right.external_repository_id)
    });
    let selected_ids = selected
        .iter()
        .map(|record| record.external_repository_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut summary = GitHubRepositoryReconciliationSummary {
        selected: u64::try_from(selected.len()).map_err(|_| ControlPlaneError::IntegerRange {
            field: "GitHub selected repository count",
        })?,
        ..GitHubRepositoryReconciliationSummary::default()
    };
    for selected in selected {
        match github_repository_catalog_tx(
            transaction,
            &installation.tenant_id,
            &installation.id,
            &selected.external_repository_id,
        )? {
            None => {
                transaction.execute(
                    "INSERT INTO github_repository_catalog
                     (installation_id, external_repository_id, tenant_id,
                      web_origin, api_origin, owner, name, full_name, clone_url,
                      visibility, default_branch, status, selection_generation,
                      first_seen_unix_ms, last_seen_unix_ms, version)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                             'selected', ?12, ?13, ?13, 1)",
                    params![
                        installation.id,
                        selected.external_repository_id,
                        installation.tenant_id,
                        incoming.web_origin,
                        incoming.api_origin,
                        selected.owner,
                        selected.name,
                        selected.full_name,
                        selected.clone_url,
                        selected.visibility,
                        selected.default_branch,
                        to_i64(incoming.lifecycle_generation)?,
                        to_i64(incoming.synchronized_unix_ms)?,
                    ],
                )?;
                summary.inserted += 1;
            }
            Some(current) => {
                if current.web_origin != incoming.web_origin
                    || current.api_origin != incoming.api_origin
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let exact = github_catalog_matches_selected(&current, selected)
                    && current.status == "selected"
                    && current.selection_generation == incoming.lifecycle_generation
                    && current.last_seen_unix_ms == incoming.synchronized_unix_ms;
                if exact {
                    continue;
                }
                if current.selection_generation >= incoming.lifecycle_generation {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                transaction.execute(
                    "UPDATE github_repository_catalog SET owner = ?4, name = ?5,
                         full_name = ?6, clone_url = ?7, visibility = ?8,
                         default_branch = ?9, status = 'selected',
                         selection_generation = ?10, last_seen_unix_ms = ?11,
                         removed_unix_ms = NULL, version = version + 1
                     WHERE tenant_id = ?1 AND installation_id = ?2
                       AND external_repository_id = ?3",
                    params![
                        installation.tenant_id,
                        installation.id,
                        selected.external_repository_id,
                        selected.owner,
                        selected.name,
                        selected.full_name,
                        selected.clone_url,
                        selected.visibility,
                        selected.default_branch,
                        to_i64(incoming.lifecycle_generation)?,
                        to_i64(incoming.synchronized_unix_ms)?,
                    ],
                )?;
                summary.updated += 1;
            }
        }
    }
    let active_ids = {
        let mut statement = transaction.prepare(
            "SELECT external_repository_id FROM github_repository_catalog
             WHERE tenant_id = ?1 AND installation_id = ?2 AND status = 'selected'",
        )?;
        let values = statement
            .query_map(params![installation.tenant_id, installation.id], |row| {
                row.get(0)
            })?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        values
    };
    for external_id in active_ids {
        if selected_ids.contains(external_id.as_str()) {
            continue;
        }
        transaction.execute(
            "UPDATE github_repository_catalog SET status = 'removed',
                 selection_generation = ?4, last_seen_unix_ms = ?5,
                 removed_unix_ms = ?5, version = version + 1
             WHERE tenant_id = ?1 AND installation_id = ?2
               AND external_repository_id = ?3 AND status = 'selected'",
            params![
                installation.tenant_id,
                installation.id,
                external_id,
                to_i64(incoming.lifecycle_generation)?,
                to_i64(incoming.synchronized_unix_ms)?,
            ],
        )?;
        summary.removed += 1;
    }
    reconcile_link_status_for_installation_tx(
        transaction,
        &installation.tenant_id,
        &installation.id,
        &installation.status,
        incoming.synchronized_unix_ms,
    )?;
    let durable = github_installation_tx(transaction, &installation.tenant_id, &installation.id)?
        .ok_or_else(|| {
        ControlPlaneError::CorruptState(
            "reconciled GitHub installation was not readable".to_owned(),
        )
    })?;
    Ok(IdempotentResult {
        value: GitHubInstallationReconciliationResult {
            installation: durable,
            repositories: summary,
        },
        replayed: installation_replayed
            && summary.inserted == 0
            && summary.updated == 0
            && summary.removed == 0,
    })
}

pub(in crate::store) fn insert_github_installation_profile_tx(
    transaction: &Transaction<'_>,
    record: &GitHubInstallationRecord,
) -> Result<(), ControlPlaneError> {
    transaction.execute(
        "INSERT INTO github_installation_profiles
         (installation_id, tenant_id, web_origin, api_origin,
          account_external_id, account_login, account_kind,
          repository_selection, lifecycle_generation, synchronized_unix_ms,
          suspended_unix_ms, revoked_unix_ms, version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            record.installation.id,
            record.installation.tenant_id,
            record.web_origin,
            record.api_origin,
            record.account_external_id,
            record.account_login,
            github_account_kind_name(record.account_kind),
            github_repository_selection_name(record.repository_selection),
            to_i64(record.lifecycle_generation)?,
            to_i64(record.synchronized_unix_ms)?,
            record.suspended_unix_ms.map(to_i64).transpose()?,
            record.revoked_unix_ms.map(to_i64).transpose()?,
            to_i64(record.version)?,
        ],
    )?;
    Ok(())
}

impl ControlPlane {
    /// Stable GitHub account identity associated with a linked repository.
    /// This is presentation-adapter metadata; secret resolution itself remains
    /// provider-neutral and accepts the returned SCM account id as input.
    pub fn github_account_id_for_repository(
        &self,
        tenant_id: &str,
        repository_id: &str,
    ) -> Result<String, ControlPlaneError> {
        validate_text("GitHub account tenant", tenant_id)?;
        validate_text("GitHub account repository", repository_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT p.account_external_id
                 FROM scm_repository_links l
                 JOIN scm_installations i
                   ON i.id = l.installation_id AND i.tenant_id = l.tenant_id
                 JOIN github_installation_profiles p
                   ON p.installation_id = i.id AND p.tenant_id = i.tenant_id
                 WHERE l.tenant_id = ?1 AND l.repository_id = ?2
                   AND l.status = 'active' AND i.provider = 'github'
                   AND i.status = 'active'",
                params![tenant_id, repository_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| not_found("GitHub repository account", repository_id))
    }

    pub fn reconcile_github_installation(
        &self,
        request: &ReconcileGitHubInstallation,
    ) -> Result<IdempotentResult<GitHubInstallationReconciliationResult>, ControlPlaneError> {
        validate_github_reconciliation(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &request.installation.installation.tenant_id)?;
        let result = reconcile_github_installation_tx(&transaction, request)?;
        if !result.replayed {
            let installation = &result.value.installation;
            append_github_audit_tx(
                &transaction,
                &self.installation_id,
                request.now_unix_ms,
                &installation.installation.tenant_id,
                "github-installation-reconciler",
                "github.installation.reconcile",
                "github-installation",
                &installation.installation.id,
                &format!(
                    "{}:{}",
                    installation.installation.id, installation.lifecycle_generation
                ),
                BTreeMap::from([
                    (
                        "external_installation_id".to_owned(),
                        AuditValue::String(installation.installation.external_id.clone()),
                    ),
                    (
                        "github_origin_digest".to_owned(),
                        AuditValue::Digest(github_origin_digest(
                            &installation.web_origin,
                            &installation.api_origin,
                        )?),
                    ),
                    (
                        "selected_repository_count".to_owned(),
                        AuditValue::Integer(to_i64(result.value.repositories.selected)?),
                    ),
                    (
                        "inserted_repository_count".to_owned(),
                        AuditValue::Integer(to_i64(result.value.repositories.inserted)?),
                    ),
                    (
                        "updated_repository_count".to_owned(),
                        AuditValue::Integer(to_i64(result.value.repositories.updated)?),
                    ),
                    (
                        "removed_repository_count".to_owned(),
                        AuditValue::Integer(to_i64(result.value.repositories.removed)?),
                    ),
                ]),
            )?;
        }
        transaction.commit()?;
        Ok(result)
    }

    pub fn set_github_installation_status(
        &self,
        request: &SetGitHubInstallationStatus,
    ) -> Result<IdempotentResult<GitHubInstallationRecord>, ControlPlaneError> {
        validate_text("GitHub installation tenant", &request.tenant_id)?;
        validate_text("GitHub installation id", &request.installation_id)?;
        if !matches!(request.status.as_str(), "active" | "suspended" | "revoked")
            || request.expected_version == 0
            || request.lifecycle_generation == 0
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid GitHub installation status transition",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &request.tenant_id)?;
        let current =
            github_installation_tx(&transaction, &request.tenant_id, &request.installation_id)?
                .ok_or_else(|| not_found("GitHub installation", &request.installation_id))?;
        if current.installation.status == request.status
            && current.lifecycle_generation == request.lifecycle_generation
        {
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: current,
                replayed: true,
            });
        }
        if current.installation.status == "revoked"
            || current.version != request.expected_version
            || request.lifecycle_generation
                != current.lifecycle_generation.checked_add(1).ok_or(
                    ControlPlaneError::IntegerRange {
                        field: "GitHub installation lifecycle generation",
                    },
                )?
            || request.now_unix_ms < current.synchronized_unix_ms
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE scm_installations SET status = ?3, updated_unix_ms = ?4
             WHERE tenant_id = ?1 AND id = ?2",
            params![
                request.tenant_id,
                request.installation_id,
                request.status,
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "UPDATE github_installation_profiles SET lifecycle_generation = ?3,
                 synchronized_unix_ms = ?4,
                 suspended_unix_ms = CASE WHEN ?5 = 'suspended' THEN ?4 ELSE NULL END,
                 revoked_unix_ms = CASE WHEN ?5 = 'revoked' THEN ?4 ELSE revoked_unix_ms END,
                 version = version + 1
             WHERE tenant_id = ?1 AND installation_id = ?2 AND version = ?6",
            params![
                request.tenant_id,
                request.installation_id,
                to_i64(request.lifecycle_generation)?,
                to_i64(request.now_unix_ms)?,
                request.status,
                to_i64(request.expected_version)?,
            ],
        )?;
        reconcile_link_status_for_installation_tx(
            &transaction,
            &request.tenant_id,
            &request.installation_id,
            &request.status,
            request.now_unix_ms,
        )?;
        let updated =
            github_installation_tx(&transaction, &request.tenant_id, &request.installation_id)?
                .ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "updated GitHub installation was not readable".to_owned(),
                    )
                })?;
        append_github_audit_tx(
            &transaction,
            &self.installation_id,
            request.now_unix_ms,
            &request.tenant_id,
            "github-installation-reconciler",
            "github.installation.status",
            "github-installation",
            &request.installation_id,
            &format!(
                "{}:{}",
                request.installation_id, request.lifecycle_generation
            ),
            BTreeMap::from([
                (
                    "lifecycle_generation".to_owned(),
                    AuditValue::Integer(to_i64(request.lifecycle_generation)?),
                ),
                (
                    "status".to_owned(),
                    AuditValue::String(request.status.clone()),
                ),
                (
                    "github_origin_digest".to_owned(),
                    AuditValue::Digest(github_origin_digest(
                        &updated.web_origin,
                        &updated.api_origin,
                    )?),
                ),
            ]),
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: updated,
            replayed: false,
        })
    }

    pub fn github_installation_for_tenant(
        &self,
        tenant_id: &str,
        installation_id: &str,
    ) -> Result<GitHubInstallationRecord, ControlPlaneError> {
        validate_text("GitHub installation tenant", tenant_id)?;
        validate_text("GitHub installation id", installation_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let record = github_installation_tx(&transaction, tenant_id, installation_id)?
            .ok_or_else(|| not_found("GitHub installation", installation_id))?;
        transaction.commit()?;
        Ok(record)
    }

    /// Provider-facing resolution for an already signature-verified lifecycle
    /// webhook. Public callers must use the tenant-filtered accessor above.
    pub fn github_installation_by_external_id(
        &self,
        web_origin: &str,
        api_origin: &str,
        external_id: &str,
    ) -> Result<GitHubInstallationRecord, ControlPlaneError> {
        validate_github_origins(web_origin, api_origin)?;
        validate_text("GitHub external installation id", external_id)?;
        if external_id
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
        {
            return Err(not_found("GitHub installation", external_id));
        }
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT i.id, i.tenant_id, i.provider, i.external_id,
                        i.credential_reference, i.permissions_json, i.status,
                        i.created_unix_ms, i.updated_unix_ms,
                        p.web_origin, p.api_origin, p.account_external_id,
                        p.account_login, p.account_kind, p.repository_selection,
                        p.lifecycle_generation, p.synchronized_unix_ms,
                        p.suspended_unix_ms, p.revoked_unix_ms, p.version
                 FROM scm_installations i
                 JOIN github_installation_profiles p ON p.installation_id = i.id
                      AND p.tenant_id = i.tenant_id
                 WHERE i.provider = 'github' AND p.web_origin = ?1
                   AND p.api_origin = ?2 AND i.external_id = ?3",
                params![web_origin, api_origin, external_id],
                github_installation_row,
            )
            .optional()?
            .ok_or_else(|| not_found("GitHub installation", external_id))
    }

    pub fn list_github_installations_for_tenant(
        &self,
        tenant_id: &str,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<GitHubInstallationRecord>, ControlPlaneError> {
        validate_text("GitHub installation tenant", tenant_id)?;
        validate_page(limit, after_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let mut statement = transaction.prepare(
            "SELECT i.id, i.tenant_id, i.provider, i.external_id,
                    i.credential_reference, i.permissions_json, i.status,
                    i.created_unix_ms, i.updated_unix_ms,
                    p.web_origin, p.api_origin, p.account_external_id,
                    p.account_login, p.account_kind, p.repository_selection,
                    p.lifecycle_generation, p.synchronized_unix_ms,
                    p.suspended_unix_ms, p.revoked_unix_ms, p.version
             FROM scm_installations i
             JOIN github_installation_profiles p ON p.installation_id = i.id
                  AND p.tenant_id = i.tenant_id
             WHERE i.tenant_id = ?1 AND i.id > ?2
             ORDER BY i.id LIMIT ?3",
        )?;
        let records = statement
            .query_map(
                params![
                    tenant_id,
                    after_id.unwrap_or(""),
                    i64::try_from(limit).map_err(|_| ControlPlaneError::InvalidInput(
                        "page limit is out of range"
                    ))?,
                ],
                github_installation_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        transaction.commit()?;
        Ok(records)
    }
}
