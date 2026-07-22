use super::super::{
    hash_serializable, not_found, params, to_i64, u64_column, validate_text, BTreeSet,
    ContentDigest, ControlPlane, ControlPlaneError, SecretMetadataReference, Transaction,
    TransactionBehavior,
};
use super::secret_metadata_row;
use crate::{
    ConfigurationProjectRecord, ConfigurationProjectTarget, ConfigurationProjectTargetKind,
    PutConfigurationProject, SecretResolutionCandidate, SecretResolutionRecord, SecretScope,
};
use rusqlite::OptionalExtension as _;
use serde::Serialize;

fn validate_project(input: &PutConfigurationProject) -> Result<(), ControlPlaneError> {
    validate_text("configuration project id", &input.id)?;
    validate_text("configuration project tenant", &input.tenant_id)?;
    validate_text("configuration project name", &input.name)?;
    if input.description.len() > 8 * 1024 {
        return Err(ControlPlaneError::InvalidInput(
            "configuration project description is too large",
        ));
    }
    if !matches!(input.status.as_str(), "active" | "archived") {
        return Err(ControlPlaneError::InvalidInput(
            "configuration project status must be active or archived",
        ));
    }
    let mut unique = BTreeSet::new();
    for target in &input.targets {
        validate_text("configuration project target", &target.id)?;
        if target.created_unix_ms > input.updated_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "configuration project target is newer than the project",
            ));
        }
        if !unique.insert((target.kind, target.id.as_str())) {
            return Err(ControlPlaneError::InvalidInput(
                "configuration project targets must be unique",
            ));
        }
    }
    Ok(())
}

fn target_kind(value: &str) -> Result<ConfigurationProjectTargetKind, ControlPlaneError> {
    match value {
        "scm_account" => Ok(ConfigurationProjectTargetKind::ScmAccount),
        "repository" => Ok(ConfigurationProjectTargetKind::Repository),
        other => Err(ControlPlaneError::CorruptState(format!(
            "unknown configuration project target kind `{other}`"
        ))),
    }
}

fn project_targets_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    project_id: &str,
) -> Result<Vec<ConfigurationProjectTarget>, ControlPlaneError> {
    let mut statement = transaction.prepare(
        "SELECT target_kind, target_id, created_unix_ms
         FROM configuration_project_targets
         WHERE tenant_id = ?1 AND project_id = ?2
         ORDER BY target_kind, target_id",
    )?;
    let rows = statement
        .query_map(params![tenant_id, project_id], |row| {
            let kind: String = row.get(0)?;
            let created_unix_ms = u64_column(row, 2, "created_unix_ms")?;
            Ok((kind, row.get(1)?, created_unix_ms))
        })?
        .collect::<rusqlite::Result<Vec<(String, String, u64)>>>()?;
    rows.into_iter()
        .map(|(kind, id, created_unix_ms)| {
            Ok(ConfigurationProjectTarget {
                kind: target_kind(&kind)?,
                id,
                created_unix_ms,
            })
        })
        .collect()
}

fn project_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    project_id: &str,
) -> Result<ConfigurationProjectRecord, ControlPlaneError> {
    let mut project = transaction
        .query_row(
            "SELECT id, tenant_id, name, description, status, version,
                    created_unix_ms, updated_unix_ms
             FROM configuration_projects WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id, project_id],
            |row| {
                Ok(ConfigurationProjectRecord {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    name: row.get(2)?,
                    description: row.get(3)?,
                    status: row.get(4)?,
                    version: u64_column(row, 5, "version")?,
                    created_unix_ms: u64_column(row, 6, "created_unix_ms")?,
                    updated_unix_ms: u64_column(row, 7, "updated_unix_ms")?,
                    targets: Vec::new(),
                })
            },
        )
        .optional()?
        .ok_or_else(|| not_found("configuration project", project_id))?;
    project.targets = project_targets_tx(transaction, tenant_id, project_id)?;
    Ok(project)
}

impl ControlPlane {
    /// Creates or exact-version updates a provider-neutral configuration project.
    pub fn put_configuration_project(
        &self,
        input: &PutConfigurationProject,
    ) -> Result<ConfigurationProjectRecord, ControlPlaneError> {
        validate_project(input)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(u64, u64)> = transaction
            .query_row(
                "SELECT version, created_unix_ms FROM configuration_projects
                 WHERE tenant_id = ?1 AND id = ?2",
                params![input.tenant_id, input.id],
                |row| {
                    Ok((
                        u64_column(row, 0, "version")?,
                        u64_column(row, 1, "created_unix_ms")?,
                    ))
                },
            )
            .optional()?;
        let (version, created_unix_ms) = match existing {
            None if input.expected_version == 0 => (1, input.updated_unix_ms),
            None => {
                return Err(ControlPlaneError::ConfigurationProjectVersionConflict {
                    id: input.id.clone(),
                    expected: input.expected_version,
                    actual: 0,
                })
            }
            Some((actual, created)) if actual == input.expected_version => (actual + 1, created),
            Some((actual, _)) => {
                return Err(ControlPlaneError::ConfigurationProjectVersionConflict {
                    id: input.id.clone(),
                    expected: input.expected_version,
                    actual,
                })
            }
        };
        transaction.execute(
            "INSERT INTO configuration_projects
             (id, tenant_id, name, description, status, version,
              created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 description = excluded.description,
                 status = excluded.status,
                 version = excluded.version,
                 updated_unix_ms = excluded.updated_unix_ms",
            params![
                input.id,
                input.tenant_id,
                input.name,
                input.description,
                input.status,
                to_i64(version)?,
                to_i64(created_unix_ms)?,
                to_i64(input.updated_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "DELETE FROM configuration_project_targets
             WHERE tenant_id = ?1 AND project_id = ?2",
            params![input.tenant_id, input.id],
        )?;
        for target in &input.targets {
            transaction.execute(
                "INSERT INTO configuration_project_targets
                 (tenant_id, project_id, target_kind, target_id, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    input.tenant_id,
                    input.id,
                    target.kind.as_str(),
                    target.id,
                    to_i64(target.created_unix_ms)?,
                ],
            )?;
        }
        let record = project_tx(&transaction, &input.tenant_id, &input.id)?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn configuration_project(
        &self,
        tenant_id: &str,
        project_id: &str,
    ) -> Result<ConfigurationProjectRecord, ControlPlaneError> {
        validate_text("configuration project tenant", tenant_id)?;
        validate_text("configuration project id", project_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let project = project_tx(&transaction, tenant_id, project_id)?;
        transaction.commit()?;
        Ok(project)
    }

    pub fn list_configuration_projects(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ConfigurationProjectRecord>, ControlPlaneError> {
        validate_text("configuration project tenant", tenant_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let ids = {
            let mut statement = transaction.prepare(
                "SELECT id FROM configuration_projects
                 WHERE tenant_id = ?1 ORDER BY name, id",
            )?;
            let ids = statement
                .query_map([tenant_id], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            ids
        };
        let projects = ids
            .iter()
            .map(|id| project_tx(&transaction, tenant_id, id))
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit()?;
        Ok(projects)
    }

    /// Metadata-only inventory. This never reads a secret vault snapshot.
    pub fn list_tenant_secret_metadata(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<SecretMetadataReference>, ControlPlaneError> {
        validate_text("secret tenant", tenant_id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, scope, name, provider, provider_reference,
                    secret_type, status, current_version, created_unix_ms, updated_unix_ms
             FROM secret_metadata WHERE tenant_id = ?1 ORDER BY scope, name, id",
        )?;
        let metadata = statement
            .query_map([tenant_id], secret_metadata_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(metadata)
    }

    pub fn resolve_secret_metadata(
        &self,
        tenant_id: &str,
        repository_id: &str,
        scm_account_id: &str,
        name: &str,
    ) -> Result<SecretResolutionRecord, ControlPlaneError> {
        for (field, value) in [
            ("secret tenant", tenant_id),
            ("secret repository", repository_id),
            ("secret SCM account", scm_account_id),
            ("secret name", name),
        ] {
            validate_text(field, value)?;
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let mut matching_projects = Vec::new();
        {
            let mut statement = transaction.prepare(
                "SELECT DISTINCT p.id, p.version
                 FROM configuration_projects p
                 JOIN configuration_project_targets t
                   ON t.tenant_id = p.tenant_id AND t.project_id = p.id
                 WHERE p.tenant_id = ?1 AND p.status = 'active'
                   AND ((t.target_kind = 'repository' AND t.target_id = ?2)
                     OR (t.target_kind = 'scm_account' AND t.target_id = ?3))
                 ORDER BY p.id",
            )?;
            let rows = statement
                .query_map(params![tenant_id, repository_id, scm_account_id], |row| {
                    Ok((row.get(0)?, u64_column(row, 1, "version")?))
                })?
                .collect::<rusqlite::Result<Vec<(String, u64)>>>()?;
            matching_projects.extend(rows);
        }

        let find =
            |scope: &SecretScope| -> Result<Option<SecretResolutionCandidate>, ControlPlaneError> {
                let key = scope.durable_key();
                Ok(transaction
                    .query_row(
                        "SELECT id, current_version FROM secret_metadata
                     WHERE tenant_id = ?1 AND scope = ?2 AND name = ?3 AND status = 'active'",
                        params![tenant_id, key, name],
                        |row| {
                            Ok(SecretResolutionCandidate {
                                scope: scope.clone(),
                                metadata_id: row.get(0)?,
                                version: super::super::optional_u64_column(
                                    row,
                                    1,
                                    "current_version",
                                )?,
                            })
                        },
                    )
                    .optional()?)
            };

        let repository = find(&SecretScope {
            kind: crate::SecretScopeKind::Repository,
            id: repository_id.to_owned(),
        })?;
        let mut project_candidates = Vec::new();
        for (project_id, _) in &matching_projects {
            if let Some(candidate) = find(&SecretScope {
                kind: crate::SecretScopeKind::Project,
                id: project_id.clone(),
            })? {
                project_candidates.push(candidate);
            }
        }
        let scm_account = find(&SecretScope {
            kind: crate::SecretScopeKind::ScmAccount,
            id: scm_account_id.to_owned(),
        })?;
        let workspace = find(&SecretScope::workspace(tenant_id))?;

        if repository.is_none() && project_candidates.len() > 1 {
            return Err(ControlPlaneError::AmbiguousSecretResolution {
                name: name.to_owned(),
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
            .ok_or_else(|| not_found("secret", name))?;
        let mut shadowed = Vec::new();
        shadowed.extend(project_candidates);
        shadowed.extend(scm_account);
        shadowed.extend(workspace);
        shadowed.retain(|candidate| candidate != &selected);

        #[derive(Serialize)]
        struct ResolutionSubject<'a> {
            version: u32,
            tenant_id: &'a str,
            repository_id: &'a str,
            scm_account_id: &'a str,
            name: &'a str,
            selected: &'a SecretResolutionCandidate,
            shadowed: &'a [SecretResolutionCandidate],
            project_versions: &'a [(String, u64)],
        }
        let resolution_digest: ContentDigest = hash_serializable(&ResolutionSubject {
            version: 1,
            tenant_id,
            repository_id,
            scm_account_id,
            name,
            selected: &selected,
            shadowed: &shadowed,
            project_versions: &matching_projects,
        })?;
        transaction.commit()?;
        Ok(SecretResolutionRecord {
            tenant_id: tenant_id.to_owned(),
            repository_id: repository_id.to_owned(),
            scm_account_id: scm_account_id.to_owned(),
            name: name.to_owned(),
            selected,
            shadowed,
            project_versions: matching_projects,
            resolution_digest,
        })
    }

    /// Re-resolves immediately before sealing and fails if metadata, versions,
    /// project membership, precedence, or the canonical digest changed.
    pub fn validate_secret_resolution(
        &self,
        expected: &SecretResolutionRecord,
    ) -> Result<(), ControlPlaneError> {
        let actual = self.resolve_secret_metadata(
            &expected.tenant_id,
            &expected.repository_id,
            &expected.scm_account_id,
            &expected.name,
        )?;
        if &actual != expected {
            return Err(ControlPlaneError::StaleSecretResolution {
                name: expected.name.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ConfigurationProjectTarget, ConfigurationProjectTargetKind, ControlPlane,
        ControlPlaneError, PutConfigurationProject, SecretMetadataReference, SecretScope,
        SecretScopeKind, TenantIdentityRecord,
    };

    fn metadata(id: &str, scope: SecretScope) -> SecretMetadataReference {
        SecretMetadataReference {
            id: id.to_owned(),
            tenant_id: "tenant".to_owned(),
            scope: scope.durable_key(),
            name: "TOKEN".to_owned(),
            provider: "external-test".to_owned(),
            provider_reference: Some(format!("reference:{id}")),
            secret_type: "opaque".to_owned(),
            status: "active".to_owned(),
            current_version: None,
            created_unix_ms: 1,
            updated_unix_ms: 1,
        }
    }

    fn project(id: &str, repository_id: &str) -> PutConfigurationProject {
        PutConfigurationProject {
            id: id.to_owned(),
            tenant_id: "tenant".to_owned(),
            name: id.to_owned(),
            description: String::new(),
            status: "active".to_owned(),
            expected_version: 0,
            targets: vec![ConfigurationProjectTarget {
                kind: ConfigurationProjectTargetKind::Repository,
                id: repository_id.to_owned(),
                created_unix_ms: 1,
            }],
            updated_unix_ms: 1,
        }
    }

    fn control_plane() -> ControlPlane {
        let control = ControlPlane::open_in_memory("installation", 1).unwrap();
        control
            .put_tenant_identity(
                &TenantIdentityRecord {
                    id: "tenant".to_owned(),
                    slug: "tenant".to_owned(),
                    name: "Tenant".to_owned(),
                    status: "active".to_owned(),
                    settings: serde_json::json!({}),
                    created_unix_ms: 1,
                    updated_unix_ms: 1,
                    version: 1,
                },
                None,
            )
            .unwrap();
        control
    }

    #[test]
    fn resolution_is_deterministic_and_project_ambiguity_fails_closed() {
        let control = control_plane();
        control
            .put_configuration_project(&project("project-a", "repo"))
            .unwrap();
        for value in [
            metadata("workspace", SecretScope::workspace("tenant")),
            metadata(
                "account",
                SecretScope {
                    kind: SecretScopeKind::ScmAccount,
                    id: "account".to_owned(),
                },
            ),
            metadata(
                "project-a-secret",
                SecretScope {
                    kind: SecretScopeKind::Project,
                    id: "project-a".to_owned(),
                },
            ),
        ] {
            control.store_secret_metadata(&value).unwrap();
        }

        let first = control
            .resolve_secret_metadata("tenant", "repo", "account", "TOKEN")
            .unwrap();
        let second = control
            .resolve_secret_metadata("tenant", "repo", "account", "TOKEN")
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.selected.metadata_id, "project-a-secret");
        assert_eq!(
            first
                .shadowed
                .iter()
                .map(|candidate| candidate.metadata_id.as_str())
                .collect::<Vec<_>>(),
            ["account", "workspace"]
        );

        control
            .put_configuration_project(&project("project-b", "repo"))
            .unwrap();
        control
            .store_secret_metadata(&metadata(
                "project-b-secret",
                SecretScope {
                    kind: SecretScopeKind::Project,
                    id: "project-b".to_owned(),
                },
            ))
            .unwrap();
        assert!(matches!(
            control.resolve_secret_metadata("tenant", "repo", "account", "TOKEN"),
            Err(ControlPlaneError::AmbiguousSecretResolution { project_ids, .. })
                if project_ids == ["project-a", "project-b"]
        ));

        control
            .store_secret_metadata(&metadata(
                "repository",
                SecretScope {
                    kind: SecretScopeKind::Repository,
                    id: "repo".to_owned(),
                },
            ))
            .unwrap();
        let repository = control
            .resolve_secret_metadata("tenant", "repo", "account", "TOKEN")
            .unwrap();
        assert_eq!(repository.selected.metadata_id, "repository");
        assert_eq!(repository.project_versions.len(), 2);
    }

    #[test]
    fn project_updates_require_the_exact_durable_version() {
        let control = control_plane();
        let created = control
            .put_configuration_project(&project("project", "repo"))
            .unwrap();
        assert_eq!(created.version, 1);
        let mut stale = project("project", "repo-two");
        stale.expected_version = 0;
        assert!(matches!(
            control.put_configuration_project(&stale),
            Err(ControlPlaneError::ConfigurationProjectVersionConflict {
                expected: 0,
                actual: 1,
                ..
            })
        ));
    }

    #[test]
    fn project_version_change_invalidates_a_pre_seal_resolution() {
        let control = control_plane();
        control
            .put_configuration_project(&project("project", "repo"))
            .unwrap();
        control
            .store_secret_metadata(&metadata(
                "project-secret",
                SecretScope {
                    kind: SecretScopeKind::Project,
                    id: "project".to_owned(),
                },
            ))
            .unwrap();
        let resolution = control
            .resolve_secret_metadata("tenant", "repo", "account", "TOKEN")
            .unwrap();
        let mut changed = project("project", "repo");
        changed.expected_version = 1;
        changed.description = "membership policy changed".to_owned();
        changed.updated_unix_ms = 2;
        changed.targets[0].created_unix_ms = 2;
        control.put_configuration_project(&changed).unwrap();
        assert!(matches!(
            control.validate_secret_resolution(&resolution),
            Err(ControlPlaneError::StaleSecretResolution { name }) if name == "TOKEN"
        ));
    }
}
