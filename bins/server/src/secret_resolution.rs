use runtrue_compiler::{Compilation, ResolvedSecretMetadata};
use runtrue_control_plane::{
    ControlPlaneError, ControlPlaneStore, RepositoryRecord, SecretResolutionRecord,
};
use runtrue_model::{SecretProjectVersion, SecretResolutionBinding};
use std::collections::BTreeMap;

pub(crate) async fn bind_compilation_secrets(
    store: &dyn ControlPlaneStore,
    repository: &RepositoryRecord,
    compilation: &mut Compilation,
) -> Result<(), ControlPlaneError> {
    let names = compilation.resolvable_secret_names();
    if names.is_empty() {
        return Ok(());
    }
    let scm_account_id = store
        .github_account_id_for_repository(&repository.tenant_id, &repository.id)
        .await?;
    let mut records = Vec::<SecretResolutionRecord>::with_capacity(names.len());
    for name in names {
        records.push(
            store
                .resolve_secret(
                    &repository.tenant_id,
                    &repository.id,
                    &scm_account_id,
                    &name,
                )
                .await?,
        );
    }
    for record in &records {
        store.validate_resolution(record).await?;
    }
    bind_secret_resolution_records(compilation, records)
}

fn bind_secret_resolution_records(
    compilation: &mut Compilation,
    records: Vec<SecretResolutionRecord>,
) -> Result<(), ControlPlaneError> {
    let resolutions = records
        .into_iter()
        .map(|record| {
            let name = record.name.clone();
            let resolved = ResolvedSecretMetadata {
                metadata_id: record.selected.metadata_id,
                binding: SecretResolutionBinding {
                    scope: record.selected.scope.durable_key(),
                    metadata_version: record.selected.version,
                    resolution_digest: record.resolution_digest,
                    project_versions: record
                        .project_versions
                        .into_iter()
                        .map(|(project_id, version)| SecretProjectVersion {
                            project_id,
                            version,
                        })
                        .collect(),
                },
            };
            (name, resolved)
        })
        .collect::<BTreeMap<_, _>>();
    compilation
        .bind_secret_resolutions(&resolutions)
        .map_err(|_| ControlPlaneError::InvalidInput("secret resolution could not be bound"))
}
