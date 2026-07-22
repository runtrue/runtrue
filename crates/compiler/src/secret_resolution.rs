use crate::{
    canonical_bytes, digest_json, job_steps, job_steps_mut, ApprovalSubject, Compilation,
    CompileError,
};
use runtrue_model::{ContentDigest, SecretReference, SecretResolutionBinding};
use runtrue_workflow_ir as ir;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Metadata-only trusted resolution supplied by the control-plane adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSecretMetadata {
    pub metadata_id: String,
    pub binding: SecretResolutionBinding,
}

const RESERVED_SCM_PROVIDER_SECRET: &str = "runtrue-scm-provider-token";

fn references(capsule: &ir::ExecutionCapsule) -> impl Iterator<Item = &SecretReference> {
    capsule.permissions.secrets.iter().chain(
        capsule
            .jobs
            .iter()
            .chain(
                capsule
                    .dynamic_jobs
                    .iter()
                    .map(|template| &template.template),
            )
            .flat_map(|job| {
                job.permissions
                    .secrets
                    .iter()
                    .chain(job_steps(job).flat_map(|step| step.capabilities.secrets.iter()))
            }),
    )
}

fn bind_reference(
    reference: &mut SecretReference,
    resolutions: &BTreeMap<String, ResolvedSecretMetadata>,
) -> Result<(), CompileError> {
    if reference.name == RESERVED_SCM_PROVIDER_SECRET {
        return Ok(());
    }
    let resolved = resolutions.get(&reference.name).ok_or_else(|| {
        CompileError::semantic(
            "permissions.secrets",
            format!(
                "secret `{}` has no trusted metadata resolution",
                reference.name
            ),
        )
    })?;
    reference.metadata_id.clone_from(&resolved.metadata_id);
    reference.resolution = Some(resolved.binding.clone());
    Ok(())
}

fn permission_snapshot_digest(
    capsule: &ir::ExecutionCapsule,
) -> Result<ContentDigest, CompileError> {
    let snapshot = capsule
        .jobs
        .iter()
        .chain(
            capsule
                .dynamic_jobs
                .iter()
                .map(|template| &template.template),
        )
        .map(|job| {
            (
                &job.id,
                &job.permissions,
                job_steps(job)
                    .map(|step| (&step.id, &step.capabilities))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    digest_json(&(&capsule.permissions, snapshot))
}

fn refresh_approval_subject(
    capsule: &ir::ExecutionCapsule,
    capsule_digest: &ContentDigest,
    subject: &mut ApprovalSubject,
) -> Result<(), CompileError> {
    let mut secret_metadata_ids = references(capsule)
        .filter(|reference| reference.name != RESERVED_SCM_PROVIDER_SECRET)
        .map(|reference| reference.metadata_id.clone())
        .collect::<Vec<_>>();
    secret_metadata_ids.sort();
    secret_metadata_ids.dedup();
    subject.execution_capsule_digest = capsule_digest.clone();
    subject.permission_set_digest = permission_snapshot_digest(capsule)?;
    subject.secret_metadata_ids = secret_metadata_ids;
    Ok(())
}

impl Compilation {
    pub fn resolvable_secret_names(&self) -> BTreeSet<String> {
        references(&self.capsule)
            .filter(|reference| reference.name != RESERVED_SCM_PROVIDER_SECRET)
            .map(|reference| reference.name.clone())
            .collect()
    }

    /// Replaces compiler-local secret identities and refreshes every digest
    /// affected by the signed resolution proof.
    pub fn bind_secret_resolutions(
        &mut self,
        resolutions: &BTreeMap<String, ResolvedSecretMetadata>,
    ) -> Result<(), CompileError> {
        let required = self.resolvable_secret_names();
        let supplied = resolutions.keys().cloned().collect::<BTreeSet<_>>();
        if required != supplied {
            return Err(CompileError::semantic(
                "permissions.secrets",
                "trusted secret resolutions do not exactly match declared secret names",
            ));
        }

        for reference in &mut self.capsule.permissions.secrets {
            bind_reference(reference, resolutions)?;
        }
        for job in self.capsule.jobs.iter_mut().chain(
            self.capsule
                .dynamic_jobs
                .iter_mut()
                .map(|template| &mut template.template),
        ) {
            for reference in &mut job.permissions.secrets {
                bind_reference(reference, resolutions)?;
            }
            for step in job_steps_mut(job) {
                for reference in &mut step.capabilities.secrets {
                    bind_reference(reference, resolutions)?;
                }
            }
        }

        self.capsule_digest = self.capsule.digest()?;
        refresh_approval_subject(
            &self.capsule,
            &self.capsule_digest,
            &mut self.approval_subject,
        )?;
        self.approval_subject_digest = self.approval_subject.digest()?;

        // Prove that the stored digest corresponds to the exact canonical
        // capsule after binding, not merely to the in-memory structure.
        let canonical = canonical_bytes(&self.capsule)?;
        if ContentDigest::sha256(canonical) != self.capsule_digest {
            return Err(CompileError::semantic(
                "permissions.secrets",
                "secret resolution produced an inconsistent capsule digest",
            ));
        }
        Ok(())
    }
}
