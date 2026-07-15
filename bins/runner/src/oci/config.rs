use super::{
    AdmittedLease, Arc, AssignmentKey, BTreeMap, BTreeSet, ContentDigest, ImageVerifyingKey,
    Isolation, LoadedAssignments, PathBuf, ProcessCommandRunner, RunnerError, RuntimeCommandRunner,
    SelectedAssignments,
};

#[derive(Debug, Clone)]
pub struct OciRuntimePaths {
    pub state_root: PathBuf,
    pub podman: PathBuf,
    pub seccomp_profile: PathBuf,
    pub image_store: PathBuf,
    pub runtime_environment: PathBuf,
    pub manifest_directory: PathBuf,
    pub keyring_directory: PathBuf,
}

pub trait OciRuntimeFactory: Send + Sync {
    fn create(&self) -> Result<Box<dyn RuntimeCommandRunner>, RunnerError>;
}

#[derive(Debug)]
pub(super) struct ProcessRuntimeFactory;

impl OciRuntimeFactory for ProcessRuntimeFactory {
    fn create(&self) -> Result<Box<dyn RuntimeCommandRunner>, RunnerError> {
        Ok(Box::new(ProcessCommandRunner::new()?))
    }
}

#[derive(Clone)]
pub(super) struct LoadedOciConfiguration {
    pub(super) state_root: PathBuf,
    pub(super) podman: PathBuf,
    pub(super) seccomp_profile: PathBuf,
    pub(super) image_store: PathBuf,
    pub(super) runtime_environment: BTreeMap<String, String>,
    pub(super) keys: Arc<BTreeMap<ContentDigest, ImageVerifyingKey>>,
    pub(super) assignments: LoadedAssignments,
}

impl LoadedOciConfiguration {
    pub(super) fn select(&self, lease: &AdmittedLease) -> Result<SelectedAssignments, RunnerError> {
        let job = lease
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == lease.job_id)
            .ok_or_else(|| RunnerError::OfferedJobMissing(lease.job_id.clone()))?;
        if job.runner.isolation != Isolation::Oci {
            return Err(RunnerError::UnsupportedIsolation(format!(
                "{:?}",
                job.runner.isolation
            )));
        }
        let capsule_digest = lease
            .capsule
            .digest()
            .map_err(|error| RunnerError::OciManifestMismatch(error.to_string()))?;
        let job_key = AssignmentKey {
            capsule_digest: capsule_digest.clone(),
            job_id: job.id.clone(),
            service_id: None,
        };
        let planned_job_image = job.runner.image.as_deref().ok_or_else(|| {
            RunnerError::OciManifestMismatch(format!(
                "OCI job `{}` has no approval-bound runner image",
                job.id
            ))
        })?;
        let job_record = self
            .assignments
            .exact
            .get(&job_key)
            .or_else(|| self.assignments.reusable.get(planned_job_image))
            .ok_or_else(|| RunnerError::MissingOciManifest {
                job_id: job.id.clone(),
                service_id: None,
            })?
            .clone();
        job_record.verify(&self.keys, job.runner.os, job.runner.arch)?;
        if job_record.locked.reference() != planned_job_image {
            return Err(RunnerError::OciManifestMismatch(format!(
                "job `{}` image differs from its signed approved assignment",
                job.id
            )));
        }
        let mut services = BTreeMap::new();
        for service in &job.services {
            let key = AssignmentKey {
                capsule_digest: capsule_digest.clone(),
                job_id: job.id.clone(),
                service_id: Some(service.id.clone()),
            };
            let record = self
                .assignments
                .exact
                .get(&key)
                .or_else(|| self.assignments.reusable.get(&service.image))
                .ok_or_else(|| RunnerError::MissingOciManifest {
                    job_id: job.id.clone(),
                    service_id: Some(service.id.clone()),
                })?
                .clone();
            record.verify(&self.keys, job.runner.os, job.runner.arch)?;
            if record.locked.reference() != service.image {
                return Err(RunnerError::OciManifestMismatch(format!(
                    "service `{}.{}` image differs from its signed assignment",
                    job.id, service.id
                )));
            }
            services.insert(service.id.clone(), record);
        }
        let expected = job
            .services
            .iter()
            .map(|service| Some(service.id.as_str()))
            .chain(std::iter::once(None))
            .collect::<BTreeSet<_>>();
        if self.assignments.exact.keys().any(|key| {
            key.capsule_digest == capsule_digest
                && key.job_id == job.id
                && !expected.contains(&key.service_id.as_deref())
        }) {
            return Err(RunnerError::OciManifestMismatch(format!(
                "signed assignment set for job `{}` contains an unused service",
                job.id
            )));
        }
        Ok(SelectedAssignments {
            job: job_record,
            services,
        })
    }

    pub(super) fn lease_state_path(&self, lease: &AdmittedLease) -> PathBuf {
        let identity = ContentDigest::sha256(format!(
            "{}\0{}\0{}",
            lease.lease_id, lease.fencing_generation, lease.installation_fencing_epoch
        ));
        self.state_root
            .join(identity.as_str().trim_start_matches("sha256:"))
    }
}
