#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OciPlatform {
    pub os: OperatingSystem,
    pub architecture: Architecture,
}

impl OciPlatform {
    #[must_use]
    pub const fn new(os: OperatingSystem, architecture: Architecture) -> Self {
        Self { os, architecture }
    }

    #[must_use]
    pub const fn linux_amd64() -> Self {
        Self::new(OperatingSystem::Linux, Architecture::Amd64)
    }

    pub(crate) fn as_oci(self) -> &'static str {
        match (self.os, self.architecture) {
            (OperatingSystem::Linux, Architecture::Amd64) => "linux/amd64",
            (OperatingSystem::Linux, Architecture::Arm64) => "linux/arm64",
            (OperatingSystem::Windows, Architecture::Amd64) => "windows/amd64",
            (OperatingSystem::Windows, Architecture::Arm64) => "windows/arm64",
            (OperatingSystem::Macos, Architecture::Amd64) => "darwin/amd64",
            (OperatingSystem::Macos, Architecture::Arm64) => "darwin/arm64",
        }
    }
}

/// Runtime, image-lock, mount, environment, resource, and cleanup policy for
/// the OCI executor.
#[derive(Debug, Clone)]
pub struct OciExecutorConfig {
    pub runtime_program: PathBuf,
    pub seccomp_profile: PathBuf,
    /// Optional prehydrated Podman image store. Job/container metadata remains
    /// in the private per-job graph root; execution never pulls into this store.
    pub image_store: Option<PathBuf>,
    pub job_images: BTreeMap<String, LockedImage>,
    pub service_images: BTreeMap<(String, String), LockedImage>,
    pub additional_mounts: Vec<OciMount>,
    /// One runner-owned, capability-scoped broker socket. This is distinct
    /// from arbitrary mounts and is admitted only by the executor's exact
    /// socket validator.
    pub broker_socket: Option<OciMount>,
    pub runtime_environment: BTreeMap<String, String>,
    pub limits: OciLimits,
    pub cleanup_timeout: Duration,
}

impl OciExecutorConfig {
    #[must_use]
    pub fn new(runtime_program: impl Into<PathBuf>, seccomp_profile: impl Into<PathBuf>) -> Self {
        Self {
            runtime_program: runtime_program.into(),
            seccomp_profile: seccomp_profile.into(),
            image_store: None,
            job_images: BTreeMap::new(),
            service_images: BTreeMap::new(),
            additional_mounts: Vec::new(),
            broker_socket: None,
            runtime_environment: BTreeMap::new(),
            limits: OciLimits::default(),
            cleanup_timeout: DEFAULT_CLEANUP_TIMEOUT,
        }
    }

    pub fn insert_job_image(
        &mut self,
        job_id: impl Into<String>,
        image: LockedImage,
    ) -> Result<(), OciError> {
        let job_id = job_id.into();
        validate_identifier("job image key", &job_id)?;
        if self.job_images.insert(job_id.clone(), image).is_some() {
            return Err(OciError::InvalidConfiguration(format!(
                "duplicate image assignment for job `{job_id}`"
            )));
        }
        Ok(())
    }

    /// Assign an immutable, signature-constrained image to one planned service.
    /// The capsule reference must exactly equal this lock during preflight.
    pub fn insert_service_image(
        &mut self,
        job_id: impl Into<String>,
        service_id: impl Into<String>,
        image: LockedImage,
    ) -> Result<(), OciError> {
        let job_id = job_id.into();
        let service_id = service_id.into();
        validate_identifier("service image job key", &job_id)?;
        validate_identifier("service image service key", &service_id)?;
        let key = (job_id, service_id);
        if self.service_images.insert(key.clone(), image).is_some() {
            return Err(OciError::InvalidConfiguration(format!(
                "duplicate image assignment for service `{}.{}`",
                key.0, key.1
            )));
        }
        Ok(())
    }
}
use crate::{
    validate_identifier, Architecture, BTreeMap, Duration, LockedImage, OciError, OciLimits,
    OciMount, OperatingSystem, PathBuf, DEFAULT_CLEANUP_TIMEOUT,
};
