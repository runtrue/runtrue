use super::decode_key;
use super::{
    now_unix_ms, read_bounded_private_file, sorted_directory_files, strict_json, Arc, Architecture,
    BTreeMap, ContentDigest, ImageKind, ImageVerifyingKey, LockedImage, OciPlatform,
    OperatingSystem, Path, RunnerError, SignedImageManifest, COMPAT_ASSIGNMENT_SCOPE,
    COMPAT_CAPSULE_DIGEST, COMPAT_JOB_ID, COMPAT_OCI_REFERENCE, COMPAT_SERVICE_ID,
    COMPAT_SIGNATURE_IDENTITY, JOB_ROLE, MAX_ASSIGNMENTS, MAX_KEY_BYTES, MAX_MANIFEST_BYTES,
    REUSABLE_IMAGE_SCOPE,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct AssignmentKey {
    pub(super) capsule_digest: ContentDigest,
    pub(super) job_id: String,
    pub(super) service_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct AssignmentRecord {
    pub(super) signed: SignedImageManifest,
    pub(super) locked: LockedImage,
}

#[derive(Debug, Clone)]
pub(super) struct LoadedAssignments {
    pub(super) exact: BTreeMap<AssignmentKey, AssignmentRecord>,
    pub(super) reusable: BTreeMap<String, AssignmentRecord>,
}

impl LoadedAssignments {
    pub(super) fn len(&self) -> usize {
        self.exact.len() + self.reusable.len()
    }

    pub(super) fn records(&self) -> impl Iterator<Item = &AssignmentRecord> {
        self.exact.values().chain(self.reusable.values())
    }
}

impl AssignmentRecord {
    pub(super) fn verify(
        &self,
        keys: &BTreeMap<ContentDigest, ImageVerifyingKey>,
        os: OperatingSystem,
        architecture: Architecture,
    ) -> Result<(), RunnerError> {
        keys.get(&self.signed.key_id)
            .ok_or_else(|| RunnerError::UntrustedOciImageKey(self.signed.key_id.clone()))?
            .verify_manifest(&self.signed)?;
        if self.signed.manifest.kind != ImageKind::OciImage {
            return Err(RunnerError::OciManifestMismatch(
                "signed assignment is not an OCI image".to_owned(),
            ));
        }
        if self.signed.manifest.operating_system != os_text(os)
            || self.signed.manifest.architecture != architecture_text(architecture)
            || self.locked.platform() != OciPlatform::new(os, architecture)
            || self.signed.manifest.payload_digest != *self.locked.digest()
        {
            return Err(RunnerError::OciManifestMismatch(
                "signed OCI digest or platform does not match the job".to_owned(),
            ));
        }
        if let Some(expiry) = self.signed.manifest.expires_unix_ms {
            if now_unix_ms()? >= expiry {
                return Err(RunnerError::OciManifestExpired);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(super) struct SelectedAssignments {
    pub(super) job: AssignmentRecord,
    pub(super) services: BTreeMap<String, AssignmentRecord>,
}

impl SelectedAssignments {
    pub(super) fn all_records(&self) -> impl Iterator<Item = &AssignmentRecord> {
        std::iter::once(&self.job).chain(self.services.values())
    }
}

pub(super) fn load_image_keys(
    directory: &Path,
) -> Result<Arc<BTreeMap<ContentDigest, ImageVerifyingKey>>, RunnerError> {
    let mut keys = BTreeMap::new();
    for path in sorted_directory_files(directory)? {
        let bytes = read_bounded_private_file(&path, MAX_KEY_BYTES)?;
        let decoded = decode_key(&bytes).ok_or_else(|| {
            RunnerError::OciConfiguration(format!("invalid OCI image key `{}`", path.display()))
        })?;
        let key = ImageVerifyingKey::from_bytes(&decoded)?;
        let key_id = key.key_id();
        if keys.insert(key_id.clone(), key).is_some() {
            return Err(RunnerError::OciConfiguration(format!(
                "duplicate OCI image key `{key_id}`"
            )));
        }
    }
    if keys.is_empty() {
        return Err(RunnerError::OciConfiguration(
            "OCI image keyring is empty".to_owned(),
        ));
    }
    Ok(Arc::new(keys))
}

pub(super) fn load_assignments(
    directory: &Path,
    keys: &BTreeMap<ContentDigest, ImageVerifyingKey>,
) -> Result<LoadedAssignments, RunnerError> {
    let mut exact = BTreeMap::new();
    let mut reusable = BTreeMap::new();
    let paths = sorted_directory_files(directory)?;
    if paths.len() > MAX_ASSIGNMENTS {
        return Err(RunnerError::OciConfiguration(format!(
            "OCI manifest count exceeds {MAX_ASSIGNMENTS}"
        )));
    }
    for path in paths {
        let bytes = read_bounded_private_file(&path, MAX_MANIFEST_BYTES)?;
        let signed: SignedImageManifest = strict_json(&bytes).map_err(|error| {
            RunnerError::OciConfiguration(format!(
                "invalid OCI manifest `{}`: {error}",
                path.display()
            ))
        })?;
        keys.get(&signed.key_id)
            .ok_or_else(|| RunnerError::UntrustedOciImageKey(signed.key_id.clone()))?
            .verify_manifest(&signed)?;
        let compatibility = signed.manifest.compatibility.clone();
        let reference = required(&compatibility, COMPAT_OCI_REFERENCE)?;
        let signature_identity = required(&compatibility, COMPAT_SIGNATURE_IDENTITY)?;
        let platform = platform(
            &signed.manifest.operating_system,
            &signed.manifest.architecture,
        )?;
        let locked = LockedImage::new(reference.clone(), signature_identity, platform)?;
        let record = AssignmentRecord { signed, locked };
        record.verify(keys, platform.os, platform.architecture)?;
        if compatibility
            .get(COMPAT_ASSIGNMENT_SCOPE)
            .is_some_and(|scope| scope == REUSABLE_IMAGE_SCOPE)
        {
            if compatibility.contains_key(COMPAT_CAPSULE_DIGEST)
                || compatibility.contains_key(COMPAT_JOB_ID)
                || compatibility.contains_key(COMPAT_SERVICE_ID)
            {
                return Err(RunnerError::OciManifestMismatch(
                    "reusable OCI image manifest also contains an exact assignment".to_owned(),
                ));
            }
            if reusable.insert(reference.clone(), record).is_some() {
                return Err(RunnerError::OciManifestMismatch(
                    "duplicate reusable OCI image assignment".to_owned(),
                ));
            }
            continue;
        }
        if compatibility.contains_key(COMPAT_ASSIGNMENT_SCOPE) {
            return Err(RunnerError::OciManifestMismatch(
                "unsupported OCI assignment scope".to_owned(),
            ));
        }
        let capsule_digest = ContentDigest::parse(required(&compatibility, COMPAT_CAPSULE_DIGEST)?)
            .map_err(|_| {
                RunnerError::OciManifestMismatch("invalid assigned capsule digest".to_owned())
            })?;
        let job_id = required(&compatibility, COMPAT_JOB_ID)?;
        let service = required(&compatibility, COMPAT_SERVICE_ID)?;
        let service_id = (service != JOB_ROLE).then_some(service);
        let key = AssignmentKey {
            capsule_digest,
            job_id,
            service_id,
        };
        if exact.insert(key, record).is_some() {
            return Err(RunnerError::OciManifestMismatch(
                "duplicate signed OCI assignment".to_owned(),
            ));
        }
    }
    if exact.is_empty() && reusable.is_empty() {
        return Err(RunnerError::OciConfiguration(
            "OCI manifest directory is empty".to_owned(),
        ));
    }
    Ok(LoadedAssignments { exact, reusable })
}

fn required(
    compatibility: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, RunnerError> {
    compatibility
        .get(name)
        .cloned()
        .ok_or_else(|| RunnerError::OciManifestMismatch(format!("missing signed `{name}`")))
}

fn platform(os: &str, architecture: &str) -> Result<OciPlatform, RunnerError> {
    let os = match os {
        "linux" => OperatingSystem::Linux,
        _ => {
            return Err(RunnerError::OciManifestMismatch(
                "OCI manifest operating system is unsupported".to_owned(),
            ))
        }
    };
    let architecture = match architecture {
        "amd64" => Architecture::Amd64,
        "arm64" => Architecture::Arm64,
        _ => {
            return Err(RunnerError::OciManifestMismatch(
                "OCI manifest architecture is unsupported".to_owned(),
            ))
        }
    };
    Ok(OciPlatform::new(os, architecture))
}

const fn os_text(os: OperatingSystem) -> &'static str {
    match os {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Windows => "windows",
        OperatingSystem::Macos => "macos",
    }
}

const fn architecture_text(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
    }
}
