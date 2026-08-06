#[derive(Debug, Clone)]
pub struct OciRecoveryConfig {
    pub runtime_program: PathBuf,
    pub runtime_environment: BTreeMap<String, String>,
    pub image_store: Option<PathBuf>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

impl OciRecoveryConfig {
    #[must_use]
    pub fn new(runtime_program: impl Into<PathBuf>) -> Self {
        Self {
            runtime_program: runtime_program.into(),
            runtime_environment: BTreeMap::new(),
            image_store: None,
            timeout: DEFAULT_CLEANUP_TIMEOUT,
            max_output_bytes: 64 * 1024,
        }
    }
}

/// Recover one abandoned per-job Podman state directory after runner restart.
/// Every container is force-removed with anonymous volumes, and emptiness of
/// the container, volume, and Runtrue-network sets is proven before state bytes
/// are deleted. This must only run while no executor uses the directory.
pub fn recover_abandoned_job_state<R: RuntimeCommandRunner>(
    job_state: &Path,
    config: &OciRecoveryConfig,
    runtime: &mut R,
) -> Result<(), OciError> {
    if !config.runtime_program.is_absolute()
        || config
            .runtime_program
            .file_name()
            .and_then(|name| name.to_str())
            != Some("podman")
        || config.timeout.is_zero()
        || config.max_output_bytes == 0
    {
        return Err(OciError::InvalidConfiguration(
            "invalid abandoned-state recovery configuration".to_owned(),
        ));
    }
    validate_runtime_environment(&config.runtime_environment)?;
    let job_state = canonical_real_directory(job_state, "abandoned job state")?;
    for child in ["storage", "run", "tmp"] {
        let path = job_state.join(child);
        let canonical = canonical_real_directory(&path, "abandoned runtime directory")?;
        ensure_descendant(&job_state, &canonical)?;
    }
    let image_store = config
        .image_store
        .as_deref()
        .map(|path| canonical_real_directory(path, "OCI image store"))
        .transpose()?;
    if image_store.is_some() {
        return Err(OciError::InvalidState(
            "automatic cleanup of an abandoned job is disabled for the shared prehydrated OCI store"
                .to_owned(),
        ));
    }
    let prefix = recovery_runtime_prefix(&job_state, image_store.as_deref())?;
    let control = RuntimeControl {
        timeout: config.timeout,
        cancellation: CancellationToken::default(),
        max_output_bytes: config.max_output_bytes,
    };
    let operations = [
        (
            RuntimeInvocationKind::RecoveryRemoveContainers,
            vec!["rm", "--all", "--force", "--volumes"],
            false,
        ),
        (
            RuntimeInvocationKind::RecoveryListContainers,
            vec!["ps", "--all", "--quiet", "--no-trunc"],
            true,
        ),
        (
            RuntimeInvocationKind::RecoveryPruneVolumes,
            vec!["volume", "prune", "--force"],
            false,
        ),
        (
            RuntimeInvocationKind::RecoveryListVolumes,
            vec!["volume", "ls", "--quiet"],
            true,
        ),
        (
            RuntimeInvocationKind::RecoveryPruneNetworks,
            vec!["network", "prune", "--force"],
            false,
        ),
        (
            RuntimeInvocationKind::RecoveryListNetworks,
            vec!["network", "ls", "--quiet", "--filter=name=runtrue-net-"],
            true,
        ),
    ];
    for (kind, operation, must_be_empty) in operations {
        let mut arguments = prefix.clone();
        arguments.extend(operation.into_iter().map(str::to_owned));
        let result = runtime.invoke(
            &RuntimeInvocation {
                kind,
                program: config.runtime_program.clone(),
                arguments,
                environment: config.runtime_environment.clone(),
            },
            &control,
        )?;
        validate_cleanup_result(&result, Some(0))?;
        if must_be_empty
            && (!result.stdout.iter().all(u8::is_ascii_whitespace)
                || !result.stderr.iter().all(u8::is_ascii_whitespace))
        {
            return Err(OciError::RuntimeContractViolation(
                "abandoned OCI resources remain after recovery".to_owned(),
            ));
        }
    }
    fs::remove_dir_all(&job_state)
        .map_err(|source| io_error("remove recovered job state", &job_state, source))
}

pub(crate) fn recovery_runtime_prefix(
    job_state: &Path,
    image_store: Option<&Path>,
) -> Result<Vec<String>, OciError> {
    let mut prefix = vec![
        format!(
            "--root={}",
            utf8_path(&job_state.join("storage"), "recovery storage")?
        ),
        format!(
            "--runroot={}",
            utf8_path(&job_state.join("run"), "recovery runroot")?
        ),
        format!(
            "--tmpdir={}",
            utf8_path(&job_state.join("tmp"), "recovery tmpdir")?
        ),
    ];
    if let Some(image_store) = image_store {
        prefix.push(format!(
            "--imagestore={}",
            utf8_path(image_store, "recovery image store")?
        ));
    }
    Ok(prefix)
}

/// Prove that every admitted digest-only image is already available in the
/// configured private Podman image store. The probe owns its Podman graph and
/// runtime state; the admitted image store is attached read-only by contract.
pub fn verify_preloaded_images<R, I, S>(
    probe_state: &Path,
    config: &OciRecoveryConfig,
    images: I,
    runtime: &mut R,
) -> Result<(), OciError>
where
    R: RuntimeCommandRunner,
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    match fs::symlink_metadata(probe_state) {
        Ok(_) => {
            return Err(OciError::InvalidState(
                "OCI image probe state already exists".to_owned(),
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(io_error(
                "inspect OCI image probe state",
                probe_state,
                source,
            ))
        }
    }
    create_private_directory(probe_state)?;
    for child in ["storage", "run", "tmp"] {
        create_private_directory(&probe_state.join(child))?;
    }
    let result = (|| {
        validate_runtime_environment(&config.runtime_environment)?;
        if config.timeout.is_zero() || config.max_output_bytes == 0 {
            return Err(OciError::InvalidConfiguration(
                "invalid OCI image probe bounds".to_owned(),
            ));
        }
        let image_store = config
            .image_store
            .as_deref()
            .map(|path| canonical_real_directory(path, "OCI image store"))
            .transpose()?;
        let prefix = recovery_runtime_prefix(probe_state, image_store.as_deref())?;
        let control = RuntimeControl {
            timeout: config.timeout,
            cancellation: CancellationToken::default(),
            max_output_bytes: config.max_output_bytes,
        };
        for image in images {
            let image = image.as_ref();
            validate_exact_image_reference(image)?;
            let mut arguments = prefix.clone();
            arguments.extend(["image".to_owned(), "exists".to_owned(), image.to_owned()]);
            let result = runtime.invoke(
                &RuntimeInvocation {
                    kind: RuntimeInvocationKind::ImageExists,
                    program: config.runtime_program.clone(),
                    arguments,
                    environment: config.runtime_environment.clone(),
                },
                &control,
            )?;
            validate_cleanup_result(&result, Some(0))?;
        }
        Ok(())
    })();
    let removal = fs::remove_dir_all(probe_state)
        .map_err(|source| io_error("remove OCI image probe state", probe_state, source));
    match (result, removal) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(OciError::LifecycleCleanup {
            cause: error.to_string(),
            cleanup: cleanup.to_string(),
        }),
    }
}
use crate::{
    canonical_real_directory, create_private_directory, ensure_descendant, fs, io, io_error,
    utf8_path, validate_cleanup_result, validate_exact_image_reference,
    validate_runtime_environment, BTreeMap, CancellationToken, Duration, OciError, Path, PathBuf,
    RuntimeCommandRunner, RuntimeControl, RuntimeInvocation, RuntimeInvocationKind,
    DEFAULT_CLEANUP_TIMEOUT,
};
