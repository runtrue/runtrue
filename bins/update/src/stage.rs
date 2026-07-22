use crate::{
    error::CliError,
    verify::{read_bounded, supplied_now, verify_release, MAX_CLI_TARGET_BYTES},
};
use runtrue_model::ContentDigest;
use runtrue_update::{RunnerComponentProfile, TrustStore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

const MAX_PROFILE_BYTES: usize = 64 * 1024;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StagedManifest {
    version: u32,
    generation: u64,
    component_profile_digest: ContentDigest,
    installed_digest: ContentDigest,
    executable: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn stage_runner(
    state: PathBuf,
    bundle: PathBuf,
    target_path: String,
    target_file: PathBuf,
    component_profile: PathBuf,
    installation_root: PathBuf,
    generation: u64,
    now: Option<u64>,
) -> Result<(), CliError> {
    if generation == 0 {
        return invalid("generation must be positive");
    }
    let store = TrustStore::open(&state)?;
    let transaction = store.transaction()?;
    let trusted = transaction.load()?.ok_or(CliError::TrustNotInitialized)?;
    let verified = verify_release(
        &trusted,
        &bundle,
        &target_path,
        &target_file,
        supplied_now(now)?,
    )?;
    let target = read_bounded(&target_file, MAX_CLI_TARGET_BYTES)?;
    verified.target.verify_bytes(&target)?;
    let profile: RunnerComponentProfile =
        serde_json::from_slice(&read_bounded(&component_profile, MAX_PROFILE_BYTES)?)
            .map_err(|_| CliError::InvalidRunnerProfile("profile JSON is not closed".into()))?;
    let profile_digest = profile.digest()?;
    validate_profile(&profile, &profile_digest, &verified.target, &target)?;
    let relative = Path::new(&profile.allowed_installation_paths[0]);
    validate_installation_root(&installation_root)?;
    let final_directory = installation_root.join(format!("generation-{generation}"));
    let staging_directory = installation_root.join(format!(".staging-generation-{generation}"));
    let manifest = StagedManifest {
        version: 1,
        generation,
        component_profile_digest: profile_digest,
        installed_digest: profile.installed_digest,
        executable: profile.allowed_installation_paths[0].clone(),
    };
    if final_directory.exists() {
        validate_staged(&final_directory, relative, &target, &manifest)?;
    } else {
        if staging_directory.exists() {
            validate_staged(&staging_directory, relative, &target, &manifest)?;
        } else {
            create_staging(&staging_directory, relative, &target, &manifest)?;
        }
        fs::rename(&staging_directory, &final_directory)
            .map_err(|source| stage_io("publish generation", &final_directory, source))?;
        sync_directory(&installation_root, "sync installation root")?;
    }
    transaction.replace(&trusted, &verified.next_state)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "staged",
            "generation": generation,
            "installation": final_directory,
            "installed_digest": manifest.installed_digest,
            "component_profile_digest": manifest.component_profile_digest,
        }))?
    );
    Ok(())
}

fn validate_profile(
    profile: &RunnerComponentProfile,
    profile_digest: &ContentDigest,
    target: &runtrue_update::TargetDescription,
    target_bytes: &[u8],
) -> Result<(), CliError> {
    let installed = ContentDigest::sha256(target_bytes);
    if profile.package_format != "raw"
        || profile.allowed_installation_paths.as_slice() != ["bin/runtrue-runner"]
        || profile.allowed_modes.as_slice() != [0o555]
        || profile.installed_digest != installed
        || &profile.digest()? != profile_digest
        || profile.verify_signed_target(target).is_err()
    {
        return invalid("profile does not match the signed target and raw runner policy");
    }
    Ok(())
}

fn validate_installation_root(root: &Path) -> Result<(), CliError> {
    if !root.is_absolute() {
        return invalid("installation root must be absolute");
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| stage_io("inspect installation root", root, source))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return invalid("installation root must be an owner-only real directory");
    }
    Ok(())
}

fn create_staging(
    directory: &Path,
    relative: &Path,
    target: &[u8],
    manifest: &StagedManifest,
) -> Result<(), CliError> {
    fs::create_dir(directory)
        .map_err(|source| stage_io("create staging directory", directory, source))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|source| stage_io("set staging mode", directory, source))?;
    let bin = directory.join("bin");
    fs::create_dir(&bin).map_err(|source| stage_io("create executable directory", &bin, source))?;
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700))
        .map_err(|source| stage_io("set executable directory mode", &bin, source))?;
    write_new(&directory.join(relative), target, 0o555)?;
    let manifest_bytes = serde_json::to_vec(manifest)?;
    write_new(&directory.join("manifest.json"), &manifest_bytes, 0o600)?;
    validate_staged(directory, relative, target, manifest)?;
    sync_directory(&bin, "sync executable directory")?;
    sync_directory(directory, "sync staging directory")
}

fn validate_staged(
    directory: &Path,
    relative: &Path,
    target: &[u8],
    expected_manifest: &StagedManifest,
) -> Result<(), CliError> {
    let executable = directory.join(relative);
    let metadata = fs::symlink_metadata(&executable)
        .map_err(|source| stage_io("inspect staged executable", &executable, source))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o555
        || fs::read(&executable)
            .map_err(|source| stage_io("read staged executable", &executable, source))?
            != target
    {
        return invalid("staged executable is not the exact owner-controlled signed target");
    }
    let manifest_path = directory.join("manifest.json");
    let manifest: StagedManifest = serde_json::from_slice(
        &fs::read(&manifest_path)
            .map_err(|source| stage_io("read staged manifest", &manifest_path, source))?,
    )
    .map_err(|_| CliError::InvalidRunnerProfile("staged manifest is malformed".into()))?;
    if &manifest != expected_manifest {
        return invalid("staged generation already exists with different content");
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|source| stage_io("create staged file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| stage_io("write staged file", path, source))?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|source| stage_io("set staged file mode", path, source))?;
    file.sync_all()
        .map_err(|source| stage_io("sync staged file", path, source))
}

fn sync_directory(path: &Path, operation: &'static str) -> Result<(), CliError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| stage_io(operation, path, source))
}

fn invalid<T>(detail: impl Into<String>) -> Result<T, CliError> {
    Err(CliError::InvalidRunnerProfile(detail.into()))
}

fn stage_io(operation: &'static str, path: &Path, source: std::io::Error) -> CliError {
    CliError::StageIo {
        operation,
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn raw_runner_profile_is_exactly_bound_and_staged_create_new() {
        let bytes = b"signed-runner-v2";
        let mut profile = RunnerComponentProfile {
            component_name: "runtrue-runner".into(),
            release_version: "2.0.0".into(),
            artifact_name: "runtrue-runner".into(),
            artifact_length: bytes.len() as u64,
            artifact_digest: ContentDigest::sha256(bytes),
            artifact_media_type: "application/octet-stream".into(),
            platform: "linux".into(),
            architecture: "amd64".into(),
            installed_digest: ContentDigest::sha256(bytes),
            runner_version: "2.0.0".into(),
            engine_version: "2.0.0".into(),
            protocol_min: 1,
            protocol_max: 1,
            package_format: "raw".into(),
            allowed_installation_paths: vec!["bin/runtrue-runner".into()],
            allowed_modes: vec![0o555],
        };
        let digest = profile.digest().unwrap();
        let target = runtrue_update::TargetDescription::from_bytes(
            bytes,
            profile.artifact_media_type.clone(),
            profile.platform.clone(),
            profile.architecture.clone(),
            profile.release_version.clone(),
            BTreeMap::from([(
                runtrue_update::RUNNER_COMPONENT_PROFILE_DIGEST_FIELD.into(),
                digest.to_string(),
            )]),
        )
        .unwrap();
        validate_profile(&profile, &digest, &target, bytes).unwrap();
        profile.installed_digest = ContentDigest::sha256(b"other");
        assert!(validate_profile(&profile, &digest, &target, bytes).is_err());

        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join(".staging-generation-2");
        let manifest = StagedManifest {
            version: 1,
            generation: 2,
            component_profile_digest: digest,
            installed_digest: ContentDigest::sha256(bytes),
            executable: "bin/runtrue-runner".into(),
        };
        create_staging(&staging, Path::new("bin/runtrue-runner"), bytes, &manifest).unwrap();
        validate_staged(&staging, Path::new("bin/runtrue-runner"), bytes, &manifest).unwrap();
        assert_eq!(
            fs::metadata(staging.join("bin/runtrue-runner"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
    }
}
