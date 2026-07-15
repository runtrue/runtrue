pub(super) fn publish_new_private_file(
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), CredentialError> {
    validate_pending_rotation_directory(directory)?;
    let parent = directory
        .parent()
        .ok_or(CredentialError::InvalidPendingRotation)?;
    let temporary = parent.join(format!("{ROTATION_RESPONSE_TEMP_PREFIX}{}", random_hex()?));
    let destination = directory.join(name);
    write_new_private_file(&temporary, bytes)?;
    let result = rename_no_replace(&temporary, &destination);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    sync_directory(directory)?;
    Ok(())
}

pub(super) fn rename_no_replace(source: &Path, destination: &Path) -> Result<(), CredentialError> {
    rustix::fs::renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE)
        .map_err(|source| io_error(destination, source.into()).into())
}

pub(super) fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), CredentialError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(CredentialError::CredentialSize);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(path, source))?;
    validate_private_file(
        path,
        &file.metadata().map_err(|source| io_error(path, source))?,
    )?;
    Ok(())
}
use super::{
    load::{
        optional_current_generation, valid_nonce, validate_existing_current,
        validate_generation_directory, validate_generation_name, validate_metadata,
        validate_protocol_version,
    },
    rotation::validate_pending_rotation_directory,
    secure_fs::{remove_unpublished_directory, set_private_directory_permissions},
    validation::validate_credential_pair,
    CredentialError, CredentialMetadata, LoadedRunnerCredentials, NewRunnerCredentials,
    RunnerCredentialStore, CERTIFICATE_FILE, CREDENTIAL_FORMAT_VERSION, CURRENT_FILE,
    MAX_CREDENTIAL_BYTES, MAX_RETAINED_GENERATIONS, METADATA_FILE, PRIVATE_KEY_FILE,
    PROTOCOL_VERSION_FILE, ROTATION_RESPONSE_TEMP_PREFIX,
};
use crate::state::{io_error, random_hex, sync_directory, validate_private_file};
use rustix::fs::{RenameFlags, CWD};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{fs, fs::OpenOptions, io::Write as _, path::Path};

impl RunnerCredentialStore {
    pub fn install(
        &self,
        credentials: &NewRunnerCredentials,
    ) -> Result<LoadedRunnerCredentials, CredentialError> {
        validate_protocol_version(credentials.selected_protocol_version)?;
        let metadata = CredentialMetadata {
            version: CREDENTIAL_FORMAT_VERSION,
            runner_id: credentials.runner_id.clone(),
            pool_id: credentials.pool_id.clone(),
            certificate_expires_unix_ms: credentials.certificate_expires_unix_ms,
            authoritative_posture_digest: credentials.authoritative_posture_digest.clone(),
        };
        validate_metadata(&metadata)?;
        let normalized_certificate_chain = validate_credential_pair(
            &metadata,
            credentials.private_key_pem.as_bytes(),
            &credentials.certificate_chain_pem,
        )?;
        let previous_generation = optional_current_generation(&self.current)?;
        // Prune before creating or publishing the replacement generation. A
        // cleanup error therefore cannot make `install` report failure after
        // the current marker has already changed.
        self.prune_generations_before_install(previous_generation.as_deref())?;

        let nonce = random_hex()?;
        let pending_name = format!(".pending-{nonce}");
        let generation_name = format!("generation-{nonce}");
        let pending = self.generations.join(&pending_name);
        let generation = self.generations.join(&generation_name);
        fs::create_dir(&pending).map_err(|source| io_error(&pending, source))?;
        set_private_directory_permissions(&pending)?;

        let result: Result<(), CredentialError> = (|| {
            write_new_private_file(
                &pending.join(PRIVATE_KEY_FILE),
                credentials.private_key_pem.as_bytes(),
            )?;
            write_new_private_file(
                &pending.join(CERTIFICATE_FILE),
                &normalized_certificate_chain,
            )?;
            let metadata_bytes =
                serde_json::to_vec(&metadata).map_err(CredentialError::Metadata)?;
            write_new_private_file(&pending.join(METADATA_FILE), &metadata_bytes)?;
            write_new_private_file(
                &pending.join(PROTOCOL_VERSION_FILE),
                format!("{}\n", credentials.selected_protocol_version).as_bytes(),
            )?;
            sync_directory(&pending)?;
            fs::rename(&pending, &generation).map_err(|source| io_error(&generation, source))?;
            sync_directory(&self.generations)?;

            validate_existing_current(&self.current)?;
            let marker_temporary = self.root.join(format!(".{CURRENT_FILE}.tmp-{nonce}"));
            write_new_private_file(&marker_temporary, format!("{generation_name}\n").as_bytes())?;
            fs::rename(&marker_temporary, &self.current)
                .map_err(|source| io_error(&self.current, source))?;
            sync_directory(&self.root)?;
            Ok(())
        })();
        if result.is_err() {
            remove_unpublished_directory(&pending);
        }
        result?;
        self.load_current()
    }

    /// Bind a credential generation created by an older runner to an explicit
    /// operator-provided protocol generation. The create-new sidecar is a
    /// monotonic, crash-safe metadata upgrade; certificate and key bytes are
    /// never rewritten and a conflicting replay is rejected.
    pub fn bind_current_protocol_version(
        &self,
        protocol_version: u32,
    ) -> Result<LoadedRunnerCredentials, CredentialError> {
        validate_protocol_version(protocol_version)?;
        let _rotation_guard = self.rotation_lock()?;
        let current = self.load_current()?;
        if let Some(persisted) = current.selected_protocol_version {
            if persisted != protocol_version {
                return Err(CredentialError::ProtocolVersionMismatch {
                    persisted,
                    configured: protocol_version,
                });
            }
            return Ok(current);
        }
        let generation = optional_current_generation(&self.current)?
            .ok_or_else(|| CredentialError::MissingCredentials(self.current.clone()))?;
        let directory = self.generations.join(generation);
        validate_generation_directory(&directory)?;
        write_new_private_file(
            &directory.join(PROTOCOL_VERSION_FILE),
            format!("{protocol_version}\n").as_bytes(),
        )?;
        sync_directory(&directory)?;
        let upgraded = self.load_current()?;
        if upgraded.selected_protocol_version != Some(protocol_version) {
            return Err(CredentialError::InvalidProtocolVersion);
        }
        Ok(upgraded)
    }

    fn prune_generations_before_install(
        &self,
        current: Option<&str>,
    ) -> Result<(), CredentialError> {
        let retained = current
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        debug_assert!(retained.len() < MAX_RETAINED_GENERATIONS);

        let entries = fs::read_dir(&self.generations)
            .map_err(|source| io_error(&self.generations, source))?;
        let mut stale = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| io_error(&self.generations, source))?;
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CredentialError::UnsafeGeneration(path.clone()))?;
            let valid_name = if name.starts_with("generation-") {
                validate_generation_name(&name).is_ok()
            } else {
                name.strip_prefix(".pending-").is_some_and(valid_nonce)
            };
            if !valid_name {
                return Err(CredentialError::UnsafeGeneration(path));
            }
            validate_generation_directory(&path)?;
            if !retained.contains(name.as_str()) {
                stale.push(path);
            }
        }
        for path in stale {
            fs::remove_dir_all(&path).map_err(|source| io_error(&path, source))?;
        }
        sync_directory(&self.generations)?;
        Ok(())
    }
}
