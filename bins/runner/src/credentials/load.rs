pub(super) fn optional_current_generation(path: &Path) -> Result<Option<String>, CredentialError> {
    validate_existing_current(path)?;
    let marker = match read_bounded_private_file(path, 128) {
        Ok(marker) => marker,
        Err(StateError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let generation = std::str::from_utf8(&marker)
        .map_err(|_| CredentialError::InvalidCurrent)?
        .trim_end_matches(['\r', '\n']);
    validate_generation_name(generation)?;
    Ok(Some(generation.to_owned()))
}

pub(super) fn validate_existing_current(path: &Path) -> Result<(), CredentialError> {
    validate_no_symlink_components(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_file(path, &metadata).map_err(CredentialError::from),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source).into()),
    }
}

pub(super) fn validate_generation_name(value: &str) -> Result<(), CredentialError> {
    let Some(suffix) = value.strip_prefix("generation-") else {
        return Err(CredentialError::InvalidCurrent);
    };
    if !valid_nonce(suffix) {
        return Err(CredentialError::InvalidCurrent);
    }
    Ok(())
}

pub(super) fn valid_nonce(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn validate_generation_directory(path: &Path) -> Result<(), CredentialError> {
    validate_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CredentialError::UnsafeGeneration(path.to_owned()));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(CredentialError::UnsafeGeneration(path.to_owned()));
    }
    Ok(())
}

fn load_protocol_version(directory: &Path) -> Result<Option<u32>, CredentialError> {
    let path = directory.join(PROTOCOL_VERSION_FILE);
    let bytes = match read_bounded_private_file(&path, 16) {
        Ok(bytes) => bytes,
        Err(StateError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| CredentialError::InvalidProtocolVersion)?
        .trim_end_matches(['\r', '\n']);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CredentialError::InvalidProtocolVersion);
    }
    let value = value
        .parse::<u32>()
        .map_err(|_| CredentialError::InvalidProtocolVersion)?;
    validate_protocol_version(value)?;
    Ok(Some(value))
}

pub(super) fn validate_protocol_version(value: u32) -> Result<(), CredentialError> {
    if runtrue_protocol::supports_protocol_version(value) {
        Ok(())
    } else {
        Err(CredentialError::InvalidProtocolVersion)
    }
}

pub(super) fn validate_metadata(metadata: &CredentialMetadata) -> Result<(), CredentialError> {
    if metadata.version != CREDENTIAL_FORMAT_VERSION
        || !valid_identity(&metadata.runner_id)
        || !valid_identity(&metadata.pool_id)
        || metadata.certificate_expires_unix_ms == 0
    {
        return Err(CredentialError::InvalidMetadata);
    }
    Ok(())
}
use super::{
    secure_fs::map_missing_current,
    validation::{certificate_chain_fingerprints, valid_identity, validate_credential_pair},
    CredentialError, CredentialMetadata, LoadedRunnerCredentials, RunnerCredentialStore,
    CERTIFICATE_FILE, CREDENTIAL_FORMAT_VERSION, CURRENT_FILE, GENERATIONS_DIRECTORY,
    MAX_CREDENTIAL_BYTES, MAX_METADATA_BYTES, METADATA_FILE, PRIVATE_KEY_FILE,
    PROTOCOL_VERSION_FILE,
};
use crate::state::{
    io_error, prepare_private_directory, read_bounded_private_file, validate_no_symlink_components,
    validate_private_file, StateError,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{fs, io, path::Path};
use zeroize::Zeroizing;

impl RunnerCredentialStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, CredentialError> {
        let root = prepare_private_directory(root.as_ref())?;
        let generations = prepare_private_directory(&root.join(GENERATIONS_DIRECTORY))?;
        let current = root.join(CURRENT_FILE);
        Ok(Self {
            root,
            generations,
            current,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Load an exact pending rotation, if one has been durably published.
    /// Abandoned unpublished staging directories are removed only after their
    /// shape has been proven private and confined to the credential root.
    pub fn load_current(&self) -> Result<LoadedRunnerCredentials, CredentialError> {
        let marker = read_bounded_private_file(&self.current, 128)
            .map_err(|error| map_missing_current(error, &self.current))?;
        let generation = std::str::from_utf8(&marker)
            .map_err(|_| CredentialError::InvalidCurrent)?
            .trim_end_matches(['\r', '\n']);
        validate_generation_name(generation)?;
        let directory = self.generations.join(generation);
        validate_generation_directory(&directory)?;
        let metadata_path = directory.join(METADATA_FILE);
        let metadata_bytes = read_bounded_private_file(&metadata_path, MAX_METADATA_BYTES)?;
        let metadata: CredentialMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(CredentialError::Metadata)?;
        validate_metadata(&metadata)?;
        let selected_protocol_version = load_protocol_version(&directory)?;
        let certificate_path = directory.join(CERTIFICATE_FILE);
        let private_key_path = directory.join(PRIVATE_KEY_FILE);
        let certificate = read_bounded_private_file(&certificate_path, MAX_CREDENTIAL_BYTES)?;
        let private_key = Zeroizing::new(read_bounded_private_file(
            &private_key_path,
            MAX_CREDENTIAL_BYTES,
        )?);
        let normalized = validate_credential_pair(&metadata, &private_key, &certificate)?;
        if certificate != normalized {
            return Err(CredentialError::InvalidCertificate);
        }
        let (certificate_fingerprint, issuer_fingerprint) =
            certificate_chain_fingerprints(&certificate)?;
        Ok(LoadedRunnerCredentials {
            runner_id: metadata.runner_id,
            pool_id: metadata.pool_id,
            certificate_expires_unix_ms: metadata.certificate_expires_unix_ms,
            certificate_fingerprint,
            issuer_fingerprint,
            authoritative_posture_digest: metadata.authoritative_posture_digest,
            selected_protocol_version,
            client_certificate: certificate_path,
            client_private_key: private_key_path,
        })
    }
}
