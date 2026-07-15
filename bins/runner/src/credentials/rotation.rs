fn pending_metadata(pending: &PendingRunnerRotation) -> PendingRotationMetadata {
    PendingRotationMetadata {
        version: ROTATION_FORMAT_VERSION,
        runner_id: pending.runner_id.clone(),
        pool_id: pending.pool_id.clone(),
        previous_certificate_fingerprint: pending.previous_certificate_fingerprint.clone(),
        issuer_fingerprint: pending.issuer_fingerprint.clone(),
        csr_digest: runtrue_model::ContentDigest::sha256(&pending.csr_der),
    }
}

fn validate_pending_metadata(metadata: &PendingRotationMetadata) -> Result<(), CredentialError> {
    if metadata.version != ROTATION_FORMAT_VERSION
        || !valid_identity(&metadata.runner_id)
        || !valid_identity(&metadata.pool_id)
    {
        return Err(CredentialError::InvalidPendingRotation);
    }
    Ok(())
}

fn validate_rotation_key_and_csr(
    private_key_pem: &str,
    csr_der: &[u8],
    expected_digest: &runtrue_model::ContentDigest,
) -> Result<(), CredentialError> {
    if csr_der.is_empty()
        || csr_der.len() as u64 > MAX_CREDENTIAL_BYTES
        || runtrue_model::ContentDigest::sha256(csr_der) != *expected_digest
    {
        return Err(CredentialError::InvalidCertificateRequest);
    }
    let key = Zeroizing::new(
        KeyPair::from_pem(private_key_pem).map_err(|_| CredentialError::InvalidKey)?,
    );
    if key.algorithm() != &PKCS_ED25519 {
        return Err(CredentialError::InvalidKey);
    }
    let (remainder, parsed) = X509CertificationRequest::from_der(csr_der)
        .map_err(|_| CredentialError::InvalidCertificateRequest)?;
    if !remainder.is_empty() || parsed.verify_signature().is_err() {
        return Err(CredentialError::InvalidCertificateRequest);
    }
    let request_der = CertificateSigningRequestDer::from(csr_der);
    let request = CertificateSigningRequestParams::from_der(&request_der)
        .map_err(|_| CredentialError::InvalidCertificateRequest)?;
    if request.public_key.algorithm() != &PKCS_ED25519
        || request.public_key.subject_public_key_info() != key.subject_public_key_info()
    {
        return Err(CredentialError::InvalidCertificateRequest);
    }
    Ok(())
}

fn validate_rotation_response(
    metadata: &PendingRotationMetadata,
    private_key_pem: &str,
    response: &PendingRotationResponse,
) -> Result<(), CredentialError> {
    if response.certificate_expires_unix_ms == 0
        || response.certificate_chain_pem.is_empty()
        || response.certificate_chain_pem.len() as u64 > MAX_CREDENTIAL_BYTES
    {
        return Err(CredentialError::InvalidCertificate);
    }
    let credential_metadata = CredentialMetadata {
        version: CREDENTIAL_FORMAT_VERSION,
        runner_id: metadata.runner_id.clone(),
        pool_id: metadata.pool_id.clone(),
        certificate_expires_unix_ms: response.certificate_expires_unix_ms,
        authoritative_posture_digest: None,
    };
    let normalized = validate_credential_pair(
        &credential_metadata,
        private_key_pem.as_bytes(),
        &response.certificate_chain_pem,
    )?;
    if normalized != response.certificate_chain_pem {
        return Err(CredentialError::InvalidCertificate);
    }
    let (_, issuer_fingerprint) = certificate_chain_fingerprints(&response.certificate_chain_pem)?;
    if issuer_fingerprint != metadata.issuer_fingerprint {
        return Err(CredentialError::RotationIssuerMismatch);
    }
    Ok(())
}

fn require_pending_for_current(
    pending: &PendingRunnerRotation,
    current: &LoadedRunnerCredentials,
) -> Result<(), CredentialError> {
    let current_is_issued = pending
        .response
        .as_ref()
        .map(|response| certificate_fingerprint(&response.certificate_chain_pem))
        .transpose()?
        .as_ref()
        == Some(&current.certificate_fingerprint);
    if pending.runner_id != current.runner_id
        || pending.pool_id != current.pool_id
        || pending.issuer_fingerprint != current.issuer_fingerprint
        || (current.certificate_fingerprint != pending.previous_certificate_fingerprint
            && !current_is_issued)
    {
        return Err(CredentialError::RotationStateMismatch);
    }
    Ok(())
}

pub(super) fn validate_pending_rotation_directory(path: &Path) -> Result<(), CredentialError> {
    validate_generation_directory(path)?;
    for entry in fs::read_dir(path).map_err(|source| io_error(path, source))? {
        let entry = entry.map_err(|source| io_error(path, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CredentialError::UnsafeGeneration(entry.path()))?;
        if !matches!(
            name.as_str(),
            PRIVATE_KEY_FILE | METADATA_FILE | ROTATION_CSR_FILE | ROTATION_RESPONSE_FILE
        ) {
            return Err(CredentialError::UnsafeGeneration(entry.path()));
        }
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|source| io_error(&entry.path(), source))?;
        validate_private_file(&entry.path(), &metadata)?;
    }
    Ok(())
}
use super::{
    load::{valid_nonce, validate_generation_directory},
    publish::{publish_new_private_file, rename_no_replace, write_new_private_file},
    secure_fs::{remove_unpublished_directory, set_private_directory_permissions},
    validation::{
        certificate_chain_fingerprints, certificate_fingerprint, valid_identity,
        validate_credential_pair,
    },
    CredentialError, CredentialMetadata, LoadedRunnerCredentials, NewRunnerCredentials,
    PendingRotationMetadata, PendingRotationResponse, PendingRunnerRotation, RunnerCredentialStore,
    CREDENTIAL_FORMAT_VERSION, MAX_CREDENTIAL_BYTES, MAX_METADATA_BYTES, METADATA_FILE,
    PENDING_ROTATION_DIRECTORY, PENDING_ROTATION_PREFIX, PRIVATE_KEY_FILE, ROTATION_CSR_FILE,
    ROTATION_FORMAT_VERSION, ROTATION_LOCK_FILE, ROTATION_RESPONSE_FILE,
    ROTATION_RESPONSE_TEMP_PREFIX,
};
use crate::state::{
    io_error, random_hex, read_bounded_private_file, sync_directory,
    validate_no_symlink_components, validate_private_file, StateError,
};
use rcgen::{CertificateSigningRequestParams, KeyPair, PublicKeyData as _, PKCS_ED25519};
use rustix::fs::FlockOperation;
use rustls_pki_types::CertificateSigningRequestDer;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::{
    fs,
    fs::{File, OpenOptions},
    io,
    path::Path,
};
use x509_parser::{certification_request::X509CertificationRequest, prelude::FromDer as _};
use zeroize::Zeroizing;

impl RunnerCredentialStore {
    pub fn load_pending_rotation(&self) -> Result<Option<PendingRunnerRotation>, CredentialError> {
        let directory = self.root.join(PENDING_ROTATION_DIRECTORY);
        match fs::symlink_metadata(&directory) {
            Ok(_) => validate_pending_rotation_directory(&directory)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(io_error(&directory, source).into()),
        }
        let metadata_bytes =
            read_bounded_private_file(&directory.join(METADATA_FILE), MAX_METADATA_BYTES)?;
        let metadata: PendingRotationMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(CredentialError::Metadata)?;
        validate_pending_metadata(&metadata)?;
        let private_key = Zeroizing::new(read_bounded_private_file(
            &directory.join(PRIVATE_KEY_FILE),
            MAX_CREDENTIAL_BYTES,
        )?);
        let private_key_pem = Zeroizing::new(
            String::from_utf8(private_key.to_vec()).map_err(|_| CredentialError::InvalidKey)?,
        );
        let csr_der =
            read_bounded_private_file(&directory.join(ROTATION_CSR_FILE), MAX_CREDENTIAL_BYTES)?;
        validate_rotation_key_and_csr(&private_key_pem, &csr_der, &metadata.csr_digest)?;
        let response_path = directory.join(ROTATION_RESPONSE_FILE);
        let response = match fs::symlink_metadata(&response_path) {
            Ok(_) => {
                let bytes = read_bounded_private_file(&response_path, MAX_CREDENTIAL_BYTES)?;
                let response: PendingRotationResponse =
                    serde_json::from_slice(&bytes).map_err(CredentialError::Metadata)?;
                validate_rotation_response(&metadata, &private_key_pem, &response)?;
                Some(response)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(source) => return Err(io_error(&response_path, source).into()),
        };
        Ok(Some(PendingRunnerRotation {
            runner_id: metadata.runner_id,
            pool_id: metadata.pool_id,
            previous_certificate_fingerprint: metadata.previous_certificate_fingerprint,
            issuer_fingerprint: metadata.issuer_fingerprint,
            private_key_pem,
            csr_der,
            response,
        }))
    }

    /// Publish the generated key and CSR before the rotation RPC. A concurrent
    /// caller either wins the no-replace publication or reuses the exact
    /// already-published request.
    pub fn begin_rotation(
        &self,
        current: &LoadedRunnerCredentials,
        private_key_pem: Zeroizing<String>,
        csr_der: Vec<u8>,
    ) -> Result<PendingRunnerRotation, CredentialError> {
        let _rotation_guard = self.rotation_lock()?;
        self.remove_stale_rotation_staging()?;
        if let Some(pending) = self.load_pending_rotation()? {
            require_pending_for_current(&pending, current)?;
            return Ok(pending);
        }
        let csr_digest = runtrue_model::ContentDigest::sha256(&csr_der);
        validate_rotation_key_and_csr(&private_key_pem, &csr_der, &csr_digest)?;
        let metadata = PendingRotationMetadata {
            version: ROTATION_FORMAT_VERSION,
            runner_id: current.runner_id.clone(),
            pool_id: current.pool_id.clone(),
            previous_certificate_fingerprint: current.certificate_fingerprint.clone(),
            issuer_fingerprint: current.issuer_fingerprint.clone(),
            csr_digest,
        };
        validate_pending_metadata(&metadata)?;
        let nonce = random_hex()?;
        let staging = self.root.join(format!("{PENDING_ROTATION_PREFIX}{nonce}"));
        let destination = self.root.join(PENDING_ROTATION_DIRECTORY);
        fs::create_dir(&staging).map_err(|source| io_error(&staging, source))?;
        set_private_directory_permissions(&staging)?;
        let result = (|| {
            write_new_private_file(&staging.join(PRIVATE_KEY_FILE), private_key_pem.as_bytes())?;
            write_new_private_file(&staging.join(ROTATION_CSR_FILE), &csr_der)?;
            let metadata_bytes =
                serde_json::to_vec(&metadata).map_err(CredentialError::Metadata)?;
            write_new_private_file(&staging.join(METADATA_FILE), &metadata_bytes)?;
            sync_directory(&staging)?;
            rename_no_replace(&staging, &destination)?;
            sync_directory(&self.root)?;
            Ok::<(), CredentialError>(())
        })();
        if let Err(error) = result {
            remove_unpublished_directory(&staging);
            if matches!(&error, CredentialError::State(StateError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists)
            {
                let pending = self
                    .load_pending_rotation()?
                    .ok_or(CredentialError::InvalidPendingRotation)?;
                require_pending_for_current(&pending, current)?;
                return Ok(pending);
            }
            return Err(error);
        }
        self.load_pending_rotation()?
            .ok_or(CredentialError::InvalidPendingRotation)
    }

    /// Persist the exact public response before installing its matching key.
    /// Replays must be byte-for-byte identical.
    pub fn record_rotation_response(
        &self,
        response: PendingRotationResponse,
    ) -> Result<PendingRunnerRotation, CredentialError> {
        let _rotation_guard = self.rotation_lock()?;
        self.remove_stale_rotation_staging()?;
        let pending = self
            .load_pending_rotation()?
            .ok_or(CredentialError::InvalidPendingRotation)?;
        let metadata = pending_metadata(&pending);
        validate_rotation_response(&metadata, &pending.private_key_pem, &response)?;
        if let Some(existing) = &pending.response {
            if existing != &response {
                return Err(CredentialError::ConflictingRotationResponse);
            }
            return Ok(pending);
        }
        let bytes = serde_json::to_vec(&response).map_err(CredentialError::Metadata)?;
        publish_new_private_file(
            &self.root.join(PENDING_ROTATION_DIRECTORY),
            ROTATION_RESPONSE_FILE,
            &bytes,
        )?;
        let recorded = self
            .load_pending_rotation()?
            .ok_or(CredentialError::InvalidPendingRotation)?;
        if recorded.response.as_ref() != Some(&response) {
            return Err(CredentialError::ConflictingRotationResponse);
        }
        Ok(recorded)
    }

    /// Install a persisted response and erase the pending key only after the
    /// active generation proves it owns that exact certificate.
    pub fn install_pending_rotation(&self) -> Result<LoadedRunnerCredentials, CredentialError> {
        let _rotation_guard = self.rotation_lock()?;
        let current = self.load_current()?;
        let pending = self
            .load_pending_rotation()?
            .ok_or(CredentialError::InvalidPendingRotation)?;
        let response = pending
            .response
            .as_ref()
            .ok_or(CredentialError::RotationResponseMissing)?;
        let installed = self.install(&NewRunnerCredentials {
            runner_id: pending.runner_id.clone(),
            pool_id: pending.pool_id.clone(),
            certificate_expires_unix_ms: response.certificate_expires_unix_ms,
            private_key_pem: Zeroizing::new(pending.private_key_pem.as_str().to_owned()),
            certificate_chain_pem: response.certificate_chain_pem.clone(),
            authoritative_posture_digest: current.authoritative_posture_digest,
            selected_protocol_version: current
                .selected_protocol_version
                .ok_or(CredentialError::MissingProtocolVersion)?,
        })?;
        self.clear_installed_pending_rotation(&installed)?;
        Ok(installed)
    }

    /// Clean up the final pending directory after a crash between generation
    /// installation and pending-state deletion.
    pub fn reconcile_pending_rotation(&self) -> Result<bool, CredentialError> {
        let _rotation_guard = self.rotation_lock()?;
        self.remove_stale_rotation_staging()?;
        let Some(pending) = self.load_pending_rotation()? else {
            return Ok(false);
        };
        let Some(response) = pending.response.as_ref() else {
            return Ok(false);
        };
        let current = self.load_current()?;
        let issued_fingerprint = certificate_fingerprint(&response.certificate_chain_pem)?;
        if current.certificate_fingerprint == issued_fingerprint
            && current.issuer_fingerprint == pending.issuer_fingerprint
        {
            self.clear_installed_pending_rotation(&current)?;
            return Ok(true);
        }
        if current.certificate_fingerprint != pending.previous_certificate_fingerprint {
            return Err(CredentialError::RotationStateMismatch);
        }
        Ok(false)
    }

    pub(super) fn rotation_lock(&self) -> Result<File, CredentialError> {
        let path = self.root.join(ROTATION_LOCK_FILE);
        validate_no_symlink_components(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error(&path, source))?;
        let opened = file.metadata().map_err(|source| io_error(&path, source))?;
        validate_private_file(&path, &opened)?;
        rustix::fs::flock(&file, FlockOperation::LockExclusive)
            .map_err(|source| io_error(&path, source.into()))?;
        let linked = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        validate_private_file(&path, &linked)?;
        #[cfg(unix)]
        if linked.dev() != opened.dev() || linked.ino() != opened.ino() {
            return Err(CredentialError::State(StateError::UnsafePath(path)));
        }
        Ok(file)
    }

    fn clear_installed_pending_rotation(
        &self,
        current: &LoadedRunnerCredentials,
    ) -> Result<(), CredentialError> {
        let Some(pending) = self.load_pending_rotation()? else {
            return Ok(());
        };
        let response = pending
            .response
            .as_ref()
            .ok_or(CredentialError::RotationResponseMissing)?;
        let issued_fingerprint = certificate_fingerprint(&response.certificate_chain_pem)?;
        if current.runner_id != pending.runner_id
            || current.pool_id != pending.pool_id
            || current.certificate_fingerprint != issued_fingerprint
            || current.issuer_fingerprint != pending.issuer_fingerprint
        {
            return Err(CredentialError::RotationStateMismatch);
        }
        let directory = self.root.join(PENDING_ROTATION_DIRECTORY);
        validate_pending_rotation_directory(&directory)?;
        fs::remove_dir_all(&directory).map_err(|source| io_error(&directory, source))?;
        sync_directory(&self.root)?;
        Ok(())
    }

    fn remove_stale_rotation_staging(&self) -> Result<(), CredentialError> {
        let entries = fs::read_dir(&self.root).map_err(|source| io_error(&self.root, source))?;
        let mut removed = false;
        for entry in entries {
            let entry = entry.map_err(|source| io_error(&self.root, source))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CredentialError::UnsafeGeneration(entry.path()))?;
            if let Some(nonce) = name.strip_prefix(ROTATION_RESPONSE_TEMP_PREFIX) {
                if !valid_nonce(nonce) {
                    return Err(CredentialError::UnsafeGeneration(entry.path()));
                }
                let metadata = fs::symlink_metadata(entry.path())
                    .map_err(|source| io_error(&entry.path(), source))?;
                validate_private_file(&entry.path(), &metadata)?;
                fs::remove_file(entry.path()).map_err(|source| io_error(&entry.path(), source))?;
                removed = true;
                continue;
            }
            if !name.starts_with(PENDING_ROTATION_PREFIX) {
                continue;
            }
            let Some(nonce) = name.strip_prefix(PENDING_ROTATION_PREFIX) else {
                continue;
            };
            if !valid_nonce(nonce) {
                return Err(CredentialError::UnsafeGeneration(entry.path()));
            }
            validate_pending_rotation_directory(&entry.path())?;
            fs::remove_dir_all(entry.path()).map_err(|source| io_error(&entry.path(), source))?;
            removed = true;
        }
        if removed {
            sync_directory(&self.root)?;
        }
        Ok(())
    }
}
