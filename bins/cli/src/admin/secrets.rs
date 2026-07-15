use super::{
    secure_fs::{
        display_path, ensure_secrets_directory, print_json, read_regular_file,
        reject_internal_admin_path, resolve_explicit_path, secure_file_exists, sync_directory,
        validate_name, write_private_atomic, write_revealed_secret,
    },
    AdminError, SecretDeleteArgs, SecretGetArgs, SecretRotateArgs, SecretSetArgs, LOCAL_KEK_ID,
    LOCAL_SCOPE, LOCAL_TENANT_ID, MAX_SECRET_INPUT_BYTES, MAX_SECRET_STATE_BYTES,
};
use runtrue_secrets::{
    LocalMasterKeyFile, SecretIdentity, SecretMetadata, SecretPlaintext, SecretStatus, SecretVault,
    SecretVaultSnapshot, SecretsError,
};
use serde::Serialize;
use std::{
    fs,
    io::{self, IsTerminal as _, Read as _},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub(super) fn secret_set(workspace: &Path, args: SecretSetArgs) -> Result<(), AdminError> {
    if !args.forbidden_values.is_empty() {
        return Err(AdminError::SecretValueArgument);
    }
    validate_name(&args.name)?;
    let plaintext = read_secret_input(workspace, args.file.as_deref())?;
    let mut loaded = load_secret_vault(workspace, true)?;
    let identity = secret_identity(&args.name)?;
    let metadata = match loaded.vault.create_secret(identity, &plaintext) {
        Ok(metadata) => metadata,
        Err(error) => {
            loaded.cleanup_uncommitted_initialization();
            return Err(AdminError::SecretOperation(error));
        }
    };
    if let Err(error) = persist_secret_vault(&loaded) {
        loaded.cleanup_uncommitted_initialization();
        return Err(error);
    }
    print_secret_result("created", &metadata, None, args.json)
}

pub(super) fn secret_rotate(workspace: &Path, args: SecretRotateArgs) -> Result<(), AdminError> {
    if !args.forbidden_values.is_empty() {
        return Err(AdminError::SecretValueArgument);
    }
    validate_name(&args.name)?;
    let identity = secret_identity(&args.name)?;
    let mut loaded = load_secret_vault(workspace, false)?;
    let existing = loaded
        .vault
        .metadata(&identity)
        .map_err(AdminError::SecretOperation)?;
    if existing.status != SecretStatus::Active {
        return Err(AdminError::SecretOperation(SecretsError::SecretTombstoned(
            identity,
        )));
    }
    let plaintext = read_secret_input(workspace, args.file.as_deref())?;
    let metadata = loaded
        .vault
        .add_version(&existing.identity, &plaintext)
        .map_err(AdminError::SecretOperation)?;
    persist_secret_vault(&loaded)?;
    print_secret_result("rotated", &metadata, None, args.json)
}

pub(super) fn secret_get(workspace: &Path, args: SecretGetArgs) -> Result<(), AdminError> {
    validate_name(&args.name)?;
    let identity = secret_identity(&args.name)?;
    let loaded = load_secret_vault(workspace, false)?;
    let metadata = loaded
        .vault
        .metadata(&identity)
        .map_err(AdminError::SecretOperation)?;
    let revealed_to = if let Some(path) = args.reveal_to {
        let plaintext = loaded
            .vault
            .reveal_for_administration(&identity, None)
            .map_err(AdminError::SecretOperation)?;
        let destination = write_revealed_secret(workspace, &path, plaintext.as_bytes())?;
        Some(display_path(workspace, &destination))
    } else {
        None
    };
    let operation = if revealed_to.is_some() {
        "revealed"
    } else {
        "metadata"
    };
    print_secret_result(operation, &metadata, revealed_to, args.json)
}

pub(super) fn secret_delete(workspace: &Path, args: SecretDeleteArgs) -> Result<(), AdminError> {
    validate_name(&args.name)?;
    let identity = secret_identity(&args.name)?;
    let mut loaded = load_secret_vault(workspace, false)?;
    let metadata = loaded
        .vault
        .tombstone(&identity)
        .map_err(AdminError::SecretOperation)?;
    persist_secret_vault(&loaded)?;
    print_secret_result("deleted", &metadata, None, args.json)
}

fn secret_identity(name: &str) -> Result<SecretIdentity, AdminError> {
    SecretIdentity::new(LOCAL_TENANT_ID, LOCAL_SCOPE, name).map_err(AdminError::SecretOperation)
}

struct LoadedSecretVault {
    vault: SecretVault,
    directory: PathBuf,
    key_path: PathBuf,
    state_path: PathBuf,
    newly_initialized: bool,
}

impl LoadedSecretVault {
    fn cleanup_uncommitted_initialization(&mut self) {
        if self.newly_initialized
            && matches!(
                fs::symlink_metadata(&self.state_path),
                Err(error) if error.kind() == io::ErrorKind::NotFound
            )
        {
            let _ = fs::remove_file(&self.key_path);
            let _ = sync_directory(&self.directory);
        }
        self.newly_initialized = false;
    }
}

fn load_secret_vault(
    workspace: &Path,
    allow_initialize: bool,
) -> Result<LoadedSecretVault, AdminError> {
    let directory = ensure_secrets_directory(workspace, allow_initialize)?;
    let key_path = directory.join("master.key");
    let state_path = directory.join("vault.json");
    let key_exists = secure_file_exists(&key_path, "secret master key")?;
    let state_exists = secure_file_exists(&state_path, "secret vault state")?;
    match (key_exists, state_exists) {
        (false, false) if allow_initialize => {
            let key = LocalMasterKeyFile::new(&key_path)
                .load_or_create()
                .map_err(AdminError::MasterKey)?;
            let vault = SecretVault::new(LOCAL_KEK_ID, key).map_err(AdminError::SecretState)?;
            Ok(LoadedSecretVault {
                vault,
                directory,
                key_path,
                state_path,
                newly_initialized: true,
            })
        }
        (true, true) => {
            let key = LocalMasterKeyFile::new(&key_path)
                .load()
                .map_err(AdminError::MasterKey)?;
            let bytes = read_regular_file(
                &state_path,
                MAX_SECRET_STATE_BYTES,
                "secret vault state",
                true,
            )?;
            let snapshot: SecretVaultSnapshot =
                serde_json::from_slice(&bytes).map_err(|source| AdminError::InvalidState {
                    kind: "secret vault",
                    source,
                })?;
            let vault =
                SecretVault::from_snapshot(snapshot, key).map_err(AdminError::SecretState)?;
            Ok(LoadedSecretVault {
                vault,
                directory,
                key_path,
                state_path,
                newly_initialized: false,
            })
        }
        (false, false) => Err(AdminError::StateMissing("secret vault")),
        _ => Err(AdminError::IncompleteSecretState),
    }
}

fn persist_secret_vault(loaded: &LoadedSecretVault) -> Result<(), AdminError> {
    let bytes = serde_json::to_vec(&loaded.vault.snapshot()).map_err(AdminError::SerializeState)?;
    if bytes.len() as u64 > MAX_SECRET_STATE_BYTES {
        return Err(AdminError::StateTooLarge {
            kind: "secret vault",
            limit: MAX_SECRET_STATE_BYTES,
            actual: bytes.len() as u64,
        });
    }
    write_private_atomic(&loaded.directory, &loaded.state_path, &bytes)
}

fn read_secret_input(
    workspace: &Path,
    source_path: Option<&Path>,
) -> Result<SecretPlaintext, AdminError> {
    let mut bytes = if let Some(source_path) = source_path {
        let path = resolve_explicit_path(workspace, source_path)?;
        reject_internal_admin_path(workspace, &path)?;
        Zeroizing::new(read_regular_file(
            &path,
            MAX_SECRET_INPUT_BYTES,
            "secret input",
            false,
        )?)
    } else {
        let stdin = io::stdin();
        if stdin.is_terminal() {
            return Err(AdminError::TerminalSecretInput);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        stdin
            .lock()
            .take(MAX_SECRET_INPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(AdminError::ReadStdin)?;
        if bytes.len() as u64 > MAX_SECRET_INPUT_BYTES {
            return Err(AdminError::InputTooLarge {
                kind: "secret input",
                limit: MAX_SECRET_INPUT_BYTES,
                actual: bytes.len() as u64,
            });
        }
        bytes
    };
    Ok(SecretPlaintext::new(std::mem::take(&mut *bytes)))
}

#[derive(Debug, Serialize)]
struct SecretResult {
    operation: &'static str,
    metadata: SecretMetadataView,
    revealed_to: Option<String>,
}

#[derive(Debug, Serialize)]
struct SecretMetadataView {
    name: String,
    scope: String,
    status: SecretStatus,
    version: u64,
}

impl From<&SecretMetadata> for SecretMetadataView {
    fn from(metadata: &SecretMetadata) -> Self {
        Self {
            name: metadata.identity.name().to_owned(),
            scope: metadata.identity.scope().to_owned(),
            status: metadata.status,
            version: metadata.current_version,
        }
    }
}

fn print_secret_result(
    operation: &'static str,
    metadata: &SecretMetadata,
    revealed_to: Option<String>,
    json: bool,
) -> Result<(), AdminError> {
    if json {
        print_json(&SecretResult {
            operation,
            metadata: metadata.into(),
            revealed_to,
        })
    } else {
        println!(
            "secret {}: {operation} (scope={}, status={:?}, version={})",
            metadata.identity.name(),
            metadata.identity.scope(),
            metadata.status,
            metadata.current_version
        );
        if let Some(path) = revealed_to {
            println!("revealed to {path}");
        }
        Ok(())
    }
}
