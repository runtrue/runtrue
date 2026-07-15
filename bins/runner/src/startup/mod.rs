mod args;
mod backends;
mod config;
mod doctor;
mod error;

use self::{
    args::{Args, Command},
    config::{Config, MAX_CAPSULE_BYTES},
    error::StartupError,
};
use clap::Parser;
use runtrue_runner::{
    apply_authoritative_posture, enroll_runner_from_token_file, load_capsule_trust_store,
    probe_inventory_with_backends_for_protocol, CredentialError, EndpointSecurity,
    EnrollmentEndpointSecurity, FirecrackerJobExecutor, OciJobExecutor, RemoteJobExecutor, RunMode,
    RunnerCredentialStore, RunnerDaemon, RunnerDaemonConfig, RunnerError, RunnerStateStore,
    WasmJobExecutor, WorkspaceManager,
};
use runtrue_workflow_ir::Isolation;
use serde::Serialize;
use std::{collections::BTreeSet, error::Error};

pub async fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = Config::load(Args::parse())?;
    let oci = config.oci.as_ref().map(OciJobExecutor::load).transpose()?;
    let wasm = config
        .wasm
        .as_ref()
        .map(WasmJobExecutor::load)
        .transpose()?;
    let firecracker = config
        .firecracker
        .as_ref()
        .map(FirecrackerJobExecutor::load)
        .transpose()?;
    let mut backends = BTreeSet::new();
    if config.trusted_native {
        backends.insert(Isolation::Native);
    }
    if oci.is_some() {
        backends.insert(Isolation::Oci);
    }
    if wasm.is_some() {
        backends.insert(Isolation::Wasm);
    }
    if firecracker.is_some() {
        backends.insert(Isolation::Microvm);
    }
    if backends.is_empty() {
        return Err(StartupError::NoExecutionBackend.into());
    }

    if matches!(config.command, Command::Enroll) {
        if config.runner_id.is_some()
            || config.client_certificate.is_some()
            || config.client_private_key.is_some()
            || config.insecure_loopback
            || config.protocol_version.is_some()
        {
            return Err(StartupError::InvalidEnrollmentOptions.into());
        }
        let endpoint = EnrollmentEndpointSecurity {
            endpoint: config
                .enrollment_endpoint
                .clone()
                .ok_or(StartupError::MissingEnrollmentEndpoint)?,
            ca_certificate: config
                .ca_certificate
                .clone()
                .ok_or(StartupError::MissingCaCertificate)?,
        };
        let token_file = config
            .enrollment_token_file
            .as_ref()
            .ok_or(StartupError::MissingEnrollmentTokenFile)?;
        let credential_store = RunnerCredentialStore::open(&config.credential_directory)?;
        match credential_store.load_current() {
            Ok(_) => return Err(StartupError::CredentialsAlreadyInstalled.into()),
            Err(CredentialError::MissingCredentials(_)) => {}
            Err(error) => return Err(error.into()),
        }
        let workspaces = WorkspaceManager::open(&config.workspace_directory)?;
        let inventory = probe_inventory_with_backends_for_protocol(
            "enrollment-pending",
            workspaces.root(),
            config.region.clone(),
            backends,
            runtrue_protocol::PROTOCOL_MIN,
        )?;
        let installed = enroll_runner_from_token_file(
            &endpoint,
            token_file,
            inventory.wire,
            &credential_store,
            config.ephemeral,
        )
        .await?;
        #[derive(Serialize)]
        struct EnrollmentResult<'a> {
            status: &'static str,
            runner_id: &'a str,
            runner_pool_id: &'a str,
            certificate_expires_unix_ms: u64,
            selected_protocol_version: u32,
            ephemeral: bool,
            credential_directory: String,
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&EnrollmentResult {
                status: "enrolled",
                runner_id: &installed.runner_id,
                runner_pool_id: &installed.pool_id,
                certificate_expires_unix_ms: installed.certificate_expires_unix_ms,
                selected_protocol_version: installed
                    .selected_protocol_version
                    .ok_or(StartupError::MissingProtocolVersion)?,
                ephemeral: config.ephemeral,
                credential_directory: credential_store.root().display().to_string(),
            })?
        );
        return Ok(());
    }

    if config.enrollment_token_file.is_some() || config.enrollment_endpoint.is_some() {
        return Err(StartupError::InvalidEnrollmentOptions.into());
    }
    let endpoint_value = config
        .endpoint
        .clone()
        .ok_or(StartupError::MissingEndpoint)?;
    let (
        runner_id,
        credential_store,
        direct_certificate,
        direct_private_key,
        authoritative_posture,
        selected_protocol_version,
    ) = match (
        config.runner_id.clone(),
        config.client_certificate.clone(),
        config.client_private_key.clone(),
    ) {
        (Some(runner_id), Some(certificate), Some(private_key)) => (
            runner_id,
            None,
            Some(certificate),
            Some(private_key),
            None,
            config
                .protocol_version
                .ok_or(StartupError::MissingProtocolVersion)?,
        ),
        (Some(runner_id), None, None) if config.insecure_loopback => (
            runner_id,
            None,
            None,
            None,
            None,
            config
                .protocol_version
                .ok_or(StartupError::MissingProtocolVersion)?,
        ),
        (None, None, None) => {
            let store = RunnerCredentialStore::open(&config.credential_directory)?;
            let loaded = match config.protocol_version {
                Some(protocol_version) => store.bind_current_protocol_version(protocol_version)?,
                None => store.load_current()?,
            };
            let protocol_version = loaded
                .selected_protocol_version
                .ok_or(StartupError::MissingProtocolVersion)?;
            (
                loaded.runner_id,
                Some(store),
                Some(loaded.client_certificate),
                Some(loaded.client_private_key),
                loaded.authoritative_posture_digest,
                protocol_version,
            )
        }
        _ => return Err(StartupError::IncompleteDirectCredentials.into()),
    };
    let workspaces = WorkspaceManager::open(&config.workspace_directory)?;
    let mut inventory = probe_inventory_with_backends_for_protocol(
        &runner_id,
        workspaces.root(),
        config.region.clone(),
        backends.clone(),
        selected_protocol_version,
    )?;
    if let Some(authoritative) = authoritative_posture.as_ref() {
        apply_authoritative_posture(&mut inventory, authoritative)?;
    }
    let trusted_keys = load_capsule_trust_store(&config.capsule_keyring)?;
    let initial_endpoint = EndpointSecurity {
        endpoint: endpoint_value.clone(),
        ca_certificate: config.ca_certificate.clone(),
        client_certificate: direct_certificate.clone(),
        client_private_key: direct_private_key.clone(),
        insecure_loopback: config.insecure_loopback,
    };
    initial_endpoint.validate_configuration()?;

    if matches!(config.command, Command::Doctor) {
        println!(
            "{}",
            doctor::report(
                doctor::DoctorContext {
                    runner_id: &runner_id,
                    endpoint: &endpoint_value,
                    inventory: &inventory,
                    trusted_keys: &trusted_keys,
                    trusted_native: config.trusted_native,
                },
                doctor::DoctorBackends {
                    oci: oci.as_ref(),
                    wasm: wasm.as_ref(),
                    firecracker: firecracker.as_ref(),
                },
            )?
        );
        return Ok(());
    }

    let mode = match config.command {
        Command::Once => RunMode::Once,
        Command::Daemon => RunMode::Daemon,
        Command::Enroll => unreachable!("enroll returned above"),
        Command::Doctor => unreachable!("doctor returned above"),
    };
    loop {
        let (
            active_runner_id,
            client_certificate,
            client_private_key,
            active_protocol_version,
            active_authoritative_posture,
        ) = if let Some(store) = &credential_store {
            let loaded = store.load_current()?;
            if loaded.runner_id != runner_id
                || loaded.selected_protocol_version != Some(selected_protocol_version)
            {
                return Err(StartupError::IncompleteDirectCredentials.into());
            }
            (
                loaded.runner_id,
                Some(loaded.client_certificate),
                Some(loaded.client_private_key),
                selected_protocol_version,
                loaded.authoritative_posture_digest,
            )
        } else {
            (
                runner_id.clone(),
                direct_certificate.clone(),
                direct_private_key.clone(),
                selected_protocol_version,
                None,
            )
        };
        let endpoint = EndpointSecurity {
            endpoint: endpoint_value.clone(),
            ca_certificate: config.ca_certificate.clone(),
            client_certificate,
            client_private_key,
            insecure_loopback: config.insecure_loopback,
        };
        let transport = endpoint.connect().await?;
        let state = RunnerStateStore::open(&config.state_directory)?;
        let workspaces = WorkspaceManager::open(&config.workspace_directory)?;
        let mut inventory = probe_inventory_with_backends_for_protocol(
            &active_runner_id,
            workspaces.root(),
            config.region.clone(),
            backends.clone(),
            active_protocol_version,
        )?;
        if let Some(authoritative) = active_authoritative_posture.as_ref() {
            apply_authoritative_posture(&mut inventory, authoritative)?;
        }
        let daemon_config = RunnerDaemonConfig {
            runner_id: active_runner_id,
            inventory,
            trust_store: trusted_keys.store.clone(),
            allow_trusted_native: config.trusted_native,
            mode,
            max_capsule_bytes: MAX_CAPSULE_BYTES,
            credential_store: credential_store.clone(),
        };
        match RunnerDaemon::new(
            transport,
            RemoteJobExecutor::with_all_backends(
                config.trusted_native,
                oci.clone(),
                wasm.clone(),
                firecracker.clone(),
            ),
            daemon_config,
            state,
            workspaces,
        )
        .run()
        .await
        {
            Err(RunnerError::CertificateRotated) => continue,
            result => return result.map_err(Into::into),
        }
    }
}
