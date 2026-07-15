use super::bindings::invoke_adapter;
use super::filesystem::{MAX_CAPABILITY_PATH_BYTES, MAX_CAPABILITY_PATH_SEGMENTS};
use super::*;
use crate::runtrue::action::host::{DirectoryAccess as WitDirectoryAccess, Host};
use runtrue_engine::CancellationToken;
use runtrue_model::SecretReference;
use runtrue_workflow_ir::NetworkPermission;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

fn state(adapters: CapabilityAdapters) -> HostState {
    HostState::new(HostInvocation {
        input: b"{}".to_vec(),
        limits: HostLimits {
            max_output_bytes: 1024,
            max_log_bytes: 1024,
            max_log_entry_bytes: 128,
            max_adapter_request_bytes: 1024,
            max_adapter_response_bytes: 1024,
            max_secret_bytes: 128,
            max_oidc_token_bytes: 256,
        },
        call_context: CapabilityCallContext::new(
            Instant::now() + Duration::from_secs(1),
            CancellationToken::default(),
            1024,
            1024,
        ),
        adapters,
        directories: BTreeMap::new(),
        networks: BTreeMap::new(),
        secrets: BTreeMap::new(),
        oidc_audiences: BTreeMap::new(),
        store_limits: AggregateStoreLimits::new(1024 * 1024, 1024, 16, 16, 16),
    })
}

#[test]
fn wasi_03_context_does_not_inherit_process_configuration() {
    let mut state = state(CapabilityAdapters::new());
    let mut cli = wasmtime_wasi::cli::WasiCliView::cli(&mut state);
    use wasmtime_wasi::p3::bindings::cli::environment::Host as _;

    assert!(cli.get_environment().unwrap().is_empty());
    assert!(cli.get_arguments().unwrap().is_empty());
    assert_eq!(cli.get_initial_cwd().unwrap(), None);
}

#[test]
fn output_requires_duplicate_free_canonical_json() {
    let mut state = state(CapabilityAdapters::new());
    assert!(state.set_output(br#"{"b":1,"a":2}"#.to_vec()).is_err());
    assert!(state.set_output(br#"{"a":1,"a":2}"#.to_vec()).is_err());
    assert!(state.set_output(br#"{"a":2,"b":1}"#.to_vec()).is_ok());
}

struct LeakyFilesystem;

impl FilesystemAdapter for LeakyFilesystem {
    fn read_file(
        &self,
        _context: &CapabilityCallContext,
        _grant: &DirectoryGrant,
        _relative_path: &str,
    ) -> Result<Vec<u8>, CapabilityAdapterError> {
        Err(CapabilityAdapterError::Failed(
            "/host/private/tenant/secret".to_owned(),
        ))
    }

    fn write_file(
        &self,
        _context: &CapabilityCallContext,
        _grant: &DirectoryGrant,
        _relative_path: &str,
        _value: &[u8],
    ) -> Result<(), CapabilityAdapterError> {
        Err(CapabilityAdapterError::Denied(
            "policy internals".to_owned(),
        ))
    }
}

#[test]
fn provider_error_details_are_not_exposed_to_guest() {
    let adapters = CapabilityAdapters::new().with_filesystem(Arc::new(LeakyFilesystem));
    let mut state = state(adapters);
    state.directories.insert(
        7,
        DirectoryGrant::new("scope".to_owned(), FilesystemAccess::ReadWrite),
    );
    assert_eq!(
        state.read_file(7, "file".to_owned()),
        Err("capability-adapter-failed".to_owned())
    );
    assert_eq!(
        state.write_file(7, "file".to_owned(), Vec::new()),
        Err("capability-denied".to_owned())
    );
}

struct ExactSecret;

impl SecretAdapter for ExactSecret {
    fn read_secret(
        &self,
        _context: &CapabilityCallContext,
        grant: &SecretReference,
    ) -> Result<SecretValue, CapabilityAdapterError> {
        if grant.metadata_id == "declared" && grant.name == "TOKEN" {
            Ok(SecretValue::new(b"value".to_vec()))
        } else {
            Err(CapabilityAdapterError::Denied("wrong grant".to_owned()))
        }
    }
}

struct ExactOidc;

impl OidcAdapter for ExactOidc {
    fn mint_token(
        &self,
        _context: &CapabilityCallContext,
        audience: &str,
    ) -> Result<OidcToken, CapabilityAdapterError> {
        if audience == "https://registry.example" {
            Ok(OidcToken::new(b"token-value".to_vec()))
        } else {
            Err(CapabilityAdapterError::Denied("wrong audience".to_owned()))
        }
    }
}

#[test]
fn secret_reads_require_the_exact_declared_handle() {
    let adapters = CapabilityAdapters::new().with_secrets(Arc::new(ExactSecret));
    let mut state = state(adapters);
    state.secrets.insert(
        11,
        SecretReference {
            metadata_id: "declared".to_owned(),
            name: "TOKEN".to_owned(),
            purpose: Some("test".to_owned()),
        },
    );
    assert_eq!(
        state.read_secret(10),
        Err("invalid secret handle".to_owned())
    );
    assert_eq!(state.read_secret(11), Ok(b"value".to_vec()));
    let handles = state.secret_handles();
    assert_eq!(handles.len(), 1);
    assert_eq!(handles[0].id, 11);
    assert_eq!(handles[0].name, "TOKEN");
    assert_eq!(handles[0].purpose.as_deref(), Some("test"));
    assert_eq!(
        state.output().credential_taint,
        runtrue_engine::CredentialTaint::CredentialReleased
    );
}

#[test]
fn declared_but_unused_credentials_do_not_taint_guest_output() {
    let mut state = state(CapabilityAdapters::new().with_secrets(Arc::new(ExactSecret)));
    state.secrets.insert(
        11,
        SecretReference {
            metadata_id: "declared".to_owned(),
            name: "TOKEN".to_owned(),
            purpose: None,
        },
    );
    state
        .set_output(br#"{"status":"unused"}"#.to_vec())
        .unwrap();
    state
        .log(
            "stdout".to_owned(),
            "credential was not requested".to_owned(),
        )
        .unwrap();

    let output = state.output();
    assert_eq!(
        output.credential_taint,
        runtrue_engine::CredentialTaint::None
    );
    assert_eq!(
        output.output.as_deref(),
        Some(br#"{"status":"unused"}"#.as_slice())
    );
    assert_eq!(output.stdout, "credential was not requested");
}

#[test]
fn successful_credential_release_suppresses_transformed_and_split_guest_material() {
    let adapters = CapabilityAdapters::new()
        .with_secrets(Arc::new(ExactSecret))
        .with_oidc(Arc::new(ExactOidc));
    let mut state = state(adapters);
    state.secrets.insert(
        11,
        SecretReference {
            metadata_id: "declared".to_owned(),
            name: "TOKEN".to_owned(),
            purpose: None,
        },
    );
    state
        .oidc_audiences
        .insert(12, "https://registry.example".to_owned());

    assert_eq!(
        state.mint_oidc_token(99),
        Err("invalid OIDC audience handle".to_owned())
    );
    // A component can prepare durable material before asking for the
    // credential, then transform or split it afterward. Taint must suppress
    // the complete guest-controlled channels, not only literal substrings.
    state
        .set_output(br#"{"encoded":"dmFsdWU="}"#.to_vec())
        .unwrap();
    assert_eq!(state.read_secret(11), Ok(b"value".to_vec()));
    assert_eq!(state.mint_oidc_token(12), Ok(b"token-value".to_vec()));
    assert!(state
        .set_output(br#"{"split":["val","ue"]}"#.to_vec())
        .is_err());
    state
        .log(
            "stdout".to_owned(),
            "encoded=dmFsdWU= split=val|ue".to_owned(),
        )
        .unwrap();
    let output = state.output();
    assert_eq!(
        output.credential_taint,
        runtrue_engine::CredentialTaint::CredentialReleased
    );
    assert!(output.output.is_none());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(state.oidc_handles()[0].audience, "https://registry.example");
    assert_eq!(
        format!("{:?}", OidcToken::new(b"hidden".to_vec())),
        "OidcToken(<redacted>)"
    );
}

#[test]
fn directory_descriptors_identify_scope_and_access_without_host_paths() {
    let mut state = state(CapabilityAdapters::new());
    state.directories.insert(
        5,
        DirectoryGrant::new("workspace/src".to_owned(), FilesystemAccess::Read),
    );
    let handles = state.directory_handles();
    assert_eq!(handles.len(), 1);
    assert_eq!(handles[0].id, 5);
    assert_eq!(handles[0].scope, "workspace/src");
    assert_eq!(handles[0].access, WitDirectoryAccess::Read);
}

#[test]
fn filesystem_grants_match_exact_files_and_directory_prefixes() {
    let exact = DirectoryGrant::new("Cargo.toml".to_owned(), FilesystemAccess::Read);
    assert!(exact.contains("Cargo.toml"));
    assert!(!exact.contains("nested/Cargo.toml"));

    let directory = DirectoryGrant::new("src".to_owned(), FilesystemAccess::Read);
    assert!(directory.contains("src/lib.rs"));
    assert!(directory.contains("src/nested/module.rs"));
    assert!(!directory.contains("src-other/module.rs"));
    assert!(!directory.contains("outside.rs"));
    assert!(!directory.contains(&"x".repeat(MAX_CAPABILITY_PATH_BYTES + 1)));
    assert!(!directory.contains(&vec!["x"; MAX_CAPABILITY_PATH_SEGMENTS + 1].join("/")));
}

#[test]
fn logs_are_bounded_per_entry_and_stream() {
    let mut state = state(CapabilityAdapters::new());
    assert!(state.log("stdout".to_owned(), "x".repeat(129)).is_err());
    assert!(state.log("unknown".to_owned(), "value".to_owned()).is_err());
}

#[test]
fn blocking_adapter_returns_at_deadline_without_hanging_executor() {
    let context = CapabilityCallContext::new(
        Instant::now() + Duration::from_millis(10),
        CancellationToken::default(),
        16,
        16,
    );
    let started = Instant::now();
    let result = invoke_adapter(&context, |_context| {
        thread::sleep(Duration::from_millis(500));
        Ok::<_, CapabilityAdapterError>(())
    });
    assert_eq!(result, Err(CapabilityAdapterError::DeadlineExceeded));
    assert!(started.elapsed() < Duration::from_millis(250));
}

#[test]
fn canceled_adapter_context_never_starts_the_operation() {
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let context = CapabilityCallContext::new(
        Instant::now() + Duration::from_secs(1),
        cancellation,
        16,
        16,
    );
    let started = Arc::new(AtomicUsize::new(0));
    let worker_started = started.clone();
    let result = invoke_adapter(&context, move |_context| {
        worker_started.fetch_add(1, Ordering::Release);
        Ok::<_, CapabilityAdapterError>(())
    });

    assert_eq!(result, Err(CapabilityAdapterError::Canceled));
    assert_eq!(started.load(Ordering::Acquire), 0);
}

struct OversizedNetwork;

impl NetworkAdapter for OversizedNetwork {
    fn http_request(
        &self,
        _context: &CapabilityCallContext,
        _grant: &NetworkPermission,
        _request: &[u8],
    ) -> Result<Vec<u8>, CapabilityAdapterError> {
        Ok(vec![0; 1025])
    }
}

struct OversizedSecret;

impl SecretAdapter for OversizedSecret {
    fn read_secret(
        &self,
        _context: &CapabilityCallContext,
        _grant: &SecretReference,
    ) -> Result<SecretValue, CapabilityAdapterError> {
        Ok(SecretValue::new(vec![0; 129]))
    }
}

#[test]
fn host_enforces_adapter_request_response_and_secret_budgets() {
    let adapters = CapabilityAdapters::new()
        .with_network(Arc::new(OversizedNetwork))
        .with_secrets(Arc::new(OversizedSecret));
    let mut state = state(adapters);
    state.networks.insert(7, NetworkPermission::Deny);
    state.secrets.insert(
        8,
        SecretReference {
            metadata_id: "declared".to_owned(),
            name: "TOKEN".to_owned(),
            purpose: None,
        },
    );

    assert_eq!(
        state.http_request(7, vec![0; 1025]),
        Err("capability request exceeds the configured byte limit".to_owned())
    );
    assert_eq!(
        state.http_request(7, Vec::new()),
        Err("capability response exceeds the configured byte limit".to_owned())
    );
    assert_eq!(
        state.read_secret(8),
        Err("secret exceeds the configured byte limit".to_owned())
    );
    assert_eq!(
        state.output().credential_taint,
        runtrue_engine::CredentialTaint::None
    );
}
