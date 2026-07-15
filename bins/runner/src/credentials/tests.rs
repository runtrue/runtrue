use super::load::optional_current_generation;
use super::publish::write_new_private_file;
use super::secure_fs::set_private_directory_permissions;
use super::*;
use crate::state::StateError;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType, SerialNumber, PKCS_ED25519,
};
use runtrue_model::ContentDigest;
use runtrue_protocol::{PROTOCOL_MAX, PROTOCOL_MIN};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use time::OffsetDateTime;
use zeroize::Zeroizing;

fn credentials(runner_id: &str, pool_id: &str) -> NewRunnerCredentials {
    let ca_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca_params.not_before = OffsetDateTime::from_unix_timestamp(1).unwrap();
    ca_params.not_after = OffsetDateTime::from_unix_timestamp(4_102_444_800).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::from_unix_timestamp(1).unwrap();
    params.not_after = OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, runner_id);
    params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, pool_id);
    params.subject_alt_names = vec![SanType::URI(
        Ia5String::try_from(format!("urn:runtrue:runner:{pool_id}:{runner_id}")).unwrap(),
    )];
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let certificate = params.signed_by(&key, &issuer).unwrap();
    NewRunnerCredentials {
        runner_id: runner_id.to_owned(),
        pool_id: pool_id.to_owned(),
        certificate_expires_unix_ms: 2_000_000_000_000,
        private_key_pem: Zeroizing::new(key.serialize_pem()),
        certificate_chain_pem: format!("{}\n{}\n", certificate.pem(), ca.pem()).into_bytes(),
        authoritative_posture_digest: None,
        selected_protocol_version: runtrue_protocol::PROTOCOL_MAX,
    }
}

#[test]
fn authoritative_posture_survives_install_and_reload() {
    let directory = tempfile::tempdir().unwrap();
    let store = RunnerCredentialStore::open(directory.path()).unwrap();
    let expected = ContentDigest::sha256(b"server-authoritative-posture");
    let mut initial = credentials("runner-1", "pool-1");
    initial.authoritative_posture_digest = Some(expected.clone());
    let installed = store.install(&initial).unwrap();
    assert_eq!(
        installed.authoritative_posture_digest,
        Some(expected.clone())
    );
    assert_eq!(
        store.load_current().unwrap().authoritative_posture_digest,
        Some(expected)
    );
}

#[test]
fn selected_protocol_survives_restart_without_changing_legacy_json() {
    let directory = tempfile::tempdir().unwrap();
    let store = RunnerCredentialStore::open(directory.path()).unwrap();
    let installed = store.install(&credentials("runner-1", "pool-1")).unwrap();
    assert_eq!(
        installed.selected_protocol_version,
        Some(runtrue_protocol::PROTOCOL_MAX)
    );
    let generation = optional_current_generation(&store.current)
        .unwrap()
        .unwrap();
    let metadata = fs::read(store.generations.join(generation).join(METADATA_FILE)).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
    assert!(json.get("selected_protocol_version").is_none());
    assert_eq!(
        store.load_current().unwrap().selected_protocol_version,
        Some(runtrue_protocol::PROTOCOL_MAX)
    );
}

#[test]
fn legacy_credentials_require_one_explicit_monotonic_protocol_upgrade() {
    let directory = tempfile::tempdir().unwrap();
    let store = RunnerCredentialStore::open(directory.path()).unwrap();
    store.install(&credentials("runner-1", "pool-1")).unwrap();
    let generation = optional_current_generation(&store.current)
        .unwrap()
        .unwrap();
    let protocol = store
        .generations
        .join(generation)
        .join(PROTOCOL_VERSION_FILE);
    fs::remove_file(&protocol).unwrap();
    assert_eq!(
        store.load_current().unwrap().selected_protocol_version,
        None
    );

    let upgraded = store.bind_current_protocol_version(PROTOCOL_MIN).unwrap();
    assert_eq!(upgraded.selected_protocol_version, Some(PROTOCOL_MIN));
    assert_eq!(
        store
            .bind_current_protocol_version(PROTOCOL_MIN)
            .unwrap()
            .selected_protocol_version,
        Some(PROTOCOL_MIN)
    );
    assert!(matches!(
        store.bind_current_protocol_version(PROTOCOL_MAX),
        Err(CredentialError::ProtocolVersionMismatch {
            persisted: PROTOCOL_MIN,
            configured: PROTOCOL_MAX,
        }) if PROTOCOL_MIN != PROTOCOL_MAX
    ));
}

#[test]
fn malformed_protocol_sidecar_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let store = RunnerCredentialStore::open(directory.path()).unwrap();
    store.install(&credentials("runner-1", "pool-1")).unwrap();
    let generation = optional_current_generation(&store.current)
        .unwrap()
        .unwrap();
    let protocol = store
        .generations
        .join(generation)
        .join(PROTOCOL_VERSION_FILE);
    fs::write(&protocol, b"0\n").unwrap();
    assert!(matches!(
        store.load_current(),
        Err(CredentialError::InvalidProtocolVersion)
    ));
}

fn rotation_request() -> (Zeroizing<String>, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .der()
        .to_vec();
    (Zeroizing::new(key.serialize_pem()), csr)
}

fn rotation_fixture() -> (
    NewRunnerCredentials,
    Zeroizing<String>,
    Vec<u8>,
    PendingRotationResponse,
    PendingRotationResponse,
) {
    let ca_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca_params.not_before = OffsetDateTime::from_unix_timestamp(1).unwrap();
    ca_params.not_after = OffsetDateTime::from_unix_timestamp(4_102_444_800).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let issue = |key: &KeyPair, serial: u8| {
        let mut params = CertificateParams::default();
        params.not_before = OffsetDateTime::from_unix_timestamp(1).unwrap();
        params.not_after = OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
        params.serial_number = Some(SerialNumber::from_slice(&[serial]));
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "runner-1");
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, "pool-1");
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from("urn:runtrue:runner:pool-1:runner-1").unwrap(),
        )];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        params.signed_by(key, &issuer).unwrap()
    };

    let current_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let current_certificate = issue(&current_key, 1);
    let current = NewRunnerCredentials {
        runner_id: "runner-1".to_owned(),
        pool_id: "pool-1".to_owned(),
        certificate_expires_unix_ms: 2_000_000_000_000,
        private_key_pem: Zeroizing::new(current_key.serialize_pem()),
        certificate_chain_pem: format!("{}\n{}\n", current_certificate.pem(), ca.pem())
            .into_bytes(),
        authoritative_posture_digest: None,
        selected_protocol_version: runtrue_protocol::PROTOCOL_MAX,
    };

    let rotation_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&rotation_key)
        .unwrap()
        .der()
        .to_vec();
    let response = |serial| PendingRotationResponse {
        certificate_expires_unix_ms: 2_000_000_000_000,
        certificate_chain_pem: format!(
            "{}\n{}\n",
            issue(&rotation_key, serial).pem().trim(),
            ca.pem().trim()
        )
        .into_bytes(),
    };
    let first_response = response(2);
    (
        current,
        Zeroizing::new(rotation_key.serialize_pem()),
        csr,
        first_response,
        response(3),
    )
}

#[test]
fn pending_rotation_survives_lost_response_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("credentials");
    let (current, private_key, csr, response, _) = rotation_fixture();
    let store = RunnerCredentialStore::open(&root).unwrap();
    let current = store.install(&current).unwrap();
    let pending = store.begin_rotation(&current, private_key, csr).unwrap();
    let expected_csr = pending.csr_der.clone();
    drop(store);

    let reopened = RunnerCredentialStore::open(&root).unwrap();
    let recovered = reopened.load_pending_rotation().unwrap().unwrap();
    assert_eq!(recovered.csr_der, expected_csr);
    assert!(recovered.response.is_none());
    reopened.record_rotation_response(response.clone()).unwrap();
    drop(reopened);

    let restarted = RunnerCredentialStore::open(&root).unwrap();
    let recovered = restarted.load_pending_rotation().unwrap().unwrap();
    assert_eq!(recovered.response.as_ref(), Some(&response));
    let installed = restarted.install_pending_rotation().unwrap();
    assert_eq!(
        installed.certificate_fingerprint,
        response.certificate_fingerprint().unwrap()
    );
    assert!(restarted.load_pending_rotation().unwrap().is_none());
}

#[test]
fn restart_clears_only_an_exact_already_installed_rotation() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("credentials");
    let (current, private_key, csr, response, _) = rotation_fixture();
    let store = RunnerCredentialStore::open(&root).unwrap();
    let current = store.install(&current).unwrap();
    store.begin_rotation(&current, private_key, csr).unwrap();
    let pending = store.record_rotation_response(response.clone()).unwrap();

    // Simulate a crash after the generation switch but before pending
    // state deletion by calling the lower-level generation installer.
    store
        .install(&NewRunnerCredentials {
            runner_id: pending.runner_id.clone(),
            pool_id: pending.pool_id.clone(),
            certificate_expires_unix_ms: response.certificate_expires_unix_ms,
            private_key_pem: Zeroizing::new(pending.private_key_pem.as_str().to_owned()),
            certificate_chain_pem: response.certificate_chain_pem.clone(),
            authoritative_posture_digest: None,
            selected_protocol_version: runtrue_protocol::PROTOCOL_MAX,
        })
        .unwrap();
    drop(store);

    let restarted = RunnerCredentialStore::open(&root).unwrap();
    assert!(restarted.reconcile_pending_rotation().unwrap());
    assert!(restarted.load_pending_rotation().unwrap().is_none());
    assert_eq!(
        restarted.load_current().unwrap().certificate_fingerprint,
        response.certificate_fingerprint().unwrap()
    );
}

#[test]
fn conflicting_rotation_response_and_csr_tampering_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("credentials");
    let (current, private_key, csr, response, conflicting) = rotation_fixture();
    let store = RunnerCredentialStore::open(&root).unwrap();
    let current = store.install(&current).unwrap();
    store.begin_rotation(&current, private_key, csr).unwrap();
    store.record_rotation_response(response).unwrap();
    assert!(matches!(
        store.record_rotation_response(conflicting),
        Err(CredentialError::ConflictingRotationResponse)
    ));

    let csr_path = root
        .join(PENDING_ROTATION_DIRECTORY)
        .join(ROTATION_CSR_FILE);
    let mut bytes = fs::read(&csr_path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(&csr_path, bytes).unwrap();
    assert!(matches!(
        store.load_pending_rotation(),
        Err(CredentialError::InvalidCertificateRequest)
    ));
}

#[test]
fn concurrent_rotation_publishers_reuse_one_exact_csr() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("credentials");
    let store = RunnerCredentialStore::open(&root).unwrap();
    let current = store.install(&credentials("runner-1", "pool-1")).unwrap();
    let first = rotation_request();
    let second = rotation_request();
    let (left, right) = std::thread::scope(|scope| {
        let left_store = store.clone();
        let right_store = store.clone();
        let left_current = current.clone();
        let right_current = current.clone();
        let left = scope.spawn(move || left_store.begin_rotation(&left_current, first.0, first.1));
        let right =
            scope.spawn(move || right_store.begin_rotation(&right_current, second.0, second.1));
        (
            left.join().unwrap().unwrap(),
            right.join().unwrap().unwrap(),
        )
    });
    assert_eq!(left.csr_der, right.csr_der);
    assert_eq!(
        ContentDigest::sha256(left.private_key_pem.as_bytes()),
        ContentDigest::sha256(right.private_key_pem.as_bytes())
    );
}

#[test]
fn complete_generation_switch_is_atomic_and_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("credentials");
    let store = RunnerCredentialStore::open(&root).unwrap();
    let first = store.install(&credentials("runner-1", "pool-1")).unwrap();
    assert_eq!(first.runner_id, "runner-1");
    drop(store);
    let reopened = RunnerCredentialStore::open(&root).unwrap();
    let loaded = reopened.load_current().unwrap();
    assert_eq!(loaded, first);
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&loaded.client_private_key)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(&loaded.client_certificate)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
}

#[test]
fn rotation_retains_only_active_and_previous_private_keys() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("credentials");
    let store = RunnerCredentialStore::open(&root).unwrap();

    let first = store.install(&credentials("runner-1", "pool-1")).unwrap();
    let second = store.install(&credentials("runner-1", "pool-1")).unwrap();
    assert!(first.client_private_key.exists());
    assert!(second.client_private_key.exists());

    let third = store.install(&credentials("runner-1", "pool-1")).unwrap();
    assert!(!first.client_private_key.exists());
    assert!(second.client_private_key.exists());
    assert!(third.client_private_key.exists());
    assert_eq!(store.load_current().unwrap(), third);
    assert_eq!(
        fs::read_dir(root.join(GENERATIONS_DIRECTORY))
            .unwrap()
            .count(),
        MAX_RETAINED_GENERATIONS
    );
}

#[test]
fn rotation_removes_abandoned_pending_private_keys() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("credentials");
    let store = RunnerCredentialStore::open(&root).unwrap();
    store.install(&credentials("runner-1", "pool-1")).unwrap();

    let pending = root
        .join(GENERATIONS_DIRECTORY)
        .join(".pending-00000000000000000000000000000000");
    fs::create_dir(&pending).unwrap();
    set_private_directory_permissions(&pending).unwrap();
    write_new_private_file(&pending.join(PRIVATE_KEY_FILE), b"abandoned private key").unwrap();

    store.install(&credentials("runner-1", "pool-1")).unwrap();
    assert!(!pending.exists());
}

#[cfg(unix)]
#[test]
fn unsafe_stale_entry_fails_before_current_credentials_change() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("credentials");
    let store = RunnerCredentialStore::open(&root).unwrap();
    let first = store.install(&credentials("runner-1", "pool-1")).unwrap();
    let target = directory.path().join("must-not-be-traversed");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), b"present").unwrap();
    let stale = root
        .join(GENERATIONS_DIRECTORY)
        .join("generation-00000000000000000000000000000000");
    symlink(&target, &stale).unwrap();

    assert!(matches!(
        store.install(&credentials("runner-1", "pool-1")),
        Err(CredentialError::State(StateError::UnsafePath(path))) if path == stale
    ));
    assert_eq!(store.load_current().unwrap(), first);
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"present");
}

#[cfg(unix)]
#[test]
fn current_symlink_and_partial_generation_fail_closed() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("credentials");
    let store = RunnerCredentialStore::open(&root).unwrap();
    let target = directory.path().join("target");
    fs::write(&target, b"generation-00000000000000000000000000000000\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, root.join(CURRENT_FILE)).unwrap();
    assert!(matches!(
        store.install(&credentials("runner-1", "pool-1")),
        Err(CredentialError::State(StateError::UnsafePath(_)))
    ));
    fs::remove_file(root.join(CURRENT_FILE)).unwrap();
    let partial_name = "generation-00000000000000000000000000000000";
    let partial = root.join(GENERATIONS_DIRECTORY).join(partial_name);
    fs::create_dir(&partial).unwrap();
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o700)).unwrap();
    write_new_private_file(
        &root.join(CURRENT_FILE),
        format!("{partial_name}\n").as_bytes(),
    )
    .unwrap();
    assert!(reopened_error_is_partial(store.load_current().unwrap_err()));
}

fn reopened_error_is_partial(error: CredentialError) -> bool {
    matches!(error, CredentialError::State(StateError::Io { .. }))
}
