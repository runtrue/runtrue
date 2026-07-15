use super::{
    apply_authoritative_posture, load_capsule_trust_store,
    probe::isolation_backend_name,
    probe_inventory,
    storage::{run_storage_probe, storage_probe_program_is_safe},
    InventoryError,
};
use runtrue_attest::CapsuleSigningKey;
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::Isolation;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[test]
fn wasm_and_microvm_inventory_names_are_explicit() {
    assert_eq!(isolation_backend_name(Isolation::Wasm).unwrap(), "wasm");
    assert_eq!(
        isolation_backend_name(Isolation::Microvm).unwrap(),
        "microvm"
    );
}

#[test]
fn authoritative_posture_drives_profile_and_hello_capability() {
    let directory = tempfile::tempdir().unwrap();
    let mut inventory = probe_inventory("runner-1", directory.path(), None).unwrap();
    let local = inventory.profile.posture_digest.clone();
    let authoritative = ContentDigest::sha256(b"server-authoritative");
    assert_ne!(local, authoritative);
    apply_authoritative_posture(&mut inventory, &authoritative).unwrap();
    assert_eq!(inventory.profile.posture_digest, authoritative);
    let capability = inventory
        .wire
        .capabilities
        .iter()
        .find(|capability| capability.key == "runtrue.posture.digest")
        .unwrap();
    assert_eq!(
        capability.json_value,
        serde_json::to_string(authoritative.as_str()).unwrap()
    );
    assert_eq!(capability.evidence_source, "enrollment-authoritative");
}

#[test]
fn host_runner_inventory_binds_binary_as_deployment_image() {
    let directory = tempfile::tempdir().unwrap();
    let inventory = probe_inventory("runner-1", directory.path(), None).unwrap();
    assert_eq!(
        inventory.wire.runner_image_digest,
        inventory.wire.runner_binary_digest
    );
}

#[cfg(unix)]
#[test]
fn keyring_loads_multiple_private_mode_public_keys() {
    let directory = tempfile::tempdir().unwrap();
    let keyring = directory.path().join("keys");
    fs::create_dir(&keyring).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();
    for (name, seed) in [("one", 1_u8), ("two", 2_u8)] {
        let path = keyring.join(name);
        let key = CapsuleSigningKey::from_seed([seed; 32]);
        fs::write(&path, hex::encode(key.verifying_key().to_bytes())).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let loaded = load_capsule_trust_store(&keyring).unwrap();
    assert_eq!(loaded.key_ids.len(), 2);
    for key_id in loaded.key_ids {
        assert!(loaded.store.contains(&key_id));
    }
}

#[cfg(unix)]
#[test]
fn storage_probe_deadline_kills_fake_process_group() {
    let directory = tempfile::tempdir().unwrap();
    let program = directory.path().join("fake-df");
    fs::write(&program, "#!/bin/sh\nsleep 30 & wait\n").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    let started = Instant::now();
    assert!(matches!(
        run_storage_probe(&program, directory.path(), Duration::from_millis(50)),
        Err(InventoryError::StorageProbeTimedOut)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[cfg(unix)]
#[test]
fn storage_probe_rejects_symlinked_program() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let program = directory.path().join("fake-df");
    let link = directory.path().join("fake-df-link");
    fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&program, &link).unwrap();
    assert!(!storage_probe_program_is_safe(&link));
}
