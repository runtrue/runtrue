#![cfg(unix)]

use runtrue_attest::CapsuleSigningKey;
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    process::{Command, Output},
};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_runtrue-runner"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn doctor_validates_local_runner_without_connecting_or_claiming_enrollment() {
    let directory = tempfile::tempdir().unwrap();
    let keyring = directory.path().join("keys");
    fs::create_dir(&keyring).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();
    let key = CapsuleSigningKey::from_seed([11; 32]);
    let key_file = keyring.join("control-plane.hex");
    fs::write(&key_file, hex::encode(key.verifying_key().to_bytes())).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();

    let state = directory.path().join("state");
    let workspaces = directory.path().join("workspaces");
    let output = run(&[
        "--endpoint",
        "http://127.0.0.1:9",
        "--runner-id",
        "runner-doctor",
        "--state-directory",
        state.to_str().unwrap(),
        "--workspace-directory",
        workspaces.to_str().unwrap(),
        "--capsule-keyring",
        keyring.to_str().unwrap(),
        "--insecure-loopback",
        "--protocol-version",
        "1",
        "--trusted-native",
        "doctor",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["runner_id"], "runner-doctor");
    assert_eq!(report["protocol_version"], 1);
    assert_eq!(report["trusted_native_enabled"], true);
    assert_eq!(report["oci_enabled"], false);
    assert_eq!(report["wasm_enabled"], false);
    assert_eq!(report["firecracker_enabled"], false);
    assert_eq!(report["firecracker_snapshot_enabled"], false);
    assert_eq!(report["verified_wasm_components"], 0);
    assert_eq!(
        report["trusted_capsule_key_ids"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn doctor_rejects_direct_credentials_without_an_explicit_protocol_version() {
    let directory = tempfile::tempdir().unwrap();
    let keyring = directory.path().join("keys");
    fs::create_dir(&keyring).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();
    let key = CapsuleSigningKey::from_seed([12; 32]);
    let key_file = keyring.join("control-plane.hex");
    fs::write(&key_file, hex::encode(key.verifying_key().to_bytes())).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    let output = run(&[
        "--endpoint",
        "http://127.0.0.1:9",
        "--runner-id",
        "runner-doctor",
        "--workspace-directory",
        directory.path().join("workspaces").to_str().unwrap(),
        "--capsule-keyring",
        keyring.to_str().unwrap(),
        "--insecure-loopback",
        "--trusted-native",
        "doctor",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("require --protocol-version"));
}

#[test]
fn partial_wasm_configuration_is_rejected_before_backend_advertisement() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(&[
        "--trusted-native",
        "--wasm-component-directory",
        directory.path().to_str().unwrap(),
        "doctor",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Wasm execution requires all five --wasm-* paths"));
}

#[test]
fn partial_firecracker_configuration_is_rejected_before_backend_advertisement() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(&[
        "--trusted-native",
        "--firecracker-state-directory",
        directory.path().to_str().unwrap(),
        "doctor",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Firecracker execution requires all eleven --firecracker-* paths"));
}
