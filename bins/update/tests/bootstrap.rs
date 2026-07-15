use runtrue_update::{
    root_envelope_digest, MetadataHeader, RoleAssignment, RoleType, RootMetadata, SignedEnvelope,
    UpdateSigningKey,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    process::Command,
};
use tempfile::tempdir;

fn signed_root() -> SignedEnvelope<RootMetadata> {
    let keys = [
        (RoleType::Root, UpdateSigningKey::from_seed([1; 32])),
        (RoleType::Targets, UpdateSigningKey::from_seed([2; 32])),
        (RoleType::Snapshot, UpdateSigningKey::from_seed([3; 32])),
        (RoleType::Timestamp, UpdateSigningKey::from_seed([4; 32])),
    ];
    let root = RootMetadata {
        header: MetadataHeader::new(RoleType::Root, 1, 100, 50_000),
        keys: keys
            .iter()
            .map(|(_, key)| (key.key_id(), key.public_key()))
            .collect::<BTreeMap<_, _>>(),
        roles: keys
            .iter()
            .map(|(role, key)| {
                (
                    *role,
                    RoleAssignment {
                        key_ids: BTreeSet::from([key.key_id()]),
                        threshold: 1,
                    },
                )
            })
            .collect(),
    };
    SignedEnvelope::unsigned(root)
        .unwrap()
        .sign(&keys[0].1)
        .unwrap()
}

#[test]
fn bootstrap_requires_exact_out_of_band_digest_and_never_resets_state() {
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = signed_root();
    let root_path = directory.path().join("root.json");
    let state_path = directory.path().join("state.json");
    fs::write(&root_path, root.canonical_bytes().unwrap()).unwrap();
    let binary = env!("CARGO_BIN_EXE_runtrue-update");

    let wrong = Command::new(binary)
        .args([
            "bootstrap",
            "--root",
            root_path.to_str().unwrap(),
            "--expected-root-digest",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--state",
            state_path.to_str().unwrap(),
            "--now-unix-seconds",
            "1000",
        ])
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(!state_path.exists());

    let expected = root_envelope_digest(&root).unwrap().to_string();
    let valid = Command::new(binary)
        .args([
            "bootstrap",
            "--root",
            root_path.to_str().unwrap(),
            "--expected-root-digest",
            &expected,
            "--state",
            state_path.to_str().unwrap(),
            "--now-unix-seconds",
            "1000",
        ])
        .output()
        .unwrap();
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let reset = Command::new(binary)
        .args([
            "bootstrap",
            "--root",
            root_path.to_str().unwrap(),
            "--expected-root-digest",
            &expected,
            "--state",
            state_path.to_str().unwrap(),
            "--now-unix-seconds",
            "1000",
        ])
        .output()
        .unwrap();
    assert!(!reset.status.success());
}
