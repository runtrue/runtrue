use super::*;
use runtrue_model::ContentDigest;
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::{Arc, Barrier},
    thread,
};
use tempfile::tempdir;

const NOW: u64 = 1_000;
const ROOT_EXPIRY: u64 = 50_000;
const TARGET_PATH: &str = "runtrue/linux/amd64/runtrue-update";

struct RoleKeys {
    root: UpdateSigningKey,
    targets: UpdateSigningKey,
    snapshot: UpdateSigningKey,
    timestamp: UpdateSigningKey,
}

impl RoleKeys {
    fn from_base(base: u8) -> Self {
        Self {
            root: UpdateSigningKey::from_seed([base; 32]),
            targets: UpdateSigningKey::from_seed([base + 1; 32]),
            snapshot: UpdateSigningKey::from_seed([base + 2; 32]),
            timestamp: UpdateSigningKey::from_seed([base + 3; 32]),
        }
    }
}

fn root_metadata(version: u64, keys: &RoleKeys) -> RootMetadata {
    let assignments = [
        (RoleType::Root, &keys.root),
        (RoleType::Targets, &keys.targets),
        (RoleType::Snapshot, &keys.snapshot),
        (RoleType::Timestamp, &keys.timestamp),
    ];
    let key_map = assignments
        .iter()
        .map(|(_, key)| (key.key_id(), key.public_key()))
        .collect();
    let roles = assignments
        .into_iter()
        .map(|(role, key)| {
            (
                role,
                RoleAssignment {
                    key_ids: BTreeSet::from([key.key_id()]),
                    threshold: 1,
                },
            )
        })
        .collect();
    RootMetadata {
        header: MetadataHeader::new(RoleType::Root, version, 100, ROOT_EXPIRY),
        keys: key_map,
        roles,
    }
}

fn signed_root(version: u64, keys: &RoleKeys) -> SignedEnvelope<RootMetadata> {
    SignedEnvelope::unsigned(root_metadata(version, keys))
        .unwrap()
        .sign(&keys.root)
        .unwrap()
}

fn pinned_bootstrap(
    root: SignedEnvelope<RootMetadata>,
    now_unix_seconds: u64,
) -> Result<TrustedState, UpdateError> {
    let expected = root_envelope_digest(&root)?;
    TrustedState::bootstrap(root, &expected, now_unix_seconds)
}

fn release_bundle(
    keys: &RoleKeys,
    target_bytes: &[u8],
    targets_version: u64,
    snapshot_version: u64,
    timestamp_version: u64,
) -> ReleaseBundle {
    let target = TargetDescription::from_bytes(
        target_bytes,
        "application/octet-stream",
        "linux",
        "amd64",
        "0.1.0",
        BTreeMap::from([("channel".to_owned(), "stable".to_owned())]),
    )
    .unwrap();
    let targets = SignedEnvelope::unsigned(TargetsMetadata {
        header: MetadataHeader::new(RoleType::Targets, targets_version, 200, 40_000),
        targets: BTreeMap::from([(TARGET_PATH.to_owned(), target)]),
    })
    .unwrap()
    .sign(&keys.targets)
    .unwrap();
    let snapshot = SignedEnvelope::unsigned(SnapshotMetadata {
        header: MetadataHeader::new(RoleType::Snapshot, snapshot_version, 300, 30_000),
        targets: MetadataReference::for_envelope(targets_version, &targets).unwrap(),
    })
    .unwrap()
    .sign(&keys.snapshot)
    .unwrap();
    let timestamp = SignedEnvelope::unsigned(TimestampMetadata {
        header: MetadataHeader::new(RoleType::Timestamp, timestamp_version, 400, 20_000),
        snapshot: MetadataReference::for_envelope(snapshot_version, &snapshot).unwrap(),
    })
    .unwrap()
    .sign(&keys.timestamp)
    .unwrap();
    ReleaseBundle {
        root_rotations: Vec::new(),
        targets,
        snapshot,
        timestamp,
    }
}

fn state_and_bundle() -> (TrustedState, RoleKeys, ReleaseBundle, Vec<u8>) {
    let keys = RoleKeys::from_base(1);
    let state = pinned_bootstrap(signed_root(1, &keys), NOW).unwrap();
    let target = b"runtrue-update-binary".to_vec();
    let bundle = release_bundle(&keys, &target, 1, 1, 1);
    (state, keys, bundle, target)
}

#[test]
fn full_chain_verifies_exact_target_and_advances_monotonic_state() {
    let (state, _keys, bundle, target) = state_and_bundle();
    let verified = state
        .verify_release(&bundle, TARGET_PATH, &target, NOW)
        .unwrap();
    assert_eq!(verified.target.sha256, ContentDigest::sha256(&target));
    assert_eq!(verified.next_state.targets.as_ref().unwrap().version, 1);
    assert_eq!(verified.next_state.snapshot.as_ref().unwrap().version, 1);
    assert_eq!(verified.next_state.timestamp.as_ref().unwrap().version, 1);
    assert!(verified
        .next_state
        .verify_release(&bundle, TARGET_PATH, &target, NOW + 1)
        .is_ok());
}

#[test]
fn digest_length_path_and_mix_and_match_substitution_fail_closed() {
    let (state, _keys, bundle, target) = state_and_bundle();
    assert!(matches!(
        state.verify_release(&bundle, TARGET_PATH, b"wrong", NOW),
        Err(UpdateError::TargetLengthMismatch | UpdateError::TargetDigestMismatch)
    ));
    assert!(matches!(
        state.verify_release(&bundle, "../escape", &target, NOW),
        Err(UpdateError::UnsafeTargetPath(_))
    ));

    let mut mixed = bundle.clone();
    mixed.snapshot.signed.targets.sha256 = ContentDigest::sha256(b"other-targets");
    assert!(matches!(
        state.verify_release(&mixed, TARGET_PATH, &target, NOW),
        Err(UpdateError::InvalidSignature | UpdateError::MetadataReferenceMismatch)
    ));
}

#[test]
fn rollback_same_version_change_and_freeze_are_rejected() {
    let (state, keys, first, target) = state_and_bundle();
    let second = release_bundle(&keys, &target, 2, 2, 2);
    let advanced = state
        .verify_release(&second, TARGET_PATH, &target, NOW)
        .unwrap()
        .next_state;
    assert!(matches!(
        advanced.verify_release(&first, TARGET_PATH, &target, NOW),
        Err(UpdateError::MetadataRollback(RoleType::Timestamp))
    ));

    let changed = release_bundle(&keys, b"changed", 2, 2, 2);
    assert!(matches!(
        advanced.verify_release(&changed, TARGET_PATH, b"changed", NOW),
        Err(UpdateError::SameVersionMetadataChanged(RoleType::Timestamp))
    ));
    assert!(matches!(
        state.verify_release(&first, TARGET_PATH, &target, 20_000),
        Err(UpdateError::MetadataExpired(RoleType::Timestamp))
    ));
}

#[test]
fn root_rotation_requires_old_and_new_thresholds_and_exact_increment() {
    let old = RoleKeys::from_base(10);
    let new = RoleKeys::from_base(20);
    let state = pinned_bootstrap(signed_root(1, &old), NOW).unwrap();
    let new_root = root_metadata(2, &new);
    let dual = SignedEnvelope::unsigned(new_root.clone())
        .unwrap()
        .sign(&old.root)
        .unwrap()
        .sign(&new.root)
        .unwrap();
    let target = b"rotated-release".to_vec();
    let mut bundle = release_bundle(&new, &target, 1, 1, 1);
    bundle.root_rotations.push(dual);
    let rotated = state
        .verify_release(&bundle, TARGET_PATH, &target, NOW)
        .unwrap();
    assert_eq!(rotated.next_state.trusted_root.signed.header.version, 2);
    assert!(rotated.next_state.canonical_bytes().is_ok());

    let mut only_new = release_bundle(&new, &target, 1, 1, 1);
    only_new.root_rotations.push(
        SignedEnvelope::unsigned(new_root.clone())
            .unwrap()
            .sign(&new.root)
            .unwrap(),
    );
    assert!(matches!(
        state.verify_release(&only_new, TARGET_PATH, &target, NOW),
        Err(UpdateError::SignatureThresholdNotMet {
            role: RoleType::Root,
            ..
        })
    ));

    let mut only_old = release_bundle(&new, &target, 1, 1, 1);
    only_old.root_rotations.push(
        SignedEnvelope::unsigned(new_root)
            .unwrap()
            .sign(&old.root)
            .unwrap(),
    );
    assert!(matches!(
        state.verify_release(&only_old, TARGET_PATH, &target, NOW),
        Err(UpdateError::SignatureThresholdNotMet {
            role: RoleType::Root,
            ..
        })
    ));

    let skipped = SignedEnvelope::unsigned(root_metadata(3, &new))
        .unwrap()
        .sign(&old.root)
        .unwrap()
        .sign(&new.root)
        .unwrap();
    let mut skipped_bundle = release_bundle(&new, &target, 1, 1, 1);
    skipped_bundle.root_rotations.push(skipped);
    assert!(matches!(
        state.verify_release(&skipped_bundle, TARGET_PATH, &target, NOW),
        Err(UpdateError::NonSequentialRootRotation {
            expected: 2,
            actual: 3
        })
    ));
}

#[test]
fn duplicate_signatures_never_count_toward_threshold() {
    let keys = RoleKeys::from_base(30);
    let extra = UpdateSigningKey::from_seed([39; 32]);
    let mut root = root_metadata(1, &keys);
    root.keys.insert(extra.key_id(), extra.public_key());
    root.roles
        .get_mut(&RoleType::Root)
        .unwrap()
        .key_ids
        .insert(extra.key_id());
    root.roles.get_mut(&RoleType::Root).unwrap().threshold = 2;
    let once = SignedEnvelope::unsigned(root.clone())
        .unwrap()
        .sign(&keys.root)
        .unwrap();
    let mut duplicated = once.clone();
    duplicated.signatures.push(once.signatures[0].clone());
    assert!(matches!(
        pinned_bootstrap(duplicated, NOW),
        Err(UpdateError::InvalidSignatureSet)
    ));
    assert!(matches!(
        pinned_bootstrap(once, NOW),
        Err(UpdateError::SignatureThresholdNotMet { required: 2, .. })
    ));
    assert!(pinned_bootstrap(
        SignedEnvelope::unsigned(root)
            .unwrap()
            .sign(&keys.root)
            .unwrap()
            .sign(&extra)
            .unwrap(),
        NOW
    )
    .is_ok());
}

#[test]
fn role_separation_key_ids_and_algorithms_are_strict() {
    let keys = RoleKeys::from_base(40);
    let mut root = root_metadata(1, &keys);
    root.roles.get_mut(&RoleType::Targets).unwrap().key_ids = BTreeSet::from([keys.root.key_id()]);
    assert!(matches!(
        root.validate_structure(),
        Err(UpdateError::RoleKeyReuse)
    ));

    let mut wrong_key_id = root_metadata(1, &keys);
    let key = wrong_key_id.keys.remove(&keys.root.key_id()).unwrap();
    wrong_key_id
        .keys
        .insert(ContentDigest::sha256(b"wrong"), key);
    assert!(matches!(
        wrong_key_id.validate_structure(),
        Err(UpdateError::KeyIdMismatch)
    ));

    let mut wrong_algorithm = root_metadata(1, &keys);
    wrong_algorithm
        .keys
        .get_mut(&keys.root.key_id())
        .unwrap()
        .algorithm = "rsa".to_owned();
    assert!(matches!(
        wrong_algorithm.validate_structure(),
        Err(UpdateError::InvalidPublicKey)
    ));
}

#[test]
fn strict_decoder_rejects_duplicates_unknown_fields_and_noncanonical_json() {
    let keys = RoleKeys::from_base(50);
    let root = signed_root(1, &keys);
    let bytes = root.canonical_bytes().unwrap();
    assert_eq!(decode_root(&bytes).unwrap(), root);

    let duplicate = format!(
        "{{\"signed\":{},\"signed\":{},\"signatures\":[]}}",
        serde_json::to_string(&root.signed).unwrap(),
        serde_json::to_string(&root.signed).unwrap()
    );
    assert!(matches!(
        decode_root(duplicate.as_bytes()),
        Err(UpdateError::DuplicateJsonKey)
    ));

    let mut unknown: Value = serde_json::from_slice(&bytes).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), Value::Bool(true));
    let unknown = canonical_bytes(&unknown).unwrap();
    assert!(matches!(
        decode_root(&unknown),
        Err(UpdateError::Deserialize(_))
    ));

    let mut whitespace = bytes;
    whitespace.push(b'\n');
    assert!(matches!(
        decode_root(&whitespace),
        Err(UpdateError::NonCanonicalMetadata)
    ));
}

#[test]
fn every_signature_nibble_and_target_byte_flip_is_rejected() {
    let (state, _keys, bundle, target) = state_and_bundle();
    let signature = &bundle.timestamp.signatures[0].signature_hex;
    for index in 0..signature.len() {
        let mut corrupted = bundle.clone();
        let mut bytes = corrupted.timestamp.signatures[0]
            .signature_hex
            .as_bytes()
            .to_vec();
        bytes[index] = if bytes[index] == b'a' { b'b' } else { b'a' };
        corrupted.timestamp.signatures[0].signature_hex = String::from_utf8(bytes).unwrap();
        assert!(matches!(
            state.verify_release(&corrupted, TARGET_PATH, &target, NOW),
            Err(UpdateError::InvalidSignature)
        ));
    }

    for index in 0..target.len() {
        let mut corrupted = target.clone();
        corrupted[index] ^= 1;
        assert!(matches!(
            state.verify_release(&bundle, TARGET_PATH, &corrupted, NOW),
            Err(UpdateError::TargetDigestMismatch)
        ));
    }
}

#[test]
fn future_metadata_and_inner_role_rollbacks_are_rejected() {
    let (state, keys, first, target) = state_and_bundle();
    let mut future = first.clone();
    future.timestamp.signed.header.issued_unix_seconds = NOW + 1;
    future.timestamp.signatures.clear();
    future = ReleaseBundle {
        timestamp: future.timestamp.sign(&keys.timestamp).unwrap(),
        ..future
    };
    assert!(matches!(
        state.verify_release(&future, TARGET_PATH, &target, NOW),
        Err(UpdateError::MetadataFromFuture(RoleType::Timestamp))
    ));

    let advanced = state
        .verify_release(
            &release_bundle(&keys, &target, 2, 2, 2),
            TARGET_PATH,
            &target,
            NOW,
        )
        .unwrap()
        .next_state;
    let snapshot_rollback = release_bundle(&keys, &target, 2, 1, 3);
    assert!(matches!(
        advanced.verify_release(&snapshot_rollback, TARGET_PATH, &target, NOW),
        Err(UpdateError::MetadataRollback(RoleType::Snapshot))
    ));
    let targets_rollback = release_bundle(&keys, &target, 1, 3, 3);
    assert!(matches!(
        advanced.verify_release(&targets_rollback, TARGET_PATH, &target, NOW),
        Err(UpdateError::MetadataRollback(RoleType::Targets))
    ));
}

#[test]
fn oversized_declared_targets_fail_before_signature_or_content_acceptance() {
    let (state, _keys, mut bundle, target) = state_and_bundle();
    bundle
        .targets
        .signed
        .targets
        .get_mut(TARGET_PATH)
        .unwrap()
        .length = MAX_TARGET_BYTES + 1;
    assert!(matches!(
        state.verify_release(&bundle, TARGET_PATH, &target, NOW),
        Err(UpdateError::InvalidTargetDescription)
    ));
}

#[test]
fn provenance_and_cyclonedx_outputs_are_canonical_and_digest_exact() {
    let first = ReleaseSubject::from_bytes("bin/runtrue", b"first").unwrap();
    let second = ReleaseSubject::from_bytes("bin/runtrue-update", b"second").unwrap();
    let provenance = ReleaseProvenance::new(
        vec![second.clone(), first.clone()],
        "https://example.invalid/runtrue",
        "0123456789abcdef",
        "refs/tags/v0.1.0",
        "https://github.com/example/runtrue/actions/runs/1",
        NOW,
    )
    .unwrap();
    let bytes = provenance.canonical_bytes().unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["subject"][0]["digest"]["sha256"],
        digest_hex(&ContentDigest::sha256(b"first"))
    );
    assert_eq!(canonical_bytes(&value).unwrap(), bytes);

    let root_id = "path+file:///src#runtrue-cli@0.1.0";
    let dependency_id = "registry+https://example.invalid#index@1.2.3";
    let bom = CycloneDxBom::from_cargo_graph(
        "runtrue-cli",
        "v0.1.0",
        vec![second, first],
        root_id,
        vec![
            CargoPackageNode {
                package_id: root_id.to_owned(),
                name: "runtrue-cli".to_owned(),
                version: "0.1.0".to_owned(),
                source: None,
                checksum_sha256: None,
                dependencies: vec![dependency_id.to_owned()],
            },
            CargoPackageNode {
                package_id: dependency_id.to_owned(),
                name: "locked-dependency".to_owned(),
                version: "1.2.3".to_owned(),
                source: Some("registry+https://example.invalid".to_owned()),
                checksum_sha256: Some("ab".repeat(32)),
                dependencies: Vec::new(),
            },
        ],
    )
    .unwrap();
    let bytes = bom.canonical_bytes().unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["bomFormat"], "CycloneDX");
    let components = value["components"].as_array().unwrap();
    let file = components
        .iter()
        .find(|component| component["name"] == "bin/runtrue")
        .unwrap();
    assert_eq!(file["hashes"][0]["alg"], "SHA-256");
    assert_eq!(
        file["hashes"][0]["content"],
        digest_hex(&ContentDigest::sha256(b"first"))
    );
    assert!(components.iter().any(|component| {
        component["type"] == "library"
            && component["name"] == "locked-dependency"
            && component["version"] == "1.2.3"
    }));
    assert_eq!(canonical_bytes(&value).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn trust_store_is_atomic_private_restart_safe_and_ignores_lost_temporaries() {
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("trusted-state.json");
    let store = TrustStore::open(&path).unwrap();
    let keys = RoleKeys::from_base(60);
    let state = pinned_bootstrap(signed_root(1, &keys), NOW).unwrap();
    store.transaction().unwrap().initialize(&state).unwrap();
    assert_eq!(store.load().unwrap(), Some(state.clone()));
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);

    fs::write(
        directory.path().join(".runtrue-update-lost.tmp"),
        b"partial",
    )
    .unwrap();
    let reopened = TrustStore::open(&path).unwrap();
    assert_eq!(reopened.load().unwrap(), Some(state.clone()));

    let newer = pinned_bootstrap(signed_root(2, &keys), NOW).unwrap();
    reopened
        .transaction()
        .unwrap()
        .replace(&state, &newer)
        .unwrap();
    assert_eq!(
        TrustStore::open(&path).unwrap().load().unwrap(),
        Some(newer)
    );
}

#[cfg(unix)]
#[test]
fn trust_store_serializes_bootstrap_and_rejects_stale_compare_and_swap() {
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = Arc::new(TrustStore::open(directory.path().join("state.json")).unwrap());
    let initial =
        Arc::new(pinned_bootstrap(signed_root(1, &RoleKeys::from_base(80)), NOW).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let threads = (0..2)
        .map(|_| {
            let store = Arc::clone(&store);
            let state = Arc::clone(&initial);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store.transaction().unwrap().initialize(&state)
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(UpdateError::TrustStateAlreadyInitialized)))
            .count(),
        1
    );

    let next_two =
        Arc::new(pinned_bootstrap(signed_root(2, &RoleKeys::from_base(90)), NOW).unwrap());
    let next_three =
        Arc::new(pinned_bootstrap(signed_root(3, &RoleKeys::from_base(100)), NOW).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let threads = [next_two, next_three]
        .into_iter()
        .map(|next| {
            let store = Arc::clone(&store);
            let expected = Arc::clone(&initial);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store.transaction().unwrap().replace(&expected, &next)
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(UpdateError::ConcurrentTrustStateChange)))
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn trust_store_rejects_symlinks_hardlinks_and_permissive_files() {
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("trusted-state.json");
    let keys = RoleKeys::from_base(70);
    let state = pinned_bootstrap(signed_root(1, &keys), NOW).unwrap();
    let store = TrustStore::open(&path).unwrap();
    store.transaction().unwrap().initialize(&state).unwrap();

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        store.load(),
        Err(UpdateError::UnsafeTrustStore(_))
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, directory.path().join("extra-link")).unwrap();
    assert!(matches!(
        store.load(),
        Err(UpdateError::UnsafeTrustStore(_))
    ));
    fs::remove_file(directory.path().join("extra-link")).unwrap();
    fs::remove_file(&path).unwrap();
    let outside = directory.path().join("outside");
    fs::write(&outside, b"outside").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(store.load().is_err());
    assert!(store.transaction().unwrap().initialize(&state).is_err());
    assert_eq!(fs::read(outside).unwrap(), b"outside");
}

#[cfg(unix)]
#[test]
fn generated_private_keys_are_mode_0600_and_debug_redacted() {
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("targets.key");
    let key = UpdateSigningKey::generate().unwrap();
    TrustStore::write_new_signing_key(&path, &key).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(format!("{key:?}"), "UpdateSigningKey(<redacted>)");
    assert_eq!(fs::read_to_string(path).unwrap().trim().len(), 64);
}

#[cfg(unix)]
#[test]
fn release_file_io_rejects_ancestor_symlinks_hardlinks_and_overwrites() {
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let real = directory.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let input = real.join("input");
    fs::write(&input, b"immutable-input").unwrap();
    assert_eq!(
        read_verified_file(&input, 1024).unwrap(),
        b"immutable-input"
    );

    let hardlink = real.join("hardlink");
    fs::hard_link(&input, &hardlink).unwrap();
    assert!(matches!(
        read_verified_file(&input, 1024),
        Err(UpdateError::UnsafeFilePath(_))
    ));
    fs::remove_file(hardlink).unwrap();

    let alias = directory.path().join("alias");
    symlink(&real, &alias).unwrap();
    assert!(read_verified_file(alias.join("input"), 1024).is_err());

    let output = real.join("output");
    write_new_public_file(&output, b"release-evidence").unwrap();
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert!(write_new_public_file(&output, b"overwrite").is_err());
    assert_eq!(fs::read(&output).unwrap(), b"release-evidence");
    assert!(write_new_public_file(alias.join("escaped"), b"no").is_err());
    assert!(!real.join("escaped").exists());
}
