use super::*;
use runtrue_attest::{ImageManifest, ImageSigningKey, SnapshotPhase};
use std::{collections::BTreeMap, fs};
use tempfile::TempDir;

fn artifact(
    directory: &TempDir,
    key: &ImageSigningKey,
    kind: ImageKind,
    name: &str,
    bytes: &[u8],
    components: BTreeMap<String, ContentDigest>,
) -> ImageArtifact {
    let path = directory.path().join(name);
    fs::write(&path, bytes).unwrap();
    let manifest = ImageManifest {
        manifest_version: 1,
        kind,
        name: name.to_owned(),
        payload_digest: ContentDigest::sha256(bytes),
        payload_size_bytes: u64::try_from(bytes.len()).unwrap(),
        payload_media_type: "application/octet-stream".to_owned(),
        operating_system: "linux".to_owned(),
        architecture: "amd64".to_owned(),
        builder_id: "test-builder".to_owned(),
        build_provenance_digest: ContentDigest::sha256(b"provenance"),
        sbom_digest: ContentDigest::sha256(b"sbom"),
        created_unix_ms: 10,
        expires_unix_ms: Some(1_000),
        snapshot_phase: (kind == ImageKind::FirecrackerSnapshot).then_some(SnapshotPhase::Sterile),
        components,
        compatibility: BTreeMap::new(),
    };
    ImageArtifact::new(key.sign_manifest(&manifest).unwrap(), path)
}

fn runtime() -> SnapshotRuntimeCompatibility {
    SnapshotRuntimeCompatibility::new(SnapshotRuntimeRequirements {
        firecracker_version: "1.12.0".to_owned(),
        firecracker_binary_digest: ContentDigest::sha256(b"firecracker-binary"),
        firecracker_binary_size_bytes: 18,
        snapshot_format_version: "1.8.0".to_owned(),
        cpu_template: "T2A".to_owned(),
        cpu_feature_digest: ContentDigest::sha256(b"cpu-features"),
        mitigation_profile_digest: ContentDigest::sha256(b"mitigations"),
        vcpu_count: 2,
        memory_bytes: 256 * 1024 * 1024,
        guest_cid: 42,
    })
    .unwrap()
}

fn snapshot_artifact(
    directory: &TempDir,
    key: &ImageSigningKey,
    role: &'static str,
    name: &str,
    bytes: &[u8],
    components: BTreeMap<String, ContentDigest>,
    runtime: &SnapshotRuntimeCompatibility,
) -> ImageArtifact {
    let mut artifact = artifact(
        directory,
        key,
        ImageKind::FirecrackerSnapshot,
        name,
        bytes,
        components,
    );
    match role {
        SNAPSHOT_STATE_ROLE => SNAPSHOT_STATE_MEDIA_TYPE,
        SNAPSHOT_MEMORY_ROLE => SNAPSHOT_MEMORY_MEDIA_TYPE,
        _ => unreachable!(),
    }
    .clone_into(&mut artifact.signed.manifest.payload_media_type);
    artifact.signed.manifest.compatibility = runtime.signed_map(role);
    artifact.signed = key.sign_manifest(&artifact.signed.manifest).unwrap();
    artifact
}

fn valid_set(directory: &TempDir, key: &ImageSigningKey) -> FirecrackerImageSet {
    let kernel = artifact(
        directory,
        key,
        ImageKind::FirecrackerKernel,
        "kernel",
        b"kernel",
        BTreeMap::new(),
    );
    let guest = artifact(
        directory,
        key,
        ImageKind::GuestAgent,
        "guest",
        b"guest",
        BTreeMap::new(),
    );
    let rootfs = artifact(
        directory,
        key,
        ImageKind::FirecrackerRootFilesystem,
        "rootfs",
        b"rootfs",
        BTreeMap::from([
            (
                "guest".to_owned(),
                guest.signed.manifest.payload_digest.clone(),
            ),
            (
                "kernel".to_owned(),
                kernel.signed.manifest.payload_digest.clone(),
            ),
        ]),
    );
    let runtime = runtime();
    let state_digest = ContentDigest::sha256(b"snapshot-state");
    let memory_digest = ContentDigest::sha256(b"snapshot-memory");
    let state = snapshot_artifact(
        directory,
        key,
        SNAPSHOT_STATE_ROLE,
        "snapshot-state",
        b"snapshot-state",
        BTreeMap::from([
            (
                "kernel".to_owned(),
                kernel.signed.manifest.payload_digest.clone(),
            ),
            (
                "rootfs".to_owned(),
                rootfs.signed.manifest.payload_digest.clone(),
            ),
            (
                "guest".to_owned(),
                guest.signed.manifest.payload_digest.clone(),
            ),
            ("snapshot-memory".to_owned(), memory_digest),
        ]),
        &runtime,
    );
    let memory = snapshot_artifact(
        directory,
        key,
        SNAPSHOT_MEMORY_ROLE,
        "snapshot-memory",
        b"snapshot-memory",
        BTreeMap::from([
            (
                "kernel".to_owned(),
                kernel.signed.manifest.payload_digest.clone(),
            ),
            (
                "rootfs".to_owned(),
                rootfs.signed.manifest.payload_digest.clone(),
            ),
            (
                "guest".to_owned(),
                guest.signed.manifest.payload_digest.clone(),
            ),
            ("snapshot-state".to_owned(), state_digest),
        ]),
        &runtime,
    );
    FirecrackerImageSet {
        kernel,
        rootfs,
        guest,
        snapshot: Some(SnapshotImageSet { state, memory }),
    }
}

fn verify(
    images: &FirecrackerImageSet,
    trust: &ImageTrustStore,
) -> Result<VerifiedImageSet, FirecrackerError> {
    images.verify(trust, Architecture::Amd64, 100, Some(&runtime()))
}

#[test]
fn verifies_exact_signed_sterile_set() {
    let directory = TempDir::new().unwrap();
    let key = ImageSigningKey::from_seed([7; 32]);
    let mut trust = ImageTrustStore::new();
    trust.insert(key.verifying_key()).unwrap();
    let verified = verify(&valid_set(&directory, &key), &trust).unwrap();
    assert!(verified.snapshot.is_some());
}

#[test]
fn rejects_payload_changed_after_signing() {
    let directory = TempDir::new().unwrap();
    let key = ImageSigningKey::from_seed([8; 32]);
    let mut trust = ImageTrustStore::new();
    trust.insert(key.verifying_key()).unwrap();
    let images = valid_set(&directory, &key);
    fs::write(&images.guest.payload_path, b"other").unwrap();
    assert!(matches!(
        verify(&images, &trust),
        Err(FirecrackerError::ArtifactDigestMismatch { .. })
    ));
}

#[test]
fn rejects_each_nonsterile_snapshot_phase_even_when_signed() {
    let directory = TempDir::new().unwrap();
    let key = ImageSigningKey::from_seed([9; 32]);
    let mut trust = ImageTrustStore::new();
    trust.insert(key.verifying_key()).unwrap();
    for phase in [
        SnapshotPhase::JobIdentityInjected,
        SnapshotPhase::SourceMounted,
        SnapshotPhase::SecretReleased,
    ] {
        for role in [SNAPSHOT_STATE_ROLE, SNAPSHOT_MEMORY_ROLE] {
            let mut images = valid_set(&directory, &key);
            let snapshot = images.snapshot.as_mut().unwrap();
            let artifact = if role == SNAPSHOT_STATE_ROLE {
                &mut snapshot.state
            } else {
                &mut snapshot.memory
            };
            artifact.signed.manifest.snapshot_phase = Some(phase);
            artifact.signed = key.sign_manifest(&artifact.signed.manifest).unwrap();
            assert!(matches!(
                verify(&images, &trust),
                Err(FirecrackerError::ImageAttestation(
                    runtrue_attest::ImageAttestError::SnapshotNotSterile
                ))
            ));
        }
    }
}

#[test]
fn rejects_state_memory_and_image_substitution() {
    let directory = TempDir::new().unwrap();
    let key = ImageSigningKey::from_seed([10; 32]);
    let mut trust = ImageTrustStore::new();
    trust.insert(key.verifying_key()).unwrap();

    for (role, component) in [
        (SNAPSHOT_STATE_ROLE, "kernel"),
        (SNAPSHOT_STATE_ROLE, "rootfs"),
        (SNAPSHOT_STATE_ROLE, "guest"),
        (SNAPSHOT_STATE_ROLE, "snapshot-memory"),
        (SNAPSHOT_MEMORY_ROLE, "kernel"),
        (SNAPSHOT_MEMORY_ROLE, "rootfs"),
        (SNAPSHOT_MEMORY_ROLE, "guest"),
        (SNAPSHOT_MEMORY_ROLE, "snapshot-state"),
    ] {
        let mut images = valid_set(&directory, &key);
        let snapshot = images.snapshot.as_mut().unwrap();
        let artifact = if role == SNAPSHOT_STATE_ROLE {
            &mut snapshot.state
        } else {
            &mut snapshot.memory
        };
        artifact
            .signed
            .manifest
            .components
            .insert(component.to_owned(), ContentDigest::sha256(b"substitute"));
        artifact.signed = key.sign_manifest(&artifact.signed.manifest).unwrap();
        assert!(
            verify(&images, &trust).is_err(),
            "accepted {role}/{component}"
        );
    }

    let mut swapped = valid_set(&directory, &key);
    let snapshot = swapped.snapshot.as_mut().unwrap();
    std::mem::swap(&mut snapshot.state, &mut snapshot.memory);
    assert!(verify(&swapped, &trust).is_err());

    for role in [SNAPSHOT_STATE_ROLE, SNAPSHOT_MEMORY_ROLE] {
        let mut images = valid_set(&directory, &key);
        let snapshot = images.snapshot.as_mut().unwrap();
        let artifact = if role == SNAPSHOT_STATE_ROLE {
            &mut snapshot.state
        } else {
            &mut snapshot.memory
        };
        "application/octet-stream".clone_into(&mut artifact.signed.manifest.payload_media_type);
        artifact.signed = key.sign_manifest(&artifact.signed.manifest).unwrap();
        assert!(verify(&images, &trust).is_err());
    }
}

#[test]
fn rejects_whole_artifact_substitution_between_valid_pairs() {
    let first_directory = TempDir::new().unwrap();
    let second_directory = TempDir::new().unwrap();
    let key = ImageSigningKey::from_seed([13; 32]);
    let mut trust = ImageTrustStore::new();
    trust.insert(key.verifying_key()).unwrap();
    let first = valid_set(&first_directory, &key);
    let mut second = valid_set(&second_directory, &key);
    let second_snapshot = second.snapshot.as_mut().unwrap();
    fs::write(&second_snapshot.memory.payload_path, b"different-memory").unwrap();
    second_snapshot.memory.signed.manifest.payload_digest =
        ContentDigest::sha256(b"different-memory");
    second_snapshot.memory.signed.manifest.payload_size_bytes = 16;
    second_snapshot.memory.signed = key
        .sign_manifest(&second_snapshot.memory.signed.manifest)
        .unwrap();
    second_snapshot.state.signed.manifest.components.insert(
        "snapshot-memory".to_owned(),
        second_snapshot
            .memory
            .signed
            .manifest
            .payload_digest
            .clone(),
    );
    second_snapshot.state.signed = key
        .sign_manifest(&second_snapshot.state.signed.manifest)
        .unwrap();
    assert!(verify(&second, &trust).is_ok());

    let mut mixed_memory = first.clone();
    mixed_memory.snapshot.as_mut().unwrap().memory =
        second.snapshot.as_ref().unwrap().memory.clone();
    assert!(verify(&mixed_memory, &trust).is_err());

    let second_snapshot = second.snapshot.as_mut().unwrap();
    fs::write(&second_snapshot.state.payload_path, b"different-state").unwrap();
    second_snapshot.state.signed.manifest.payload_digest =
        ContentDigest::sha256(b"different-state");
    second_snapshot.state.signed.manifest.payload_size_bytes = 15;
    second_snapshot.state.signed = key
        .sign_manifest(&second_snapshot.state.signed.manifest)
        .unwrap();
    second_snapshot.memory.signed.manifest.components.insert(
        "snapshot-state".to_owned(),
        second_snapshot.state.signed.manifest.payload_digest.clone(),
    );
    second_snapshot.memory.signed = key
        .sign_manifest(&second_snapshot.memory.signed.manifest)
        .unwrap();
    assert!(verify(&second, &trust).is_ok());

    let mut mixed_state = first;
    mixed_state.snapshot.as_mut().unwrap().state = second.snapshot.as_ref().unwrap().state.clone();
    assert!(verify(&mixed_state, &trust).is_err());
}

#[test]
fn rejects_every_runtime_tuple_substitution() {
    let directory = TempDir::new().unwrap();
    let key = ImageSigningKey::from_seed([11; 32]);
    let mut trust = ImageTrustStore::new();
    trust.insert(key.verifying_key()).unwrap();
    for compatibility_key in [
        COMPAT_FIRECRACKER_VERSION,
        COMPAT_FIRECRACKER_BINARY,
        COMPAT_FIRECRACKER_BINARY_SIZE,
        COMPAT_SNAPSHOT_FORMAT,
        COMPAT_CPU_TEMPLATE,
        COMPAT_CPU_FEATURES,
        COMPAT_MITIGATIONS,
        COMPAT_VCPU_COUNT,
        COMPAT_MEMORY_BYTES,
        COMPAT_GUEST_CID,
        COMPAT_NETWORK_PROFILE,
        COMPAT_ROOTFS_PATH,
        COMPAT_BOOT_CONFIG_PATH,
        COMPAT_VSOCK_PATH,
        COMPAT_SNAPSHOT_ROLE,
    ] {
        let mut images = valid_set(&directory, &key);
        let snapshot = images.snapshot.as_mut().unwrap();
        for artifact in [&mut snapshot.state, &mut snapshot.memory] {
            artifact
                .signed
                .manifest
                .compatibility
                .insert(compatibility_key.to_owned(), "substitute".to_owned());
            artifact.signed = key.sign_manifest(&artifact.signed.manifest).unwrap();
        }
        assert!(
            verify(&images, &trust).is_err(),
            "accepted compatibility substitution {compatibility_key}"
        );
    }
}

#[test]
fn snapshot_requires_host_runtime_evidence() {
    let directory = TempDir::new().unwrap();
    let key = ImageSigningKey::from_seed([12; 32]);
    let mut trust = ImageTrustStore::new();
    trust.insert(key.verifying_key()).unwrap();
    assert!(valid_set(&directory, &key)
        .verify(&trust, Architecture::Amd64, 100, None)
        .is_err());
}

#[cfg(unix)]
#[test]
fn rejects_symlink_artifact() {
    use std::os::unix::fs::symlink;
    let directory = TempDir::new().unwrap();
    let target = directory.path().join("target");
    let link = directory.path().join("link");
    fs::write(&target, b"bytes").unwrap();
    symlink(&target, &link).unwrap();
    assert!(verify_payload(&link, 5, &ContentDigest::sha256(b"bytes")).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_symlink_ancestor() {
    use std::os::unix::fs::symlink;
    let directory = TempDir::new().unwrap();
    let target = directory.path().join("real");
    let link = directory.path().join("linked-directory");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("artifact"), b"bytes").unwrap();
    symlink(&target, &link).unwrap();
    assert!(verify_payload(&link.join("artifact"), 5, &ContentDigest::sha256(b"bytes")).is_err());
}
