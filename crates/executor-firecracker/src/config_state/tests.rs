use super::*;
use crate::{state_io, VerifiedImageSet};
use runtrue_attest::{ImageKind, ImageManifest, ImageSigningKey, SnapshotPhase};
use runtrue_guest_core::{GuestBootstrap, GUEST_PROTOCOL_VERSION};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::Architecture;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{collections::BTreeMap, fs};
use tempfile::TempDir;

struct FakeReflink;

impl ReflinkProvisioner for FakeReflink {
    fn reflink(&self, source: &Path, destination: &Path) -> Result<(), FirecrackerError> {
        fs::copy(source, destination).map_err(|error| state_io(destination, error))?;
        Ok(())
    }
}

fn artifact(
    directory: &TempDir,
    key: &ImageSigningKey,
    kind: ImageKind,
    name: &str,
    bytes: &[u8],
) -> crate::VerifiedArtifact {
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
        builder_id: "test".to_owned(),
        build_provenance_digest: ContentDigest::sha256(b"p"),
        sbom_digest: ContentDigest::sha256(b"s"),
        created_unix_ms: 1,
        expires_unix_ms: None,
        snapshot_phase: (kind == ImageKind::FirecrackerSnapshot).then_some(SnapshotPhase::Sterile),
        components: BTreeMap::new(),
        compatibility: BTreeMap::new(),
    };
    crate::VerifiedArtifact {
        signed: key.sign_manifest(&manifest).unwrap(),
        payload_path: path,
    }
}

fn images(directory: &TempDir) -> VerifiedImageSet {
    let key = ImageSigningKey::from_seed([4; 32]);
    VerifiedImageSet {
        kernel: artifact(
            directory,
            &key,
            ImageKind::FirecrackerKernel,
            "kernel",
            b"k",
        ),
        rootfs: artifact(
            directory,
            &key,
            ImageKind::FirecrackerRootFilesystem,
            "rootfs",
            b"root",
        ),
        guest: artifact(directory, &key, ImageKind::GuestAgent, "guest", b"guest"),
        snapshot: None,
        architecture: Architecture::Amd64,
    }
}

fn images_with_snapshot(directory: &TempDir) -> VerifiedImageSet {
    let mut images = images(directory);
    let key = ImageSigningKey::from_seed([6; 32]);
    images.snapshot = Some(crate::VerifiedSnapshotImageSet {
        state: artifact(
            directory,
            &key,
            ImageKind::FirecrackerSnapshot,
            "snapshot-state",
            b"state",
        ),
        memory: artifact(
            directory,
            &key,
            ImageKind::FirecrackerSnapshot,
            "snapshot-memory",
            b"memory",
        ),
        compatibility: crate::SnapshotRuntimeCompatibility::new(
            crate::SnapshotRuntimeRequirements {
                firecracker_version: "1.12.0".to_owned(),
                firecracker_binary_digest: ContentDigest::sha256(b"firecracker"),
                firecracker_binary_size_bytes: 11,
                snapshot_format_version: "1.8.0".to_owned(),
                cpu_template: "T2A".to_owned(),
                cpu_feature_digest: ContentDigest::sha256(b"cpu"),
                mitigation_profile_digest: ContentDigest::sha256(b"mitigations"),
                vcpu_count: 2,
                memory_bytes: 256 * 1024 * 1024,
                guest_cid: 42,
            },
        )
        .unwrap(),
    });
    images
}

fn boot() -> GuestBootConfig {
    GuestBootConfig::new(
        GuestBootstrap {
            protocol_version: GUEST_PROTOCOL_VERSION,
            session_id: "session".to_owned(),
            lease_id: "lease".to_owned(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            job_id: "job".to_owned(),
            capsule_digest: ContentDigest::sha256(b"capsule"),
            guest_image_digest: ContentDigest::sha256(b"guest"),
            expires_unix_ms: 2_000,
        },
        &[5; 32],
        "/etc/runtrue/capsule-keys",
        5000,
    )
    .unwrap()
}

#[test]
fn stages_private_per_job_state_without_kvm() {
    let directory = TempDir::new().unwrap();
    let manager = JobStateManager::new(
        directory.path().join("active"),
        directory.path().join("quarantine"),
    )
    .unwrap();
    let state = manager
        .stage("job", "session", &images(&directory), &boot(), &FakeReflink)
        .unwrap();
    assert_eq!(
        fs::metadata(&state.paths().boot_config)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    let launch =
        crate::FirecrackerLaunchPlan::build(state.paths(), 2, 256 * 1024 * 1024, 42, None).unwrap();
    let config = launch.cold_config().unwrap();
    config
        .write_private(&state.paths().firecracker_config)
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&fs::read(&state.paths().firecracker_config).unwrap()).unwrap();
    assert_eq!(json["machine-config"]["vcpu_count"], 2);
    state.cleanup_success().unwrap();
}

#[test]
fn quarantine_erases_boot_secret_first() {
    let directory = TempDir::new().unwrap();
    let manager = JobStateManager::new(
        directory.path().join("active"),
        directory.path().join("quarantine"),
    )
    .unwrap();
    let state = manager
        .stage(
            "job",
            "bad-session",
            &images(&directory),
            &boot(),
            &FakeReflink,
        )
        .unwrap();
    let quarantined = state.quarantine("authentication failure").unwrap();
    assert!(!quarantined.join("root/boot-config.img").exists());
    assert!(quarantined.join("root/QUARANTINE_REASON").is_file());
}

#[test]
fn stages_snapshot_state_and_memory_as_private_immutable_files() {
    let directory = TempDir::new().unwrap();
    let manager = JobStateManager::new(
        directory.path().join("active"),
        directory.path().join("quarantine"),
    )
    .unwrap();
    let state = manager
        .stage(
            "job",
            "snapshot-session",
            &images_with_snapshot(&directory),
            &boot(),
            &FakeReflink,
        )
        .unwrap();
    let snapshot = state.paths().snapshot.as_ref().unwrap();
    assert_eq!(fs::read(&snapshot.state).unwrap(), b"state");
    assert_eq!(fs::read(&snapshot.memory).unwrap(), b"memory");
    for path in [&snapshot.state, &snapshot.memory] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o400
        );
    }
    let launch =
        crate::FirecrackerLaunchPlan::build(state.paths(), 2, 256 * 1024 * 1024, 42, None).unwrap();
    assert!(launch.snapshot_request().is_some());
    state.cleanup_success().unwrap();
}

#[cfg(unix)]
#[test]
fn snapshot_staging_refuses_symlink_sources() {
    use std::os::unix::fs::symlink;
    let directory = TempDir::new().unwrap();
    let manager = JobStateManager::new(
        directory.path().join("active"),
        directory.path().join("quarantine"),
    )
    .unwrap();
    let mut images = images_with_snapshot(&directory);
    let snapshot = images.snapshot.as_mut().unwrap();
    let link = directory.path().join("snapshot-state-link");
    symlink(&snapshot.state.payload_path, &link).unwrap();
    snapshot.state.payload_path = link;
    assert!(manager
        .stage("job", "symlink-session", &images, &boot(), &FakeReflink,)
        .is_err());
}
