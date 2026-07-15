pub(super) fn load_image_trust(directory: &Path) -> Result<ImageTrustStore, RunnerError> {
    let mut trust = ImageTrustStore::new();
    let paths = sorted_directory_entries(directory)?;
    if paths.is_empty() {
        return Err(RunnerError::FirecrackerConfiguration(
            "Firecracker image keyring is empty".to_owned(),
        ));
    }
    for path in paths {
        let bytes = read_bounded_private_file(&path, MAX_KEY_BYTES)?;
        let decoded = decode_key(&bytes).ok_or_else(|| {
            RunnerError::FirecrackerConfiguration(format!(
                "invalid Firecracker image key `{}`",
                path.display()
            ))
        })?;
        trust.insert(ImageVerifyingKey::from_bytes(&decoded)?)?;
    }
    Ok(trust)
}

pub(super) fn load_image_set(
    manifest_directory: &Path,
    payload_directory: &Path,
) -> Result<FirecrackerImageSet, RunnerError> {
    let paths = sorted_directory_entries(manifest_directory)?;
    if paths.len() < 3 || paths.len() > MAX_IMAGE_MANIFESTS {
        return Err(RunnerError::FirecrackerConfiguration(
            "Firecracker manifest directory must contain exactly kernel/rootfs/guest and optionally state/memory snapshot manifests"
                .to_owned(),
        ));
    }
    let mut kernel = None;
    let mut rootfs = None;
    let mut guest = None;
    let mut snapshot_state = None;
    let mut snapshot_memory = None;
    for path in paths {
        let bytes = read_bounded_private_file(&path, MAX_MANIFEST_BYTES)?;
        let signed: SignedImageManifest = strict_json(&bytes).map_err(|error| {
            RunnerError::FirecrackerConfiguration(format!(
                "invalid Firecracker image manifest `{}`: {error}",
                path.display()
            ))
        })?;
        let digest_hex = signed
            .manifest
            .payload_digest
            .as_str()
            .strip_prefix("sha256:")
            .ok_or_else(|| {
                RunnerError::FirecrackerConfiguration(
                    "Firecracker image payload digest is not SHA-256".to_owned(),
                )
            })?;
        let payload_path = payload_directory.join(digest_hex);
        validate_image_payload(&payload_path)?;
        let artifact = ImageArtifact::new(signed.clone(), payload_path);
        let slot = match signed.manifest.kind {
            ImageKind::FirecrackerKernel => &mut kernel,
            ImageKind::FirecrackerRootFilesystem => &mut rootfs,
            ImageKind::GuestAgent => &mut guest,
            ImageKind::FirecrackerSnapshot => match signed
                .manifest
                .compatibility
                .get(SNAPSHOT_ROLE_KEY)
                .map(String::as_str)
            {
                Some(SNAPSHOT_STATE_ROLE) => &mut snapshot_state,
                Some(SNAPSHOT_MEMORY_ROLE) => &mut snapshot_memory,
                _ => {
                    return Err(RunnerError::FirecrackerConfiguration(
                        "Firecracker snapshot manifest has an invalid signed role".to_owned(),
                    ))
                }
            },
            _ => {
                return Err(RunnerError::FirecrackerConfiguration(
                    "Firecracker manifest directory contains another image kind".to_owned(),
                ))
            }
        };
        if slot.replace(artifact).is_some() {
            return Err(RunnerError::FirecrackerConfiguration(
                "Firecracker manifest directory contains a duplicate image role".to_owned(),
            ));
        }
    }
    let snapshot = match (snapshot_state, snapshot_memory) {
        (None, None) => None,
        (Some(state), Some(memory)) => Some(SnapshotImageSet { state, memory }),
        _ => {
            return Err(RunnerError::FirecrackerConfiguration(
                "Firecracker snapshot state and memory manifests are all-or-none".to_owned(),
            ))
        }
    };
    Ok(FirecrackerImageSet {
        kernel: kernel.ok_or_else(|| missing_image_role("kernel"))?,
        rootfs: rootfs.ok_or_else(|| missing_image_role("rootfs"))?,
        guest: guest.ok_or_else(|| missing_image_role("guest"))?,
        snapshot,
    })
}

fn missing_image_role(role: &str) -> RunnerError {
    RunnerError::FirecrackerConfiguration(format!(
        "Firecracker image set is missing its {role} manifest"
    ))
}

pub(super) fn image_expiry(images: &FirecrackerImageSet) -> Option<u64> {
    let base = [
        images.kernel.signed.manifest.expires_unix_ms,
        images.rootfs.signed.manifest.expires_unix_ms,
        images.guest.signed.manifest.expires_unix_ms,
    ];
    let snapshots = images.snapshot.as_ref().into_iter().flat_map(|snapshot| {
        [
            snapshot.state.signed.manifest.expires_unix_ms,
            snapshot.memory.signed.manifest.expires_unix_ms,
        ]
    });
    base.into_iter().flatten().chain(snapshots.flatten()).min()
}

pub(super) fn image_set_digest(
    images: &runtrue_executor_firecracker::VerifiedImageSet,
) -> Result<ContentDigest, RunnerError> {
    let mut hasher = Sha256::new();
    hasher.update(b"runtrue.firecracker.verified-image-set.v1\0");
    for (role, artifact) in [
        ("kernel", images.kernel()),
        ("rootfs", images.rootfs()),
        ("guest", images.guest()),
    ] {
        hasher.update(role.as_bytes());
        hasher.update([0]);
        hasher.update(
            artifact
                .signed_manifest()
                .manifest_digest
                .as_str()
                .as_bytes(),
        );
        hasher.update([0]);
        hasher.update(artifact.digest().as_str().as_bytes());
        hasher.update([0]);
    }
    if let Some(snapshot) = images.snapshot() {
        for (role, artifact) in [
            ("snapshot-state", snapshot.state()),
            ("snapshot-memory", snapshot.memory()),
        ] {
            hasher.update(role.as_bytes());
            hasher.update([0]);
            hasher.update(
                artifact
                    .signed_manifest()
                    .manifest_digest
                    .as_str()
                    .as_bytes(),
            );
            hasher.update([0]);
            hasher.update(artifact.digest().as_str().as_bytes());
            hasher.update([0]);
        }
    }
    ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))
}

fn decode_key(bytes: &[u8]) -> Option<[u8; 32]> {
    if let Ok(raw) = <[u8; 32]>::try_from(bytes) {
        return Some(raw);
    }
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.len() != 64 {
        return None;
    }
    let decoded = hex::decode(text).ok()?;
    <[u8; 32]>::try_from(decoded.as_slice()).ok()
}
use super::host::sorted_directory_entries;
use super::{
    read_bounded_private_file, strict_json, validate_image_payload, ContentDigest,
    FirecrackerImageSet, ImageArtifact, ImageKind, ImageTrustStore, ImageVerifyingKey, Path,
    RunnerError, Sha256, SignedImageManifest, SnapshotImageSet, MAX_IMAGE_MANIFESTS, MAX_KEY_BYTES,
    MAX_MANIFEST_BYTES, SNAPSHOT_MEMORY_ROLE, SNAPSHOT_ROLE_KEY, SNAPSHOT_STATE_ROLE,
};
use sha2::Digest as _;
