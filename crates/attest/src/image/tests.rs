use super::*;
use runtrue_model::ContentDigest;
use std::collections::BTreeMap;

fn snapshot(phase: SnapshotPhase) -> ImageManifest {
    ImageManifest {
        manifest_version: 1,
        kind: ImageKind::FirecrackerSnapshot,
        name: "linux-amd64-base".to_owned(),
        payload_digest: ContentDigest::sha256(b"snapshot"),
        payload_size_bytes: 1024,
        payload_media_type: "application/vnd.runtrue.firecracker.snapshot".to_owned(),
        operating_system: "linux".to_owned(),
        architecture: "amd64".to_owned(),
        builder_id: "runtrue-image:test".to_owned(),
        build_provenance_digest: ContentDigest::sha256(b"provenance"),
        sbom_digest: ContentDigest::sha256(b"sbom"),
        created_unix_ms: 10,
        expires_unix_ms: Some(1_000),
        snapshot_phase: Some(phase),
        components: BTreeMap::from([
            ("guest".to_owned(), ContentDigest::sha256(b"guest")),
            ("kernel".to_owned(), ContentDigest::sha256(b"kernel")),
            ("rootfs".to_owned(), ContentDigest::sha256(b"rootfs")),
        ]),
        compatibility: BTreeMap::from([("firecracker".to_owned(), "1.x".to_owned())]),
    }
}

#[test]
fn image_signature_is_domain_bound_and_tamper_evident() {
    let key = ImageSigningKey::from_seed([11; 32]);
    let signed = key
        .sign_manifest(&snapshot(SnapshotPhase::Sterile))
        .unwrap();
    key.verifying_key().verify_manifest(&signed).unwrap();

    let mut tampered = signed;
    tampered.manifest.payload_size_bytes += 1;
    assert!(matches!(
        key.verifying_key().verify_manifest(&tampered),
        Err(ImageAttestError::ObjectDigestMismatch)
    ));
    assert_eq!(format!("{key:?}"), "ImageSigningKey(<redacted>)");
}

#[test]
fn only_sterile_snapshots_can_enter_a_warm_pool() {
    snapshot(SnapshotPhase::Sterile)
        .authorize_warm_snapshot_publication()
        .unwrap();
    for phase in [
        SnapshotPhase::JobIdentityInjected,
        SnapshotPhase::SourceMounted,
        SnapshotPhase::SecretReleased,
    ] {
        assert!(matches!(
            snapshot(phase).authorize_warm_snapshot_publication(),
            Err(ImageAttestError::SnapshotNotSterile)
        ));
    }
    let mut not_snapshot = snapshot(SnapshotPhase::Sterile);
    not_snapshot.kind = ImageKind::OciImage;
    assert!(not_snapshot.validate().is_err());
}

fn update(generation: u64) -> UpdateMetadata {
    UpdateMetadata {
        metadata_version: 1,
        channel: "stable".to_owned(),
        generation,
        issued_unix_ms: 100,
        expires_unix_ms: 1_000,
        targets: BTreeMap::from([(
            "runner-linux-amd64".to_owned(),
            UpdateTarget {
                manifest_digest: ContentDigest::sha256(b"manifest"),
                payload_digest: ContentDigest::sha256(b"payload"),
                payload_size_bytes: 42,
            },
        )]),
    }
}

#[test]
fn update_threshold_expiry_and_rollback_are_enforced() {
    let key_a = ImageSigningKey::from_seed([1; 32]);
    let key_b = ImageSigningKey::from_seed([2; 32]);
    let key_c = ImageSigningKey::from_seed([3; 32]);
    let metadata = update(8);
    let mut signed = SignedUpdateMetadata {
        signatures: vec![
            key_a.sign_update(&metadata).unwrap(),
            key_b.sign_update(&metadata).unwrap(),
        ],
        metadata,
    };
    let mut trust = TrustedUpdateState::new(
        "stable",
        7,
        2,
        [
            key_a.verifying_key(),
            key_b.verifying_key(),
            key_c.verifying_key(),
        ],
    )
    .unwrap();
    trust.verify_and_advance(&signed, 500).unwrap();
    assert_eq!(trust.highest_generation(), 8);
    assert!(matches!(
        trust.verify_and_advance(&signed, 500),
        Err(ImageAttestError::UpdateRollback { .. })
    ));

    signed.metadata = update(9);
    signed.signatures = vec![key_a.sign_update(&signed.metadata).unwrap()];
    assert!(matches!(
        trust.verify_and_advance(&signed, 500),
        Err(ImageAttestError::UpdateSignatureThreshold { .. })
    ));
    assert!(matches!(
        trust.verify_and_advance(&signed, 1_000),
        Err(ImageAttestError::UpdateMetadataExpired)
    ));
}

#[test]
fn duplicate_signers_do_not_count_toward_threshold() {
    let key = ImageSigningKey::from_seed([4; 32]);
    let other = ImageSigningKey::from_seed([5; 32]);
    let metadata = update(1);
    let signature = key.sign_update(&metadata).unwrap();
    let signed = SignedUpdateMetadata {
        metadata,
        signatures: vec![signature.clone(), signature],
    };
    let mut trust =
        TrustedUpdateState::new("stable", 0, 2, [key.verifying_key(), other.verifying_key()])
            .unwrap();
    assert!(matches!(
        trust.verify_and_advance(&signed, 500),
        Err(ImageAttestError::DuplicateUpdateSignature)
    ));
}
