use super::*;

#[cfg(unix)]
#[test]
fn symlink_special_source_and_traversal_name_are_rejected() {
    use std::os::unix::{fs::symlink, net::UnixListener};
    let (directory, store) = test_store();
    let source = directory.path().join("source");
    fs::write(&source, b"value").unwrap();
    let link = directory.path().join("link");
    symlink(&source, &link).unwrap();

    let mut unsafe_request = ticket_request(
        ArtifactClassification::UntrustedBuild,
        Some(ContentDigest::sha256(b"value")),
        5,
    );
    unsafe_request.name = "../escape".to_owned();
    assert!(matches!(
        store.issue_ticket(unsafe_request),
        Err(ArtifactError::UnsafeArtifactName(_)) | Err(ArtifactError::InvalidMetadata(_))
    ));

    let ticket = store
        .issue_ticket(ticket_request(
            ArtifactClassification::UntrustedBuild,
            Some(ContentDigest::sha256(b"value")),
            5,
        ))
        .unwrap();
    let producer = producer();
    let key = CapsuleSigningKey::generate().unwrap();
    let signed = signed_provenance(
        &key,
        &ticket.name,
        ContentDigest::sha256(b"value"),
        &producer,
    );
    let verifying = key.verifying_key();
    let link_request = ArtifactCommitRequest {
        ticket: &ticket,
        active_lease_id: "lease-1",
        active_fencing_generation: 7,
        now_unix_seconds: NOW + 1,
        source: &link,
        declared_content_digest: ContentDigest::sha256(b"value"),
        declared_size_bytes: 5,
        media_type: "text/plain".to_owned(),
        retention_until_unix_seconds: NOW + 3_600,
        legal_hold: false,
        scan_state: ArtifactScanState::Pending,
        producer: producer.clone(),
        provenance: VerifiedArtifactProvenance {
            signed: &signed,
            verifying_key: &verifying,
        },
    };
    assert!(matches!(
        store.commit(&link_request),
        Err(ArtifactError::Storage(
            StorageError::UnsafeFilesystemEntry { .. }
        ))
    ));

    let socket_path = directory.path().join("socket");
    let _listener = UnixListener::bind(&socket_path).unwrap();
    let socket_request = ArtifactCommitRequest {
        ticket: &ticket,
        active_lease_id: "lease-1",
        active_fencing_generation: 7,
        now_unix_seconds: NOW + 1,
        source: &socket_path,
        declared_content_digest: ContentDigest::sha256(b"value"),
        declared_size_bytes: 5,
        media_type: "text/plain".to_owned(),
        retention_until_unix_seconds: NOW + 3_600,
        legal_hold: false,
        scan_state: ArtifactScanState::Pending,
        producer,
        provenance: VerifiedArtifactProvenance {
            signed: &signed,
            verifying_key: &verifying,
        },
    };
    assert!(matches!(
        store.commit(&socket_request),
        Err(ArtifactError::Storage(
            StorageError::UnsafeFilesystemEntry { .. }
        ))
    ));
}

#[test]
fn directory_artifact_round_trips_without_path_escape() {
    let (directory, store) = test_store();
    let source = directory.path().join("tree");
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("nested")).unwrap();
    fs::write(source.join("nested/result"), b"tree value").unwrap();
    let snapshot = store.cas().capture_path(&source).unwrap();
    let (content_digest, size) = snapshot_identity(&snapshot);
    let ticket = store
        .issue_ticket(ticket_request(
            ArtifactClassification::UntrustedBuild,
            Some(content_digest.clone()),
            size,
        ))
        .unwrap();
    let producer = producer();
    let key = CapsuleSigningKey::generate().unwrap();
    let signed = signed_provenance(&key, &ticket.name, content_digest.clone(), &producer);
    let verifying = key.verifying_key();
    let artifact = store
        .commit(&ArtifactCommitRequest {
            ticket: &ticket,
            active_lease_id: "lease-1",
            active_fencing_generation: 7,
            now_unix_seconds: NOW + 1,
            source: &source,
            declared_content_digest: content_digest,
            declared_size_bytes: size,
            media_type: "application/vnd.runtrue.tree".to_owned(),
            retention_until_unix_seconds: NOW + 3_600,
            legal_hold: false,
            scan_state: ArtifactScanState::Pending,
            producer,
            provenance: VerifiedArtifactProvenance {
                signed: &signed,
                verifying_key: &verifying,
            },
        })
        .unwrap();
    let destination = directory.path().join("tree-restore");
    store
        .materialize(&artifact.artifact_id, &destination)
        .unwrap();
    assert_eq!(
        fs::read(destination.join("nested/result")).unwrap(),
        b"tree value"
    );
}
