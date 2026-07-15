use super::*;

#[test]
fn preverified_snapshot_rejects_missing_and_corrupt_cas_content() {
    let (directory, store) = test_store();
    let source = directory.path().join("missing-cas-source");
    fs::write(&source, b"missing-cas").unwrap();
    let snapshot = store.cas().capture_path(source).unwrap();
    let (content_digest, size) = snapshot_identity(&snapshot);
    let ticket = store
        .issue_ticket(ticket_request(
            ArtifactClassification::UntrustedBuild,
            Some(content_digest.clone()),
            size,
        ))
        .unwrap();
    let missing_producer = producer();
    let key = CapsuleSigningKey::generate().unwrap();
    let signed = signed_provenance(
        &key,
        &ticket.name,
        content_digest.clone(),
        &missing_producer,
    );
    let verifying = key.verifying_key();
    let request = ArtifactSnapshotCommitRequest {
        ticket: &ticket,
        active_lease_id: "lease-1",
        active_fencing_generation: 7,
        now_unix_seconds: NOW + 1,
        snapshot: &snapshot,
        declared_content_digest: content_digest.clone(),
        declared_size_bytes: size,
        media_type: "application/octet-stream".to_owned(),
        retention_until_unix_seconds: NOW + 3_600,
        legal_hold: false,
        scan_state: ArtifactScanState::Pending,
        producer: missing_producer,
        provenance: VerifiedArtifactProvenance {
            signed: &signed,
            verifying_key: &verifying,
        },
    };
    fs::remove_file(object_path(store.cas(), &content_digest)).unwrap();
    assert!(matches!(
        store.commit_snapshot(&request),
        Err(ArtifactError::Storage(StorageError::NotFound(_)))
    ));
    assert_eq!(store.claimed_artifact(&ticket).unwrap(), None);

    let source = directory.path().join("claimed-corrupt-source");
    fs::write(&source, b"claimed-corrupt").unwrap();
    let snapshot = store.cas().capture_path(source).unwrap();
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
    let request = ArtifactSnapshotCommitRequest {
        ticket: &ticket,
        active_lease_id: "lease-1",
        active_fencing_generation: 7,
        now_unix_seconds: NOW + 1,
        snapshot: &snapshot,
        declared_content_digest: content_digest.clone(),
        declared_size_bytes: size,
        media_type: "application/octet-stream".to_owned(),
        retention_until_unix_seconds: NOW + 3_600,
        legal_hold: false,
        scan_state: ArtifactScanState::Pending,
        producer,
        provenance: VerifiedArtifactProvenance {
            signed: &signed,
            verifying_key: &verifying,
        },
    };
    store.commit_snapshot(&request).unwrap();
    let blob_path = object_path(store.cas(), &content_digest);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&blob_path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(blob_path, b"changed-bytes").unwrap();
    assert!(matches!(
        store.claimed_artifact(&ticket),
        Err(ArtifactError::Storage(StorageError::CorruptBlob { .. }))
    ));
    assert!(matches!(
        store.commit_snapshot(&request),
        Err(ArtifactError::TicketConsumed)
    ));
}
