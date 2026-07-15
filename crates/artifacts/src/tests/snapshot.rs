use super::*;

#[test]
fn preverified_snapshot_commit_has_identical_ticket_and_recovery_semantics() {
    let (directory, store) = test_store();
    let source = directory.path().join("preverified");
    fs::write(&source, b"preverified-bytes").unwrap();
    let snapshot = store.cas().capture_path(&source).unwrap();
    fs::remove_file(source).unwrap();
    let (content_digest, size) = snapshot_identity(&snapshot);
    let ticket = store
        .issue_ticket(ticket_request(
            ArtifactClassification::VerifiedTestOutput,
            Some(content_digest.clone()),
            size,
        ))
        .unwrap();
    let producer = producer();
    let key = CapsuleSigningKey::generate().unwrap();
    let signed = signed_provenance(&key, &ticket.name, content_digest.clone(), &producer);
    let verifying = key.verifying_key();
    let mut request = ArtifactSnapshotCommitRequest {
        ticket: &ticket,
        active_lease_id: "lease-1",
        active_fencing_generation: 8,
        now_unix_seconds: NOW + 1,
        snapshot: &snapshot,
        declared_content_digest: content_digest,
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
    assert!(matches!(
        store.commit_snapshot(&request),
        Err(ArtifactError::StaleFence { .. })
    ));
    request.active_fencing_generation = 7;
    request.now_unix_seconds = ticket.expires_at_unix_seconds;
    assert!(matches!(
        store.commit_snapshot(&request),
        Err(ArtifactError::TicketExpired)
    ));
    request.now_unix_seconds = NOW + 1;
    let artifact = store.commit_snapshot(&request).unwrap();
    assert_eq!(artifact.record.content, snapshot);
    assert_eq!(
        store.claimed_artifact(&ticket).unwrap(),
        Some(artifact.artifact_id.clone())
    );
    assert!(matches!(
        store.commit_snapshot(&request),
        Err(ArtifactError::TicketConsumed)
    ));

    let reopened =
        ArtifactStore::open(store.root(), store.cas().clone(), ArtifactLimits::default()).unwrap();
    assert_eq!(
        reopened.claimed_artifact(&ticket).unwrap(),
        Some(artifact.artifact_id)
    );
}

#[test]
fn preverified_snapshot_digest_size_and_summary_must_match_exactly() {
    let (directory, store) = test_store();
    let source = directory.path().join("snapshot-tree");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("result"), b"tree-content").unwrap();
    let snapshot = store.cas().capture_path(source).unwrap();
    let (content_digest, size) = snapshot_identity(&snapshot);
    let ticket = store
        .issue_ticket(ticket_request(
            ArtifactClassification::UntrustedBuild,
            Some(content_digest.clone()),
            size + 1,
        ))
        .unwrap();
    let producer = producer();
    let key = CapsuleSigningKey::generate().unwrap();
    let signed = signed_provenance(&key, &ticket.name, content_digest.clone(), &producer);
    let verifying = key.verifying_key();
    let mut request = ArtifactSnapshotCommitRequest {
        ticket: &ticket,
        active_lease_id: "lease-1",
        active_fencing_generation: 7,
        now_unix_seconds: NOW + 1,
        snapshot: &snapshot,
        declared_content_digest: content_digest.clone(),
        declared_size_bytes: size + 1,
        media_type: "application/vnd.runtrue.tree".to_owned(),
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
        store.commit_snapshot(&request),
        Err(ArtifactError::ContentSizeMismatch { .. })
    ));
    request.declared_size_bytes = size;
    request.declared_content_digest = digest("substituted");
    assert!(matches!(
        store.commit_snapshot(&request),
        Err(ArtifactError::ContentDigestMismatch { .. })
    ));
    request.declared_content_digest = content_digest;
    let mut wrong_summary = snapshot.clone();
    match &mut wrong_summary {
        PathSnapshot::Directory { file_count, .. } => *file_count += 1,
        PathSnapshot::File { .. } => unreachable!(),
    }
    request.snapshot = &wrong_summary;
    assert!(matches!(
        store.commit_snapshot(&request),
        Err(ArtifactError::InvalidMetadata(message))
            if message.contains("tree summary failed verification")
    ));
    assert_eq!(store.claimed_artifact(&ticket).unwrap(), None);
}
