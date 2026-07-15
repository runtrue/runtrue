use super::*;

#[test]
fn stale_expired_and_duplicate_tickets_are_rejected() {
    let (directory, store) = test_store();
    let source = directory.path().join("source");
    fs::write(&source, b"value").unwrap();
    let content_digest = ContentDigest::sha256(b"value");
    let ticket = store
        .issue_ticket(ticket_request(
            ArtifactClassification::UntrustedBuild,
            Some(content_digest.clone()),
            5,
        ))
        .unwrap();
    let producer = producer();
    let key = CapsuleSigningKey::generate().unwrap();
    let signed = signed_provenance(&key, &ticket.name, content_digest.clone(), &producer);
    let verifying = key.verifying_key();
    let request = |fence, now| ArtifactCommitRequest {
        ticket: &ticket,
        active_lease_id: "lease-1",
        active_fencing_generation: fence,
        now_unix_seconds: now,
        source: &source,
        declared_content_digest: content_digest.clone(),
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
        store.commit(&request(8, NOW + 1)),
        Err(ArtifactError::StaleFence { .. })
    ));
    assert!(matches!(
        store.commit(&request(7, ticket.expires_at_unix_seconds)),
        Err(ArtifactError::TicketExpired)
    ));
    store.commit(&request(7, NOW + 1)).unwrap();
    assert!(matches!(
        store.commit(&request(7, NOW + 1)),
        Err(ArtifactError::TicketConsumed)
    ));
}

#[test]
fn concurrent_ticket_commits_have_exactly_one_winner() {
    let (directory, store) = test_store();
    let source = directory.path().join("source");
    fs::write(&source, b"value").unwrap();
    let content_digest = ContentDigest::sha256(b"value");
    let ticket = store
        .issue_ticket(ticket_request(
            ArtifactClassification::UntrustedBuild,
            Some(content_digest.clone()),
            5,
        ))
        .unwrap();
    let producer = producer();
    let key = CapsuleSigningKey::generate().unwrap();
    let signed = signed_provenance(&key, &ticket.name, content_digest.clone(), &producer);
    let verifying = key.verifying_key();
    let store = Arc::new(store);
    let handles = (0..2)
        .map(|_| {
            let store = Arc::clone(&store);
            let ticket = ticket.clone();
            let source = source.clone();
            let content_digest = content_digest.clone();
            let producer = producer.clone();
            let signed = signed.clone();
            let verifying = verifying.clone();
            thread::spawn(move || {
                store.commit(&ArtifactCommitRequest {
                    ticket: &ticket,
                    active_lease_id: "lease-1",
                    active_fencing_generation: 7,
                    now_unix_seconds: NOW + 1,
                    source: &source,
                    declared_content_digest: content_digest,
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
                })
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(ArtifactError::TicketConsumed)))
            .count(),
        1
    );
}

#[test]
fn ticket_claim_recovery_rejects_a_substituted_artifact() {
    let (directory, store) = test_store();
    let (first_ticket, _) = commit_file(
        &store,
        directory.path(),
        b"first",
        ArtifactClassification::UntrustedBuild,
        ArtifactScanState::Pending,
    );
    let (_, second) = commit_file(
        &store,
        directory.path(),
        b"second-value",
        ArtifactClassification::Sensitive,
        ArtifactScanState::Pending,
    );
    let claim_path = store
        .ticket_directory(&first_ticket.ticket_id)
        .unwrap()
        .join("claim.json");
    fs::remove_file(&claim_path).unwrap();
    fs::write(
        &claim_path,
        serde_json::to_vec(&TicketClaim {
            claim_version: CLAIM_VERSION,
            ticket_id: first_ticket.ticket_id.clone(),
            artifact_id: second.artifact_id,
        })
        .unwrap(),
    )
    .unwrap();

    assert!(matches!(
        store.claimed_artifact(&first_ticket),
        Err(ArtifactError::InvalidMetadata(message))
            if message.contains("outside the ticket subject")
    ));
}

#[test]
fn preverified_snapshot_cross_scope_and_concurrent_claims_fail_closed() {
    let (directory, store) = test_store();
    let source = directory.path().join("concurrent-snapshot");
    fs::write(&source, b"snapshot-race").unwrap();
    let snapshot = store.cas().capture_path(source).unwrap();
    let (content_digest, size) = snapshot_identity(&snapshot);
    let ticket = store
        .issue_ticket(ticket_request(
            ArtifactClassification::UntrustedBuild,
            Some(content_digest.clone()),
            size,
        ))
        .unwrap();
    let mut cross_scope = ticket.clone();
    cross_scope.tenant_id = "other-tenant".to_owned();
    assert!(matches!(
        store.claimed_artifact(&cross_scope),
        Err(ArtifactError::InvalidTicket(_))
    ));

    let producer = producer();
    let key = CapsuleSigningKey::generate().unwrap();
    let signed = signed_provenance(&key, &ticket.name, content_digest.clone(), &producer);
    let verifying = key.verifying_key();
    let store = Arc::new(store);
    let handles = (0..2)
        .map(|_| {
            let store = Arc::clone(&store);
            let ticket = ticket.clone();
            let snapshot = snapshot.clone();
            let content_digest = content_digest.clone();
            let producer = producer.clone();
            let signed = signed.clone();
            let verifying = verifying.clone();
            thread::spawn(move || {
                store.commit_snapshot(&ArtifactSnapshotCommitRequest {
                    ticket: &ticket,
                    active_lease_id: "lease-1",
                    active_fencing_generation: 7,
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
                })
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(ArtifactError::TicketConsumed)))
            .count(),
        1
    );
    assert!(store.claimed_artifact(&ticket).unwrap().is_some());
}
