use super::*;

#[test]
fn file_commit_is_content_addressed_and_materializes_safely() {
    let (directory, store) = test_store();
    let (ticket, artifact) = commit_file(
        &store,
        directory.path(),
        b"release bytes",
        ArtifactClassification::VerifiedTestOutput,
        ArtifactScanState::Passed {
            scanner: "scanner-v1".to_owned(),
            report_digest: digest("scan-report"),
        },
    );
    assert_eq!(artifact.record.name, "package");
    assert_eq!(artifact.record.tenant_id, "tenant");
    assert_eq!(artifact.record.producer.capsule_digest, digest("capsule"));
    assert_eq!(
        store.claimed_artifact(&ticket).unwrap(),
        Some(artifact.artifact_id.clone())
    );
    assert_eq!(store.load(&artifact.artifact_id).unwrap(), artifact);
    let destination = directory.path().join("download");
    store
        .materialize(&artifact.artifact_id, &destination)
        .unwrap();
    assert_eq!(fs::read(destination).unwrap(), b"release bytes");
}

#[test]
fn digest_and_size_substitution_are_rejected_without_consuming_ticket() {
    let (directory, store) = test_store();
    let source = directory.path().join("source");
    fs::write(&source, b"actual").unwrap();
    let ticket = store
        .issue_ticket(ticket_request(
            ArtifactClassification::UntrustedBuild,
            Some(digest("expected")),
            20,
        ))
        .unwrap();
    let producer = producer();
    let key = CapsuleSigningKey::generate().unwrap();
    let signed = signed_provenance(&key, &ticket.name, digest("declared"), &producer);
    let verifying = key.verifying_key();
    let mut request = ArtifactCommitRequest {
        ticket: &ticket,
        active_lease_id: "lease-1",
        active_fencing_generation: 7,
        now_unix_seconds: NOW + 1,
        source: &source,
        declared_content_digest: digest("declared"),
        declared_size_bytes: 6,
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
        store.commit(&request),
        Err(ArtifactError::ContentDigestMismatch { .. })
    ));
    request.declared_content_digest = ContentDigest::sha256(b"actual");
    request.declared_size_bytes = 5;
    assert!(matches!(
        store.commit(&request),
        Err(ArtifactError::ContentSizeMismatch { .. })
    ));
    assert_eq!(store.claimed_artifact(&ticket).unwrap(), None);
}
