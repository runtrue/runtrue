use super::*;

#[test]
fn provenance_must_link_exact_producer_and_content() {
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
    let signed = signed_provenance(&key, &ticket.name, digest("wrong-output"), &producer);
    let verifying = key.verifying_key();
    assert!(matches!(
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
            legal_hold: true,
            scan_state: ArtifactScanState::Pending,
            producer,
            provenance: VerifiedArtifactProvenance {
                signed: &signed,
                verifying_key: &verifying,
            },
        }),
        Err(ArtifactError::ProvenanceMismatch)
    ));

    let (_, valid) = commit_file(
        &store,
        directory.path(),
        b"self-verifying",
        ArtifactClassification::VerifiedTestOutput,
        ArtifactScanState::Passed {
            scanner: "scanner-v1".to_owned(),
            report_digest: digest("report"),
        },
    );
    let mut forged = valid.record;
    forged.producer.capsule_digest = digest("substituted-capsule");
    assert!(matches!(
        store.store_record(&forged),
        Err(ArtifactError::ProvenanceMismatch)
    ));
}

#[test]
fn public_load_reverifies_the_persisted_provenance_signature() {
    let (directory, store) = test_store();
    let (_, valid) = commit_file(
        &store,
        directory.path(),
        b"signed-content",
        ArtifactClassification::UntrustedBuild,
        ArtifactScanState::Pending,
    );
    let mut forged = valid.record;
    forged.provenance.signed.signature[0] ^= 0x01;
    let forged_bytes = serde_json::to_vec(&forged).unwrap();
    let forged_id = store.cas().put_bytes(&forged_bytes).unwrap().digest;

    assert!(matches!(
        store.load(&forged_id),
        Err(ArtifactError::Attestation(_))
    ));
    let destination = directory.path().join("forged-download");
    assert!(matches!(
        store.materialize(&forged_id, &destination),
        Err(ArtifactError::Attestation(_))
    ));
    assert!(!destination.exists());
}
