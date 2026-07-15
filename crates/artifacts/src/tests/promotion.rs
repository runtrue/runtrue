use super::*;

#[test]
fn promotion_is_one_way_evidence_bearing_and_never_changes_content() {
    let (directory, store) = test_store();
    let (_, source) = commit_file(
        &store,
        directory.path(),
        b"candidate",
        ArtifactClassification::Quarantined,
        ArtifactScanState::Passed {
            scanner: "scanner-v1".to_owned(),
            report_digest: digest("report"),
        },
    );
    assert!(matches!(
        store.promote(
            &source.artifact_id,
            ArtifactClassification::VerifiedTestOutput,
            ArtifactPromotionEvidence {
                kind: ArtifactPromotionKind::ReleaseApproval,
                evidence_digest: digest("wrong-kind"),
                approval_id: Some("approval".to_owned()),
                policy_version_ids: vec!["policy-v1".to_owned()],
            },
            NOW + 2
        ),
        Err(ArtifactError::InvalidPromotion(_))
    ));
    let promoted = store
        .promote(
            &source.artifact_id,
            ArtifactClassification::VerifiedTestOutput,
            ArtifactPromotionEvidence {
                kind: ArtifactPromotionKind::VerifiedAttestation,
                evidence_digest: digest("attestation"),
                approval_id: None,
                policy_version_ids: vec!["policy-v1".to_owned()],
            },
            NOW + 2,
        )
        .unwrap();
    assert_ne!(source.artifact_id, promoted.artifact_id);
    assert_eq!(source.record.content, promoted.record.content);
    assert_eq!(source.record.content_digest, promoted.record.content_digest);
    assert_eq!(source.record.size_bytes, promoted.record.size_bytes);
    assert_eq!(source.record.provenance, promoted.record.provenance);
    assert_eq!(
        promoted
            .record
            .promotion
            .as_ref()
            .unwrap()
            .source_record_digest,
        source.artifact_id
    );
    assert!(matches!(
        store.promote(
            &promoted.artifact_id,
            ArtifactClassification::Quarantined,
            ArtifactPromotionEvidence {
                kind: ArtifactPromotionKind::QuarantineReview,
                evidence_digest: digest("downward"),
                approval_id: Some("approval".to_owned()),
                policy_version_ids: vec!["policy-v1".to_owned()],
            },
            NOW + 3
        ),
        Err(ArtifactError::InvalidPromotion(_))
    ));
}
