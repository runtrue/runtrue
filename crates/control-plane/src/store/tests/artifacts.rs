use super::*;

fn catalog_record() -> ArtifactCatalogRecord {
    ArtifactCatalogRecord {
        artifact_id: "artifact-digest".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        run_id: "run-1".to_owned(),
        job_id: "job-1".to_owned(),
        job_attempt: 1,
        step_id: "package".to_owned(),
        output_name: "bundle".to_owned(),
        content_digest: ContentDigest::sha256(b"content"),
        manifest_digest: ContentDigest::sha256(b"manifest"),
        provenance_digest: ContentDigest::sha256(b"provenance"),
        size_bytes: 7,
        media_type: "application/octet-stream".to_owned(),
        classification: "verified".to_owned(),
        scan_state: "pending".to_owned(),
        retention_until_unix_seconds: 10_000,
        legal_hold: false,
        state: "quarantined".to_owned(),
        created_unix_ms: NOW,
    }
}

#[test]
fn artifact_security_subjects_bind_scanner_and_promotion_target() {
    let catalog = catalog_record();
    assert_ne!(
        artifact_scan_subject_digest(&catalog, "scanner-a").unwrap(),
        artifact_scan_subject_digest(&catalog, "scanner-b").unwrap()
    );

    let promotion = ArtifactPromotionIntent {
        id: "promotion-1".to_owned(),
        subject_digest: ContentDigest::sha256(b"placeholder"),
        tenant_id: catalog.tenant_id.clone(),
        source_artifact_id: catalog.artifact_id.clone(),
        source_manifest_digest: catalog.manifest_digest.clone(),
        source_provenance_digest: catalog.provenance_digest.clone(),
        source_classification: catalog.classification.clone(),
        target_classification: "release-candidate".to_owned(),
        evidence_digest: ContentDigest::sha256(b"evidence"),
        evidence: serde_json::json!({"approval": "release"}),
        scan_evidence_digest: Some(ContentDigest::sha256(b"scan")),
        approval_evidence_digest: Some(ContentDigest::sha256(b"approval")),
        status: "pending".to_owned(),
        promoted_artifact_id: None,
        promoted_manifest_digest: None,
        created_unix_ms: NOW + 1,
        completed_unix_ms: None,
        last_error_code: None,
    };
    let original = artifact_promotion_subject_digest(&promotion).unwrap();
    let mut changed = promotion;
    changed.target_classification = "release".to_owned();
    assert_ne!(
        original,
        artifact_promotion_subject_digest(&changed).unwrap()
    );
}
