use super::*;

#[test]
fn cache_generations_promotion_and_observations_are_durable_exact_and_tenant_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache-trust.sqlite");
    let control = ControlPlane::open(&path, "installation", NOW).unwrap();
    bootstrap(&control);
    control
        .create_run_idempotent(
            "cache-trust-run",
            &run_request("run-cache-trust", "job-cache-trust"),
        )
        .unwrap();
    let source = CacheTrustGenerationRecord {
        cache_entry_id: "cache-source".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        identity_digest: ContentDigest::sha256(b"source identity"),
        key_material_digest: ContentDigest::sha256(b"neutral material"),
        key_material: serde_json::json!({"purpose":"build"}),
        trust_domain: serde_json::json!({"kind":"pull_request_quarantine","change_id":"7"}),
        generation: 1,
        manifest_digest: ContentDigest::sha256(b"source manifest"),
        tree_manifest_digest: ContentDigest::sha256(b"immutable tree"),
        fencing_generation: 7,
        source_cache_entry_id: None,
        promotion_evidence_digest: None,
        created_unix_ms: NOW + 1,
    };
    assert!(!control
        .record_cache_trust_generation(&source, None)
        .unwrap());
    assert!(control
        .record_cache_trust_generation(&source, None)
        .unwrap());
    let mut substituted = source.clone();
    substituted.tree_manifest_digest = ContentDigest::sha256(b"substitution");
    assert!(matches!(
        control.record_cache_trust_generation(&substituted, None),
        Err(ControlPlaneError::IdempotencyConflict)
    ));

    let mut intent = CachePromotionRecord {
        id: "cache-promotion-1".to_owned(),
        subject_digest: ContentDigest::sha256(b"pending subject"),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        source_cache_entry_id: source.cache_entry_id.clone(),
        target_identity_digest: ContentDigest::sha256(b"main identity"),
        target_trust_domain: serde_json::json!({"kind":"repository_main_verified"}),
        expected_target_cache_entry_id: None,
        evidence_digest: ContentDigest::sha256(b"scan approval evidence"),
        evidence: serde_json::json!({"kind":"verified_attestation","scan":"passed"}),
        state: CachePromotionState::Pending,
        promoted_cache_entry_id: None,
        created_unix_ms: NOW + 2,
        completed_unix_ms: None,
        last_error: None,
    };
    intent.subject_digest = cache_promotion_subject_digest(&intent).unwrap();
    assert!(!control.create_cache_promotion_idempotent(&intent).unwrap());
    assert!(control.create_cache_promotion_idempotent(&intent).unwrap());
    let promoted = CacheTrustGenerationRecord {
        cache_entry_id: "cache-promoted".to_owned(),
        tenant_id: source.tenant_id.clone(),
        repository_id: source.repository_id.clone(),
        identity_digest: intent.target_identity_digest.clone(),
        key_material_digest: source.key_material_digest.clone(),
        key_material: source.key_material.clone(),
        trust_domain: intent.target_trust_domain.clone(),
        generation: 1,
        manifest_digest: ContentDigest::sha256(b"promoted manifest"),
        tree_manifest_digest: source.tree_manifest_digest.clone(),
        fencing_generation: 8,
        source_cache_entry_id: Some(source.cache_entry_id.clone()),
        promotion_evidence_digest: Some(intent.evidence_digest.clone()),
        created_unix_ms: NOW + 3,
    };
    assert!(!control
        .complete_cache_promotion("tenant-1", &intent.id, &promoted, NOW + 3)
        .unwrap());
    assert!(control
        .complete_cache_promotion("tenant-1", &intent.id, &promoted, NOW + 4)
        .unwrap());
    assert_eq!(
        control
            .cache_promotion("tenant-1", &intent.id)
            .unwrap()
            .state,
        CachePromotionState::Completed
    );
    assert!(matches!(
        control.cache_promotion("tenant-attacker", &intent.id),
        Err(ControlPlaneError::NotFound { .. })
    ));

    let observation = CacheAccessObservation {
        id: "cache-observation-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        run_id: "run-cache-trust".to_owned(),
        job_id: "job-cache-trust".to_owned(),
        job_attempt: 1,
        step_id: "build".to_owned(),
        operation: "restore".to_owned(),
        key_material_digest: source.key_material_digest.clone(),
        candidates: vec![serde_json::json!({"kind":"repository_main_verified"})],
        outcome: "hit".to_owned(),
        selected_trust_domain: Some(promoted.trust_domain.clone()),
        selected_generation: Some(1),
        transferred_bytes: 4096,
        latency_ms: 12,
        breaker_state: "closed".to_owned(),
        created_unix_ms: NOW + 4,
    };
    assert!(!control
        .record_cache_access_observation(&observation)
        .unwrap());
    assert!(control
        .record_cache_access_observation(&observation)
        .unwrap());
    assert_eq!(control.cache_trust_metrics("tenant-1").unwrap().hits, 1);
    drop(control);

    let reopened = ControlPlane::open(&path, "installation", NOW + 5).unwrap();
    assert_eq!(
        reopened
            .cache_promotion("tenant-1", &intent.id)
            .unwrap()
            .promoted_cache_entry_id
            .as_deref(),
        Some("cache-promoted")
    );
    assert_eq!(
        reopened
            .cache_trust_metrics("tenant-1")
            .unwrap()
            .promotions_completed,
        1
    );
    assert!(reopened
        .audit_events()
        .unwrap()
        .iter()
        .any(|event| event.data.action == "cache.promote"));
}
