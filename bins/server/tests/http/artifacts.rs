use super::support::*;
#[tokio::test]
async fn artifact_metadata_and_download_tickets_are_tenant_scoped() {
    let (control, application) = application(None);
    control
        .create_repository(&tenant_repository(
            "repo-artifact",
            "tenant-artifact",
            "artifact",
        ))
        .unwrap();
    store_tenant_capsule(&control, "repo-artifact", "capsule-artifact");
    store_tenant_run(
        &control,
        "repo-artifact",
        "capsule-artifact",
        "run-artifact",
        "job-artifact",
    );
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-artifact".to_owned(),
            tenant_id: "tenant-artifact".to_owned(),
            name: "artifact".to_owned(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: 1,
        })
        .unwrap();
    control
        .register_runner_with_inventory(
            &RunnerRecord {
                id: "runner-artifact".to_owned(),
                tenant_id: "tenant-artifact".to_owned(),
                pool_id: "pool-artifact".to_owned(),
                ephemeral: false,
                retired: false,
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation_backends: BTreeSet::from([Isolation::Microvm]),
                logical_cpus: 2,
                memory_bytes: 4096,
                storage_bytes: 8192,
                max_concurrent_wasm_jobs: 1,
                region: None,
                verified_capabilities: BTreeSet::from(["kvm".to_owned()]),
                self_reported_capabilities: BTreeSet::new(),
                status: RunnerStatus::Online,
                active_jobs: 0,
                active_wasm_jobs: 0,
                used_cpus: 0,
                used_memory_bytes: 0,
                used_storage_bytes: 0,
                locality: BTreeSet::new(),
                package_tiers: Default::default(),
                last_heartbeat_unix_ms: 1,
            },
            &ContentDigest::sha256(b"artifact-runner-inventory"),
            1,
        )
        .unwrap();
    let offered = control
        .offer_next_lease_for_runner("runner-artifact", 2)
        .unwrap()
        .unwrap();
    let lease = control
        .accept_lease(
            &offered.id,
            "runner-artifact",
            offered.fencing_generation,
            offered.installation_fencing_epoch,
            3,
        )
        .unwrap();
    control
        .record_runner_data_commit(
            &RunnerDataCommit {
                kind: RunnerDataCommitKind::Artifact,
                object_id: "artifact-catalog-1".to_owned(),
                tenant_id: "tenant-artifact".to_owned(),
                repository_id: "repo-artifact".to_owned(),
                run_id: "run-artifact".to_owned(),
                job_id: "job-artifact".to_owned(),
                job_attempt: 1,
                step_id: "job-finalize".to_owned(),
                output_name: Some("result".to_owned()),
                lease_id: lease.id.clone(),
                fencing_generation: lease.fencing_generation,
                ticket_id: "artifact-ticket-1".to_owned(),
                committed_unix_ms: 4,
            },
            "runner-artifact",
        )
        .unwrap();
    control
        .transition_job_state("job-artifact", JobState::Running, 5)
        .unwrap();
    control
        .transition_job_state("job-artifact", JobState::Finalizing, 6)
        .unwrap();
    control
        .complete_lease_with_objects(
            &lease.id,
            "runner-artifact",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            &ContentDigest::sha256(b"artifact-failed-result"),
            JobState::Failed,
            runtrue_control_plane::CredentialTaintState::None,
            1,
            &["artifact-catalog-1".to_owned()],
            &[],
            &[],
            7,
        )
        .unwrap();
    control
        .catalog_artifact(&ArtifactCatalogRecord {
            artifact_id: "artifact-catalog-1".to_owned(),
            tenant_id: "tenant-artifact".to_owned(),
            repository_id: "repo-artifact".to_owned(),
            run_id: "run-artifact".to_owned(),
            job_id: "job-artifact".to_owned(),
            job_attempt: 1,
            step_id: "job-finalize".to_owned(),
            output_name: "result".to_owned(),
            content_digest: ContentDigest::sha256(b"artifact-content"),
            manifest_digest: ContentDigest::sha256(b"artifact-manifest"),
            provenance_digest: ContentDigest::sha256(b"artifact-provenance"),
            size_bytes: 16,
            media_type: "application/octet-stream".to_owned(),
            classification: "verified-test-output".to_owned(),
            scan_state: "pending".to_owned(),
            retention_until_unix_seconds: 10_000,
            legal_hold: false,
            state: "available".to_owned(),
            created_unix_ms: 8,
        })
        .unwrap();

    let owner = issue_http_token(
        &application,
        "artifact-owner-token",
        "artifact-reader",
        "tenant-artifact",
        &["api:read", "api:write"],
    )
    .await;
    let attacker = issue_http_token(
        &application,
        "artifact-attacker-token",
        "attacker",
        "tenant-attacker",
        &["api:read", "api:write"],
    )
    .await;
    let metadata = application
        .clone()
        .oneshot(token_request(
            &owner,
            "GET",
            "/api/v1/artifacts/artifact-catalog-1",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    assert_eq!(
        json_body(metadata).await["artifact_id"],
        "artifact-catalog-1"
    );
    let hidden = application
        .clone()
        .oneshot(token_request(
            &attacker,
            "GET",
            "/api/v1/artifacts/artifact-catalog-1",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
    let issued = application
        .oneshot(token_request(
            &owner,
            "POST",
            "/api/v1/artifacts/artifact-catalog-1/download-tickets",
            serde_json::to_vec(&json!({"ttl_seconds": 60})).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    let issued = json_body(issued).await;
    assert!(issued["token"]
        .as_str()
        .is_some_and(|token| token.starts_with("artifact-download_")));
}
