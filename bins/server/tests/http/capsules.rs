use super::support::*;
#[tokio::test]
async fn create_capsule_binds_lockfile_selected_job_and_idempotency() {
    let (control_plane, application) = application(None);
    control_plane
        .create_repository(&tenant_repository("repo-submit", "tenant-submit", "submit"))
        .unwrap();

    let digest = "b".repeat(64);
    let workflow = r#"version: 1
name: submit-parity
permissions:
  network: deny
  repository: deny
jobs:
  build:
    services:
      db:
        image: registry.example/postgres:17
    steps:
      - run: { command: ["true"] }
  report:
    needs: [build]
    steps:
      - run: { command: ["true"] }
  unrelated:
    steps:
      - run: { command: ["true"] }
"#;
    let mut lockfile = format!(
        r#"lock_version = 1
[[image]]
source = "registry.example/postgres:17"
resolved = "registry.example/postgres@sha256:{digest}"
platform = "linux/amd64"
"#
    );
    // The capsule route has a larger aggregate request bound than unrelated API
    // routes so a valid bounded lockfile can accompany the workflow/event.
    lockfile.push('#');
    lockfile.push_str(&" bounded lockfile comment".repeat(48_000));
    lockfile.push('\n');
    let request = json!({
        "source_commit": "c".repeat(40),
        "base_commit": "a".repeat(40),
        "workflow_path": ".runtrue/workflows/submit.yaml",
        "workflow_yaml": workflow,
        "event": {"type": "manual"},
        "lockfile_toml": lockfile,
        "selected_job": "report"
    });

    let first = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/repositories/repo-submit/capsules",
            "submit-capsule-key",
            request.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(first.headers()["idempotency-replayed"], "false");
    let first = json_body(first).await;
    assert!(first["lock_digest"].is_string());
    let jobs = first["capsule"]["jobs"].as_array().unwrap();
    assert_eq!(
        jobs.iter()
            .map(|job| job["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["build", "report"]
    );
    assert_eq!(
        jobs[0]["services"][0]["image"],
        format!("registry.example/postgres@sha256:{digest}")
    );

    let replay = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/repositories/repo-submit/capsules",
            "submit-capsule-key",
            request.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(replay.headers()["idempotency-replayed"], "true");
    let replay = json_body(replay).await;
    assert_eq!(replay["id"], first["id"]);
    assert_eq!(replay["digest"], first["digest"]);
    assert_eq!(replay["capsule"], first["capsule"]);

    let mut missing_lock = request.clone();
    missing_lock
        .as_object_mut()
        .unwrap()
        .remove("lockfile_toml");
    let rejected = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/repositories/repo-submit/capsules",
            "submit-missing-lock",
            missing_lock,
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let mut malformed_lock = request;
    malformed_lock["lockfile_toml"] = json!("lock_version = 1\nunknown = true\n");
    let rejected = application
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/repositories/repo-submit/capsules",
            "submit-malformed-lock",
            malformed_lock,
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_capsule_accepts_only_exact_bounded_reusable_source_bundle() {
    let (control_plane, application) = application(None);
    control_plane
        .create_repository(&tenant_repository(
            "repo-reusable",
            "tenant-reusable",
            "reusable",
        ))
        .unwrap();
    let reference = "git+https://github.com/octo/shared.git//ci.yaml@v1";
    let commit = "a".repeat(40);
    let reusable = b"version: 1\njobs:\n  build:\n    steps: [{ run: { command: [\"true\"] } }]\n";
    let digest = ContentDigest::sha256(reusable);
    let lockfile = format!(
        "lock_version = 1\n[[workflow]]\nsource = \"{reference}\"\ncommit = \"{commit}\"\ndigest = \"{digest}\"\n"
    );
    let workflow_yaml = format!("version: 1\njobs:\n  shared:\n    uses: {reference}\n");
    let expected = Compiler::default()
        .compile_yaml(
            &workflow_yaml,
            CompileContext {
                installation_id: "test-installation".to_owned(),
                tenant_id: "tenant-reusable".to_owned(),
                repository_id: "repo-reusable".to_owned(),
                workflow_path: ".runtrue/workflows/ci.yaml".to_owned(),
                source_commit: "b".repeat(40),
                event: json!({"type": "manual"}),
                lockfile: Some(LockFile::parse(lockfile.as_bytes()).unwrap()),
                reusable_workflows: ReusableWorkflowSources::new(BTreeMap::from([(
                    reference.to_owned(),
                    ReusableWorkflowSource::new(&commit, reusable.to_vec()).unwrap(),
                )]))
                .unwrap(),
                policy_version_ids: vec!["server-default-deny-v1".to_owned()],
                workflow_changed: true,
                ..CompileContext::default()
            },
        )
        .unwrap();
    let request = json!({
        "source_commit": "b".repeat(40),
        "workflow_yaml": workflow_yaml,
        "event": {"type": "manual"},
        "lockfile_toml": lockfile,
        "reusable_workflows": [{
            "reference": reference,
            "commit": commit,
            "source_hex": hex::encode(reusable),
        }],
    });
    let accepted = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/repositories/repo-reusable/capsules",
            "reusable-ok",
            request.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::CREATED);
    let accepted = json_body(accepted).await;
    assert_eq!(accepted["digest"], expected.capsule_digest.to_string());
    assert_eq!(accepted["capsule"]["jobs"][0]["id"], "shared__build");

    let mut missing = request.clone();
    missing["reusable_workflows"] = json!([]);
    assert_eq!(
        application
            .clone()
            .oneshot(idempotent_request(
                "POST",
                "/api/v1/repositories/repo-reusable/capsules",
                "reusable-missing",
                missing,
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let mut duplicate = request.clone();
    duplicate["reusable_workflows"] = json!([
        request["reusable_workflows"][0].clone(),
        request["reusable_workflows"][0].clone()
    ]);
    assert_eq!(
        application
            .clone()
            .oneshot(idempotent_request(
                "POST",
                "/api/v1/repositories/repo-reusable/capsules",
                "reusable-duplicate",
                duplicate,
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let mut tampered = request.clone();
    tampered["reusable_workflows"][0]["source_hex"] = json!(hex::encode(b"tampered"));
    assert_eq!(
        application
            .clone()
            .oneshot(idempotent_request(
                "POST",
                "/api/v1/repositories/repo-reusable/capsules",
                "reusable-tampered",
                tampered,
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let mut oversized = request;
    oversized["reusable_workflows"][0]["source_hex"] =
        json!("00".repeat(runtrue_compiler::MAX_REUSABLE_SOURCE_BYTES + 1));
    assert_eq!(
        application
            .oneshot(idempotent_request(
                "POST",
                "/api/v1/repositories/repo-reusable/capsules",
                "reusable-oversized",
                oversized,
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}
