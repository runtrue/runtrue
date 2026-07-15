use super::*;

#[test]
fn signed_expanded_job_set_is_durable_exact_and_tenant_bound() {
    let control = ControlPlane::open_in_memory("r7-expansion", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    let mut capsule = execution_capsule();
    let mut template_job = capsule.jobs[0].clone();
    template_job.id = "dynamic".to_owned();
    template_job.base_id = "dynamic".to_owned();
    template_job.needs = vec!["build".to_owned()];
    let template = runtrue_workflow_ir::DynamicJobTemplate {
        id: "dynamic".to_owned(),
        source: runtrue_workflow_ir::DynamicMatrixSource {
            producer_job_id: "build".to_owned(),
            output_name: "axes".to_owned(),
            maximum_jobs: 4,
        },
        template: template_job,
    };
    capsule.dynamic_jobs = vec![template.clone()];
    let signing = CapsuleSigningKey::from_seed([71; 32]);
    let capsule_signature = signing.sign_capsule(&capsule).unwrap();
    let signed_capsule = SignedCapsuleRecord {
        id: "dynamic-capsule".to_owned(),
        repository_id: "repo-1".to_owned(),
        digest: capsule_signature.capsule_digest.clone(),
        canonical_capsule: capsule.canonical_bytes().unwrap(),
        signature: capsule_signature,
        created_unix_ms: NOW,
    };
    control
        .store_signed_capsule(&signed_capsule, &signing.verifying_key())
        .unwrap();
    control
        .create_run_idempotent(
            "dynamic-run-create",
            &CreateRunRequest {
                id: "dynamic-run".to_owned(),
                repository_id: "repo-1".to_owned(),
                capsule_id: signed_capsule.id.clone(),
                priority: 0,
                remote: true,
                created_unix_ms: NOW + 1,
                jobs: vec![NewJob {
                    id: "dynamic-producer-job".to_owned(),
                    job_key: "build".to_owned(),
                    attempt: 1,
                    requirements: requirements(),
                }],
            },
        )
        .unwrap();
    let set = runtrue_workflow_ir::expand_dynamic_job_set(
        signed_capsule.digest.clone(),
        &template,
        &json!({"shard": [1, 2]}),
        9,
    )
    .unwrap();
    let signature = signing.sign_expanded_job_set(&set).unwrap();
    let record = ExpandedJobSetRecord {
        id: "expanded-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        run_id: "dynamic-run".to_owned(),
        parent_capsule_digest: signed_capsule.digest,
        template_id: template.id,
        producer_job_id: set.producer_job_id.clone(),
        producer_output_name: set.producer_output_name.clone(),
        matrix_input_digest: set.matrix_input_digest.clone(),
        policy_epoch: set.policy_epoch,
        generated_job_count: set.jobs.len() as u64,
        canonical_job_set: set.canonical_bytes().unwrap(),
        job_set_digest: signature.job_set_digest.clone(),
        signing_key_id: signature.key_id.to_string(),
        signature: signature.signature,
        created_unix_ms: NOW + 2,
    };
    assert!(!control
        .record_expanded_job_set(&record, &signing.verifying_key())
        .unwrap());
    assert!(control
        .record_expanded_job_set(&record, &signing.verifying_key())
        .unwrap());
    let mut substitution = record.clone();
    substitution.created_unix_ms += 1;
    assert!(matches!(
        control.record_expanded_job_set(&substitution, &signing.verifying_key()),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    let mut wrong_tenant = record;
    wrong_tenant.tenant_id = "tenant-other".to_owned();
    assert!(matches!(
        control.record_expanded_job_set(&wrong_tenant, &signing.verifying_key()),
        Err(ControlPlaneError::NotFound { kind: "run", .. })
    ));
}

#[test]
fn normalized_triggers_and_schedule_cursors_replay_or_conflict() {
    let control = ControlPlane::open_in_memory("r7-triggers", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    let envelope = json!({"type": "manual", "inputs": {"release": false}});
    let canonical =
        serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(envelope.clone())).unwrap();
    let trigger = NormalizedTriggerEventRecord {
        id: "trigger-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        trigger_kind: "manual".to_owned(),
        idempotency_identity: "principal:request-1".to_owned(),
        normalized_digest: ContentDigest::sha256(canonical),
        normalized_envelope: envelope,
        actor_identity: "principal-1".to_owned(),
        created_unix_ms: NOW,
    };
    assert!(!control.record_normalized_trigger(&trigger).unwrap());
    assert!(control.record_normalized_trigger(&trigger).unwrap());
    let mut changed = trigger.clone();
    changed.actor_identity = "principal-2".to_owned();
    assert!(matches!(
        control.record_normalized_trigger(&changed),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    let cursor = ScheduleTriggerCursor {
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        workflow_identity: "sha256:workflow".to_owned(),
        schedule_key: "nightly".to_owned(),
        cron_utc: "0 2 * * *".to_owned(),
        catch_up_policy: "latest".to_owned(),
        maximum_catch_up: 1,
        next_fire_unix_ms: NOW + 100,
        last_fire_unix_ms: None,
        version: 1,
        updated_unix_ms: NOW,
    };
    control.put_schedule_cursor(&cursor, None).unwrap();
    let mut next = cursor.clone();
    next.last_fire_unix_ms = Some(cursor.next_fire_unix_ms);
    next.next_fire_unix_ms += 100;
    next.version = 2;
    next.updated_unix_ms += 100;
    control.put_schedule_cursor(&next, Some(1)).unwrap();
    assert_eq!(
        control
            .schedule_cursor("tenant-1", "repo-1", "sha256:workflow", "nightly")
            .unwrap(),
        next
    );
    let metrics = control
        .workflow_semantics_metrics("tenant-1", next.next_fire_unix_ms)
        .unwrap();
    assert_eq!(metrics.normalized_triggers, 1);
    assert_eq!(metrics.due_schedules, 1);
    assert!(matches!(
        control.put_schedule_cursor(&next, Some(1)),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    let mut unbounded_zero = cursor;
    unbounded_zero.schedule_key = "invalid-zero-bound".to_owned();
    unbounded_zero.catch_up_policy = "all-bounded".to_owned();
    unbounded_zero.maximum_catch_up = 0;
    assert!(matches!(
        control.put_schedule_cursor(&unbounded_zero, None),
        Err(ControlPlaneError::InvalidInput(_))
    ));
}
