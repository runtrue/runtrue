use super::*;
use runtrue_workflow_ir::WorkflowFrontendProvenance;

#[test]
fn workflow_frontend_report_round_trips_only_against_exact_signed_provenance() {
    let control = ControlPlane::open_in_memory("frontend-report-test", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    let bytes = br#"{"status":"partial","unsupported":["strategy.fail-fast"]}"#.to_vec();
    let provenance = WorkflowFrontendProvenance {
        frontend_id: "runtrue.github-actions".to_owned(),
        contract_generation: 1,
        frontend_generation: 3,
        configuration_digest: ContentDigest::sha256(b"frontend config"),
        input_digest: ContentDigest::sha256(b"workflow source"),
        native_digest: ContentDigest::sha256(b"native yaml"),
        report_digest: Some(ContentDigest::sha256(&bytes)),
    };
    let mut capsule = execution_capsule();
    capsule.context.workflow_frontend = Some(provenance);
    let signed = store_test_capsule(&control, "capsule-frontend-report", capsule);
    let record = WorkflowFrontendReportRecord {
        capsule_id: signed.id.clone(),
        media_type: "application/vnd.runtrue.frontend-compatibility+json".to_owned(),
        bytes,
    };

    control.store_workflow_frontend_report(&record).unwrap();
    assert_eq!(
        control
            .workflow_frontend_report("capsule-frontend-report")
            .unwrap(),
        record
    );
    let mut substituted = record;
    substituted.capsule_id = "capsule-1".to_owned();
    assert!(matches!(
        control.store_workflow_frontend_report(&substituted),
        Err(ControlPlaneError::NotFound { .. }) | Err(ControlPlaneError::InvalidInput(_))
    ));
}
