use super::{conversion::completion_v2_to_v1, *};
use runtrue_protocol::v2;
use std::path::PathBuf;

#[test]
fn plaintext_is_limited_to_explicit_ip_loopback_and_https_requires_mtls() {
    let mut base = EndpointSecurity {
        endpoint: "http://127.0.0.1:9".to_owned(),
        ca_certificate: None,
        client_certificate: None,
        client_private_key: None,
        insecure_loopback: false,
    };
    assert!(matches!(
        base.validate_configuration(),
        Err(TransportError::InsecureEndpoint)
    ));
    base.insecure_loopback = true;
    base.validate_configuration().unwrap();
    let mut remote = base.clone();
    remote.endpoint = "http://192.0.2.1:9".to_owned();
    assert!(matches!(
        remote.validate_configuration(),
        Err(TransportError::InsecureEndpoint)
    ));
    let mut tls = base;
    tls.endpoint = "https://runner.example.invalid".to_owned();
    tls.insecure_loopback = false;
    assert!(matches!(
        tls.validate_configuration(),
        Err(TransportError::MissingMutualTls)
    ));
    let enrollment = EnrollmentEndpointSecurity {
        endpoint: "http://127.0.0.1:9".to_owned(),
        ca_certificate: PathBuf::from("unused.pem"),
    };
    assert!(matches!(
        enrollment.validate_configuration(),
        Err(TransportError::EnrollmentRequiresTls)
    ));
}

#[test]
fn typed_completion_adapter_preserves_kinds_names_and_attempts() {
    let request = v2::CompleteLeaseRequest {
        lease_id: "lease-1".to_owned(),
        fencing_generation: 3,
        installation_fencing_epoch: 8,
        final_state: v2::LeaseFinalState::Succeeded as i32,
        exit_code: Some(0),
        error_code: String::new(),
        result_digest_algorithm: "sha256".to_owned(),
        result_digest: vec![7; 32],
        committed_objects: vec![
            v2::CommittedObject {
                kind: v2::CommittedObjectKind::Artifact as i32,
                object_id: "artifact-1".to_owned(),
                declaration_name: Some("package".to_owned()),
                job_attempt: 2,
            },
            v2::CommittedObject {
                kind: v2::CommittedObjectKind::Cache as i32,
                object_id: "cache-1".to_owned(),
                declaration_name: None,
                job_attempt: 2,
            },
        ],
        completed_at: Some(prost_types::Timestamp {
            seconds: 1,
            nanos: 0,
        }),
        final_job_attempt: 2,
        expected_log_frames: 3,
    };
    let legacy = completion_v2_to_v1(request).unwrap();
    assert_eq!(legacy.final_state, "succeeded");
    assert_eq!(legacy.artifact_ids, ["artifact-1"]);
    assert_eq!(legacy.cache_entry_ids, ["cache-1"]);
    assert_eq!(legacy.expected_log_frames, 3);
}

#[test]
fn typed_completion_adapter_rejects_unknown_or_misshaped_objects() {
    let mut request = v2::CompleteLeaseRequest {
        final_state: v2::LeaseFinalState::Succeeded as i32,
        committed_objects: vec![v2::CommittedObject {
            kind: v2::CommittedObjectKind::Cache as i32,
            object_id: "cache-1".to_owned(),
            declaration_name: Some("must-be-absent".to_owned()),
            job_attempt: 1,
        }],
        final_job_attempt: 1,
        ..v2::CompleteLeaseRequest::default()
    };
    assert!(matches!(
        completion_v2_to_v1(request.clone()),
        Err(TransportError::InvalidBlobStream)
    ));
    request.committed_objects[0].declaration_name = None;
    request.committed_objects[0].kind = 99;
    assert!(matches!(
        completion_v2_to_v1(request),
        Err(TransportError::InvalidBlobStream)
    ));
}
