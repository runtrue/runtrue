use super::support::*;

#[test]
fn generation_two_object_frames_and_typed_completion_round_trip_without_redefining_v1() {
    assert_message_round_trip(v2::SourceTicketRequest {
        execution_lease_id: "lease-1".to_owned(),
        fencing_generation: 7,
        job_id: "build".to_owned(),
        job_attempt: 2,
    });
    assert_message_round_trip(v2::ObjectDownloadFrame {
        body: Some(v2::object_download_frame::Body::Header(
            v2::ObjectDownloadHeader {
                digest_algorithm: "sha256".to_owned(),
                digest: vec![7; 32],
                size_bytes: 42,
            },
        )),
    });
    assert_message_round_trip(v2::ObjectDownloadFrame {
        body: Some(v2::object_download_frame::Body::Chunk(v2::ObjectChunk {
            offset: 0,
            payload: b"bounded".to_vec(),
        })),
    });
    assert_message_round_trip(v2::ObjectUploadFrame {
        body: Some(v2::object_upload_frame::Body::Header(
            v2::ObjectUploadHeader {
                ticket_id: "ticket-1".to_owned(),
                ticket_kind: "artifact".to_owned(),
                execution_lease_id: "lease-1".to_owned(),
                fencing_generation: 7,
                job_id: "build".to_owned(),
                job_attempt: 2,
                step_id: "job-finalize".to_owned(),
                digest_algorithm: "sha256".to_owned(),
                digest: vec![8; 32],
                size_bytes: 7,
            },
        )),
    });
    assert_message_round_trip(v2::ObjectUploadFrame {
        body: Some(v2::object_upload_frame::Body::Chunk(v2::ObjectChunk {
            offset: 0,
            payload: b"bounded".to_vec(),
        })),
    });
    assert_message_round_trip(v2::ObjectUploadResponse {
        digest_algorithm: "sha256".to_owned(),
        digest: vec![8; 32],
        size_bytes: 7,
        already_present: false,
    });
    assert_message_round_trip(v2::CompleteLeaseRequest {
        lease_id: "lease-1".to_owned(),
        fencing_generation: 7,
        installation_fencing_epoch: 11,
        final_state: v2::LeaseFinalState::Succeeded as i32,
        exit_code: Some(0),
        error_code: String::new(),
        result_digest_algorithm: "sha256".to_owned(),
        result_digest: vec![9; 32],
        committed_objects: vec![v2::CommittedObject {
            kind: v2::CommittedObjectKind::Artifact as i32,
            object_id: "artifact-1".to_owned(),
            declaration_name: Some("package".to_owned()),
            job_attempt: 2,
        }],
        completed_at: Some(prost_types::Timestamp {
            seconds: 123,
            nanos: 456,
        }),
        final_job_attempt: 2,
        expected_log_frames: 4,
    });
    assert_message_round_trip(v2::CompleteLeaseResponse {
        accepted: true,
        resulting_job_state: v2::LeaseFinalState::Succeeded as i32,
    });
}

#[test]
fn generation_two_typed_completion_fields_are_stable() {
    let file = protocol_v2_file();
    let messages = messages(&file);
    let committed = messages["CommittedObject"];
    let committed_fields = committed
        .field
        .iter()
        .map(|field| {
            (
                field.name.as_deref().expect("field name"),
                field.number.expect("field number"),
                field.proto3_optional.unwrap_or(false),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        committed_fields,
        vec![
            ("kind", 1, false),
            ("object_id", 2, false),
            ("declaration_name", 3, true),
            ("job_attempt", 4, false),
        ]
    );
    let completion = messages["CompleteLeaseRequest"];
    let completion_fields = completion
        .field
        .iter()
        .map(|field| {
            (
                field.name.as_deref().expect("field name"),
                field.number.expect("field number"),
                field.proto3_optional.unwrap_or(false),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        completion_fields,
        vec![
            ("lease_id", 1, false),
            ("fencing_generation", 2, false),
            ("installation_fencing_epoch", 3, false),
            ("final_state", 4, false),
            ("exit_code", 5, true),
            ("error_code", 6, false),
            ("result_digest_algorithm", 7, false),
            ("result_digest", 8, false),
            ("committed_objects", 9, false),
            ("completed_at", 10, false),
            ("final_job_attempt", 11, false),
            ("expected_log_frames", 12, false),
        ]
    );
}
