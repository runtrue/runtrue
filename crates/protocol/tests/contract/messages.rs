use super::support::*;

#[test]
fn runner_and_control_oneof_arms_are_stable() {
    let file = protocol_file();
    let messages = messages(&file);

    for (message_name, expected) in [
        (
            "RunnerMessage",
            vec![
                ("hello", 1),
                ("heartbeat", 2),
                ("lease_decision", 3),
                ("job_state", 4),
                ("step_state", 5),
                ("log_batch", 6),
                ("cancellation_ack", 7),
                ("locality", 8),
                ("health", 9),
            ],
        ),
        (
            "ControlMessage",
            vec![
                ("hello", 1),
                ("lease_offer", 2),
                ("cancel_lease", 3),
                ("drain_runner", 4),
                ("rotate_certificate", 5),
                ("invalidate_content", 6),
            ],
        ),
    ] {
        let message = messages[message_name];
        assert_eq!(message.oneof_decl.len(), 1);
        assert_eq!(message.oneof_decl[0].name.as_deref(), Some("body"));
        let actual = message
            .field
            .iter()
            .filter(|field| field.oneof_index == Some(0))
            .map(|field| {
                (
                    field.name.as_deref().expect("field name"),
                    field.number.expect("field number"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
}

#[test]
fn generated_oneof_arms_round_trip() {
    use v1::{control_message, runner_message};

    let runner_arms = vec![
        runner_message::Body::Hello(v1::RunnerHello::default()),
        runner_message::Body::Heartbeat(v1::Heartbeat::default()),
        runner_message::Body::LeaseDecision(v1::LeaseDecision::default()),
        runner_message::Body::JobState(v1::JobStateUpdate::default()),
        runner_message::Body::StepState(v1::StepStateUpdate::default()),
        runner_message::Body::LogBatch(v1::LogBatch::default()),
        runner_message::Body::CancellationAck(v1::CancellationAck::default()),
        runner_message::Body::Locality(v1::LocalitySummary::default()),
        runner_message::Body::Health(v1::RunnerHealth::default()),
    ];
    for body in runner_arms {
        assert_message_round_trip(v1::RunnerMessage { body: Some(body) });
    }

    let control_arms = vec![
        control_message::Body::Hello(v1::ControlHello::default()),
        control_message::Body::LeaseOffer(Box::default()),
        control_message::Body::CancelLease(v1::CancelLease::default()),
        control_message::Body::DrainRunner(v1::DrainRunner::default()),
        control_message::Body::RotateCertificate(v1::RotateCertificateNow::default()),
        control_message::Body::InvalidateContent(v1::InvalidateContent::default()),
    ];
    for body in control_arms {
        assert_message_round_trip(v1::ControlMessage { body: Some(body) });
    }
}

#[test]
fn explicit_optional_zero_values_round_trip_with_presence() {
    assert_message_round_trip(v1::EnrollRequest {
        attestation: Some(v1::AttestationEvidence::default()),
        ..v1::EnrollRequest::default()
    });
    assert_message_round_trip(v1::RotateCertificateRequest {
        attestation: Some(v1::AttestationEvidence::default()),
        ..v1::RotateCertificateRequest::default()
    });
    assert_message_round_trip(v1::StepStateUpdate {
        exit_code: Some(0),
        ..v1::StepStateUpdate::default()
    });
    assert_message_round_trip(v1::CommitCacheEntryRequest {
        expected_generation: Some(0),
        ..v1::CommitCacheEntryRequest::default()
    });
    assert_message_round_trip(v1::CompleteLeaseRequest {
        exit_code: Some(0),
        ..v1::CompleteLeaseRequest::default()
    });
}
