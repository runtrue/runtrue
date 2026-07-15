use super::support::*;

#[test]
fn enrollment_negotiation_and_posture_fields_are_additive() {
    let file = protocol_file();
    let request = messages(&file)["EnrollRequest"];
    let request_fields = request
        .field
        .iter()
        .map(|field| {
            (
                field.name.as_deref().expect("request field name"),
                field.number.expect("request field number"),
            )
        })
        .collect::<BTreeSet<_>>();
    assert!(request_fields.contains(&("protocol_min", 5)));
    assert!(request_fields.contains(&("protocol_max", 6)));
    assert!(request_fields.contains(&("ephemeral", 7)));

    let response = messages(&file)["EnrollResponse"];
    let posture = response
        .field
        .iter()
        .find(|field| field.name.as_deref() == Some("authoritative_posture_digest"))
        .expect("additive posture field");
    assert_eq!(posture.number, Some(7));
    assert_eq!(
        posture.type_name.as_deref(),
        Some(".runtrue.runner.v1.Digest")
    );
    let selected = response
        .field
        .iter()
        .find(|field| field.name.as_deref() == Some("selected_protocol_version"))
        .expect("additive selected protocol field");
    assert_eq!(selected.number, Some(8));

    let legacy_shape = v1::EnrollResponse {
        runner_id: "runner-1".to_owned(),
        certificate_chain_pem: b"certificate".to_vec(),
        certificate_expires_at: None,
        runner_pool_id: "pool-1".to_owned(),
        protocol_min: 1,
        protocol_max: 1,
        authoritative_posture_digest: None,
        selected_protocol_version: 0,
    };
    let decoded = v1::EnrollResponse::decode(legacy_shape.encode_to_vec().as_slice()).unwrap();
    assert!(decoded.authoritative_posture_digest.is_none());

    let current = v1::EnrollResponse {
        authoritative_posture_digest: Some(v1::Digest {
            algorithm: "sha256".to_owned(),
            value: vec![9; 32],
        }),
        ..legacy_shape
    };
    assert_message_round_trip(current);
}

#[test]
fn old_and_new_enrollment_messages_decode_each_other() {
    let inventory = v1::RunnerInventory {
        protocol_version: 1,
        ..v1::RunnerInventory::default()
    };
    let current_request = v1::EnrollRequest {
        enrollment_token: "token".to_owned(),
        certificate_signing_request: b"csr".to_vec(),
        inventory: Some(inventory.clone()),
        attestation: None,
        protocol_min: 1,
        protocol_max: 2,
        ephemeral: true,
    };
    let old_decoded = LegacyEnrollRequest::decode(current_request.encode_to_vec().as_slice())
        .expect("old request decoder ignores additive range");
    assert_eq!(old_decoded.enrollment_token, "token");
    assert_eq!(old_decoded.inventory, Some(inventory.clone()));

    let legacy_request = LegacyEnrollRequest {
        enrollment_token: "legacy-token".to_owned(),
        certificate_signing_request: b"legacy-csr".to_vec(),
        inventory: Some(inventory),
        attestation: None,
    };
    let new_decoded = v1::EnrollRequest::decode(legacy_request.encode_to_vec().as_slice())
        .expect("new request decoder accepts absent range");
    assert_eq!((new_decoded.protocol_min, new_decoded.protocol_max), (0, 0));
    assert!(!new_decoded.ephemeral);

    let current_response = v1::EnrollResponse {
        runner_id: "runner".to_owned(),
        certificate_chain_pem: b"certificate".to_vec(),
        certificate_expires_at: None,
        runner_pool_id: "pool".to_owned(),
        protocol_min: 1,
        protocol_max: 2,
        authoritative_posture_digest: Some(v1::Digest {
            algorithm: "sha256".to_owned(),
            value: vec![7; 32],
        }),
        selected_protocol_version: 2,
    };
    let old_response = LegacyEnrollResponse::decode(current_response.encode_to_vec().as_slice())
        .expect("old response decoder ignores additive fields");
    assert_eq!(old_response.protocol_max, 2);

    let legacy_response = LegacyEnrollResponse {
        runner_id: "old-runner".to_owned(),
        certificate_chain_pem: b"old-certificate".to_vec(),
        certificate_expires_at: None,
        runner_pool_id: "old-pool".to_owned(),
        protocol_min: 1,
        protocol_max: 1,
    };
    let new_response = v1::EnrollResponse::decode(legacy_response.encode_to_vec().as_slice())
        .expect("new response decoder accepts absent additive fields");
    assert_eq!(new_response.selected_protocol_version, 0);
    assert!(new_response.authoritative_posture_digest.is_none());
}
