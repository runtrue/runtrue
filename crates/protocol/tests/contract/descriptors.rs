use super::support::*;

#[test]
fn descriptor_covers_the_declared_package_and_messages() {
    let file = protocol_file();
    assert_eq!(file.name.as_deref(), Some("runner/v1/runner.proto"));
    assert_eq!(file.syntax.as_deref(), Some("proto3"));

    let actual = file
        .message_type
        .iter()
        .map(|message| message.name.as_deref().expect("message name"))
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "Digest",
        "EnrollRequest",
        "EnrollResponse",
        "RotateCertificateRequest",
        "RotateCertificateResponse",
        "RunnerInventory",
        "Capability",
        "AttestationEvidence",
        "RunnerMessage",
        "ControlMessage",
        "RunnerHello",
        "ControlHello",
        "Heartbeat",
        "ActiveLease",
        "LeaseOffer",
        "RunnerRequirements",
        "LeaseDecision",
        "FetchExecutionCapsuleRequest",
        "FetchExecutionCapsuleResponse",
        "JobStateUpdate",
        "StepStateUpdate",
        "LogFrame",
        "LogBatch",
        "SecretLeaseRequest",
        "SecretLeaseResponse",
        "RevokeSecretLeaseRequest",
        "OidcTokenRequest",
        "OidcTokenResponse",
        "CacheTicketRequest",
        "CacheTicketResponse",
        "CommitCacheEntryRequest",
        "CommitCacheEntryResponse",
        "ArtifactTicketRequest",
        "ArtifactTicketResponse",
        "CommitArtifactRequest",
        "CommitArtifactResponse",
        "UploadBlobChunk",
        "UploadBlobResponse",
        "DownloadBlobRequest",
        "BlobChunk",
        "CancellationAck",
        "CancelLease",
        "DrainRunner",
        "RotateCertificateNow",
        "InvalidateContent",
        "LocalitySummary",
        "PackageLocality",
        "LocalityClass",
        "RunnerHealth",
        "CompleteLeaseRequest",
        "CompleteLeaseResponse",
    ]);

    assert_eq!(actual.len(), 51);
    assert_eq!(actual, expected);
}

#[test]
fn checked_in_descriptor_hashes_freeze_both_protocol_generations() {
    assert_eq!(FILE_DESCRIPTOR_SET, V1_FILE_DESCRIPTOR_SET);
    for (generation, descriptor, expected) in [
        (
            "v1",
            V1_FILE_DESCRIPTOR_SET,
            include_str!("../fixtures/runner-v1.sha256"),
        ),
        (
            "v2",
            V2_FILE_DESCRIPTOR_SET,
            include_str!("../fixtures/runner-v2.sha256"),
        ),
    ] {
        let actual = hex::encode(Sha256::digest(descriptor));
        assert_eq!(
            actual,
            expected.trim(),
            "{generation} protobuf descriptor changed; compatibility changes must be reviewed and the frozen hash updated intentionally"
        );
    }
}

#[test]
fn generation_two_descriptor_keeps_the_bounded_streaming_skeleton() {
    let file = protocol_v2_file();
    assert_eq!(
        file.name.as_deref(),
        Some("runner/v2/object_transfer.proto")
    );
    assert_eq!(file.syntax.as_deref(), Some("proto3"));
    let service = file
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("RunnerObjectTransfer"))
        .expect("RunnerObjectTransfer service");
    let methods = service
        .method
        .iter()
        .map(|method| {
            (
                method.name.as_deref().expect("method name"),
                method.client_streaming.unwrap_or(false),
                method.server_streaming.unwrap_or(false),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        vec![
            ("RequestSourceTicket", false, false),
            ("DownloadObject", false, true),
            ("UploadObject", true, false),
            ("CompleteLease", false, false),
        ]
    );
}

#[test]
fn descriptor_covers_every_rpc_and_streaming_shape() {
    let file = protocol_file();
    let service = file
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("RunnerControl"))
        .expect("RunnerControl service");
    assert_eq!(file.service.len(), 1);

    let actual = service
        .method
        .iter()
        .map(|method| {
            (
                method.name.as_deref().expect("method name"),
                method.input_type.as_deref().expect("input type"),
                method.output_type.as_deref().expect("output type"),
                method.client_streaming.unwrap_or(false),
                method.server_streaming.unwrap_or(false),
            )
        })
        .collect::<Vec<_>>();
    let expected = vec![
        (
            "Enroll",
            ".runtrue.runner.v1.EnrollRequest",
            ".runtrue.runner.v1.EnrollResponse",
            false,
            false,
        ),
        (
            "RotateCertificate",
            ".runtrue.runner.v1.RotateCertificateRequest",
            ".runtrue.runner.v1.RotateCertificateResponse",
            false,
            false,
        ),
        (
            "Open",
            ".runtrue.runner.v1.RunnerMessage",
            ".runtrue.runner.v1.ControlMessage",
            true,
            true,
        ),
        (
            "FetchExecutionCapsule",
            ".runtrue.runner.v1.FetchExecutionCapsuleRequest",
            ".runtrue.runner.v1.FetchExecutionCapsuleResponse",
            false,
            false,
        ),
        (
            "RequestSecretLease",
            ".runtrue.runner.v1.SecretLeaseRequest",
            ".runtrue.runner.v1.SecretLeaseResponse",
            false,
            false,
        ),
        (
            "RevokeSecretLease",
            ".runtrue.runner.v1.RevokeSecretLeaseRequest",
            ".google.protobuf.Empty",
            false,
            false,
        ),
        (
            "MintOidcToken",
            ".runtrue.runner.v1.OidcTokenRequest",
            ".runtrue.runner.v1.OidcTokenResponse",
            false,
            false,
        ),
        (
            "RequestCacheTicket",
            ".runtrue.runner.v1.CacheTicketRequest",
            ".runtrue.runner.v1.CacheTicketResponse",
            false,
            false,
        ),
        (
            "CommitCacheEntry",
            ".runtrue.runner.v1.CommitCacheEntryRequest",
            ".runtrue.runner.v1.CommitCacheEntryResponse",
            false,
            false,
        ),
        (
            "RequestArtifactTicket",
            ".runtrue.runner.v1.ArtifactTicketRequest",
            ".runtrue.runner.v1.ArtifactTicketResponse",
            false,
            false,
        ),
        (
            "CommitArtifact",
            ".runtrue.runner.v1.CommitArtifactRequest",
            ".runtrue.runner.v1.CommitArtifactResponse",
            false,
            false,
        ),
        (
            "UploadBlob",
            ".runtrue.runner.v1.UploadBlobChunk",
            ".runtrue.runner.v1.UploadBlobResponse",
            true,
            false,
        ),
        (
            "DownloadBlob",
            ".runtrue.runner.v1.DownloadBlobRequest",
            ".runtrue.runner.v1.BlobChunk",
            false,
            true,
        ),
        (
            "CompleteLease",
            ".runtrue.runner.v1.CompleteLeaseRequest",
            ".runtrue.runner.v1.CompleteLeaseResponse",
            false,
            false,
        ),
    ];

    assert_eq!(actual.len(), 14);
    assert_eq!(actual, expected);
}

#[test]
fn explicit_optional_fields_and_numbers_are_stable() {
    let file = protocol_file();
    let actual = file
        .message_type
        .iter()
        .flat_map(|message| {
            message
                .field
                .iter()
                .filter(|field| field.proto3_optional.unwrap_or(false))
                .map(|field| {
                    (
                        message.name.as_deref().expect("message name"),
                        field.name.as_deref().expect("field name"),
                        field.number.expect("field number"),
                    )
                })
        })
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        ("EnrollRequest", "attestation", 4),
        ("RotateCertificateRequest", "attestation", 3),
        ("StepStateUpdate", "exit_code", 6),
        ("CacheTicketRequest", "expected_tree_manifest_digest", 11),
        ("CacheTicketRequest", "user_suffix", 13),
        ("CommitCacheEntryRequest", "expected_generation", 8),
        ("CompleteLeaseRequest", "exit_code", 5),
    ]);

    assert_eq!(actual, expected);
}
