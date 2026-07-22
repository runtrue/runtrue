use crate::*;
use runtrue_attest::{CapsuleSigningKey, ProvenanceStatement, SignedProvenance};
use runtrue_model::ContentDigest;
use runtrue_storage::{CasLimits, FsCas, PathSnapshot, StorageError};
use runtrue_workflow_ir::ParityGrade;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};
use tempfile::tempdir;

const NOW: u64 = 10_000;

fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}

fn test_store() -> (tempfile::TempDir, ArtifactStore) {
    let directory = tempdir().unwrap();
    let cas = FsCas::open(directory.path().join("cas"), CasLimits::default()).unwrap();
    let store = ArtifactStore::open(
        directory.path().join("artifacts"),
        cas,
        ArtifactLimits::default(),
    )
    .unwrap();
    (directory, store)
}

fn object_path(cas: &FsCas, digest: &ContentDigest) -> PathBuf {
    let encoded = digest.as_str().strip_prefix("sha256:").unwrap();
    cas.root()
        .join("objects/sha256")
        .join(&encoded[..2])
        .join(&encoded[2..])
}

fn ticket_request(
    classification: ArtifactClassification,
    expected: Option<ContentDigest>,
    size: u64,
) -> ArtifactTicketRequest {
    ArtifactTicketRequest {
        tenant_id: "tenant".to_owned(),
        repository_id: "repository".to_owned(),
        run_id: "run-1".to_owned(),
        job_id: "build".to_owned(),
        job_attempt: 1,
        step_id: "package".to_owned(),
        lease_id: "lease-1".to_owned(),
        fencing_generation: 7,
        name: "package".to_owned(),
        classification,
        max_bytes: size,
        expected_content_digest: expected,
        issued_at_unix_seconds: NOW,
        expires_at_unix_seconds: NOW + 300,
    }
}

fn producer() -> ArtifactProducer {
    ArtifactProducer {
        capsule_digest: digest("capsule"),
        workflow_digest: digest("workflow"),
        source_repository: "acme/widget".to_owned(),
        source_commit: "0123456789abcdef".to_owned(),
        runner_id: "runner-1".to_owned(),
        runner_image_digest: digest("runner-image"),
        runner_attestation_digest: Some(digest("runner-attestation")),
    }
}

fn signed_provenance(
    key: &CapsuleSigningKey,
    name: &str,
    output: ContentDigest,
    producer: &ArtifactProducer,
) -> SignedProvenance {
    let mut outputs = BTreeMap::new();
    outputs.insert(name.to_owned(), output);
    key.sign_provenance(&ProvenanceStatement {
        statement_version: 1,
        source_repository: producer.source_repository.clone(),
        source_commit: producer.source_commit.clone(),
        workflow_digest: producer.workflow_digest.clone(),
        capsule_digest: producer.capsule_digest.clone(),
        workflow_frontend: None,
        builder_id: producer.runner_id.clone(),
        runner_image_digest: producer.runner_image_digest.clone(),
        parity_grade: ParityGrade::AExact,
        resolved_dependencies: Vec::new(),
        inputs: BTreeMap::new(),
        outputs,
        policy_version_ids: Vec::new(),
    })
    .unwrap()
}

fn commit_file(
    store: &ArtifactStore,
    directory: &Path,
    bytes: &[u8],
    classification: ArtifactClassification,
    scan_state: ArtifactScanState,
) -> (ArtifactTicket, ArtifactHandle) {
    let source = directory.join(format!("source-{}", bytes.len()));
    fs::write(&source, bytes).unwrap();
    let content_digest = ContentDigest::sha256(bytes);
    let ticket = store
        .issue_ticket(ticket_request(
            classification,
            Some(content_digest.clone()),
            bytes.len() as u64,
        ))
        .unwrap();
    let producer = producer();
    let key = CapsuleSigningKey::generate().unwrap();
    let signed = signed_provenance(&key, &ticket.name, content_digest.clone(), &producer);
    let handle = store
        .commit(&ArtifactCommitRequest {
            ticket: &ticket,
            active_lease_id: "lease-1",
            active_fencing_generation: 7,
            now_unix_seconds: NOW + 1,
            source: &source,
            declared_content_digest: content_digest,
            declared_size_bytes: bytes.len() as u64,
            media_type: "application/octet-stream".to_owned(),
            retention_until_unix_seconds: NOW + 3_600,
            legal_hold: false,
            scan_state,
            producer,
            provenance: VerifiedArtifactProvenance {
                signed: &signed,
                verifying_key: &key.verifying_key(),
            },
        })
        .unwrap();
    (ticket, handle)
}

mod commit;
mod corruption;
mod filesystem;
mod promotion;
mod provenance;
mod snapshot;
mod ticket;
