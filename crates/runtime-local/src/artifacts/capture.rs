use super::{
    ensure_private_artifact_root, load_or_create_signing_key, LocalArtifactCapture,
    LocalArtifactConfig, PreparedArtifact, PreparedArtifacts,
};
use crate::cache::{architecture_name, os_name, relative_path, validate_exact_path};
use rand_core::{OsRng, RngCore as _};
use runtrue_artifacts::{
    ArtifactClassification as StoredArtifactClassification, ArtifactCommitRequest,
    ArtifactProducer, ArtifactScanState, ArtifactStore, ArtifactTicketRequest,
    VerifiedArtifactProvenance,
};
use runtrue_attest::{CapsuleSigningKey, ProvenanceStatement};
use runtrue_model::ContentDigest;
use runtrue_storage::{FsCas, PathSnapshot, StorageError};
use runtrue_workflow_ir::{
    Access, ArtifactClassification as PlannedArtifactClassification, ExecutionCapsule,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

pub(crate) fn prepare_artifacts(
    capsule: &ExecutionCapsule,
    config: &LocalArtifactConfig,
) -> Result<PreparedArtifacts, String> {
    if config.ticket_lifetime_seconds == 0
        || config.ticket_lifetime_seconds > config.artifact_limits.max_ticket_lifetime_seconds
    {
        return Err("local artifact ticket lifetime is outside installation limits".to_owned());
    }
    let capsule_digest = capsule.digest().map_err(|error| error.to_string())?;
    let mut jobs = BTreeMap::new();
    for job in &capsule.jobs {
        if job.outputs.is_empty() {
            continue;
        }
        if job.permissions.artifacts != Access::Write {
            return Err(format!(
                "job {} declares durable outputs without artifacts: write permission",
                job.id
            ));
        }
        let mut paths = BTreeSet::new();
        let mut outputs = Vec::new();
        for (name, output) in &job.outputs {
            let path = validate_exact_path(&output.path)?;
            if !paths.insert(path.clone()) {
                return Err(format!(
                    "job {} declares more than one artifact for path {}",
                    job.id, path
                ));
            }
            let classification = stored_classification(output.classification);
            if !classification.can_upload_directly() {
                return Err(format!(
                    "job {} output {} classification {:?} requires promotion rather than direct capture",
                    job.id, name, classification
                ));
            }
            let retention_seconds = output
                .retention_ms
                .checked_add(999)
                .ok_or("artifact retention overflow")?
                / 1000;
            if retention_seconds == 0
                || retention_seconds > config.artifact_limits.max_retention_seconds
            {
                return Err(format!(
                    "job {} output {} retention is outside installation limits",
                    job.id, name
                ));
            }
            outputs.push(PreparedArtifact {
                job_id: job.id.clone(),
                name: name.clone(),
                path,
                classification,
                retention_seconds,
                runner_os: job.runner.os,
                runner_architecture: job.runner.arch,
            });
        }
        jobs.insert(job.id.clone(), outputs);
    }
    Ok(PreparedArtifacts {
        capsule_digest,
        jobs,
    })
}

pub(crate) const fn stored_classification(
    classification: PlannedArtifactClassification,
) -> StoredArtifactClassification {
    match classification {
        PlannedArtifactClassification::UntrustedBuild => {
            StoredArtifactClassification::UntrustedBuild
        }
        PlannedArtifactClassification::Quarantined => StoredArtifactClassification::Quarantined,
        PlannedArtifactClassification::VerifiedTestOutput => {
            StoredArtifactClassification::VerifiedTestOutput
        }
        PlannedArtifactClassification::ReleaseCandidate => {
            StoredArtifactClassification::ReleaseCandidate
        }
        PlannedArtifactClassification::PromotedRelease => {
            StoredArtifactClassification::PromotedRelease
        }
        PlannedArtifactClassification::Sensitive => StoredArtifactClassification::Sensitive,
        PlannedArtifactClassification::Public => StoredArtifactClassification::Public,
    }
}

pub(crate) fn open_artifact_runtime(
    config: &LocalArtifactConfig,
) -> Result<(ArtifactStore, CapsuleSigningKey), String> {
    ensure_private_artifact_root(config)?;
    let cas = FsCas::open(config.artifact_root.join("cas"), config.cas_limits)
        .map_err(|error| error.to_string())?;
    let store = ArtifactStore::open(
        config.artifact_root.join("metadata"),
        cas,
        config.artifact_limits,
    )
    .map_err(|error| error.to_string())?;
    let signing_key = load_or_create_signing_key(
        &config.artifact_root,
        &config.artifact_root.join("local-signing-key"),
    )?;
    Ok((store, signing_key))
}

pub(crate) fn new_local_lease_id() -> Result<String, String> {
    let mut nonce = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| "operating system randomness is unavailable".to_owned())?;
    let digest = ContentDigest::sha256(nonce);
    nonce.zeroize();
    Ok(format!("local-artifact-lease:{digest}"))
}

pub(crate) fn capture_one_artifact(
    store: &ArtifactStore,
    signing_key: &CapsuleSigningKey,
    config: &LocalArtifactConfig,
    capsule: &ExecutionCapsule,
    capsule_digest: &ContentDigest,
    output: &PreparedArtifact,
    lease_id: &str,
) -> Result<LocalArtifactCapture, String> {
    let source = config.workspace.join(relative_path(&output.path));
    // Snapshot first so tickets are issued only for content that passed the
    // safe filesystem walk, and bind the ticket to that exact digest rather
    // than granting a store-wide byte allowance.
    let snapshot = match store
        .cas()
        .capture_path_beneath(&config.workspace, &output.path)
    {
        Ok(snapshot) => snapshot,
        Err(StorageError::NotFound(_)) => {
            return Err(format!(
                "declared output path {} does not exist",
                output.path
            ))
        }
        Err(error) => return Err(error.to_string()),
    };
    let (content_digest, size_bytes, media_type) = snapshot_artifact_identity(&snapshot);
    if size_bytes > config.artifact_limits.max_artifact_bytes {
        return Err(format!(
            "artifact size {size_bytes} exceeds installation bound {}",
            config.artifact_limits.max_artifact_bytes
        ));
    }
    let now = unix_seconds()?;
    let expires = now
        .checked_add(config.ticket_lifetime_seconds)
        .ok_or("artifact ticket expiry overflow")?;
    let retention_until = now
        .checked_add(output.retention_seconds)
        .ok_or("artifact retention overflow")?;
    let fencing_generation = 1;
    let run_id = format!(
        "{}:{}:{}",
        capsule_digest,
        os_name(output.runner_os),
        architecture_name(output.runner_architecture)
    );
    let ticket = store
        .issue_ticket(ArtifactTicketRequest {
            tenant_id: config.tenant_id.clone(),
            repository_id: config.repository_id.clone(),
            run_id,
            job_id: output.job_id.clone(),
            job_attempt: 1,
            step_id: "job-finalize".to_owned(),
            lease_id: lease_id.to_owned(),
            fencing_generation,
            name: output.name.clone(),
            classification: output.classification,
            // Empty files/directories have a declared size of zero, while the
            // ticket protocol deliberately requires a positive upper bound.
            max_bytes: size_bytes.max(1),
            expected_content_digest: Some(content_digest.clone()),
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: expires,
        })
        .map_err(|error| error.to_string())?;

    let mut policy_version_ids = capsule.context.policy_version_ids.clone();
    policy_version_ids.sort();
    policy_version_ids.dedup();
    let producer = ArtifactProducer {
        capsule_digest: capsule_digest.clone(),
        workflow_digest: capsule.workflow.digest.clone(),
        source_repository: config.repository_id.clone(),
        source_commit: capsule.context.source_commit.clone(),
        runner_id: config.runner_id.clone(),
        runner_image_digest: config.runner_image_digest.clone(),
        runner_attestation_digest: None,
    };
    let statement = ProvenanceStatement {
        statement_version: 1,
        source_repository: config.repository_id.clone(),
        source_commit: capsule.context.source_commit.clone(),
        workflow_digest: capsule.workflow.digest.clone(),
        capsule_digest: capsule_digest.clone(),
        workflow_frontend: capsule.context.workflow_frontend.clone(),
        builder_id: config.runner_id.clone(),
        runner_image_digest: config.runner_image_digest.clone(),
        parity_grade: capsule.expected_parity,
        resolved_dependencies: Vec::new(),
        inputs: BTreeMap::from([(
            "normalized-event".to_owned(),
            capsule.context.normalized_event_digest.clone(),
        )]),
        outputs: BTreeMap::from([(output.name.clone(), content_digest.clone())]),
        policy_version_ids,
    };
    let signed = signing_key
        .sign_provenance(&statement)
        .map_err(|error| error.to_string())?;
    let verifying_key = signing_key.verifying_key();
    let handle = store
        .commit(&ArtifactCommitRequest {
            ticket: &ticket,
            active_lease_id: lease_id,
            active_fencing_generation: fencing_generation,
            now_unix_seconds: now,
            source: &source,
            declared_content_digest: content_digest.clone(),
            declared_size_bytes: size_bytes,
            media_type,
            retention_until_unix_seconds: retention_until,
            legal_hold: false,
            scan_state: ArtifactScanState::Pending,
            producer,
            provenance: VerifiedArtifactProvenance {
                signed: &signed,
                verifying_key: &verifying_key,
            },
        })
        .map_err(|error| error.to_string())?;
    Ok(LocalArtifactCapture {
        job_id: output.job_id.clone(),
        output_name: output.name.clone(),
        source_path: output.path.clone(),
        artifact_id: handle.artifact_id,
        content_digest,
        classification: output.classification,
        retention_until_unix_seconds: retention_until,
    })
}

pub(crate) fn snapshot_artifact_identity(snapshot: &PathSnapshot) -> (ContentDigest, u64, String) {
    match snapshot {
        PathSnapshot::File {
            digest, size_bytes, ..
        } => (
            digest.clone(),
            *size_bytes,
            "application/octet-stream".to_owned(),
        ),
        PathSnapshot::Directory {
            manifest_digest,
            total_file_bytes,
            ..
        } => (
            manifest_digest.clone(),
            *total_file_bytes,
            "application/vnd.runtrue.directory+json".to_owned(),
        ),
    }
}

pub(crate) fn unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())
        .map(|duration| duration.as_secs())
}
