use super::{
    patterns::expand_pattern,
    wire::{canonical_bytes, canonical_json, wire_digest},
};
use crate::{
    broker::{ObjectUploadBinding, RunnerBrokerClient},
    daemon::RunnerError,
};
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_runner_core::AdmittedLease;
use runtrue_storage::{CasLimits, FsCas, PathSnapshot, TreeEntryKind, TreeManifest, TreeSnapshot};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    io::{Seek, SeekFrom},
    path::Path,
    thread,
    time::Duration,
};
use tempfile::TempDir;

const CACHE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(10);
const LIFECYCLE_RETRY_ATTEMPTS: usize = 5;
const RPC_TIMEOUT: Duration = Duration::from_secs(60);

pub(super) fn call_after_lifecycle<T>(
    mut operation: impl FnMut() -> Result<T, crate::transport::TransportError>,
) -> Result<T, RunnerError> {
    for attempt in 0..LIFECYCLE_RETRY_ATTEMPTS {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error)
                if error.is_data_plane_state_not_observed()
                    && attempt + 1 < LIFECYCLE_RETRY_ATTEMPTS =>
            {
                thread::sleep(Duration::from_millis(10_u64 << attempt));
            }
            Err(error) => return Err(RunnerError::DataPlane(error.to_string())),
        }
    }
    Err(RunnerError::DataPlane(
        "runner lifecycle synchronization retry bound exhausted".to_owned(),
    ))
}

pub(super) struct UploadContext<'a> {
    pub(super) broker: &'a dyn RunnerBrokerClient,
    pub(super) lease: &'a AdmittedLease,
    pub(super) step_id: &'a str,
    pub(super) job_attempt: u32,
    pub(super) ticket_id: &'a str,
    pub(super) kind: &'a str,
    pub(super) cas: &'a FsCas,
}

pub(super) fn upload_snapshot(
    context: &UploadContext<'_>,
    snapshot: &PathSnapshot,
) -> Result<(), RunnerError> {
    match snapshot {
        PathSnapshot::File { digest, .. } => upload_digest(context, digest),
        PathSnapshot::Directory {
            manifest_digest, ..
        } => {
            let tree = context
                .cas
                .inspect_tree(manifest_digest)
                .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
            upload_tree(context, &tree)
        }
    }
}

pub(super) fn upload_tree(
    context: &UploadContext<'_>,
    snapshot: &TreeSnapshot,
) -> Result<(), RunnerError> {
    let manifest = context
        .cas
        .load_tree_manifest(&snapshot.manifest_digest)
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    upload_digest(context, &snapshot.manifest_digest)?;
    let mut digests = manifest
        .entries
        .iter()
        .filter_map(|entry| match &entry.kind {
            TreeEntryKind::File { digest, .. } => Some(digest.clone()),
            TreeEntryKind::Directory => None,
        })
        .collect::<BTreeSet<_>>();
    for digest in std::mem::take(&mut digests) {
        upload_digest(context, &digest)?;
    }
    Ok(())
}

fn upload_digest(context: &UploadContext<'_>, digest: &ContentDigest) -> Result<(), RunnerError> {
    let reader = context
        .cas
        .verified_reader(digest, context.cas.limits().max_blob_bytes)
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    let size_bytes = reader.size_bytes();
    let wire = wire_digest(digest)?;
    let response = context
        .broker
        .upload_object(
            ObjectUploadBinding {
                execution_lease_id: context.lease.lease_id.clone(),
                fencing_generation: context.lease.fencing_generation,
                job_id: context.lease.job_id.clone(),
                step_id: context.step_id.to_owned(),
                job_attempt: context.job_attempt,
                ticket_id: context.ticket_id.to_owned(),
                ticket_kind: context.kind.to_owned(),
                declared_digest: wire,
            },
            Box::new(reader),
            size_bytes,
            if context.kind == "cache" {
                CACHE_TRANSFER_TIMEOUT
            } else {
                RPC_TIMEOUT
            },
        )
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    let actual = response
        .digest
        .as_ref()
        .ok_or_else(|| RunnerError::DataPlane("upload response omitted its digest".to_owned()))?;
    let actual = ContentDigest::try_from(actual)
        .map_err(|_| RunnerError::DataPlane("upload response digest is invalid".to_owned()))?;
    if actual != *digest || response.size_bytes != size_bytes {
        return Err(RunnerError::DataPlane(
            "upload response does not match the source blob".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn download_tree(
    broker: &dyn RunnerBrokerClient,
    lease: &AdmittedLease,
    step_id: &str,
    job_attempt: u32,
    ticket_id: &str,
    cas: &FsCas,
    snapshot: &TreeSnapshot,
) -> Result<(), RunnerError> {
    download_digest_to_cas(
        broker,
        lease,
        step_id,
        job_attempt,
        ticket_id,
        &snapshot.manifest_digest,
        cas,
        cas.limits().max_manifest_bytes,
    )?;
    let manifest_bytes = cas
        .read_blob_limited(&snapshot.manifest_digest, cas.limits().max_manifest_bytes)
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    let manifest: TreeManifest = canonical_json(&manifest_bytes, "cache tree manifest")?;
    for (digest, size_bytes) in manifest
        .entries
        .iter()
        .filter_map(|entry| match &entry.kind {
            TreeEntryKind::File {
                digest, size_bytes, ..
            } => Some((digest, *size_bytes)),
            TreeEntryKind::Directory => None,
        })
    {
        download_digest_to_cas(
            broker,
            lease,
            step_id,
            job_attempt,
            ticket_id,
            digest,
            cas,
            size_bytes,
        )?;
    }
    cas.inspect_tree(&snapshot.manifest_digest)
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn download_digest_to_cas(
    broker: &dyn RunnerBrokerClient,
    lease: &AdmittedLease,
    step_id: &str,
    job_attempt: u32,
    ticket_id: &str,
    digest: &ContentDigest,
    cas: &FsCas,
    expected_size: u64,
) -> Result<(), RunnerError> {
    let mut staging =
        tempfile::tempfile().map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    let received = broker
        .download_object_to(
            v1::DownloadBlobRequest {
                execution_lease_id: lease.lease_id.clone(),
                fencing_generation: lease.fencing_generation,
                job_id: lease.job_id.clone(),
                step_id: step_id.to_owned(),
                job_attempt,
                ticket_id: ticket_id.to_owned(),
                digest: Some(wire_digest(digest)?),
            },
            &mut staging,
            expected_size,
            CACHE_TRANSFER_TIMEOUT,
        )
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    if received != expected_size {
        return Err(RunnerError::DataPlane(
            "downloaded object size mismatch".to_owned(),
        ));
    }
    staging
        .seek(SeekFrom::Start(0))
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    cas.put_verified_reader(staging, digest, expected_size, expected_size.max(1))
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    Ok(())
}

pub(super) fn declared_inputs_digest(
    cas: &FsCas,
    workspace: &Path,
    inputs: &[String],
) -> Result<ContentDigest, RunnerError> {
    #[derive(Serialize)]
    struct Input {
        pattern: String,
        path: String,
        snapshot: Option<PathSnapshot>,
    }
    let mut records = Vec::new();
    for pattern in inputs {
        let paths = expand_pattern(workspace, pattern)?;
        if paths.is_empty() {
            records.push(Input {
                pattern: pattern.clone(),
                path: String::new(),
                snapshot: None,
            });
        } else {
            for relative in paths {
                let snapshot = match cas.capture_path_beneath(workspace, &relative) {
                    Ok(snapshot) => Some(snapshot),
                    Err(runtrue_storage::StorageError::NotFound(_)) => None,
                    Err(error) => return Err(RunnerError::DataPlane(error.to_string())),
                };
                records.push(Input {
                    pattern: pattern.clone(),
                    path: relative,
                    snapshot,
                });
            }
        }
    }
    records.sort_by(|left, right| (&left.pattern, &left.path).cmp(&(&right.pattern, &right.path)));
    Ok(ContentDigest::sha256(canonical_bytes(&records)?))
}

pub(super) fn temporary_cas() -> Result<(TempDir, FsCas), RunnerError> {
    let temporary =
        tempfile::tempdir().map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    let cas = FsCas::open(temporary.path().join("cas"), CasLimits::default())
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    Ok((temporary, cas))
}
