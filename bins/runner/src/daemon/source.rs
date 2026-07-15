use super::error::RunnerError;
use crate::{
    broker::RunnerBrokerClient,
    state::{StateError, WorkspaceManager},
};
use runtrue_git::{GitTreeEntryKind, GitTreeManifest};
use runtrue_model::{ContentDigest, DIGEST_ALGORITHM};
use runtrue_protocol::v2;
use runtrue_runner_core::AdmittedLease;
use std::{
    fs::File,
    io::{Seek as _, SeekFrom},
    path::Path,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

const SOURCE_RPC_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_SOURCE_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn hydrate_source(
    lease: &AdmittedLease,
    workspace: &Path,
    workspaces: &WorkspaceManager,
    broker: Arc<dyn RunnerBrokerClient>,
    cancelled: Arc<AtomicBool>,
) -> Result<ContentDigest, RunnerError> {
    let expected = lease
        .capsule
        .context
        .source_tree_digest
        .as_ref()
        .ok_or_else(|| RunnerError::DataPlane("source digest missing".to_owned()))?;
    let ticket = broker.request_source_ticket(
        v2::SourceTicketRequest {
            execution_lease_id: lease.lease_id.clone(),
            fencing_generation: lease.fencing_generation,
            job_id: lease.job_id.clone(),
            job_attempt: 1,
        },
        SOURCE_RPC_TIMEOUT,
    )?;
    let ticket_digest = digest_from_wire(&ticket.digest_algorithm, &ticket.tree_manifest_digest)?;
    if &ticket_digest != expected || ticket.maximum_bytes == 0 {
        return Err(RunnerError::DataPlane(
            "source ticket binding mismatch".to_owned(),
        ));
    }
    let staging = tempfile::Builder::new()
        .prefix("source-")
        .tempdir_in(workspaces.root())
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    let manifest_limit = ticket.maximum_bytes.min(MAX_SOURCE_MANIFEST_BYTES);
    let cache = workspaces.source_cache();
    let mut consumed = 0_u64;
    if cache
        .reader(expected, manifest_limit)
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?
        .is_none()
    {
        let manifest_path = staging.path().join("manifest");
        let mut manifest_file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&manifest_path)
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
        consumed = download_source_object(
            broker.as_ref(),
            lease,
            &ticket.ticket_id,
            expected,
            &mut manifest_file,
            manifest_limit,
            cancelled.clone(),
        )?;
        manifest_file
            .seek(SeekFrom::Start(0))
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
        cache
            .store(&mut manifest_file, expected, consumed, manifest_limit)
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    }
    let manifest_reader = cache
        .reader(expected, manifest_limit)
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?
        .ok_or_else(|| RunnerError::DataPlane("source manifest cache commit failed".to_owned()))?;
    let manifest: GitTreeManifest = serde_json::from_reader(manifest_reader)
        .map_err(|_| RunnerError::DataPlane("invalid source manifest".to_owned()))?;
    if manifest
        .digest()
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?
        != *expected
    {
        return Err(RunnerError::DataPlane(
            "source manifest digest mismatch".to_owned(),
        ));
    }
    for entry in &manifest.entries {
        let GitTreeEntryKind::File {
            digest, size_bytes, ..
        } = &entry.kind
        else {
            continue;
        };
        if cache
            .reader(digest, *size_bytes)
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?
            .is_some()
        {
            continue;
        }
        let remaining = ticket
            .maximum_bytes
            .checked_sub(consumed)
            .ok_or_else(|| RunnerError::DataPlane("source ticket quota exceeded".to_owned()))?;
        let path = staging
            .path()
            .join(digest.as_str().trim_start_matches("sha256:"));
        let mut file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
        let downloaded = download_source_object(
            broker.as_ref(),
            lease,
            &ticket.ticket_id,
            digest,
            &mut file,
            (*size_bytes).min(remaining),
            cancelled.clone(),
        )?;
        if downloaded != *size_bytes {
            return Err(RunnerError::DataPlane(
                "source blob size does not match its manifest".to_owned(),
            ));
        }
        consumed = consumed
            .checked_add(downloaded)
            .ok_or_else(|| RunnerError::DataPlane("source ticket quota exceeded".to_owned()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
        cache
            .store(&mut file, digest, *size_bytes, *size_bytes)
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    }
    workspaces.materialize_source(workspace, &manifest, ticket.maximum_bytes, |digest| {
        cache
            .reader(digest, ticket.maximum_bytes)?
            .map(|reader| Box::new(reader) as Box<dyn std::io::Read>)
            .ok_or(StateError::SourceIntegrity)
    })?;
    cache
        .complete_snapshot(expected, &manifest)
        .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
    Ok(expected.clone())
}

fn download_source_object(
    broker: &dyn RunnerBrokerClient,
    lease: &AdmittedLease,
    ticket_id: &str,
    digest: &ContentDigest,
    writer: &mut File,
    maximum_bytes: u64,
    cancelled: Arc<AtomicBool>,
) -> Result<u64, RunnerError> {
    let bytes = hex::decode(digest.as_str().trim_start_matches("sha256:"))
        .map_err(|_| RunnerError::DataPlane("invalid source digest".to_owned()))?;
    Ok(broker.download_source_object_to_cancellable(
        v2::ObjectDownloadRequest {
            ticket_id: ticket_id.to_owned(),
            execution_lease_id: lease.lease_id.clone(),
            fencing_generation: lease.fencing_generation,
            job_id: lease.job_id.clone(),
            job_attempt: 1,
            digest_algorithm: DIGEST_ALGORITHM.to_owned(),
            digest: bytes,
        },
        writer,
        maximum_bytes,
        SOURCE_RPC_TIMEOUT,
        cancelled,
    )?)
}

pub(super) fn digest_from_wire(
    algorithm: &str,
    bytes: &[u8],
) -> Result<ContentDigest, RunnerError> {
    if algorithm != DIGEST_ALGORITHM || bytes.len() != 32 {
        return Err(RunnerError::DataPlane("invalid source digest".to_owned()));
    }
    ContentDigest::parse(format!("sha256:{}", hex::encode(bytes)))
        .map_err(|_| RunnerError::DataPlane("invalid source digest".to_owned()))
}
