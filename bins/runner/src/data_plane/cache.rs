use super::{
    patterns::{ensure_real_parent, expand_patterns},
    session::RemoteDataPlaneSession,
    transfer::{
        call_after_lifecycle, declared_inputs_digest, download_tree, temporary_cas, upload_tree,
        UploadContext,
    },
    wire::{canonical_bytes, canonical_json, wire_digest},
};
use crate::daemon::RunnerError;
use runtrue_cache::CacheEntry;
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_runner_core::AdmittedLease;
use runtrue_storage::CasLimits;
use runtrue_workflow_ir::CacheMode;
use std::{fs, sync::atomic::Ordering, time::Duration};
const CACHE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const RPC_TIMEOUT: Duration = Duration::from_secs(60);

impl RemoteDataPlaneSession {
    pub(super) fn restore_cache(&self, step_id: &str, job_attempt: u32) -> Result<(), RunnerError> {
        if self.cache_breaker_open.load(Ordering::Acquire) {
            self.cache_bypassed_operations
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let step = self.step(step_id)?;
        let Some(declaration) = &step.cache else {
            return Ok(());
        };
        if matches!(declaration.mode, CacheMode::WriteOnly) {
            return Ok(());
        }
        let (_temporary, cas) = temporary_cas()?;
        let input_digest = declared_inputs_digest(&cas, &self.workspace, &declaration.inputs)?;
        let ticket_request = cache_ticket_request(
            &self.lease,
            step_id,
            job_attempt,
            "restore",
            declaration
                .max_size_bytes
                .unwrap_or(CasLimits::default().max_tree_total_bytes),
            input_digest,
            None,
        )?;
        let response = call_after_lifecycle(|| {
            self.broker
                .request_cache_ticket(ticket_request.clone(), CACHE_LOOKUP_TIMEOUT)
        })?;
        if response.cache_entry_json.is_empty() {
            return Ok(());
        }
        let entry: CacheEntry = canonical_json(&response.cache_entry_json, "cache entry")?;
        download_tree(
            self.broker.as_ref(),
            &self.lease,
            step_id,
            job_attempt,
            &response.ticket_id,
            &cas,
            &entry.manifest.tree,
        )?;
        let stage = tempfile::tempdir_in(&self.workspace)
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
        let restored = stage.path().join("tree");
        cas.materialize_tree(&entry.manifest.tree.manifest_digest, &restored)
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
        let mut moves = Vec::new();
        for relative in expand_patterns(&restored, &declaration.outputs)? {
            let source = restored.join(&relative);
            if !source.exists() {
                continue;
            }
            let destination = self.workspace.join(&relative);
            if fs::symlink_metadata(&destination).is_ok() {
                return Err(RunnerError::DataPlane(format!(
                    "cache restore destination `{relative}` appeared concurrently"
                )));
            }
            ensure_real_parent(&self.workspace, &relative)?;
            moves.push((source, destination));
        }
        let mut moved = Vec::new();
        for (source, destination) in moves {
            if let Err(error) = fs::rename(&source, &destination) {
                for (previous_source, previous_destination) in moved.into_iter().rev() {
                    let _ = fs::rename(previous_destination, previous_source);
                }
                return Err(RunnerError::DataPlane(error.to_string()));
            }
            moved.push((source, destination));
        }
        Ok(())
    }

    pub(super) fn save_cache(&self, step_id: &str, job_attempt: u32) -> Result<(), RunnerError> {
        if self.cache_breaker_open.load(Ordering::Acquire) {
            self.cache_bypassed_operations
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let step = self.step(step_id)?;
        let Some(declaration) = &step.cache else {
            return Ok(());
        };
        if matches!(declaration.mode, CacheMode::ReadOnly) {
            return Ok(());
        }
        let (temporary, cas) = temporary_cas()?;
        let stage = temporary.path().join("capture");
        fs::create_dir(&stage).map_err(|error| RunnerError::DataPlane(error.to_string()))?;
        let mut captured = 0_usize;
        for relative in expand_patterns(&self.workspace, &declaration.outputs)? {
            let snapshot = match cas.capture_path_beneath(&self.workspace, &relative) {
                Ok(snapshot) => snapshot,
                Err(runtrue_storage::StorageError::NotFound(_)) => continue,
                Err(error) => return Err(RunnerError::DataPlane(error.to_string())),
            };
            let destination = stage.join(&relative);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
            }
            cas.materialize_path(&snapshot, &destination)
                .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
            captured += 1;
        }
        if captured == 0 {
            return Ok(());
        }
        let snapshot = cas
            .capture_tree(&stage)
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
        let input_digest = declared_inputs_digest(&cas, &self.workspace, &declaration.inputs)?;
        let ticket_request = cache_ticket_request(
            &self.lease,
            step_id,
            job_attempt,
            "commit",
            declaration
                .max_size_bytes
                .unwrap_or(CasLimits::default().max_tree_total_bytes),
            input_digest,
            Some(snapshot.manifest_digest.clone()),
        )?;
        let response = call_after_lifecycle(|| {
            self.broker
                .request_cache_ticket(ticket_request.clone(), CACHE_LOOKUP_TIMEOUT)
        })?;
        upload_tree(
            &UploadContext {
                broker: self.broker.as_ref(),
                lease: &self.lease,
                step_id,
                job_attempt,
                ticket_id: &response.ticket_id,
                kind: "cache",
                cas: &cas,
            },
            &snapshot,
        )?;
        let committed = self
            .broker
            .commit_cache_entry(
                v1::CommitCacheEntryRequest {
                    execution_lease_id: self.lease.lease_id.clone(),
                    fencing_generation: self.lease.fencing_generation,
                    ticket_id: response.ticket_id,
                    cache_identity: None,
                    manifest_digest: Some(wire_digest(&snapshot.manifest_digest)?),
                    trust_domain: String::new(),
                    size_bytes: snapshot.total_file_bytes,
                    expected_generation: None,
                    job_attempt,
                    tree_snapshot_json: canonical_bytes(&snapshot)?,
                },
                RPC_TIMEOUT,
            )
            .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
        self.cache_entry_ids
            .lock()
            .map_err(|_| RunnerError::DataPlane("cache result state is poisoned".to_owned()))?
            .insert(committed.cache_entry_id, job_attempt);
        Ok(())
    }
}

fn cache_ticket_request(
    lease: &AdmittedLease,
    step_id: &str,
    job_attempt: u32,
    operation: &str,
    maximum_bytes: u64,
    declared_inputs: ContentDigest,
    expected_tree: Option<ContentDigest>,
) -> Result<v1::CacheTicketRequest, RunnerError> {
    Ok(v1::CacheTicketRequest {
        execution_lease_id: lease.lease_id.clone(),
        fencing_generation: lease.fencing_generation,
        job_id: lease.job_id.clone(),
        step_id: step_id.to_owned(),
        operation: operation.to_owned(),
        cache_identity: None,
        trust_domain: String::new(),
        maximum_bytes,
        job_attempt,
        cache_identity_json: Vec::new(),
        expected_tree_manifest_digest: expected_tree.as_ref().map(wire_digest).transpose()?,
        declared_inputs_digest: Some(wire_digest(&declared_inputs)?),
        user_suffix: None,
    })
}
