use crate::object_graph::ObjectGraph;
use crate::{GcSummary, LifecycleError, OutputLifecycleWorker};

impl OutputLifecycleWorker<'_> {
    /// Run one fenced mark/sweep cycle. Graphs are decoded from the exact real
    /// cache, artifact, source, and storage manifest formats. Unknown root kinds
    /// remain opaque single-object roots.
    pub fn gc_once(
        &self,
        worker_id: &str,
        lease_token: &str,
        now_unix_ms: u64,
    ) -> Result<GcSummary, LifecycleError> {
        self.control
            .retire_expired_artifacts(now_unix_ms, self.limits.maximum_roots.min(100_000))?;
        self.control.prune_lifecycle_ledgers(
            now_unix_ms,
            self.limits.ledger_retention_ms,
            100_000,
        )?;
        let lease = self.control.acquire_lifecycle_gc(
            worker_id,
            lease_token,
            now_unix_ms,
            self.limits.gc_lease_duration_ms,
        )?;
        let marked_objects = if lease.phase == "marking" {
            let roots =
                self.control
                    .lifecycle_gc_roots(&lease, now_unix_ms, self.limits.maximum_roots)?;
            let marked = ObjectGraph::new(self.cas, self.limits).expand_roots(&roots)?;
            self.control
                .record_lifecycle_gc_marks(&lease, &marked, now_unix_ms)?;
            marked.len()
        } else if lease.phase == "sweeping" {
            usize::try_from(self.control.lifecycle_metrics()?.marked_objects)
                .map_err(|_| LifecycleError::IntegerOverflow)?
        } else {
            return Err(LifecycleError::InvalidGcPhase);
        };

        let inventory = self
            .cas
            .inventory_objects(self.limits.maximum_inventory_objects)?;
        for chunk in inventory.chunks(100_000) {
            let batch = chunk
                .iter()
                .map(|object| {
                    (
                        object.digest.clone(),
                        object.size_bytes,
                        object.created_unix_ms,
                    )
                })
                .collect::<Vec<_>>();
            self.control.observe_lifecycle_gc_inventory(
                &lease,
                &batch,
                now_unix_ms,
                self.limits.safety_horizon_ms,
            )?;
        }
        let candidates = self.control.lifecycle_gc_sweep_candidates(
            &lease,
            now_unix_ms,
            self.limits.safety_horizon_ms,
            100_000,
        )?;
        let mut swept = Vec::with_capacity(candidates.len());
        for (digest, recorded_size) in candidates {
            let actual = self.cas.remove_verified_object(&digest)?;
            if actual.is_some_and(|actual| actual != recorded_size) {
                return Err(LifecycleError::InventoryChanged);
            }
            swept.push((digest, recorded_size));
        }
        self.control
            .complete_lifecycle_gc(&lease, &swept, now_unix_ms)?;
        let swept_bytes = swept.iter().try_fold(0_u64, |total, (_, size)| {
            total
                .checked_add(*size)
                .ok_or(LifecycleError::IntegerOverflow)
        })?;
        Ok(GcSummary {
            generation: lease.generation,
            marked_objects,
            swept_objects: swept.len(),
            swept_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{LifecycleLimits, OutputLifecycleWorker};
    use runtrue_artifacts::{ArtifactLimits, ArtifactStore};
    use runtrue_control_plane::ControlPlane;
    use runtrue_storage::{CasLimits, FsCas, StorageError};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn worker_reclaims_only_after_two_durable_generations() {
        let directory = tempfile::tempdir().unwrap();
        let cas = FsCas::open(directory.path().join("cas"), CasLimits::default()).unwrap();
        let artifacts = ArtifactStore::open(
            directory.path().join("artifacts"),
            cas.clone(),
            ArtifactLimits::default(),
        )
        .unwrap();
        let object = cas.put_bytes(b"two-generation orphan").unwrap();
        let control = ControlPlane::open_in_memory("output-lifecycle-test", 1).unwrap();
        let worker = OutputLifecycleWorker::new(
            &control,
            &artifacts,
            LifecycleLimits {
                maximum_roots: 100,
                maximum_reachable_objects: 100,
                maximum_inventory_objects: 100,
                maximum_manifest_bytes: 1024 * 1024,
                maximum_scan_evidence_bytes: 1024 * 1024,
                safety_horizon_ms: 1,
                gc_lease_duration_ms: 10_000,
                ledger_retention_ms: 10_000,
            },
        )
        .unwrap();
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
            + 10;
        let first = worker.gc_once("gc-worker", "cycle-one", now).unwrap();
        assert_eq!(first.swept_objects, 0);
        assert!(cas.verify_blob(&object.digest).is_ok());
        let interrupted = control
            .acquire_lifecycle_gc("gc-worker", "cycle-two", now + 1, 10_000)
            .unwrap();
        let roots = control
            .lifecycle_gc_roots(&interrupted, now + 1, 100)
            .unwrap();
        control
            .record_lifecycle_gc_marks(&interrupted, &roots, now + 1)
            .unwrap();
        let inventory = cas.inventory_objects(100).unwrap();
        control
            .observe_lifecycle_gc_inventory(
                &interrupted,
                &inventory
                    .iter()
                    .map(|entry| {
                        (
                            entry.digest.clone(),
                            entry.size_bytes,
                            entry.created_unix_ms,
                        )
                    })
                    .collect::<Vec<_>>(),
                now + 1,
                1,
            )
            .unwrap();
        // Simulate a worker restart after mark/inventory but before unlink.
        let second = worker.gc_once("gc-worker", "cycle-two", now + 1).unwrap();
        assert_eq!(second.swept_objects, 1);
        assert_eq!(second.swept_bytes, object.size_bytes);
        assert!(matches!(
            cas.verify_blob(&object.digest),
            Err(StorageError::NotFound(_))
        ));
    }
}
