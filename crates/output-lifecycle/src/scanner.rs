use crate::{LifecycleError, OutputLifecycleWorker};
use runtrue_control_plane::ArtifactScanState;
use runtrue_model::ContentDigest;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    pub tenant_id: String,
    pub artifact_id: String,
    pub artifact_record_digest: ContentDigest,
    pub manifest_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanVerdict {
    Passed(Vec<u8>),
    Failed(Vec<u8>),
}

/// Narrow client interface for an isolated scanner service.
pub trait ArtifactScannerClient {
    fn scan(&self, request: &ScanRequest) -> Result<ScanVerdict, ScannerFailure>;
}

#[derive(Debug, Error)]
#[error("isolated scanner failed with bounded code `{code}`")]
pub struct ScannerFailure {
    pub code: &'static str,
}

impl OutputLifecycleWorker<'_> {
    /// Claim at most one scan. Every authoritative CAS root is verified before
    /// the isolated scanner is called. Outage/error leaves the artifact quarantined.
    pub fn scan_once(
        &self,
        worker_id: &str,
        scanner: &dyn ArtifactScannerClient,
        now_unix_ms: u64,
    ) -> Result<bool, LifecycleError> {
        let Some(claim) = self.control.claim_artifact_scan(
            worker_id,
            now_unix_ms,
            self.limits.gc_lease_duration_ms,
        )?
        else {
            return Ok(false);
        };
        let catalog = self
            .control
            .artifact_for_tenant(&claim.tenant_id, &claim.artifact_id)?;
        let artifact_record_digest = ContentDigest::parse(catalog.artifact_id.as_str())
            .map_err(|_| LifecycleError::ArtifactRecordIdentity)?;
        let artifact = self.artifacts.load(&artifact_record_digest)?;
        if artifact.record.tenant_id != catalog.tenant_id
            || artifact.record.repository_id != catalog.repository_id
            || artifact.record.run_id != catalog.run_id
            || artifact.record.job_id != catalog.job_id
            || artifact.record.name != catalog.output_name
            || artifact.record.content_digest != catalog.content_digest
            || artifact.record.content_digest != catalog.manifest_digest
            || artifact.record.provenance.statement_digest != catalog.provenance_digest
        {
            return Err(LifecycleError::ArtifactCatalogMismatch);
        }
        let request = ScanRequest {
            tenant_id: claim.tenant_id.clone(),
            artifact_id: claim.artifact_id.clone(),
            artifact_record_digest,
            manifest_digest: catalog.manifest_digest,
            provenance_digest: catalog.provenance_digest,
        };
        match scanner.scan(&request) {
            Ok(ScanVerdict::Passed(evidence)) => {
                let Some(digest) = self.persist_scan_evidence_or_finish(
                    &claim.tenant_id,
                    &claim.id,
                    worker_id,
                    &evidence,
                    now_unix_ms,
                )?
                else {
                    return Ok(true);
                };
                self.control.finish_artifact_scan(
                    &claim.tenant_id,
                    &claim.id,
                    worker_id,
                    ArtifactScanState::Passed,
                    Some(&digest),
                    None,
                    now_unix_ms,
                )?;
            }
            Ok(ScanVerdict::Failed(evidence)) => {
                let Some(digest) = self.persist_scan_evidence_or_finish(
                    &claim.tenant_id,
                    &claim.id,
                    worker_id,
                    &evidence,
                    now_unix_ms,
                )?
                else {
                    return Ok(true);
                };
                self.control.finish_artifact_scan(
                    &claim.tenant_id,
                    &claim.id,
                    worker_id,
                    ArtifactScanState::Failed,
                    Some(&digest),
                    None,
                    now_unix_ms,
                )?;
            }
            Err(error) => {
                let error_code = if error.code.is_empty()
                    || error.code.len() > 128
                    || !error.code.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    "scanner-invalid-error"
                } else {
                    error.code
                };
                self.control.finish_artifact_scan(
                    &claim.tenant_id,
                    &claim.id,
                    worker_id,
                    ArtifactScanState::Error,
                    None,
                    Some(error_code),
                    now_unix_ms,
                )?;
            }
        }
        Ok(true)
    }

    fn persist_scan_evidence_or_finish(
        &self,
        tenant_id: &str,
        claim_id: &str,
        worker_id: &str,
        evidence: &[u8],
        now_unix_ms: u64,
    ) -> Result<Option<ContentDigest>, LifecycleError> {
        match self.store_scan_evidence(evidence) {
            Ok(digest) => Ok(Some(digest)),
            Err(LifecycleError::ScanEvidenceLimit) => {
                self.control.finish_artifact_scan(
                    tenant_id,
                    claim_id,
                    worker_id,
                    ArtifactScanState::Error,
                    None,
                    Some("scanner-evidence-limit"),
                    now_unix_ms,
                )?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn store_scan_evidence(&self, evidence: &[u8]) -> Result<ContentDigest, LifecycleError> {
        let size = u64::try_from(evidence.len()).map_err(|_| LifecycleError::IntegerOverflow)?;
        if evidence.is_empty() || size > self.limits.maximum_scan_evidence_bytes {
            return Err(LifecycleError::ScanEvidenceLimit);
        }
        Ok(self.cas.put_bytes(evidence)?.digest)
    }
}

#[cfg(test)]
mod tests {
    use crate::{LifecycleError, LifecycleLimits, OutputLifecycleWorker};
    use runtrue_artifacts::{ArtifactLimits, ArtifactStore};
    use runtrue_control_plane::ControlPlane;
    use runtrue_storage::{CasLimits, FsCas};

    #[test]
    fn scanner_evidence_is_nonempty_bounded_and_cas_verified() {
        let directory = tempfile::tempdir().unwrap();
        let cas = FsCas::open(directory.path().join("cas"), CasLimits::default()).unwrap();
        let artifacts = ArtifactStore::open(
            directory.path().join("artifacts"),
            cas.clone(),
            ArtifactLimits::default(),
        )
        .unwrap();
        let control = ControlPlane::open_in_memory("scan-evidence-test", 1).unwrap();
        let worker = OutputLifecycleWorker::new(
            &control,
            &artifacts,
            LifecycleLimits {
                maximum_scan_evidence_bytes: 4,
                ..LifecycleLimits::default()
            },
        )
        .unwrap();
        assert!(matches!(
            worker.store_scan_evidence(&[]),
            Err(LifecycleError::ScanEvidenceLimit)
        ));
        assert!(matches!(
            worker.store_scan_evidence(b"12345"),
            Err(LifecycleError::ScanEvidenceLimit)
        ));
        let digest = worker.store_scan_evidence(b"pass").unwrap();
        assert_eq!(cas.verify_blob(&digest).unwrap(), 4);
    }
}
