use crate::transport::TransportError;
use runtrue_protocol::{v1, v2};
use std::{
    io::{Read, Write},
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

/// Metadata sent once by the runner before a bounded object byte stream.
#[derive(Debug, Clone)]
pub struct ObjectUploadBinding {
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub job_id: String,
    pub step_id: String,
    pub job_attempt: u32,
    pub ticket_id: String,
    pub ticket_kind: String,
    pub declared_digest: v1::Digest,
}

/// Synchronous facade over the current authenticated runner channel. Calls
/// originate on Wasm adapter worker threads, never on Tokio runtime workers.
pub trait RunnerBrokerClient: Send + Sync {
    fn request_source_ticket(
        &self,
        _request: v2::SourceTicketRequest,
        _timeout: Duration,
    ) -> Result<v2::SourceTicketResponse, TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }

    fn download_source_object_to(
        &self,
        _request: v2::ObjectDownloadRequest,
        _writer: &mut dyn Write,
        _maximum_bytes: u64,
        _timeout: Duration,
    ) -> Result<u64, TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }

    fn download_source_object_to_cancellable(
        &self,
        request: v2::ObjectDownloadRequest,
        writer: &mut dyn Write,
        maximum_bytes: u64,
        timeout: Duration,
        cancelled: Arc<AtomicBool>,
    ) -> Result<u64, TransportError> {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TransportError::TransferCancelled);
        }
        let result = self.download_source_object_to(request, writer, maximum_bytes, timeout)?;
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TransportError::TransferCancelled);
        }
        Ok(result)
    }

    fn request_secret_lease(
        &self,
        request: v1::SecretLeaseRequest,
        timeout: Duration,
    ) -> Result<v1::SecretLeaseResponse, TransportError>;

    fn revoke_secret_lease(
        &self,
        request: v1::RevokeSecretLeaseRequest,
        timeout: Duration,
    ) -> Result<(), TransportError>;

    fn mint_oidc_token(
        &self,
        request: v1::OidcTokenRequest,
        timeout: Duration,
    ) -> Result<v1::OidcTokenResponse, TransportError>;

    fn request_cache_ticket(
        &self,
        _request: v1::CacheTicketRequest,
        _timeout: Duration,
    ) -> Result<v1::CacheTicketResponse, TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }

    fn commit_cache_entry(
        &self,
        _request: v1::CommitCacheEntryRequest,
        _timeout: Duration,
    ) -> Result<v1::CommitCacheEntryResponse, TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }

    fn request_artifact_ticket(
        &self,
        _request: v1::ArtifactTicketRequest,
        _timeout: Duration,
    ) -> Result<v1::ArtifactTicketResponse, TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }

    fn commit_artifact(
        &self,
        _request: v1::CommitArtifactRequest,
        _timeout: Duration,
    ) -> Result<v1::CommitArtifactResponse, TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }

    fn upload_blob(
        &self,
        _chunks: Vec<v1::UploadBlobChunk>,
        _timeout: Duration,
    ) -> Result<v1::UploadBlobResponse, TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }

    fn download_blob(
        &self,
        _request: v1::DownloadBlobRequest,
        _timeout: Duration,
    ) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::DataPlaneUnavailable)
    }

    /// Stream an object from a verified reader. Implementations must bound
    /// their queue; ownership permits a producer thread without borrowing a
    /// caller's stack.
    fn upload_object(
        &self,
        binding: ObjectUploadBinding,
        reader: Box<dyn Read + Send>,
        declared_size: u64,
        timeout: Duration,
    ) -> Result<v1::UploadBlobResponse, TransportError> {
        // Compatibility adapter for in-process generation-one brokers. The
        // configured tonic broker overrides this with a bounded channel.
        let capacity =
            usize::try_from(declared_size).map_err(|_| TransportError::InvalidBlobStream)?;
        let mut bytes = Vec::with_capacity(capacity.min(256 * 1024));
        reader
            .take(declared_size.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| TransportError::InvalidBlobStream)?;
        if bytes.len() as u64 != declared_size {
            return Err(TransportError::InvalidBlobStream);
        }
        let chunks = if bytes.is_empty() {
            vec![object_upload_chunk(&binding, 0, Vec::new())]
        } else {
            bytes
                .chunks(256 * 1024)
                .enumerate()
                .map(|(index, payload)| {
                    object_upload_chunk(&binding, (index * 256 * 1024) as u64, payload.to_vec())
                })
                .collect()
        };
        self.upload_blob(chunks, timeout)
    }

    /// Stream an object directly to caller-owned verified staging.
    fn download_object_to(
        &self,
        request: v1::DownloadBlobRequest,
        writer: &mut dyn Write,
        maximum_bytes: u64,
        timeout: Duration,
    ) -> Result<u64, TransportError> {
        let bytes = self.download_blob(request, timeout)?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(TransportError::InvalidBlobStream);
        }
        writer
            .write_all(&bytes)
            .map_err(|_| TransportError::InvalidBlobStream)?;
        Ok(bytes.len() as u64)
    }
}

fn object_upload_chunk(
    binding: &ObjectUploadBinding,
    offset: u64,
    payload: Vec<u8>,
) -> v1::UploadBlobChunk {
    v1::UploadBlobChunk {
        execution_lease_id: binding.execution_lease_id.clone(),
        fencing_generation: binding.fencing_generation,
        job_id: binding.job_id.clone(),
        step_id: binding.step_id.clone(),
        job_attempt: binding.job_attempt,
        ticket_id: binding.ticket_id.clone(),
        ticket_kind: binding.ticket_kind.clone(),
        declared_digest: Some(binding.declared_digest.clone()),
        offset,
        payload,
    }
}
