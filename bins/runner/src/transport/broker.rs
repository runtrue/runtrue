use super::{conversion::upload_frame_v1, TransportError};
use crate::broker::{ObjectUploadBinding, RunnerBrokerClient};
use ::tonic::transport::Channel;
use runtrue_protocol::{v1, v2};
use std::{
    io::Read as _,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::runtime::Handle;

pub(super) struct TonicRunnerBroker {
    pub(super) client: v1::runner_control_client::RunnerControlClient<Channel>,
    pub(super) object_client:
        v2::runner_object_transfer_client::RunnerObjectTransferClient<Channel>,
    pub(super) runtime: Handle,
    pub(super) session_open: Arc<AtomicBool>,
    pub(super) protocol_version: Arc<AtomicU32>,
}

impl TonicRunnerBroker {
    fn require_open_session(&self) -> Result<(), TransportError> {
        if self.session_open.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(TransportError::NotOpen)
        }
    }

    fn upload_object_v1(
        &self,
        binding: ObjectUploadBinding,
        mut reader: Box<dyn std::io::Read + Send>,
        declared_size: u64,
        timeout: Duration,
    ) -> Result<v1::UploadBlobResponse, TransportError> {
        const CHUNK_BYTES: usize = 256 * 1024;
        const QUEUE_DEPTH: usize = 4;
        let (sender, receiver) = tokio::sync::mpsc::channel(QUEUE_DEPTH);
        let producer = std::thread::spawn(move || -> Result<u64, TransportError> {
            let mut offset = 0_u64;
            let mut buffer = vec![0_u8; CHUNK_BYTES];
            loop {
                let read = reader
                    .read(&mut buffer)
                    .map_err(|_| TransportError::InvalidBlobStream)?;
                if read == 0 {
                    if offset == 0 {
                        sender
                            .blocking_send(upload_frame_v1(&binding, 0, Vec::new()))
                            .map_err(|_| TransportError::InvalidBlobStream)?;
                    }
                    break;
                }
                sender
                    .blocking_send(upload_frame_v1(&binding, offset, buffer[..read].to_vec()))
                    .map_err(|_| TransportError::InvalidBlobStream)?;
                offset = offset
                    .checked_add(read as u64)
                    .ok_or(TransportError::InvalidBlobStream)?;
                if offset > declared_size {
                    return Err(TransportError::InvalidBlobStream);
                }
            }
            if offset != declared_size {
                return Err(TransportError::InvalidBlobStream);
            }
            Ok(offset)
        });
        let mut client = self.client.clone();
        let result = self.runtime.block_on(async move {
            let mut request =
                tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(receiver));
            request.set_timeout(timeout);
            Ok(client.upload_blob(request).await?.into_inner())
        });
        producer
            .join()
            .map_err(|_| TransportError::InvalidBlobStream)??;
        result
    }

    fn upload_object_v2(
        &self,
        binding: ObjectUploadBinding,
        mut reader: Box<dyn std::io::Read + Send>,
        declared_size: u64,
        timeout: Duration,
    ) -> Result<v1::UploadBlobResponse, TransportError> {
        const CHUNK_BYTES: usize = 256 * 1024;
        const QUEUE_DEPTH: usize = 4;
        let (sender, receiver) = tokio::sync::mpsc::channel(QUEUE_DEPTH);
        let producer = std::thread::spawn(move || -> Result<u64, TransportError> {
            sender
                .blocking_send(v2::ObjectUploadFrame {
                    body: Some(v2::object_upload_frame::Body::Header(
                        v2::ObjectUploadHeader {
                            ticket_id: binding.ticket_id,
                            ticket_kind: binding.ticket_kind,
                            execution_lease_id: binding.execution_lease_id,
                            fencing_generation: binding.fencing_generation,
                            job_id: binding.job_id,
                            job_attempt: binding.job_attempt,
                            step_id: binding.step_id,
                            digest_algorithm: binding.declared_digest.algorithm,
                            digest: binding.declared_digest.value,
                            size_bytes: declared_size,
                        },
                    )),
                })
                .map_err(|_| TransportError::InvalidBlobStream)?;
            let mut offset = 0_u64;
            let mut buffer = vec![0_u8; CHUNK_BYTES];
            loop {
                let read = reader
                    .read(&mut buffer)
                    .map_err(|_| TransportError::InvalidBlobStream)?;
                if read == 0 {
                    break;
                }
                sender
                    .blocking_send(v2::ObjectUploadFrame {
                        body: Some(v2::object_upload_frame::Body::Chunk(v2::ObjectChunk {
                            offset,
                            payload: buffer[..read].to_vec(),
                        })),
                    })
                    .map_err(|_| TransportError::InvalidBlobStream)?;
                offset = offset
                    .checked_add(read as u64)
                    .ok_or(TransportError::InvalidBlobStream)?;
                if offset > declared_size {
                    return Err(TransportError::InvalidBlobStream);
                }
            }
            if offset != declared_size {
                return Err(TransportError::InvalidBlobStream);
            }
            Ok(offset)
        });
        let mut client = self.object_client.clone();
        let result = self.runtime.block_on(async move {
            let mut request =
                tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(receiver));
            request.set_timeout(timeout);
            let response = client.upload_object(request).await?.into_inner();
            Ok(v1::UploadBlobResponse {
                digest: Some(v1::Digest {
                    algorithm: response.digest_algorithm,
                    value: response.digest,
                }),
                size_bytes: response.size_bytes,
                already_present: response.already_present,
            })
        });
        producer
            .join()
            .map_err(|_| TransportError::InvalidBlobStream)??;
        result
    }
}

impl RunnerBrokerClient for TonicRunnerBroker {
    fn request_source_ticket(
        &self,
        request: v2::SourceTicketRequest,
        timeout: Duration,
    ) -> Result<v2::SourceTicketResponse, TransportError> {
        self.require_open_session()?;
        let mut client = self.object_client.clone();
        self.runtime.block_on(async move {
            let mut request = tonic::Request::new(request);
            request.set_timeout(timeout);
            Ok(client.request_source_ticket(request).await?.into_inner())
        })
    }

    fn download_source_object_to(
        &self,
        request: v2::ObjectDownloadRequest,
        writer: &mut dyn std::io::Write,
        maximum_bytes: u64,
        timeout: Duration,
    ) -> Result<u64, TransportError> {
        self.require_open_session()?;
        let mut client = self.object_client.clone();
        let expected_algorithm = request.digest_algorithm.clone();
        let expected_digest = request.digest.clone();
        self.runtime.block_on(async move {
            let mut request = tonic::Request::new(request);
            request.set_timeout(timeout);
            let mut stream = client.download_object(request).await?.into_inner();
            let first = stream
                .message()
                .await?
                .ok_or(TransportError::InvalidBlobStream)?;
            let header = match first.body {
                Some(v2::object_download_frame::Body::Header(header)) => header,
                _ => return Err(TransportError::InvalidBlobStream),
            };
            if header.digest_algorithm != expected_algorithm
                || header.digest != expected_digest
                || header.size_bytes > maximum_bytes
            {
                return Err(TransportError::InvalidBlobStream);
            }
            let mut offset = 0_u64;
            while let Some(frame) = stream.message().await? {
                let chunk = match frame.body {
                    Some(v2::object_download_frame::Body::Chunk(chunk)) => chunk,
                    _ => return Err(TransportError::InvalidBlobStream),
                };
                if chunk.offset != offset || chunk.payload.len() > 256 * 1024 {
                    return Err(TransportError::InvalidBlobStream);
                }
                offset = offset
                    .checked_add(chunk.payload.len() as u64)
                    .ok_or(TransportError::InvalidBlobStream)?;
                if offset > header.size_bytes || offset > maximum_bytes {
                    return Err(TransportError::InvalidBlobStream);
                }
                writer
                    .write_all(&chunk.payload)
                    .map_err(|_| TransportError::InvalidBlobStream)?;
            }
            if offset != header.size_bytes {
                return Err(TransportError::InvalidBlobStream);
            }
            Ok(offset)
        })
    }

    fn download_source_object_to_cancellable(
        &self,
        request: v2::ObjectDownloadRequest,
        writer: &mut dyn std::io::Write,
        maximum_bytes: u64,
        timeout: Duration,
        cancelled: Arc<AtomicBool>,
    ) -> Result<u64, TransportError> {
        self.require_open_session()?;
        let mut client = self.object_client.clone();
        let expected_algorithm = request.digest_algorithm.clone();
        let expected_digest = request.digest.clone();
        self.runtime.block_on(async move {
            let mut request = tonic::Request::new(request);
            request.set_timeout(timeout);
            let mut stream = client.download_object(request).await?.into_inner();
            let first = stream
                .message()
                .await?
                .ok_or(TransportError::InvalidBlobStream)?;
            let header = match first.body {
                Some(v2::object_download_frame::Body::Header(header)) => header,
                _ => return Err(TransportError::InvalidBlobStream),
            };
            if header.digest_algorithm != expected_algorithm
                || header.digest != expected_digest
                || header.size_bytes > maximum_bytes
            {
                return Err(TransportError::InvalidBlobStream);
            }
            let mut offset = 0_u64;
            while let Some(frame) = stream.message().await? {
                if cancelled.load(Ordering::Acquire) {
                    return Err(TransportError::TransferCancelled);
                }
                let chunk = match frame.body {
                    Some(v2::object_download_frame::Body::Chunk(chunk)) => chunk,
                    _ => return Err(TransportError::InvalidBlobStream),
                };
                if chunk.offset != offset || chunk.payload.len() > 256 * 1024 {
                    return Err(TransportError::InvalidBlobStream);
                }
                offset = offset
                    .checked_add(chunk.payload.len() as u64)
                    .ok_or(TransportError::InvalidBlobStream)?;
                if offset > header.size_bytes || offset > maximum_bytes {
                    return Err(TransportError::InvalidBlobStream);
                }
                writer
                    .write_all(&chunk.payload)
                    .map_err(|_| TransportError::InvalidBlobStream)?;
            }
            if cancelled.load(Ordering::Acquire) {
                return Err(TransportError::TransferCancelled);
            }
            if offset != header.size_bytes {
                return Err(TransportError::InvalidBlobStream);
            }
            Ok(offset)
        })
    }

    fn request_secret_lease(
        &self,
        request: v1::SecretLeaseRequest,
        timeout: Duration,
    ) -> Result<v1::SecretLeaseResponse, TransportError> {
        self.require_open_session()?;
        let mut client = self.client.clone();
        let mut request = tonic::Request::new(request);
        request.set_timeout(timeout);
        self.runtime
            .block_on(async move { Ok(client.request_secret_lease(request).await?.into_inner()) })
    }

    fn revoke_secret_lease(
        &self,
        request: v1::RevokeSecretLeaseRequest,
        timeout: Duration,
    ) -> Result<(), TransportError> {
        self.require_open_session()?;
        let mut client = self.client.clone();
        let mut request = tonic::Request::new(request);
        request.set_timeout(timeout);
        self.runtime.block_on(async move {
            client.revoke_secret_lease(request).await?;
            Ok(())
        })
    }

    fn mint_oidc_token(
        &self,
        request: v1::OidcTokenRequest,
        timeout: Duration,
    ) -> Result<v1::OidcTokenResponse, TransportError> {
        self.require_open_session()?;
        let mut client = self.client.clone();
        let mut request = tonic::Request::new(request);
        request.set_timeout(timeout);
        self.runtime
            .block_on(async move { Ok(client.mint_oidc_token(request).await?.into_inner()) })
    }

    fn request_cache_ticket(
        &self,
        request: v1::CacheTicketRequest,
        timeout: Duration,
    ) -> Result<v1::CacheTicketResponse, TransportError> {
        self.require_open_session()?;
        let mut client = self.client.clone();
        self.runtime.block_on(async move {
            let mut request = tonic::Request::new(request);
            request.set_timeout(timeout);
            Ok(client.request_cache_ticket(request).await?.into_inner())
        })
    }

    fn commit_cache_entry(
        &self,
        request: v1::CommitCacheEntryRequest,
        timeout: Duration,
    ) -> Result<v1::CommitCacheEntryResponse, TransportError> {
        self.require_open_session()?;
        let mut client = self.client.clone();
        self.runtime.block_on(async move {
            let mut request = tonic::Request::new(request);
            request.set_timeout(timeout);
            Ok(client.commit_cache_entry(request).await?.into_inner())
        })
    }

    fn request_artifact_ticket(
        &self,
        request: v1::ArtifactTicketRequest,
        timeout: Duration,
    ) -> Result<v1::ArtifactTicketResponse, TransportError> {
        self.require_open_session()?;
        let mut client = self.client.clone();
        self.runtime.block_on(async move {
            let mut request = tonic::Request::new(request);
            request.set_timeout(timeout);
            Ok(client.request_artifact_ticket(request).await?.into_inner())
        })
    }

    fn commit_artifact(
        &self,
        request: v1::CommitArtifactRequest,
        timeout: Duration,
    ) -> Result<v1::CommitArtifactResponse, TransportError> {
        self.require_open_session()?;
        let mut client = self.client.clone();
        self.runtime.block_on(async move {
            let mut request = tonic::Request::new(request);
            request.set_timeout(timeout);
            Ok(client.commit_artifact(request).await?.into_inner())
        })
    }

    fn upload_blob(
        &self,
        chunks: Vec<v1::UploadBlobChunk>,
        timeout: Duration,
    ) -> Result<v1::UploadBlobResponse, TransportError> {
        self.require_open_session()?;
        let mut client = self.client.clone();
        self.runtime.block_on(async move {
            let mut request = tonic::Request::new(tokio_stream::iter(chunks));
            request.set_timeout(timeout);
            Ok(client.upload_blob(request).await?.into_inner())
        })
    }

    fn download_blob(
        &self,
        request: v1::DownloadBlobRequest,
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError> {
        self.require_open_session()?;
        let mut client = self.client.clone();
        self.runtime.block_on(async move {
            let mut request = tonic::Request::new(request);
            request.set_timeout(timeout);
            let mut stream = client.download_blob(request).await?.into_inner();
            let mut bytes = Vec::new();
            let mut offset = 0_u64;
            while let Some(chunk) = stream.message().await? {
                if chunk.offset != offset {
                    return Err(TransportError::InvalidBlobStream);
                }
                offset = offset
                    .checked_add(chunk.payload.len() as u64)
                    .ok_or(TransportError::InvalidBlobStream)?;
                bytes.extend_from_slice(&chunk.payload);
            }
            Ok(bytes)
        })
    }

    fn upload_object(
        &self,
        binding: ObjectUploadBinding,
        reader: Box<dyn std::io::Read + Send>,
        declared_size: u64,
        timeout: Duration,
    ) -> Result<v1::UploadBlobResponse, TransportError> {
        self.require_open_session()?;
        match self.protocol_version.load(Ordering::Acquire) {
            2.. => self.upload_object_v2(binding, reader, declared_size, timeout),
            1 => self.upload_object_v1(binding, reader, declared_size, timeout),
            _ => Err(TransportError::NotOpen),
        }
    }

    fn download_object_to(
        &self,
        request: v1::DownloadBlobRequest,
        writer: &mut dyn std::io::Write,
        maximum_bytes: u64,
        timeout: Duration,
    ) -> Result<u64, TransportError> {
        self.require_open_session()?;
        let mut client = self.client.clone();
        self.runtime.block_on(async move {
            let mut request = tonic::Request::new(request);
            request.set_timeout(timeout);
            let mut stream = client.download_blob(request).await?.into_inner();
            let mut offset = 0_u64;
            while let Some(chunk) = stream.message().await? {
                if chunk.offset != offset || chunk.payload.len() > 256 * 1024 {
                    return Err(TransportError::InvalidBlobStream);
                }
                offset = offset
                    .checked_add(chunk.payload.len() as u64)
                    .ok_or(TransportError::InvalidBlobStream)?;
                if offset > maximum_bytes {
                    return Err(TransportError::InvalidBlobStream);
                }
                writer
                    .write_all(&chunk.payload)
                    .map_err(|_| TransportError::InvalidBlobStream)?;
            }
            Ok(offset)
        })
    }
}
