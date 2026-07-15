use super::support::*;

#[test]
fn tonic_client_and_server_contracts_are_generated() {
    fn assert_server_trait_is_public<T: v1::runner_control_server::RunnerControl>() {}
    fn assert_v2_server_trait_is_public<
        T: v2::runner_object_transfer_server::RunnerObjectTransfer,
    >() {
    }

    let _ = std::any::TypeId::of::<
        v1::runner_control_client::RunnerControlClient<tonic::transport::Channel>,
    >();
    assert_server_trait_is_public::<UnimplementedRunnerControl>();
    let _ = std::any::TypeId::of::<
        v2::runner_object_transfer_client::RunnerObjectTransferClient<tonic::transport::Channel>,
    >();
    assert_v2_server_trait_is_public::<UnimplementedRunnerObjectTransfer>();
}

#[derive(Debug, Default)]
struct UnimplementedRunnerControl;

#[tonic::async_trait]
impl v1::runner_control_server::RunnerControl for UnimplementedRunnerControl {
    type OpenStream = tonic::codec::Streaming<v1::ControlMessage>;
    type DownloadBlobStream = tonic::codec::Streaming<v1::BlobChunk>;

    async fn enroll(
        &self,
        _request: tonic::Request<v1::EnrollRequest>,
    ) -> Result<tonic::Response<v1::EnrollResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn rotate_certificate(
        &self,
        _request: tonic::Request<v1::RotateCertificateRequest>,
    ) -> Result<tonic::Response<v1::RotateCertificateResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn open(
        &self,
        _request: tonic::Request<tonic::Streaming<v1::RunnerMessage>>,
    ) -> Result<tonic::Response<Self::OpenStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn fetch_execution_capsule(
        &self,
        _request: tonic::Request<v1::FetchExecutionCapsuleRequest>,
    ) -> Result<tonic::Response<v1::FetchExecutionCapsuleResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn request_secret_lease(
        &self,
        _request: tonic::Request<v1::SecretLeaseRequest>,
    ) -> Result<tonic::Response<v1::SecretLeaseResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn revoke_secret_lease(
        &self,
        _request: tonic::Request<v1::RevokeSecretLeaseRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn mint_oidc_token(
        &self,
        _request: tonic::Request<v1::OidcTokenRequest>,
    ) -> Result<tonic::Response<v1::OidcTokenResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn request_cache_ticket(
        &self,
        _request: tonic::Request<v1::CacheTicketRequest>,
    ) -> Result<tonic::Response<v1::CacheTicketResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn commit_cache_entry(
        &self,
        _request: tonic::Request<v1::CommitCacheEntryRequest>,
    ) -> Result<tonic::Response<v1::CommitCacheEntryResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn request_artifact_ticket(
        &self,
        _request: tonic::Request<v1::ArtifactTicketRequest>,
    ) -> Result<tonic::Response<v1::ArtifactTicketResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn commit_artifact(
        &self,
        _request: tonic::Request<v1::CommitArtifactRequest>,
    ) -> Result<tonic::Response<v1::CommitArtifactResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn upload_blob(
        &self,
        _request: tonic::Request<tonic::Streaming<v1::UploadBlobChunk>>,
    ) -> Result<tonic::Response<v1::UploadBlobResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn download_blob(
        &self,
        _request: tonic::Request<v1::DownloadBlobRequest>,
    ) -> Result<tonic::Response<Self::DownloadBlobStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn complete_lease(
        &self,
        _request: tonic::Request<v1::CompleteLeaseRequest>,
    ) -> Result<tonic::Response<v1::CompleteLeaseResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }
}

#[derive(Debug, Default)]
struct UnimplementedRunnerObjectTransfer;

#[tonic::async_trait]
impl v2::runner_object_transfer_server::RunnerObjectTransfer for UnimplementedRunnerObjectTransfer {
    type DownloadObjectStream = tonic::codec::Streaming<v2::ObjectDownloadFrame>;

    async fn request_source_ticket(
        &self,
        _request: tonic::Request<v2::SourceTicketRequest>,
    ) -> Result<tonic::Response<v2::SourceTicketResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn download_object(
        &self,
        _request: tonic::Request<v2::ObjectDownloadRequest>,
    ) -> Result<tonic::Response<Self::DownloadObjectStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn upload_object(
        &self,
        _request: tonic::Request<tonic::Streaming<v2::ObjectUploadFrame>>,
    ) -> Result<tonic::Response<v2::ObjectUploadResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }

    async fn complete_lease(
        &self,
        _request: tonic::Request<v2::CompleteLeaseRequest>,
    ) -> Result<tonic::Response<v2::CompleteLeaseResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("contract test"))
    }
}
