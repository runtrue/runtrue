use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use tonic::Status;
pub(in crate::runner_service) fn parse_v2_digest(
    algorithm: &str,
    bytes: &[u8],
) -> Result<ContentDigest, Status> {
    ContentDigest::try_from(v1::Digest {
        algorithm: algorithm.to_owned(),
        value: bytes.to_vec(),
    })
    .map_err(|_| Status::invalid_argument("object digest is invalid"))
}

pub(in crate::runner_service) fn wire_v2_digest(
    digest: &ContentDigest,
) -> Result<(String, Vec<u8>), Status> {
    let wire = v1::Digest::try_from(digest)
        .map_err(|_| Status::internal("durable object digest is invalid"))?;
    Ok((wire.algorithm, wire.value))
}
