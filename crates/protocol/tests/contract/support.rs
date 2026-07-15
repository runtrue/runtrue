pub(super) use prost::Message;
pub(super) use prost_types::{DescriptorProto, FileDescriptorProto, FileDescriptorSet};
pub(super) use runtrue_protocol::{
    v1, v2, FILE_DESCRIPTOR_SET, V1_FILE_DESCRIPTOR_SET, V2_FILE_DESCRIPTOR_SET,
};
pub(super) use sha2::{Digest as _, Sha256};
pub(super) use std::collections::{BTreeMap, BTreeSet};

const PACKAGE: &str = "runtrue.runner.v1";

#[derive(Clone, PartialEq, Message)]
pub(super) struct LegacyEnrollRequest {
    #[prost(string, tag = "1")]
    pub(super) enrollment_token: String,
    #[prost(bytes = "vec", tag = "2")]
    pub(super) certificate_signing_request: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub(super) inventory: Option<v1::RunnerInventory>,
    #[prost(message, optional, tag = "4")]
    pub(super) attestation: Option<v1::AttestationEvidence>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct LegacyEnrollResponse {
    #[prost(string, tag = "1")]
    pub(super) runner_id: String,
    #[prost(bytes = "vec", tag = "2")]
    pub(super) certificate_chain_pem: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub(super) certificate_expires_at: Option<prost_types::Timestamp>,
    #[prost(string, tag = "4")]
    pub(super) runner_pool_id: String,
    #[prost(uint32, tag = "5")]
    pub(super) protocol_min: u32,
    #[prost(uint32, tag = "6")]
    pub(super) protocol_max: u32,
}

pub(super) fn protocol_file() -> FileDescriptorProto {
    FileDescriptorSet::decode(FILE_DESCRIPTOR_SET)
        .expect("generated descriptor set must decode")
        .file
        .into_iter()
        .find(|file| file.package.as_deref() == Some(PACKAGE))
        .expect("runner protocol descriptor must be present")
}

pub(super) fn protocol_v2_file() -> FileDescriptorProto {
    FileDescriptorSet::decode(V2_FILE_DESCRIPTOR_SET)
        .expect("generated v2 descriptor set must decode")
        .file
        .into_iter()
        .find(|file| file.package.as_deref() == Some("runtrue.runner.v2"))
        .expect("generation-two protocol descriptor must be present")
}

pub(super) fn messages(file: &FileDescriptorProto) -> BTreeMap<&str, &DescriptorProto> {
    file.message_type
        .iter()
        .map(|message| (message.name.as_deref().expect("message name"), message))
        .collect()
}

pub(super) fn assert_message_round_trip<T>(message: T)
where
    T: Message + Default + PartialEq + std::fmt::Debug,
{
    let encoded = message.encode_to_vec();
    let decoded = T::decode(encoded.as_slice()).expect("generated message must decode");
    assert_eq!(decoded, message);
}
