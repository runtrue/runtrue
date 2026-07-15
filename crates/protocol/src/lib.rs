//! Generated runner/control-plane transport contract and checked domain bridges.
//!
//! The protobuf source remains the compatibility authority. Generated Rust is
//! written to Cargo's build output directory and is deliberately not checked in.

mod digest;
mod generated;
mod negotiation;

pub use digest::DigestConversionError;
pub use generated::{
    runner, v1, v2, FILE_DESCRIPTOR_SET, V1_FILE_DESCRIPTOR_SET, V2_FILE_DESCRIPTOR_SET,
};
pub use negotiation::{
    advertised_protocol_range, negotiate_protocol_version,
    negotiate_protocol_version_with_supported, resolve_selected_protocol_version,
    supports_protocol_version, ProtocolVersionError, PROTOCOL_MAX, PROTOCOL_MIN,
};
