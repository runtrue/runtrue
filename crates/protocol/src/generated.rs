/// Generated types and tonic client/server definitions for `runtrue.runner.v1`.
pub mod runner {
    /// Version 1 of the runner/control-plane protocol.
    pub mod v1 {
        tonic::include_proto!("runtrue.runner.v1");
    }
}

/// Short alias for the generated versioned protocol module.
pub use runner::v1;

/// Generation-two object transfer and source hydration contract.
pub mod v2 {
    tonic::include_proto!("runtrue.runner.v2");
}

/// Encoded generation-one descriptor for reflection and compatibility tests.
pub const V1_FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("runtrue.runner.v1");

/// Encoded generation-two descriptor for reflection and compatibility tests.
pub const V2_FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("runtrue.runner.v2");

/// Backward-compatible name for the generation-one descriptor.
pub const FILE_DESCRIPTOR_SET: &[u8] = V1_FILE_DESCRIPTOR_SET;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_two_object_metadata_is_separate_from_raw_chunks() {
        let header = v2::ObjectUploadFrame {
            body: Some(v2::object_upload_frame::Body::Header(
                v2::ObjectUploadHeader {
                    ticket_id: "ticket".to_owned(),
                    ticket_kind: "source".to_owned(),
                    execution_lease_id: "lease".to_owned(),
                    fencing_generation: 7,
                    job_id: "job".to_owned(),
                    job_attempt: 2,
                    step_id: "hydrate".to_owned(),
                    digest_algorithm: "sha256".to_owned(),
                    digest: vec![0; 32],
                    size_bytes: 3,
                },
            )),
        };
        let chunk = v2::ObjectUploadFrame {
            body: Some(v2::object_upload_frame::Body::Chunk(v2::ObjectChunk {
                offset: 0,
                payload: b"raw".to_vec(),
            })),
        };
        assert!(matches!(
            header.body,
            Some(v2::object_upload_frame::Body::Header(_))
        ));
        assert!(matches!(
            chunk.body,
            Some(v2::object_upload_frame::Body::Chunk(_))
        ));
        assert_eq!(
            crate::PROTOCOL_MAX,
            2,
            "v2 is enabled after its end-to-end gate"
        );
    }
}
