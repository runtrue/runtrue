//! Immutable artifact records over Runtrue's verified filesystem CAS.
//!
//! Upload tickets bind one lease/fencing generation to one logical artifact
//! name, classification, and byte budget. A successful commit atomically
//! consumes the ticket and stores a content-addressed metadata record that
//! refers to an immutable file or tree snapshot. Promotion creates another
//! metadata record over the identical bytes; it never executes or rewrites the
//! captured content.

mod error;
mod limits;
mod metadata;
mod model;
mod promotion;
mod provenance;
mod secure_io;
mod store;
mod ticket;

pub use error::ArtifactError;
pub use limits::ArtifactLimits;
pub use model::{ArtifactClassification, ArtifactHandle, ArtifactRecord, ArtifactScanState};
pub use promotion::{ArtifactPromotion, ArtifactPromotionEvidence, ArtifactPromotionKind};
pub use provenance::{ArtifactProducer, ArtifactProvenance};
pub use store::{verify_immutable_artifact_record, ArtifactStore};
pub use ticket::{
    ArtifactCommitRequest, ArtifactSnapshotCommitRequest, ArtifactTicket, ArtifactTicketRequest,
    VerifiedArtifactProvenance,
};

pub(crate) use limits::{
    validate_artifact_name, validate_identifier, validate_media_type, validate_retention,
};
pub(crate) use metadata::snapshot_identity;
pub(crate) use metadata::ARTIFACT_RECORD_VERSION;
pub(crate) use promotion::validate_promotion_evidence;
pub(crate) use provenance::{
    validate_producer, validate_scan_state, verify_provenance_link, verify_stored_provenance,
};
pub(crate) use secure_io::{
    append_metadata, digest_hex, ensure_directory, io_failure, read_small_regular,
    require_directory, sync_directory,
};
pub(crate) use ticket::ArtifactCommitParameters;
pub(crate) use ticket::{TicketClaim, CLAIM_VERSION};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
