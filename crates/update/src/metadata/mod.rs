mod envelope;
mod root;
mod snapshot;
mod targets;
mod timestamp;

pub use envelope::{MetadataSignature, RoleMetadata, SignedEnvelope};
pub use root::{RoleAssignment, RootMetadata};
pub use snapshot::{MetadataReference, SnapshotMetadata};
pub use targets::{TargetDescription, TargetsMetadata};
pub use timestamp::TimestampMetadata;
