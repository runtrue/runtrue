mod credentials;
mod error;
mod model;
mod secure_fs;
mod source_cache;
mod store;
#[cfg(test)]
mod tests;
mod workspaces;

pub use error::StateError;
pub use model::PersistentRunnerState;
pub(crate) use source_cache::SourceCache;
pub use store::RunnerStateStore;
pub use workspaces::WorkspaceManager;

pub(crate) use credentials::{read_bounded_private_file, validate_private_file};
pub(crate) use model::{
    ActiveLeaseMarker, PersistedCommittedObject, PersistedCommittedObjectKind, PersistedCompletion,
};
pub(crate) use secure_fs::{
    io_error, prepare_private_directory, random_hex, sync_directory, validate_no_symlink_components,
};
