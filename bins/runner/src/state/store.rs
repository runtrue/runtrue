const STATE_FILE: &str = "runner-state.json";
const MAX_STATE_BYTES: u64 = 1024 * 1024;
pub struct RunnerStateStore {
    root: PathBuf,
    state_path: PathBuf,
    state: PersistentRunnerState,
}

impl RunnerStateStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StateError> {
        let root = prepare_private_directory(root.as_ref())?;
        let state_path = root.join(STATE_FILE);
        let state = match fs::symlink_metadata(&state_path) {
            Ok(metadata) => {
                validate_private_file(&state_path, &metadata)?;
                let bytes = read_bounded_private_file(&state_path, MAX_STATE_BYTES)?;
                serde_json::from_slice(&bytes).map_err(StateError::Decode)?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                PersistentRunnerState::default()
            }
            Err(source) => return Err(io_error(&state_path, source)),
        };
        let mut store = Self {
            root,
            state_path,
            state,
        };
        if !store.state_path.exists() {
            store.persist()?;
        }
        Ok(store)
    }

    #[must_use]
    pub fn state(&self) -> &PersistentRunnerState {
        &self.state
    }

    /// Accept a server epoch monotonically. Advancing the installation epoch
    /// invalidates any terminal report fenced by the previous installation.
    pub fn accept_installation_epoch(&mut self, epoch: u64) -> Result<(), StateError> {
        if epoch == 0 {
            return Err(StateError::InvalidEpoch);
        }
        match self.state.installation_fencing_epoch {
            Some(current) if epoch < current => {
                return Err(StateError::EpochRollback {
                    current,
                    received: epoch,
                });
            }
            Some(current) if epoch > current => {
                self.state.installation_fencing_epoch = Some(epoch);
                self.state.active_lease = None;
                self.state.pending_completion = None;
                self.persist()?;
            }
            Some(_) => {}
            None => {
                self.state.installation_fencing_epoch = Some(epoch);
                self.persist()?;
            }
        }
        Ok(())
    }

    pub(crate) fn mark_active(&mut self, marker: ActiveLeaseMarker) -> Result<(), StateError> {
        self.state.active_lease = Some(marker);
        self.persist()
    }

    pub(crate) fn clear_active(&mut self) -> Result<(), StateError> {
        self.state.active_lease = None;
        self.persist()
    }

    #[cfg(test)]
    pub(crate) fn set_pending_completion(
        &mut self,
        completion: &v1::CompleteLeaseRequest,
    ) -> Result<(), StateError> {
        self.state.pending_completion = Some(PersistedCompletion::from_wire(completion)?);
        self.state.active_lease = None;
        self.persist()
    }

    pub(crate) fn set_pending_completion_with_objects(
        &mut self,
        completion: &v1::CompleteLeaseRequest,
        committed_objects: Vec<PersistedCommittedObject>,
    ) -> Result<(), StateError> {
        let mut persisted = PersistedCompletion::from_wire(completion)?;
        persisted.validate_committed_objects(&committed_objects)?;
        persisted.committed_objects = Some(committed_objects);
        self.state.pending_completion = Some(persisted);
        self.persist()
    }

    pub(crate) fn pending_completion(
        &self,
    ) -> Result<Option<v1::CompleteLeaseRequest>, StateError> {
        self.state
            .pending_completion
            .as_ref()
            .map(PersistedCompletion::to_wire)
            .transpose()
    }

    pub(crate) fn pending_completion_record(&self) -> Option<PersistedCompletion> {
        self.state.pending_completion.clone()
    }

    pub(crate) fn clear_pending_completion(&mut self) -> Result<(), StateError> {
        self.state.pending_completion = None;
        self.persist()
    }

    pub(crate) fn clear_stale_active_marker(&mut self) -> Result<bool, StateError> {
        if self.state.active_lease.take().is_some() {
            self.persist()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn persist(&mut self) -> Result<(), StateError> {
        let bytes = serde_json::to_vec(&self.state).map_err(StateError::Encode)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(StateError::StateLimit);
        }
        let temporary = self
            .root
            .join(format!(".{STATE_FILE}.tmp-{}", random_hex()?));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(&temporary)
            .map_err(|source| io_error(&temporary, source))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| io_error(&temporary, source))?;
        fs::rename(&temporary, &self.state_path)
            .map_err(|source| io_error(&self.state_path, source))?;
        sync_directory(&self.root)?;
        validate_private_file(
            &self.state_path,
            &fs::symlink_metadata(&self.state_path)
                .map_err(|source| io_error(&self.state_path, source))?,
        )
    }
}

use super::{
    io_error, prepare_private_directory, random_hex, read_bounded_private_file, sync_directory,
    validate_private_file, ActiveLeaseMarker, PersistedCommittedObject, PersistedCompletion,
    PersistentRunnerState, StateError,
};
use runtrue_protocol::v1;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};
