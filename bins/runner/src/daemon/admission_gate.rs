use crate::state::{io_error, validate_no_symlink_components, validate_private_file, StateError};
use rustix::fs::{flock, FlockOperation};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub(super) struct LeaseAdmissionGate {
    gate_path: PathBuf,
    lease_path: PathBuf,
}

pub(super) enum PermitAttempt {
    Acquired(LeaseAdmissionPermit),
    AdmissionPending,
}

pub(super) struct LeaseAdmissionPermit {
    // The shared lock is intentionally held until the active execution is
    // completely reported and dropped.
    _lease: File,
}

/// Run connection-bound blocking work while retaining its active-lease permit.
///
/// A `spawn_blocking` task is detached when its `JoinHandle` is dropped. Moving
/// the permit into the task prevents a failed control stream (or cancellation
/// of the async caller) from making image admission look safe while source
/// hydration or an execution backend is still using the old runner session.
pub(super) fn spawn_admission_bound_blocking<F, R>(
    permit: Option<Arc<LeaseAdmissionPermit>>,
    operation: F,
) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
}

impl LeaseAdmissionGate {
    pub(super) fn new(path: PathBuf) -> Self {
        let lease_path = lease_path(&path);
        Self {
            gate_path: path,
            lease_path,
        }
    }

    pub(super) fn try_acquire(&self) -> Result<PermitAttempt, StateError> {
        if !self.gate_path.is_absolute() || self.gate_path.file_name().is_none() {
            return Err(StateError::UnsafePath(self.gate_path.clone()));
        }
        // The short-lived exclusive gate serializes a runner beginning a lease
        // with an image admission beginning its drain. The admission process
        // holds this gate while it waits for the shared lease locks to drain,
        // so an admission request cannot be starved by newly accepted work.
        let gate = open_lock(&self.gate_path)?;
        if !try_flock(
            &gate,
            FlockOperation::NonBlockingLockExclusive,
            &self.gate_path,
        )? {
            return Ok(PermitAttempt::AdmissionPending);
        }

        let lease = open_lock(&self.lease_path)?;
        if !try_flock(
            &lease,
            FlockOperation::NonBlockingLockShared,
            &self.lease_path,
        )? {
            return Ok(PermitAttempt::AdmissionPending);
        }
        drop(gate);
        Ok(PermitAttempt::Acquired(LeaseAdmissionPermit {
            _lease: lease,
        }))
    }

    pub(super) fn validate(&self) -> Result<(), StateError> {
        if !self.gate_path.is_absolute() || self.gate_path.file_name().is_none() {
            return Err(StateError::UnsafePath(self.gate_path.clone()));
        }
        drop(open_lock(&self.gate_path)?);
        drop(open_lock(&self.lease_path)?);
        Ok(())
    }
}

fn lease_path(path: &Path) -> PathBuf {
    let mut lease_name = OsString::from(path.file_name().unwrap_or_default());
    lease_name.push(".leases");
    path.with_file_name(lease_name)
}

fn open_lock(path: &Path) -> Result<File, StateError> {
    validate_no_symlink_components(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error(path, source))?;
    let opened = file.metadata().map_err(|source| io_error(path, source))?;
    validate_private_file(path, &opened)?;
    let linked = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    validate_private_file(path, &linked)?;
    #[cfg(unix)]
    if linked.dev() != opened.dev() || linked.ino() != opened.ino() {
        return Err(StateError::UnsafePath(path.to_owned()));
    }
    Ok(file)
}

fn try_flock(file: &File, operation: FlockOperation, path: &Path) -> Result<bool, StateError> {
    match flock(file, operation) {
        Ok(()) => Ok(true),
        Err(error) if error == rustix::io::Errno::WOULDBLOCK => Ok(false),
        Err(source) => Err(io_error(path, source.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn admission_excludes_new_leases_and_waits_for_existing_permits() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admission.lock");
        let gate = LeaseAdmissionGate::new(path.clone());
        let first = match gate.try_acquire().unwrap() {
            PermitAttempt::Acquired(permit) => permit,
            PermitAttempt::AdmissionPending => panic!("first permit was unexpectedly blocked"),
        };

        let admission_gate = open_lock(&path).unwrap();
        assert!(try_flock(
            &admission_gate,
            FlockOperation::NonBlockingLockExclusive,
            &path
        )
        .unwrap());
        assert!(matches!(
            gate.try_acquire().unwrap(),
            PermitAttempt::AdmissionPending
        ));

        let lease_path = lease_path(&path);
        let admission_leases = open_lock(&lease_path).unwrap();
        assert!(!try_flock(
            &admission_leases,
            FlockOperation::NonBlockingLockExclusive,
            &lease_path
        )
        .unwrap());

        drop(first);
        assert!(try_flock(
            &admission_leases,
            FlockOperation::NonBlockingLockExclusive,
            &lease_path
        )
        .unwrap());

        assert!(matches!(
            gate.try_acquire().unwrap(),
            PermitAttempt::AdmissionPending
        ));
        drop(admission_leases);
        drop(admission_gate);
        assert!(matches!(
            gate.try_acquire().unwrap(),
            PermitAttempt::Acquired(_)
        ));
    }

    #[test]
    fn rejects_relative_gate_paths() {
        assert!(matches!(
            LeaseAdmissionGate::new(PathBuf::from("admission.lock")).try_acquire(),
            Err(StateError::UnsafePath(_))
        ));
    }

    #[tokio::test]
    async fn detached_blocking_work_retains_the_lease_permit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admission.lock");
        let gate = LeaseAdmissionGate::new(path.clone());
        let permit = match gate.try_acquire().unwrap() {
            PermitAttempt::Acquired(permit) => Arc::new(permit),
            PermitAttempt::AdmissionPending => panic!("permit was unexpectedly blocked"),
        };
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let task = spawn_admission_bound_blocking(Some(Arc::clone(&permit)), move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        started_rx.recv().unwrap();

        // Model the async caller being dropped by a failed runner connection.
        // Its background source/backend work must continue to exclude image
        // admission until that work has actually stopped.
        drop(permit);
        let admission_gate = open_lock(&path).unwrap();
        assert!(try_flock(
            &admission_gate,
            FlockOperation::NonBlockingLockExclusive,
            &path
        )
        .unwrap());
        let lease_path = lease_path(&path);
        let admission_leases = open_lock(&lease_path).unwrap();
        assert!(!try_flock(
            &admission_leases,
            FlockOperation::NonBlockingLockExclusive,
            &lease_path
        )
        .unwrap());

        release_tx.send(()).unwrap();
        task.await.unwrap();
        assert!(try_flock(
            &admission_leases,
            FlockOperation::NonBlockingLockExclusive,
            &lease_path
        )
        .unwrap());
    }
}
