use crate::{
    canonical::canonical_bytes, validation::MAX_TEXT_BYTES, verify_chain, AuditError, AuditEvent,
    AuditEventData,
};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead as _, BufReader, Write as _},
    path::{Path, PathBuf},
    sync::Mutex,
};

pub const MAX_AUDIT_LINE_BYTES: usize = 256 * 1024;

pub struct FileAuditLog {
    path: PathBuf,
    installation_id: String,
    events: Mutex<Vec<AuditEvent>>,
}

impl FileAuditLog {
    pub fn open(
        path: impl Into<PathBuf>,
        installation_id: impl Into<String>,
    ) -> Result<Self, AuditError> {
        let path = path.into();
        let installation_id = installation_id.into();
        if installation_id.is_empty() || installation_id.len() > MAX_TEXT_BYTES {
            return Err(AuditError::InvalidText("installation_id"));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(AuditError::Io)?;
            let metadata = fs::symlink_metadata(parent).map_err(AuditError::Io)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(AuditError::UnsafeParentDirectory);
            }
        }
        let events = if path.exists() {
            read_events(&path)?
        } else {
            Vec::new()
        };
        verify_chain(&events)?;
        if events
            .first()
            .is_some_and(|event| event.installation_id != installation_id)
        {
            return Err(AuditError::WrongInstallation);
        }
        Ok(Self {
            path,
            installation_id,
            events: Mutex::new(events),
        })
    }

    pub fn append(&self, data: AuditEventData) -> Result<AuditEvent, AuditError> {
        let mut events = self.events.lock().map_err(|_| AuditError::Poisoned)?;
        let sequence = u64::try_from(events.len())
            .map_err(|_| AuditError::SequenceOverflow)?
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
        let previous = events.last().map(|event| event.event_hash.clone());
        let event = AuditEvent::create(sequence, self.installation_id.clone(), previous, data)?;
        let line = canonical_bytes(&event)?;
        if line.len() > MAX_AUDIT_LINE_BYTES {
            return Err(AuditError::LineTooLarge(line.len()));
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
            options.mode(0o600);
        }
        let mut file = options.open(&self.path).map_err(AuditError::Io)?;
        let metadata = file.metadata().map_err(AuditError::Io)?;
        validate_audit_file_metadata(&metadata)?;
        file.write_all(&line).map_err(AuditError::Io)?;
        file.write_all(b"\n").map_err(AuditError::Io)?;
        file.sync_data().map_err(AuditError::Io)?;
        events.push(event.clone());
        Ok(event)
    }

    pub fn snapshot(&self) -> Result<Vec<AuditEvent>, AuditError> {
        self.events
            .lock()
            .map(|events| events.clone())
            .map_err(|_| AuditError::Poisoned)
    }
}

fn read_events(path: &Path) -> Result<Vec<AuditEvent>, AuditError> {
    let metadata = fs::symlink_metadata(path).map_err(AuditError::Io)?;
    validate_audit_file_metadata(&metadata)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(AuditError::Io)?;
    validate_audit_file_metadata(&file.metadata().map_err(AuditError::Io)?)?;
    let mut events = Vec::new();
    for line in BufReader::new(file).split(b'\n') {
        let line = line.map_err(AuditError::Io)?;
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_AUDIT_LINE_BYTES {
            return Err(AuditError::LineTooLarge(line.len()));
        }
        let event: AuditEvent = serde_json::from_slice(&line)?;
        if canonical_bytes(&event)? != line {
            return Err(AuditError::NonCanonicalLine);
        }
        events.push(event);
    }
    Ok(events)
}

fn validate_audit_file_metadata(metadata: &fs::Metadata) -> Result<(), AuditError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AuditError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode() & 0o7777;
        if mode != 0o600 {
            return Err(AuditError::InsecureFileMode(mode));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{checkpoint, AuditPrincipal, AuditResource};
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn event(action: &str) -> AuditEventData {
        AuditEventData {
            observed_unix_ms: 1,
            tenant_id: "tenant".to_owned(),
            actor: AuditPrincipal {
                kind: "user".to_owned(),
                id: "alice".to_owned(),
            },
            action: action.to_owned(),
            resource: AuditResource {
                kind: "run".to_owned(),
                id: "run-1".to_owned(),
            },
            result: "success".to_owned(),
            request_id: "request-1".to_owned(),
            decision_id: None,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn file_log_survives_reopen_and_checkpoints() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let log = FileAuditLog::open(&path, "installation").unwrap();
        log.append(event("run.create")).unwrap();
        log.append(event("run.cancel")).unwrap();
        let events = log.snapshot().unwrap();
        let checkpoint = checkpoint(&events).unwrap();
        checkpoint.verify(&events).unwrap();
        drop(log);

        let reopened = FileAuditLog::open(&path, "installation").unwrap();
        assert_eq!(reopened.snapshot().unwrap(), events);
    }

    #[test]
    fn symlink_log_path_is_rejected() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let directory = tempdir().unwrap();
            let target = directory.path().join("target");
            fs::write(&target, b"").unwrap();
            let link = directory.path().join("audit");
            symlink(target, &link).unwrap();
            assert!(matches!(
                FileAuditLog::open(link, "installation"),
                Err(AuditError::NotRegularFile)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_audit_files_are_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            FileAuditLog::open(path, "installation"),
            Err(AuditError::InsecureFileMode(0o640))
        ));
    }
}
