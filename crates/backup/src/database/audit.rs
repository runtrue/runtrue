use super::inspection::{bounded_count, u64_column};
use crate::{BackupError, BackupLimits};
use runtrue_audit::AuditEvent;
use rusqlite::Connection;

pub(super) fn verify_audit_chain(
    connection: &Connection,
    limits: BackupLimits,
) -> Result<(), BackupError> {
    let count = bounded_count(connection, "audit_events", limits.max_database_records)?;
    let mut statement = connection
        .prepare("SELECT length(event_json), event_json FROM audit_events ORDER BY sequence")?;
    let mut rows = statement.query([])?;
    let mut seen = 0_usize;
    let mut installation: Option<String> = None;
    let mut previous: Option<runtrue_model::ContentDigest> = None;
    while let Some(row) = rows.next()? {
        let length = u64_column(row, 0)?;
        if length > limits.max_database_record_bytes {
            return Err(BackupError::LimitExceeded("audit event bytes"));
        }
        let encoded: String = row.get(1)?;
        let event = serde_json::from_str::<AuditEvent>(&encoded)?;
        event.verify_hash()?;
        let expected_sequence = u64::try_from(seen)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(BackupError::LimitExceeded("audit sequence"))?;
        if event.sequence != expected_sequence
            || event.previous_hash != previous
            || installation
                .as_deref()
                .is_some_and(|value| value != event.installation_id)
        {
            return Err(BackupError::InvalidDatabase(
                "audit event chain linkage is invalid",
            ));
        }
        installation.get_or_insert_with(|| event.installation_id.clone());
        previous = Some(event.event_hash);
        seen += 1;
    }
    if seen != count {
        return Err(BackupError::InvalidDatabase(
            "audit event count changed during verification",
        ));
    }
    Ok(())
}
