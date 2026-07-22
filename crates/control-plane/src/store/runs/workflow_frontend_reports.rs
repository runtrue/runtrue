use super::*;

const MAX_WORKFLOW_FRONTEND_REPORT_BYTES: usize = 1024 * 1024;
const MAX_WORKFLOW_FRONTEND_MEDIA_TYPE_BYTES: usize = 255;

pub(in crate::store) fn validate_workflow_frontend_report(
    record: &WorkflowFrontendReportRecord,
    capsule: &ExecutionCapsule,
    capsule_id: &str,
) -> Result<(), ControlPlaneError> {
    let signed_digest = capsule
        .context
        .workflow_frontend
        .as_ref()
        .and_then(|provenance| provenance.report_digest.as_ref());
    if record.capsule_id != capsule_id
        || signed_digest != Some(&ContentDigest::sha256(&record.bytes))
        || record.bytes.len() > MAX_WORKFLOW_FRONTEND_REPORT_BYTES
        || record.media_type.is_empty()
        || record.media_type.len() > MAX_WORKFLOW_FRONTEND_MEDIA_TYPE_BYTES
        || !record.media_type.contains('/')
        || record
            .media_type
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'*' | b','))
    {
        return Err(ControlPlaneError::InvalidInput(
            "workflow frontend report does not match its signed capsule provenance",
        ));
    }
    Ok(())
}

pub(in crate::store) fn insert_workflow_frontend_report_conn(
    connection: &Connection,
    record: &WorkflowFrontendReportRecord,
) -> Result<(), ControlPlaneError> {
    connection.execute(
        "INSERT INTO workflow_frontend_reports
         (capsule_id, media_type, report_bytes) VALUES (?1, ?2, ?3)",
        params![record.capsule_id, record.media_type, record.bytes],
    )?;
    Ok(())
}

fn workflow_frontend_report_row(row: &Row<'_>) -> rusqlite::Result<WorkflowFrontendReportRecord> {
    Ok(WorkflowFrontendReportRecord {
        capsule_id: row.get(0)?,
        media_type: row.get(1)?,
        bytes: row.get(2)?,
    })
}

impl ControlPlane {
    /// Store a validated report attachment for import and fixture setup.
    /// Trusted SCM completion uses the same insert helper inside its atomic
    /// capsule transaction.
    pub fn store_workflow_frontend_report(
        &self,
        record: &WorkflowFrontendReportRecord,
    ) -> Result<(), ControlPlaneError> {
        let connection = self.connection()?;
        let capsule = signed_capsule_conn(&connection, &record.capsule_id)?;
        let decoded: ExecutionCapsule = serde_json::from_slice(&capsule.canonical_capsule)?;
        validate_workflow_frontend_report(record, &decoded, &capsule.id)?;
        insert_workflow_frontend_report_conn(&connection, record)
    }

    pub fn workflow_frontend_report(
        &self,
        capsule_id: &str,
    ) -> Result<WorkflowFrontendReportRecord, ControlPlaneError> {
        validate_text("capsule.id", capsule_id)?;
        let connection = self.connection()?;
        let record = connection
            .query_row(
                "SELECT capsule_id, media_type, report_bytes
                 FROM workflow_frontend_reports WHERE capsule_id = ?1",
                [capsule_id],
                workflow_frontend_report_row,
            )
            .optional()?
            .ok_or_else(|| not_found("workflow frontend report", capsule_id))?;
        let capsule = signed_capsule_conn(&connection, capsule_id)?;
        let decoded: ExecutionCapsule = serde_json::from_slice(&capsule.canonical_capsule)?;
        validate_workflow_frontend_report(&record, &decoded, &capsule.id)?;
        Ok(record)
    }
}
