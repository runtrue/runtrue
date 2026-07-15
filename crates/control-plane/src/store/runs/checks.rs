use super::*;

const INITIAL_JOB_CHECK_PREFIX: &str = "job:";
const TERMINAL_JOB_CHECK_PREFIX: &str = "job-result:";
const MAX_GITHUB_LOG_BYTES: usize = 48 * 1024;
const MAX_GITHUB_LOG_FRAMES: usize = 10_000;

pub(in crate::store) fn enqueue_terminal_scm_check_tx(
    transaction: &Transaction<'_>,
    run_id: &str,
    final_state: RunState,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    if !final_state.is_terminal() {
        return Ok(());
    }
    let mut statement = transaction.prepare(
        "SELECT payload_json FROM durable_tasks
         WHERE kind = 'scm.check.publish'
           AND json_extract(payload_json, '$.run_id') = ?1
           AND json_extract(payload_json, '$.logical_name') LIKE 'job:%'
         ORDER BY id",
    )?;
    let initial = statement
        .query_map([run_id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    if initial.is_empty() {
        return Ok(());
    }
    let capsule = transaction.query_row(
        "SELECT p.canonical_capsule
         FROM runs r JOIN capsules p ON p.id = r.capsule_id WHERE r.id = ?1",
        [run_id],
        |row| json_blob_column::<ExecutionCapsule>(row, 0),
    )?;
    let mut job_statement = transaction.prepare(
        "SELECT j.id, j.job_key, j.attempt, j.status,
                COALESCE(
                    (SELECT MIN(l.issued_unix_ms) FROM leases l WHERE l.job_id = j.id),
                    r.started_unix_ms,
                    j.created_unix_ms
                ) AS execution_started_unix_ms,
                j.completed_unix_ms
         FROM jobs j
         JOIN runs r ON r.id = j.run_id
         WHERE j.run_id = ?1
         ORDER BY j.id",
    )?;
    let jobs = job_statement
        .query_map([run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, String>(3)?,
                u64_column(row, 4, "job creation")?,
                optional_u64_column(row, 5, "job completion")?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(job_statement);

    for encoded in initial {
        let initial: ScmCheckPublishTask = serde_json::from_str(&encoded)?;
        let job_id = initial
            .logical_name
            .strip_prefix(INITIAL_JOB_CHECK_PREFIX)
            .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "initial SCM job check has an invalid logical name".to_owned(),
                )
            })?;
        let (_, job_key, attempt, status, started_unix_ms, completed_unix_ms) = jobs
            .iter()
            .find(|(id, _, _, _, _, _)| id == job_id)
            .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "initial SCM job check references a missing job".to_owned(),
                )
            })?;
        let (conclusion, outcome) = match status.as_str() {
            "succeeded" => ("success", "succeeded"),
            "canceled" | "cancelled" => ("cancelled", "cancelled"),
            "timed_out" => ("timed_out", "timed out"),
            "skipped" => ("skipped", "skipped"),
            "failed" | "lost" | "rejected" => ("failure", "failed"),
            _ if final_state == RunState::Canceled => ("cancelled", "cancelled"),
            _ => ("failure", "failed"),
        };
        let display_name = capsule
            .jobs
            .iter()
            .find(|job| job.id == *job_key)
            .map(|job| job.name.as_str())
            .unwrap_or(job_key);
        let elapsed = elapsed(Some(*started_unix_ms), *completed_unix_ms)
            .unwrap_or_else(|| "not recorded".to_owned());
        let icon = match conclusion {
            "success" => "✅",
            "cancelled" => "⏹️",
            "timed_out" => "⏱️",
            "skipped" => "⏭️",
            _ => "❌",
        };
        let mut log_statement = transaction.prepare(
            "SELECT f.step_id, f.stream, f.payload
             FROM runner_log_frames f
             JOIN leases l ON l.id = f.execution_lease_id
             JOIN jobs j ON j.id = l.job_id
             WHERE j.id = ?1
               AND l.state = 'completed'
               AND l.terminal_credential_taint = 'none'
             ORDER BY f.wall_time_unix_ms DESC, f.execution_lease_id DESC,
                      f.job_attempt DESC, f.step_id DESC, f.stream DESC, f.sequence DESC
             LIMIT ?2",
        )?;
        let log_frames = log_statement
            .query_map(
                params![job_id, to_i64((MAX_GITHUB_LOG_FRAMES + 1) as u64)?],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(log_statement);
        let logs = render_check_logs(&log_frames);
        let summary = format!(
            "### {icon} {}\n\n| | |\n|---|---|\n| **Status** | **{}** |\n| **Duration** | `{}` |\n| **Workflow** | {} |\n| **Definition** | `{}` |\n| **Job** | `{}` · attempt {} |\n| **Run** | `{}` |\n| **Commit** | `{}` |\n\n{}",
            markdown_text(display_name),
            markdown_text(outcome),
            elapsed,
            markdown_text(&capsule.workflow.name),
            capsule.workflow.source_path,
            job_key,
            attempt,
            run_id,
            initial.commit_sha,
            logs,
        );

        let terminal_logical_name = format!("{TERMINAL_JOB_CHECK_PREFIX}{job_id}");
        let mut identity = Sha256::new();
        identity.update(b"runtrue.scm-check-publication.v1\0");
        for component in [
            initial.repository_id.as_str(),
            run_id,
            initial.commit_sha.as_str(),
            terminal_logical_name.as_str(),
        ] {
            identity.update(component.as_bytes());
            identity.update([0]);
        }
        let suffix = hex::encode(identity.finalize());
        let terminal_task_id = format!("scm-check-task-{suffix}");
        let terminal = ScmCheckPublishTask {
            publication_id: format!("scm-check-{suffix}"),
            logical_name: terminal_logical_name,
            status: "completed".to_owned(),
            conclusion: Some(conclusion.to_owned()),
            title: format!("{icon} {display_name} {outcome}"),
            summary,
            render_markdown: true,
            ..initial
        };
        let payload = canonicalize_json(serde_json::to_value(&terminal)?);
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO durable_tasks
             (id, kind, payload_json, status, available_unix_ms, attempts,
              last_error, created_unix_ms)
             VALUES (?1, 'scm.check.publish', ?2, 'pending', ?3, 0, NULL, ?3)",
            params![
                terminal_task_id,
                serde_json::to_string(&payload)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        if inserted == 0 {
            let existing: String = transaction.query_row(
                "SELECT payload_json FROM durable_tasks
                 WHERE id = ?1 AND kind = 'scm.check.publish'",
                [&terminal_task_id],
                |row| row.get(0),
            )?;
            if serde_json::from_str::<Value>(&existing)? != payload {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
        }
    }
    Ok(())
}

pub(in crate::store) fn render_check_logs(
    newest_first_frames: &[(String, String, Vec<u8>)],
) -> String {
    if newest_first_frames.is_empty() {
        return "<details open>\n<summary><strong>Logs</strong> · no stdout/stderr</summary>\n\n_This job did not write any stdout or stderr output._\n\n</details>".to_owned();
    }

    let mut retained = Vec::new();
    let mut retained_bytes = 0_usize;
    let mut truncated = newest_first_frames.len() > MAX_GITHUB_LOG_FRAMES;
    for (step_id, stream, payload) in newest_first_frames.iter().take(MAX_GITHUB_LOG_FRAMES) {
        let payload = sanitize_log_payload(payload);
        let entry = format_log_frame(step_id, stream, &payload);
        if retained_bytes + entry.len() <= MAX_GITHUB_LOG_BYTES {
            retained_bytes += entry.len();
            retained.push(entry);
            continue;
        }
        truncated = true;
        let remaining = MAX_GITHUB_LOG_BYTES.saturating_sub(retained_bytes);
        if retained.is_empty() && remaining > 64 {
            let overhead = step_id.len() + stream.len() + 32;
            let payload = tail_utf8(&payload, remaining.saturating_sub(overhead));
            let entry = format_log_frame(step_id, stream, payload);
            if entry.len() <= remaining {
                retained.push(entry);
            }
        }
        break;
    }
    let retained_frame_count = retained.len();
    retained.reverse();

    let mut output = format!(
        "<details open>\n<summary><strong>Logs</strong> · {} retained frame{}</summary>\n\n",
        retained_frame_count,
        if retained_frame_count == 1 { "" } else { "s" }
    );
    if truncated {
        output.push_str(
            "> **Log output was truncated to GitHub's display limit.** The most recent output is shown.\n\n",
        );
    }
    for entry in retained {
        output.push_str(&entry);
    }
    output.push_str("\n</details>");
    output
}

fn format_log_frame(step_id: &str, stream: &str, payload: &str) -> String {
    let mut output = format!("    [{step_id} · {stream}]\n");
    for line in payload.split('\n') {
        output.push_str("    ");
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn sanitize_log_payload(payload: &[u8]) -> String {
    String::from_utf8_lossy(payload)
        .chars()
        .map(|character| {
            if character == '\n' || character == '\t' || !character.is_control() {
                character
            } else {
                '�'
            }
        })
        .collect()
}

fn tail_utf8(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }
    let mut start = value.len() - maximum_bytes;
    while !value.is_char_boundary(start) {
        start += 1;
    }
    &value[start..]
}

fn markdown_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.push(' ');
        } else {
            if matches!(
                character,
                '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '<' | '>' | '#' | '!' | '|' | '~'
            ) {
                escaped.push('\\');
            }
            escaped.push(character);
        }
    }
    escaped
}

fn elapsed(start_unix_ms: Option<u64>, end_unix_ms: Option<u64>) -> Option<String> {
    let milliseconds = end_unix_ms?.checked_sub(start_unix_ms?)?;
    if milliseconds < 1_000 {
        return Some(format!("{milliseconds} ms"));
    }
    let seconds = milliseconds / 1_000;
    let tenths = (milliseconds % 1_000) / 100;
    Some(format!("{seconds}.{tenths} s"))
}
