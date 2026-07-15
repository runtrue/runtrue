use super::super::*;
use super::triggers::{append_normalized_trigger_audit_tx, persist_normalized_trigger_tx};

impl ControlPlane {
    /// Compare-and-swap one UTC schedule cursor. Missed-fire reconciliation is
    /// bounded by the signed catch-up policy stored alongside the cursor.
    pub fn put_schedule_cursor(
        &self,
        cursor: &ScheduleTriggerCursor,
        expected_version: Option<u64>,
    ) -> Result<(), ControlPlaneError> {
        validate_text("schedule tenant", &cursor.tenant_id)?;
        validate_text("schedule repository", &cursor.repository_id)?;
        validate_text("schedule workflow", &cursor.workflow_identity)?;
        validate_text("schedule key", &cursor.schedule_key)?;
        validate_utc_cron(&cursor.cron_utc)?;
        if !matches!(
            cursor.catch_up_policy.as_str(),
            "skip" | "latest" | "all-bounded"
        ) || cursor.maximum_catch_up > 100
            || (cursor.catch_up_policy == "all-bounded" && cursor.maximum_catch_up == 0)
            || cursor.version == 0
            || cursor
                .last_fire_unix_ms
                .is_some_and(|last| cursor.next_fire_unix_ms <= last)
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid durable schedule cursor bounds",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM repositories
                           WHERE id = ?1 AND tenant_id = ?2)",
            params![cursor.repository_id, cursor.tenant_id],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(not_found("repository", &cursor.repository_id));
        }
        let changed = match expected_version {
            None if cursor.version == 1 => transaction.execute(
                "INSERT INTO schedule_trigger_cursors
                 (tenant_id, repository_id, workflow_identity, schedule_key,
                  cron_utc, catch_up_policy, maximum_catch_up, next_fire_unix_ms,
                  last_fire_unix_ms, version, updated_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT DO NOTHING",
                params![
                    cursor.tenant_id,
                    cursor.repository_id,
                    cursor.workflow_identity,
                    cursor.schedule_key,
                    cursor.cron_utc,
                    cursor.catch_up_policy,
                    to_i64(cursor.maximum_catch_up)?,
                    to_i64(cursor.next_fire_unix_ms)?,
                    cursor.last_fire_unix_ms.map(to_i64).transpose()?,
                    to_i64(cursor.version)?,
                    to_i64(cursor.updated_unix_ms)?,
                ],
            )?,
            None => return Err(ControlPlaneError::IdempotencyConflict),
            Some(expected) => transaction.execute(
                "UPDATE schedule_trigger_cursors SET
                   cron_utc = ?5, catch_up_policy = ?6, maximum_catch_up = ?7,
                   next_fire_unix_ms = ?8, last_fire_unix_ms = ?9,
                   version = ?10, updated_unix_ms = ?11
                 WHERE tenant_id = ?1 AND repository_id = ?2
                   AND workflow_identity = ?3 AND schedule_key = ?4
                   AND version = ?12 AND ?10 = ?12 + 1",
                params![
                    cursor.tenant_id,
                    cursor.repository_id,
                    cursor.workflow_identity,
                    cursor.schedule_key,
                    cursor.cron_utc,
                    cursor.catch_up_policy,
                    to_i64(cursor.maximum_catch_up)?,
                    to_i64(cursor.next_fire_unix_ms)?,
                    cursor.last_fire_unix_ms.map(to_i64).transpose()?,
                    to_i64(cursor.version)?,
                    to_i64(cursor.updated_unix_ms)?,
                    to_i64(expected)?,
                ],
            )?,
        };
        if changed == 1 {
            append_audit_event_tx(
                &transaction,
                &self.installation_id,
                AuditEventData {
                    observed_unix_ms: cursor.updated_unix_ms,
                    tenant_id: cursor.tenant_id.clone(),
                    actor: AuditPrincipal {
                        kind: "worker".to_owned(),
                        id: "schedule-reconciler".to_owned(),
                    },
                    action: "workflow.schedule.cursor".to_owned(),
                    resource: AuditResource {
                        kind: "schedule-cursor".to_owned(),
                        id: cursor.schedule_key.clone(),
                    },
                    result: "persisted".to_owned(),
                    request_id: format!("{}:{}", cursor.schedule_key, cursor.version),
                    decision_id: None,
                    metadata: BTreeMap::from([(
                        "next_fire_unix_ms".to_owned(),
                        AuditValue::Integer(to_i64(cursor.next_fire_unix_ms)?),
                    )]),
                },
            )?;
            transaction.commit()?;
            Ok(())
        } else {
            Err(ControlPlaneError::IdempotencyConflict)
        }
    }

    /// Reconcile a bounded page of due UTC schedules. Trigger insertion and
    /// cursor advancement share one immediate transaction, so a restart can
    /// expose neither a trigger without its new cursor nor a cursor that lost
    /// a trigger. The caller controls only the global work bound.
    pub fn reconcile_due_schedules(
        &self,
        now_unix_ms: u64,
        limit: usize,
    ) -> Result<ScheduleReconciliationSummary, ControlPlaneError> {
        if limit == 0 || limit > MAX_DUE_SCHEDULES_PER_TICK {
            return Err(ControlPlaneError::InvalidInput(
                "due schedule reconciliation limit is invalid",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cursors = {
            let mut statement = transaction.prepare(
                "SELECT tenant_id, repository_id, workflow_identity, schedule_key,
                        cron_utc, catch_up_policy, maximum_catch_up,
                        next_fire_unix_ms, last_fire_unix_ms, version,
                        updated_unix_ms
                 FROM schedule_trigger_cursors
                 WHERE next_fire_unix_ms <= ?1
                 ORDER BY next_fire_unix_ms, tenant_id, repository_id,
                          workflow_identity, schedule_key
                 LIMIT ?2",
            )?;
            let cursors = statement
                .query_map(
                    params![to_i64(now_unix_ms)?, to_i64(limit as u64)?],
                    |row| {
                        Ok(ScheduleTriggerCursor {
                            tenant_id: row.get(0)?,
                            repository_id: row.get(1)?,
                            workflow_identity: row.get(2)?,
                            schedule_key: row.get(3)?,
                            cron_utc: row.get(4)?,
                            catch_up_policy: row.get(5)?,
                            maximum_catch_up: u64_column(row, 6, "maximum catch up")?,
                            next_fire_unix_ms: u64_column(row, 7, "next fire")?,
                            last_fire_unix_ms: optional_u64_column(row, 8, "last fire")?,
                            version: u64_column(row, 9, "schedule version")?,
                            updated_unix_ms: u64_column(row, 10, "schedule updated")?,
                        })
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            cursors
        };
        let mut summary = ScheduleReconciliationSummary {
            cursors_considered: cursors.len() as u64,
            ..ScheduleReconciliationSummary::default()
        };
        for cursor in cursors {
            validate_utc_cron(&cursor.cron_utc)?;
            if !cursor.next_fire_unix_ms.is_multiple_of(60_000)
                || !cron_matches_unix_ms(&cursor.cron_utc, cursor.next_fire_unix_ms)?
            {
                return Err(ControlPlaneError::CorruptState(
                    "durable schedule cursor is not on its UTC cron".to_owned(),
                ));
            }
            let fires = match cursor.catch_up_policy.as_str() {
                "skip" => Vec::new(),
                "latest" => vec![previous_cron_fire_at_or_before(
                    &cursor.cron_utc,
                    now_unix_ms,
                )?],
                "all-bounded" if cursor.maximum_catch_up != 0 => {
                    let mut fires = Vec::new();
                    let mut fire = cursor.next_fire_unix_ms;
                    let maximum = cursor.maximum_catch_up.min(100);
                    while fire <= now_unix_ms && fires.len() < maximum as usize {
                        fires.push(fire);
                        fire = next_cron_fire_after(&cursor.cron_utc, fire)?;
                    }
                    fires
                }
                _ => {
                    return Err(ControlPlaneError::CorruptState(
                        "durable schedule catch-up policy is invalid".to_owned(),
                    ))
                }
            };
            let next_fire = if cursor.catch_up_policy == "all-bounded" {
                fires
                    .last()
                    .copied()
                    .map(|fire| next_cron_fire_after(&cursor.cron_utc, fire))
                    .transpose()?
                    .unwrap_or(cursor.next_fire_unix_ms)
            } else {
                next_cron_fire_after(&cursor.cron_utc, now_unix_ms)?
            };
            let mut last_fire = cursor.last_fire_unix_ms;
            for scheduled_unix_ms in fires {
                let trigger = normalized_schedule_trigger(&cursor, scheduled_unix_ms)?;
                let replayed = persist_normalized_trigger_tx(&transaction, &trigger)?;
                if replayed {
                    summary.trigger_replays = summary.trigger_replays.saturating_add(1);
                } else {
                    summary.triggers_inserted = summary.triggers_inserted.saturating_add(1);
                    append_normalized_trigger_audit_tx(
                        &transaction,
                        &self.installation_id,
                        &trigger,
                    )?;
                }
                last_fire = Some(scheduled_unix_ms);
            }
            let changed = transaction.execute(
                "UPDATE schedule_trigger_cursors SET
                   next_fire_unix_ms = ?6, last_fire_unix_ms = ?7,
                   version = version + 1, updated_unix_ms = ?8
                 WHERE tenant_id = ?1 AND repository_id = ?2
                   AND workflow_identity = ?3 AND schedule_key = ?4
                   AND version = ?5",
                params![
                    cursor.tenant_id,
                    cursor.repository_id,
                    cursor.workflow_identity,
                    cursor.schedule_key,
                    to_i64(cursor.version)?,
                    to_i64(next_fire)?,
                    last_fire.map(to_i64).transpose()?,
                    to_i64(now_unix_ms)?,
                ],
            )?;
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            append_audit_event_tx(
                &transaction,
                &self.installation_id,
                AuditEventData {
                    observed_unix_ms: now_unix_ms,
                    tenant_id: cursor.tenant_id,
                    actor: AuditPrincipal {
                        kind: "worker".to_owned(),
                        id: "schedule-reconciler".to_owned(),
                    },
                    action: "workflow.schedule.reconcile".to_owned(),
                    resource: AuditResource {
                        kind: "schedule-cursor".to_owned(),
                        id: cursor.schedule_key,
                    },
                    result: "persisted".to_owned(),
                    request_id: format!("schedule-reconcile:{}", cursor.version),
                    decision_id: None,
                    metadata: BTreeMap::from([
                        (
                            "next_fire_unix_ms".to_owned(),
                            AuditValue::Integer(to_i64(next_fire)?),
                        ),
                        (
                            "triggers_inserted".to_owned(),
                            AuditValue::Integer(to_i64(summary.triggers_inserted)?),
                        ),
                    ]),
                },
            )?;
            summary.cursors_advanced = summary.cursors_advanced.saturating_add(1);
        }
        summary.due_cursors_remaining = transaction.query_row(
            "SELECT COUNT(*) FROM schedule_trigger_cursors
             WHERE next_fire_unix_ms <= ?1",
            [to_i64(now_unix_ms)?],
            |row| u64_column(row, 0, "due schedule count"),
        )?;
        transaction.commit()?;
        Ok(summary)
    }

    pub fn schedule_cursor(
        &self,
        tenant_id: &str,
        repository_id: &str,
        workflow_identity: &str,
        schedule_key: &str,
    ) -> Result<ScheduleTriggerCursor, ControlPlaneError> {
        validate_text("schedule tenant", tenant_id)?;
        validate_text("schedule repository", repository_id)?;
        validate_text("schedule workflow", workflow_identity)?;
        validate_text("schedule key", schedule_key)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT tenant_id, repository_id, workflow_identity, schedule_key,
                        cron_utc, catch_up_policy, maximum_catch_up,
                        next_fire_unix_ms, last_fire_unix_ms, version, updated_unix_ms
                 FROM schedule_trigger_cursors
                 WHERE tenant_id = ?1 AND repository_id = ?2
                   AND workflow_identity = ?3 AND schedule_key = ?4",
                params![tenant_id, repository_id, workflow_identity, schedule_key],
                |row| {
                    Ok(ScheduleTriggerCursor {
                        tenant_id: row.get(0)?,
                        repository_id: row.get(1)?,
                        workflow_identity: row.get(2)?,
                        schedule_key: row.get(3)?,
                        cron_utc: row.get(4)?,
                        catch_up_policy: row.get(5)?,
                        maximum_catch_up: u64_column(row, 6, "maximum catch up")?,
                        next_fire_unix_ms: u64_column(row, 7, "next fire")?,
                        last_fire_unix_ms: optional_u64_column(row, 8, "last fire")?,
                        version: u64_column(row, 9, "schedule version")?,
                        updated_unix_ms: u64_column(row, 10, "schedule updated")?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| not_found("schedule cursor", schedule_key))
    }

    pub fn workflow_semantics_metrics(
        &self,
        tenant_id: &str,
        now_unix_ms: u64,
    ) -> Result<WorkflowSemanticsMetrics, ControlPlaneError> {
        validate_text("workflow metrics tenant", tenant_id)?;
        let connection = self.connection()?;
        let count =
            |sql: &str, params: &[&dyn rusqlite::ToSql]| -> Result<u64, ControlPlaneError> {
                let value: i64 = connection.query_row(sql, params, |row| row.get(0))?;
                from_i64("workflow semantics metric", value)
            };
        Ok(WorkflowSemanticsMetrics {
            expanded_job_sets: count(
                "SELECT COUNT(*) FROM expanded_job_sets WHERE tenant_id = ?1",
                &[&tenant_id],
            )?,
            normalized_triggers: count(
                "SELECT COUNT(*) FROM normalized_trigger_events WHERE tenant_id = ?1",
                &[&tenant_id],
            )?,
            due_schedules: count(
                "SELECT COUNT(*) FROM schedule_trigger_cursors
                 WHERE tenant_id = ?1 AND next_fire_unix_ms <= ?2",
                &[&tenant_id, &to_i64(now_unix_ms)?],
            )?,
        })
    }
}

fn validate_utc_cron(value: &str) -> Result<(), ControlPlaneError> {
    if value.len() > 128 {
        return Err(ControlPlaneError::InvalidInput("UTC cron is too long"));
    }
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    let ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)];
    if fields.len() != ranges.len()
        || fields
            .iter()
            .zip(ranges)
            .any(|(field, (minimum, maximum))| !valid_cron_field(field, minimum, maximum))
    {
        return Err(ControlPlaneError::InvalidInput(
            "schedule cron must be a five-field UTC numeric expression",
        ));
    }
    Ok(())
}

fn valid_cron_field(field: &str, minimum: u32, maximum: u32) -> bool {
    if field.is_empty() {
        return false;
    }
    field.split(',').all(|part| {
        let mut stepped = part.split('/');
        let base = stepped.next().unwrap_or_default();
        let step = stepped.next();
        if stepped.next().is_some()
            || step.is_some_and(|step| {
                step.parse::<u32>()
                    .map_or(true, |step| step == 0 || step > maximum)
            })
        {
            return false;
        }
        if base == "*" {
            return true;
        }
        if let Some((start, end)) = base.split_once('-') {
            return start.parse::<u32>().is_ok_and(|value| value >= minimum)
                && end.parse::<u32>().is_ok_and(|value| value <= maximum)
                && start.parse::<u32>().unwrap_or(maximum)
                    <= end.parse::<u32>().unwrap_or(minimum);
        }
        base.parse::<u32>()
            .is_ok_and(|value| (minimum..=maximum).contains(&value))
    })
}

fn cron_field_matches(field: &str, value: u32, minimum: u32, maximum: u32) -> bool {
    field.split(',').any(|part| {
        let (base, step) = part.split_once('/').map_or((part, 1), |(base, step)| {
            (
                base,
                step.parse::<u32>().unwrap_or(maximum.saturating_add(1)),
            )
        });
        let (start, end) = if base == "*" {
            (minimum, maximum)
        } else if let Some((start, end)) = base.split_once('-') {
            (
                start.parse::<u32>().unwrap_or(maximum.saturating_add(1)),
                end.parse::<u32>().unwrap_or(minimum.saturating_sub(1)),
            )
        } else {
            let exact = base.parse::<u32>().unwrap_or(maximum.saturating_add(1));
            (exact, exact)
        };
        value >= start && value <= end && value.saturating_sub(start).is_multiple_of(step)
    })
}

fn civil_date_from_unix_days(days: u64) -> Result<(u32, u32), ControlPlaneError> {
    let days = i64::try_from(days).map_err(|_| ControlPlaneError::IntegerRange {
        field: "UTC schedule day",
    })?;
    let shifted = days
        .checked_add(719_468)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "UTC civil date",
        })?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let _year = year + i64::from(month <= 2);
    Ok((
        u32::try_from(month).map_err(|_| ControlPlaneError::IntegerRange { field: "UTC month" })?,
        u32::try_from(day).map_err(|_| ControlPlaneError::IntegerRange { field: "UTC day" })?,
    ))
}

fn cron_matches_unix_ms(value: &str, unix_ms: u64) -> Result<bool, ControlPlaneError> {
    validate_utc_cron(value)?;
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    let seconds = unix_ms / 1_000;
    let minute =
        u32::try_from((seconds / 60) % 60).map_err(|_| ControlPlaneError::IntegerRange {
            field: "UTC minute",
        })?;
    let hour = u32::try_from((seconds / 3_600) % 24)
        .map_err(|_| ControlPlaneError::IntegerRange { field: "UTC hour" })?;
    let days = seconds / 86_400;
    let (month, day) = civil_date_from_unix_days(days)?;
    let weekday = u32::try_from((days + 4) % 7).map_err(|_| ControlPlaneError::IntegerRange {
        field: "UTC weekday",
    })?;
    let day_of_month = cron_field_matches(fields[2], day, 1, 31);
    let day_of_week = cron_field_matches(fields[4], weekday, 0, 6);
    let day_matches = match (fields[2] == "*", fields[4] == "*") {
        (true, true) => true,
        (true, false) => day_of_week,
        (false, true) => day_of_month,
        (false, false) => day_of_month || day_of_week,
    };
    Ok(cron_field_matches(fields[0], minute, 0, 59)
        && cron_field_matches(fields[1], hour, 0, 23)
        && day_matches
        && cron_field_matches(fields[3], month, 1, 12))
}

fn next_cron_fire_after(value: &str, after_unix_ms: u64) -> Result<u64, ControlPlaneError> {
    let first_minute = after_unix_ms
        .checked_div(60_000)
        .and_then(|minute| minute.checked_add(1))
        .ok_or(ControlPlaneError::IntegerRange {
            field: "next UTC schedule minute",
        })?;
    for offset in 0..MAX_CRON_SEARCH_MINUTES {
        let candidate = first_minute
            .checked_add(offset)
            .and_then(|minute| minute.checked_mul(60_000))
            .ok_or(ControlPlaneError::IntegerRange {
                field: "next UTC schedule fire",
            })?;
        if cron_matches_unix_ms(value, candidate)? {
            return Ok(candidate);
        }
    }
    Err(ControlPlaneError::InvalidInput(
        "UTC cron has no fire within the bounded search horizon",
    ))
}

fn previous_cron_fire_at_or_before(value: &str, at_unix_ms: u64) -> Result<u64, ControlPlaneError> {
    let minute = at_unix_ms / 60_000;
    for offset in 0..MAX_CRON_SEARCH_MINUTES {
        let Some(candidate_minute) = minute.checked_sub(offset) else {
            break;
        };
        let candidate =
            candidate_minute
                .checked_mul(60_000)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "previous UTC schedule fire",
                })?;
        if cron_matches_unix_ms(value, candidate)? {
            return Ok(candidate);
        }
    }
    Err(ControlPlaneError::InvalidInput(
        "UTC cron has no prior fire within the bounded search horizon",
    ))
}

fn normalized_schedule_trigger(
    cursor: &ScheduleTriggerCursor,
    scheduled_unix_ms: u64,
) -> Result<NormalizedTriggerEventRecord, ControlPlaneError> {
    let envelope = runtrue_workflow_ir::canonicalize_value(serde_json::json!({
        "cron_utc": cursor.cron_utc,
        "repository_id": cursor.repository_id,
        "schedule_key": cursor.schedule_key,
        "scheduled_unix_ms": scheduled_unix_ms,
        "trigger_kind": "schedule",
        "version": 1,
        "workflow_identity": cursor.workflow_identity,
    }));
    let canonical = serde_json::to_vec(&envelope)?;
    let normalized_digest = ContentDigest::sha256(&canonical);
    let idempotency_identity = format!(
        "{}:{}:{}",
        cursor.workflow_identity, cursor.schedule_key, scheduled_unix_ms
    );
    let mut id = Sha256::new();
    id.update(b"runtrue.normalized-schedule-trigger.v1\0");
    id.update(cursor.tenant_id.as_bytes());
    id.update([0]);
    id.update(cursor.repository_id.as_bytes());
    id.update([0]);
    id.update(idempotency_identity.as_bytes());
    Ok(NormalizedTriggerEventRecord {
        id: format!("schedule-trigger-{}", hex::encode(id.finalize())),
        tenant_id: cursor.tenant_id.clone(),
        repository_id: cursor.repository_id.clone(),
        trigger_kind: "schedule".to_owned(),
        idempotency_identity,
        normalized_digest,
        normalized_envelope: envelope,
        actor_identity: "schedule-reconciler".to_owned(),
        created_unix_ms: scheduled_unix_ms,
    })
}
