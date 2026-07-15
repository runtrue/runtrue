use super::*;
impl ControlPlane {
    /// Persist one authenticated GitHub delivery after resolving its exact
    /// active installation and repository link. Raw payload bytes are never
    /// accepted by this boundary.
    pub fn record_scm_webhook_event(
        &self,
        event: &NewScmWebhookEvent,
    ) -> Result<IdempotentResult<ScmWebhookEventRecord>, ControlPlaneError> {
        for value in [
            event.delivery_id.as_str(),
            event.installation_external_id.as_str(),
            event.external_repository_id.as_str(),
            event.provider_event_name.as_str(),
            event.event_kind.as_str(),
            event.actor_login.as_str(),
        ] {
            validate_text("SCM webhook event field", value)?;
        }
        if event
            .ref_name
            .as_ref()
            .is_some_and(|value| validate_text("SCM webhook ref", value).is_err())
        {
            return Err(ControlPlaneError::InvalidInput("invalid SCM webhook ref"));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let binding = transaction
            .query_row(
                "SELECT i.tenant_id, l.repository_id, i.id
                   FROM scm_installations i
                   JOIN scm_repository_links l
                     ON l.tenant_id = i.tenant_id AND l.installation_id = i.id
                  WHERE i.provider = 'github' AND i.external_id = ?1
                    AND i.status = 'active' AND l.external_repository_id = ?2
                    AND l.status = 'active'",
                params![event.installation_external_id, event.external_repository_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                not_found(
                    "active GitHub repository binding",
                    &event.external_repository_id,
                )
            })?;
        let record = ScmWebhookEventRecord {
            delivery_id: event.delivery_id.clone(),
            tenant_id: binding.0,
            repository_id: binding.1,
            installation_id: binding.2,
            external_repository_id: event.external_repository_id.clone(),
            provider_event_name: event.provider_event_name.clone(),
            event_kind: event.event_kind.clone(),
            actor_login: event.actor_login.clone(),
            ref_name: event.ref_name.clone(),
            normalized_digest: event.normalized_digest.clone(),
            payload_digest: event.payload_digest.clone(),
            received_unix_ms: event.received_unix_ms,
        };
        let inserted = transaction.execute(
            "INSERT INTO scm_webhook_events
             (delivery_id, tenant_id, repository_id, installation_id,
              external_repository_id, provider_event_name, event_kind,
              actor_login, ref_name, normalized_digest, payload_digest,
              received_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(delivery_id) DO NOTHING",
            params![
                record.delivery_id,
                record.tenant_id,
                record.repository_id,
                record.installation_id,
                record.external_repository_id,
                record.provider_event_name,
                record.event_kind,
                record.actor_login,
                record.ref_name,
                record.normalized_digest.as_str(),
                record.payload_digest.as_str(),
                to_i64(record.received_unix_ms)?,
            ],
        )?;
        if inserted == 0 {
            let existing = transaction.query_row(
                "SELECT delivery_id, tenant_id, repository_id, installation_id,
                        external_repository_id, provider_event_name, event_kind,
                        actor_login, ref_name, normalized_digest, payload_digest,
                        received_unix_ms
                   FROM scm_webhook_events WHERE delivery_id = ?1",
                [&record.delivery_id],
                |row| {
                    Ok(ScmWebhookEventRecord {
                        delivery_id: row.get(0)?,
                        tenant_id: row.get(1)?,
                        repository_id: row.get(2)?,
                        installation_id: row.get(3)?,
                        external_repository_id: row.get(4)?,
                        provider_event_name: row.get(5)?,
                        event_kind: row.get(6)?,
                        actor_login: row.get(7)?,
                        ref_name: row.get(8)?,
                        normalized_digest: digest_column(row, 9)?,
                        payload_digest: digest_column(row, 10)?,
                        received_unix_ms: u64_column(row, 11, "webhook event time")?,
                    })
                },
            )?;
            if existing.tenant_id != record.tenant_id
                || existing.repository_id != record.repository_id
                || existing.installation_id != record.installation_id
                || existing.external_repository_id != record.external_repository_id
                || existing.provider_event_name != record.provider_event_name
                || existing.event_kind != record.event_kind
                || existing.actor_login != record.actor_login
                || existing.ref_name != record.ref_name
                || existing.payload_digest != record.payload_digest
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: existing,
                replayed: true,
            });
        }
        transaction.commit()?;
        Ok(IdempotentResult {
            value: record,
            replayed: false,
        })
    }

    pub fn scm_webhook_events_for_repository(
        &self,
        tenant_id: &str,
        repository_id: &str,
        before_unix_ms: Option<u64>,
        limit: usize,
    ) -> Result<Vec<ScmWebhookEventRecord>, ControlPlaneError> {
        validate_text("webhook event tenant", tenant_id)?;
        validate_text("webhook event repository", repository_id)?;
        if limit == 0 || limit > 100 {
            return Err(ControlPlaneError::InvalidInput(
                "invalid webhook event page limit",
            ));
        }
        let connection = self.connection()?;
        let authorized: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM repositories WHERE tenant_id = ?1 AND id = ?2)",
            params![tenant_id, repository_id],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(not_found("repository", repository_id));
        }
        let before = before_unix_ms.map(to_i64).transpose()?.unwrap_or(i64::MAX);
        let mut statement = connection.prepare(
            "SELECT delivery_id, tenant_id, repository_id, installation_id,
                    external_repository_id, provider_event_name, event_kind,
                    actor_login, ref_name, normalized_digest, payload_digest,
                    received_unix_ms
               FROM scm_webhook_events
              WHERE tenant_id = ?1 AND repository_id = ?2
                AND received_unix_ms < ?3
              ORDER BY received_unix_ms DESC, delivery_id DESC LIMIT ?4",
        )?;
        let records = statement
            .query_map(
                params![
                    tenant_id,
                    repository_id,
                    before,
                    i64::try_from(limit).map_err(|_| ControlPlaneError::InvalidInput(
                        "invalid webhook event page limit"
                    ))?
                ],
                |row| {
                    Ok(ScmWebhookEventRecord {
                        delivery_id: row.get(0)?,
                        tenant_id: row.get(1)?,
                        repository_id: row.get(2)?,
                        installation_id: row.get(3)?,
                        external_repository_id: row.get(4)?,
                        provider_event_name: row.get(5)?,
                        event_kind: row.get(6)?,
                        actor_login: row.get(7)?,
                        ref_name: row.get(8)?,
                        normalized_digest: digest_column(row, 9)?,
                        payload_digest: digest_column(row, 10)?,
                        received_unix_ms: u64_column(row, 11, "webhook event time")?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(ControlPlaneError::from)?;
        Ok(records)
    }
}
