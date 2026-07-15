use super::super::*;

impl ControlPlane {
    /// Replace one tenant's storage limits. The operation does not discard
    /// bytes when a limit is lowered; subsequent reservations fail closed.
    pub fn set_tenant_storage_quota(
        &self,
        quota: &TenantStorageQuota,
    ) -> Result<(), ControlPlaneError> {
        validate_text("storage quota tenant", &quota.tenant_id)?;
        if quota.maximum_stored_bytes == 0 || quota.maximum_object_count == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "storage quota bounds must be greater than zero",
            ));
        }
        let connection = self.connection()?;
        let tenant_exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM repositories WHERE tenant_id = ?1)",
            [&quota.tenant_id],
            |row| row.get(0),
        )?;
        if !tenant_exists {
            return Err(not_found("tenant", &quota.tenant_id));
        }
        connection.execute(
            "INSERT INTO tenant_storage_quotas
             (tenant_id, maximum_stored_bytes, maximum_object_count, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(tenant_id) DO UPDATE SET
               maximum_stored_bytes = excluded.maximum_stored_bytes,
               maximum_object_count = excluded.maximum_object_count,
               updated_unix_ms = excluded.updated_unix_ms",
            params![
                quota.tenant_id,
                to_i64(quota.maximum_stored_bytes)?,
                to_i64(quota.maximum_object_count)?,
                to_i64(quota.updated_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    /// Atomically charge storage before issuing an upload/create ticket.
    /// Exact replay returns the existing reservation and substitutions conflict.
    pub fn reserve_tenant_storage(
        &self,
        reservation: &TenantStorageReservation,
        now_unix_ms: u64,
    ) -> Result<bool, ControlPlaneError> {
        validate_storage_reservation(reservation)?;
        if reservation.state != StorageReservationState::Reserved
            || reservation.completed_unix_ms.is_some()
            || now_unix_ms < reservation.created_unix_ms
            || now_unix_ms >= reservation.expires_unix_ms
        {
            return Err(ControlPlaneError::InvalidInput(
                "new storage reservation is not active",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT id, tenant_id, ticket_kind, object_digest, reserved_bytes,
                        reserved_objects, state, created_unix_ms, expires_unix_ms,
                        completed_unix_ms
                 FROM tenant_storage_reservations WHERE id = ?1",
                [&reservation.id],
                storage_reservation_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == *reservation {
                transaction.commit()?;
                return Ok(true);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let tenant_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM repositories WHERE tenant_id = ?1)",
            [&reservation.tenant_id],
            |row| row.get(0),
        )?;
        if !tenant_exists {
            return Err(not_found("tenant storage quota", &reservation.tenant_id));
        }
        transaction.execute(
            "INSERT OR IGNORE INTO tenant_storage_quotas
             (tenant_id, maximum_stored_bytes, maximum_object_count, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                reservation.tenant_id,
                to_i64(DEFAULT_TENANT_MAXIMUM_STORED_BYTES)?,
                to_i64(DEFAULT_TENANT_MAXIMUM_OBJECT_COUNT)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        let quota = transaction
            .query_row(
                "SELECT tenant_id, maximum_stored_bytes, maximum_object_count, updated_unix_ms
                 FROM tenant_storage_quotas WHERE tenant_id = ?1",
                [&reservation.tenant_id],
                storage_quota_row,
            )
            .optional()?
            .ok_or_else(|| not_found("tenant storage quota", &reservation.tenant_id))?;
        transaction.execute(
            "UPDATE tenant_storage_reservations
             SET state = 'expired', completed_unix_ms = ?2
             WHERE tenant_id = ?1 AND state = 'reserved' AND expires_unix_ms <= ?2",
            params![reservation.tenant_id, to_i64(now_unix_ms)?],
        )?;
        let catalog_usage: (i64, i64) = transaction.query_row(
            "SELECT COALESCE(SUM(billed_bytes), 0), COALESCE(SUM(billed_objects), 0)
             FROM tenant_storage_objects WHERE tenant_id = ?1 AND state = 'active'",
            [&reservation.tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let reservations: (i64, i64) = transaction.query_row(
            "SELECT COALESCE(SUM(reserved_bytes), 0), COALESCE(SUM(reserved_objects), 0)
             FROM tenant_storage_reservations
             WHERE tenant_id = ?1 AND state IN ('reserved','committed')",
            [&reservation.tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let used_bytes = from_i64("tenant stored bytes", catalog_usage.0)?
            .checked_add(from_i64("tenant reserved bytes", reservations.0)?)
            .and_then(|value| value.checked_add(reservation.reserved_bytes))
            .ok_or(ControlPlaneError::IntegerRange {
                field: "tenant stored bytes",
            })?;
        let used_objects = from_i64("tenant stored objects", catalog_usage.1)?
            .checked_add(from_i64("tenant reserved objects", reservations.1)?)
            .and_then(|value| value.checked_add(reservation.reserved_objects))
            .ok_or(ControlPlaneError::IntegerRange {
                field: "tenant stored objects",
            })?;
        if used_bytes > quota.maximum_stored_bytes || used_objects > quota.maximum_object_count {
            return Err(ControlPlaneError::StorageQuotaExceeded);
        }
        transaction.execute(
            "INSERT INTO tenant_storage_reservations
             (id, tenant_id, ticket_kind, object_digest, reserved_bytes,
              reserved_objects, state, created_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'reserved', ?7, ?8)",
            params![
                reservation.id,
                reservation.tenant_id,
                reservation.ticket_kind,
                reservation
                    .object_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
                to_i64(reservation.reserved_bytes)?,
                to_i64(reservation.reserved_objects)?,
                to_i64(reservation.created_unix_ms)?,
                to_i64(reservation.expires_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    pub fn tenant_storage_reservation(
        &self,
        tenant_id: &str,
        reservation_id: &str,
    ) -> Result<Option<TenantStorageReservation>, ControlPlaneError> {
        validate_text("storage reservation tenant", tenant_id)?;
        validate_text("storage reservation id", reservation_id)?;
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT id, tenant_id, ticket_kind, object_digest, reserved_bytes,
                        reserved_objects, state, created_unix_ms, expires_unix_ms,
                        completed_unix_ms
                 FROM tenant_storage_reservations
                 WHERE id = ?1 AND tenant_id = ?2",
                params![reservation_id, tenant_id],
                storage_reservation_row,
            )
            .optional()?)
    }

    pub fn finish_tenant_storage_reservation(
        &self,
        tenant_id: &str,
        reservation_id: &str,
        target: StorageReservationState,
        now_unix_ms: u64,
    ) -> Result<bool, ControlPlaneError> {
        if !matches!(
            target,
            StorageReservationState::Committed | StorageReservationState::Released
        ) {
            return Err(ControlPlaneError::InvalidInput(
                "storage reservation finish state is invalid",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "SELECT id, tenant_id, ticket_kind, object_digest, reserved_bytes,
                        reserved_objects, state, created_unix_ms, expires_unix_ms,
                        completed_unix_ms
                 FROM tenant_storage_reservations WHERE id = ?1 AND tenant_id = ?2",
                params![reservation_id, tenant_id],
                storage_reservation_row,
            )
            .optional()?
            .ok_or_else(|| not_found("storage reservation", reservation_id))?;
        if current.state == target {
            transaction.commit()?;
            return Ok(true);
        }
        if current.state != StorageReservationState::Reserved
            || now_unix_ms >= current.expires_unix_ms
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE tenant_storage_reservations
             SET state = ?3, completed_unix_ms = ?4
             WHERE id = ?1 AND tenant_id = ?2 AND state = 'reserved'",
            params![
                reservation_id,
                tenant_id,
                storage_reservation_state_str(&target),
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    /// Join a filesystem-backed data-plane ticket to the atomic quota
    /// reservation that preceded issuance. Commit handlers must require this
    /// row; a ticket left behind by a crash before this join is not authority.
    pub fn bind_tenant_storage_ticket(
        &self,
        binding: &StorageTicketBinding,
        now_unix_ms: u64,
    ) -> Result<bool, ControlPlaneError> {
        validate_storage_ticket_binding(binding)?;
        if binding.state != StorageTicketBindingState::Issued
            || binding.object_id.is_some()
            || binding.actual_bytes.is_some()
            || binding.actual_objects.is_some()
            || binding.completed_unix_ms.is_some()
            || binding.created_unix_ms != binding.updated_unix_ms
            || binding.created_unix_ms > now_unix_ms
        {
            return Err(ControlPlaneError::InvalidInput(
                "new storage ticket binding is not issued",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = storage_ticket_binding_by_reservation_tx(
            &transaction,
            &binding.tenant_id,
            &binding.reservation_id,
        )? {
            if existing == *binding {
                transaction.commit()?;
                return Ok(true);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let reservation = transaction
            .query_row(
                "SELECT id, tenant_id, ticket_kind, object_digest, reserved_bytes,
                        reserved_objects, state, created_unix_ms, expires_unix_ms,
                        completed_unix_ms
                 FROM tenant_storage_reservations
                 WHERE id = ?1 AND tenant_id = ?2",
                params![binding.reservation_id, binding.tenant_id],
                storage_reservation_row,
            )
            .optional()?
            .ok_or_else(|| not_found("storage reservation", &binding.reservation_id))?;
        if reservation.ticket_kind != binding.ticket_kind
            || reservation.state != StorageReservationState::Reserved
            || now_unix_ms >= reservation.expires_unix_ms
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO tenant_storage_ticket_bindings
             (reservation_id, tenant_id, ticket_kind, ticket_id, state,
              created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, 'issued', ?5, ?5)",
            params![
                binding.reservation_id,
                binding.tenant_id,
                binding.ticket_kind,
                binding.ticket_id,
                to_i64(binding.created_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    pub fn storage_ticket_binding_for_reservation(
        &self,
        tenant_id: &str,
        reservation_id: &str,
    ) -> Result<Option<StorageTicketBinding>, ControlPlaneError> {
        validate_text("storage ticket tenant", tenant_id)?;
        validate_text("storage reservation id", reservation_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let value =
            storage_ticket_binding_by_reservation_tx(&transaction, tenant_id, reservation_id)?;
        transaction.commit()?;
        Ok(value)
    }

    /// Mark the exact bound ticket as having published immutable bytes. The
    /// reservation stays charged until catalog/generation metadata accounts
    /// the object in a later atomic transaction.
    pub fn commit_tenant_storage_ticket(
        &self,
        tenant_id: &str,
        ticket_id: &str,
        object_id: &str,
        actual_bytes: u64,
        actual_objects: u64,
        now_unix_ms: u64,
    ) -> Result<bool, ControlPlaneError> {
        for (field, value) in [
            ("storage ticket tenant", tenant_id),
            ("storage ticket id", ticket_id),
            ("storage ticket object", object_id),
        ] {
            validate_text(field, value)?;
        }
        if actual_objects == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "storage ticket object count is zero",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let binding = storage_ticket_binding_by_ticket_tx(&transaction, tenant_id, ticket_id)?
            .ok_or_else(|| not_found("storage ticket", ticket_id))?;
        if matches!(
            binding.state,
            StorageTicketBindingState::Committed | StorageTicketBindingState::Accounted
        ) {
            if binding.object_id.as_deref() == Some(object_id)
                && binding.actual_bytes == Some(actual_bytes)
                && binding.actual_objects == Some(actual_objects)
            {
                transaction.commit()?;
                return Ok(true);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if binding.state != StorageTicketBindingState::Issued {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let reservation = transaction
            .query_row(
                "SELECT id, tenant_id, ticket_kind, object_digest, reserved_bytes,
                        reserved_objects, state, created_unix_ms, expires_unix_ms,
                        completed_unix_ms
                 FROM tenant_storage_reservations
                 WHERE id = ?1 AND tenant_id = ?2",
                params![binding.reservation_id, tenant_id],
                storage_reservation_row,
            )
            .optional()?
            .ok_or_else(|| not_found("storage reservation", &binding.reservation_id))?;
        if reservation.state != StorageReservationState::Reserved
            || now_unix_ms >= reservation.expires_unix_ms
            || actual_bytes > reservation.reserved_bytes
            || actual_objects > reservation.reserved_objects
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE tenant_storage_ticket_bindings
             SET object_id = ?3, actual_bytes = ?4, actual_objects = ?5,
                 state = 'committed', updated_unix_ms = ?6
             WHERE tenant_id = ?1 AND ticket_id = ?2 AND state = 'issued'",
            params![
                tenant_id,
                ticket_id,
                object_id,
                to_i64(actual_bytes)?,
                to_i64(actual_objects)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "UPDATE tenant_storage_reservations
             SET state = 'committed', completed_unix_ms = ?3
             WHERE id = ?1 AND tenant_id = ?2 AND state = 'reserved'",
            params![binding.reservation_id, tenant_id, to_i64(now_unix_ms)?],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    /// Move an immutable ticket result from reservation charge to durable
    /// logical-object charge. Exact replay is accepted; substitutions fail.
    pub fn account_tenant_storage_ticket(
        &self,
        tenant_id: &str,
        ticket_id: &str,
        object_id: &str,
        now_unix_ms: u64,
    ) -> Result<bool, ControlPlaneError> {
        for (field, value) in [
            ("storage ticket tenant", tenant_id),
            ("storage ticket id", ticket_id),
            ("storage ticket object", object_id),
        ] {
            validate_text(field, value)?;
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let replayed =
            account_storage_ticket_tx(&transaction, tenant_id, ticket_id, object_id, now_unix_ms)?;
        transaction.commit()?;
        Ok(replayed)
    }

    pub fn tenant_storage_usage(
        &self,
        tenant_id: &str,
    ) -> Result<TenantStorageUsage, ControlPlaneError> {
        validate_text("storage usage tenant", tenant_id)?;
        let connection = self.connection()?;
        let active: (i64, i64) = connection.query_row(
            "SELECT COALESCE(SUM(billed_bytes), 0), COALESCE(SUM(billed_objects), 0)
             FROM tenant_storage_objects WHERE tenant_id = ?1 AND state = 'active'",
            [tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let reserved: (i64, i64) = connection.query_row(
            "SELECT COALESCE(SUM(reserved_bytes), 0), COALESCE(SUM(reserved_objects), 0)
             FROM tenant_storage_reservations
             WHERE tenant_id = ?1 AND state IN ('reserved','committed')",
            [tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(TenantStorageUsage {
            tenant_id: tenant_id.to_owned(),
            active_bytes: from_i64("active storage bytes", active.0)?,
            active_objects: from_i64("active storage objects", active.1)?,
            reserved_bytes: from_i64("reserved storage bytes", reserved.0)?,
            reserved_objects: from_i64("reserved storage objects", reserved.1)?,
        })
    }
}

fn storage_reservation_state_str(state: &StorageReservationState) -> &'static str {
    match state {
        StorageReservationState::Reserved => "reserved",
        StorageReservationState::Committed => "committed",
        StorageReservationState::Released => "released",
        StorageReservationState::Expired => "expired",
    }
}

fn validate_storage_reservation(
    reservation: &TenantStorageReservation,
) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("storage reservation id", reservation.id.as_str()),
        ("storage reservation tenant", reservation.tenant_id.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if !matches!(
        reservation.ticket_kind.as_str(),
        "cache" | "artifact" | "report" | "source"
    ) || reservation.reserved_objects == 0
        || reservation.expires_unix_ms <= reservation.created_unix_ms
    {
        return Err(ControlPlaneError::InvalidInput(
            "storage reservation metadata is invalid",
        ));
    }
    Ok(())
}

fn storage_quota_row(row: &Row<'_>) -> rusqlite::Result<TenantStorageQuota> {
    Ok(TenantStorageQuota {
        tenant_id: row.get(0)?,
        maximum_stored_bytes: u64_column(row, 1, "maximum stored bytes")?,
        maximum_object_count: u64_column(row, 2, "maximum object count")?,
        updated_unix_ms: u64_column(row, 3, "storage quota update")?,
    })
}

fn storage_reservation_row(row: &Row<'_>) -> rusqlite::Result<TenantStorageReservation> {
    let raw: String = row.get(6)?;
    let state = match raw.as_str() {
        "reserved" => StorageReservationState::Reserved,
        "committed" => StorageReservationState::Committed,
        "released" => StorageReservationState::Released,
        "expired" => StorageReservationState::Expired,
        _ => {
            return Err(conversion(
                6,
                DecodeError("invalid storage reservation state".to_owned()),
            ));
        }
    };
    Ok(TenantStorageReservation {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        ticket_kind: row.get(2)?,
        object_digest: optional_digest_column(row, 3)?,
        reserved_bytes: u64_column(row, 4, "reserved bytes")?,
        reserved_objects: u64_column(row, 5, "reserved objects")?,
        state,
        created_unix_ms: u64_column(row, 7, "storage reservation creation")?,
        expires_unix_ms: u64_column(row, 8, "storage reservation expiry")?,
        completed_unix_ms: optional_u64_column(row, 9, "storage reservation completion")?,
    })
}

fn validate_storage_ticket_binding(
    binding: &StorageTicketBinding,
) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("storage reservation id", binding.reservation_id.as_str()),
        ("storage ticket tenant", binding.tenant_id.as_str()),
        ("storage ticket id", binding.ticket_id.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if !matches!(
        binding.ticket_kind.as_str(),
        "cache" | "artifact" | "report" | "source"
    ) || binding.updated_unix_ms < binding.created_unix_ms
        || binding.actual_objects == Some(0)
    {
        return Err(ControlPlaneError::InvalidInput(
            "storage ticket binding metadata is invalid",
        ));
    }
    if let Some(object_id) = &binding.object_id {
        validate_text("storage ticket object", object_id)?;
    }
    Ok(())
}

fn storage_ticket_binding_row(row: &Row<'_>) -> rusqlite::Result<StorageTicketBinding> {
    let state: String = row.get(7)?;
    let state = match state.as_str() {
        "issued" => StorageTicketBindingState::Issued,
        "committed" => StorageTicketBindingState::Committed,
        "accounted" => StorageTicketBindingState::Accounted,
        "released" => StorageTicketBindingState::Released,
        _ => {
            return Err(conversion(
                7,
                DecodeError("invalid storage ticket binding state".to_owned()),
            ));
        }
    };
    Ok(StorageTicketBinding {
        reservation_id: row.get(0)?,
        tenant_id: row.get(1)?,
        ticket_kind: row.get(2)?,
        ticket_id: row.get(3)?,
        object_id: row.get(4)?,
        actual_bytes: optional_u64_column(row, 5, "storage ticket actual bytes")?,
        actual_objects: optional_u64_column(row, 6, "storage ticket actual objects")?,
        state,
        created_unix_ms: u64_column(row, 8, "storage ticket creation")?,
        updated_unix_ms: u64_column(row, 9, "storage ticket update")?,
        completed_unix_ms: optional_u64_column(row, 10, "storage ticket completion")?,
    })
}

const STORAGE_TICKET_BINDING_SELECT: &str =
    "SELECT reservation_id, tenant_id, ticket_kind, ticket_id, object_id,
            actual_bytes, actual_objects, state, created_unix_ms, updated_unix_ms,
            completed_unix_ms
       FROM tenant_storage_ticket_bindings";

fn storage_ticket_binding_by_reservation_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    reservation_id: &str,
) -> Result<Option<StorageTicketBinding>, ControlPlaneError> {
    Ok(transaction
        .query_row(
            &format!(
                "{STORAGE_TICKET_BINDING_SELECT}
                 WHERE tenant_id = ?1 AND reservation_id = ?2"
            ),
            params![tenant_id, reservation_id],
            storage_ticket_binding_row,
        )
        .optional()?)
}

fn storage_ticket_binding_by_ticket_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    ticket_id: &str,
) -> Result<Option<StorageTicketBinding>, ControlPlaneError> {
    Ok(transaction
        .query_row(
            &format!(
                "{STORAGE_TICKET_BINDING_SELECT}
                 WHERE tenant_id = ?1 AND ticket_id = ?2"
            ),
            params![tenant_id, ticket_id],
            storage_ticket_binding_row,
        )
        .optional()?)
}

fn account_storage_ticket_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    ticket_id: &str,
    object_id: &str,
    now_unix_ms: u64,
) -> Result<bool, ControlPlaneError> {
    let binding = storage_ticket_binding_by_ticket_tx(transaction, tenant_id, ticket_id)?
        .ok_or_else(|| not_found("storage ticket", ticket_id))?;
    if binding.object_id.as_deref() != Some(object_id) {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let actual_bytes = binding
        .actual_bytes
        .ok_or(ControlPlaneError::IdempotencyConflict)?;
    let actual_objects = binding
        .actual_objects
        .ok_or(ControlPlaneError::IdempotencyConflict)?;
    let existing: Option<(u64, u64, String, Option<u64>)> = transaction
        .query_row(
            "SELECT billed_bytes, billed_objects, state, retired_unix_ms
             FROM tenant_storage_objects
             WHERE tenant_id = ?1 AND object_kind = ?2 AND object_id = ?3",
            params![tenant_id, binding.ticket_kind, object_id],
            |row| {
                Ok((
                    u64_column(row, 0, "storage object bytes")?,
                    u64_column(row, 1, "storage object count")?,
                    row.get(2)?,
                    optional_u64_column(row, 3, "storage object retirement")?,
                ))
            },
        )
        .optional()?;
    if binding.state == StorageTicketBindingState::Accounted {
        if existing == Some((actual_bytes, actual_objects, "active".to_owned(), None)) {
            return Ok(true);
        }
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    if binding.state != StorageTicketBindingState::Committed {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    match existing {
        Some((bytes, objects, state, retired))
            if bytes == actual_bytes
                && objects == actual_objects
                && state == "active"
                && retired.is_none() => {}
        Some(_) => return Err(ControlPlaneError::IdempotencyConflict),
        None => {
            transaction.execute(
                "INSERT INTO tenant_storage_objects
                 (tenant_id, object_kind, object_id, billed_bytes, billed_objects,
                  state, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6)",
                params![
                    tenant_id,
                    binding.ticket_kind,
                    object_id,
                    to_i64(actual_bytes)?,
                    to_i64(actual_objects)?,
                    to_i64(now_unix_ms)?,
                ],
            )?;
        }
    }
    transaction.execute(
        "UPDATE tenant_storage_ticket_bindings
         SET state = 'accounted', updated_unix_ms = ?3, completed_unix_ms = ?3
         WHERE tenant_id = ?1 AND ticket_id = ?2 AND state = 'committed'",
        params![tenant_id, ticket_id, to_i64(now_unix_ms)?],
    )?;
    transaction.execute(
        "UPDATE tenant_storage_reservations
         SET state = 'released', completed_unix_ms = ?3
         WHERE id = ?1 AND tenant_id = ?2 AND state = 'committed'",
        params![binding.reservation_id, tenant_id, to_i64(now_unix_ms)?],
    )?;
    Ok(false)
}

pub(in crate::store) fn account_artifact_storage_ticket_if_present_tx(
    transaction: &Transaction<'_>,
    artifact: &ArtifactCatalogRecord,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let binding: Option<(String, u64)> = transaction
        .query_row(
            "SELECT b.ticket_id, b.updated_unix_ms
               FROM runner_data_commits c
               JOIN tenant_storage_ticket_bindings b
                 ON b.ticket_id = c.ticket_id AND b.tenant_id = c.tenant_id
              WHERE c.kind = 'artifact' AND c.object_id = ?1
                AND c.tenant_id = ?2 AND c.job_id = ?3
                AND c.job_attempt = ?4",
            params![
                artifact.artifact_id,
                artifact.tenant_id,
                artifact.job_id,
                i64::from(artifact.job_attempt),
            ],
            |row| Ok((row.get(0)?, u64_column(row, 1, "storage ticket update")?)),
        )
        .optional()?;
    if let Some((ticket_id, updated_unix_ms)) = binding {
        account_storage_ticket_tx(
            transaction,
            &artifact.tenant_id,
            &ticket_id,
            &artifact.artifact_id,
            now_unix_ms.max(updated_unix_ms),
        )?;
    }
    Ok(())
}
