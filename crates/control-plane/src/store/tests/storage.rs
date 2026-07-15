use super::*;

#[test]
fn storage_quota_reservations_are_atomic_and_exact() {
    let control = ControlPlane::open_in_memory("storage-quota", NOW).unwrap();
    bootstrap(&control);
    control
        .set_tenant_storage_quota(&TenantStorageQuota {
            tenant_id: "tenant-1".to_owned(),
            maximum_stored_bytes: 10,
            maximum_object_count: 1,
            updated_unix_ms: NOW,
        })
        .unwrap();
    let first = TenantStorageReservation {
        id: "reservation-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        ticket_kind: "artifact".to_owned(),
        object_digest: Some(ContentDigest::sha256(b"reserved-object")),
        reserved_bytes: 6,
        reserved_objects: 1,
        state: StorageReservationState::Reserved,
        created_unix_ms: NOW,
        expires_unix_ms: NOW + 1_000,
        completed_unix_ms: None,
    };
    assert!(!control.reserve_tenant_storage(&first, NOW).unwrap());
    assert!(control.reserve_tenant_storage(&first, NOW).unwrap());
    let mut changed = first.clone();
    changed.reserved_bytes = 7;
    assert!(matches!(
        control.reserve_tenant_storage(&changed, NOW),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    let mut overflow = first.clone();
    overflow.id = "reservation-2".to_owned();
    overflow.reserved_bytes = 1;
    assert!(matches!(
        control.reserve_tenant_storage(&overflow, NOW),
        Err(ControlPlaneError::StorageQuotaExceeded)
    ));
    assert!(!control
        .finish_tenant_storage_reservation(
            "tenant-1",
            &first.id,
            StorageReservationState::Released,
            NOW + 1,
        )
        .unwrap());
    assert!(!control.reserve_tenant_storage(&overflow, NOW + 1).unwrap());
    assert!(matches!(
        control.set_tenant_storage_quota(&TenantStorageQuota {
            tenant_id: "tenant-attacker".to_owned(),
            maximum_stored_bytes: 10,
            maximum_object_count: 1,
            updated_unix_ms: NOW,
        }),
        Err(ControlPlaneError::NotFound { .. })
    ));
    control
        .set_tenant_storage_quota(&TenantStorageQuota {
            tenant_id: "tenant-1".to_owned(),
            maximum_stored_bytes: 10,
            maximum_object_count: 10,
            updated_unix_ms: NOW + 2,
        })
        .unwrap();
    let outcomes = std::thread::scope(|scope| {
        (0..2)
            .map(|index| {
                let control = &control;
                scope.spawn(move || {
                    control.reserve_tenant_storage(
                        &TenantStorageReservation {
                            id: format!("quota-race-{index}"),
                            tenant_id: "tenant-1".to_owned(),
                            ticket_kind: "cache".to_owned(),
                            object_digest: None,
                            reserved_bytes: 9,
                            reserved_objects: 1,
                            state: StorageReservationState::Reserved,
                            created_unix_ms: NOW + 2,
                            expires_unix_ms: NOW + 1_000,
                            completed_unix_ms: None,
                        },
                        NOW + 2,
                    )
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(ControlPlaneError::StorageQuotaExceeded)))
            .count(),
        1
    );
}

#[test]
fn storage_ticket_binding_closes_issue_crash_window_and_accounts_exactly() {
    let control = ControlPlane::open_in_memory("storage-ticket-binding", NOW).unwrap();
    bootstrap(&control);
    control
        .set_tenant_storage_quota(&TenantStorageQuota {
            tenant_id: "tenant-1".to_owned(),
            maximum_stored_bytes: 10,
            maximum_object_count: 2,
            updated_unix_ms: NOW,
        })
        .unwrap();
    let reservation = TenantStorageReservation {
        id: "reservation-bound-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        ticket_kind: "artifact".to_owned(),
        object_digest: Some(ContentDigest::sha256(b"content")),
        reserved_bytes: 6,
        reserved_objects: 1,
        state: StorageReservationState::Reserved,
        created_unix_ms: NOW,
        expires_unix_ms: NOW + 1_000,
        completed_unix_ms: None,
    };
    control.reserve_tenant_storage(&reservation, NOW).unwrap();
    assert!(matches!(
        control.commit_tenant_storage_ticket(
            "tenant-1",
            "unbound-ticket",
            "artifact-record",
            5,
            1,
            NOW + 1,
        ),
        Err(ControlPlaneError::NotFound { .. })
    ));
    let binding = StorageTicketBinding {
        reservation_id: reservation.id.clone(),
        tenant_id: reservation.tenant_id.clone(),
        ticket_kind: reservation.ticket_kind.clone(),
        ticket_id: "artifact-ticket-1".to_owned(),
        object_id: None,
        actual_bytes: None,
        actual_objects: None,
        state: StorageTicketBindingState::Issued,
        created_unix_ms: NOW + 1,
        updated_unix_ms: NOW + 1,
        completed_unix_ms: None,
    };
    assert!(!control
        .bind_tenant_storage_ticket(&binding, NOW + 1)
        .unwrap());
    assert!(control
        .bind_tenant_storage_ticket(&binding, NOW + 1)
        .unwrap());
    let mut substitution = binding.clone();
    substitution.ticket_id = "artifact-ticket-substitution".to_owned();
    assert!(matches!(
        control.bind_tenant_storage_ticket(&substitution, NOW + 1),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert!(control
        .storage_ticket_binding_for_reservation("tenant-attacker", &reservation.id)
        .unwrap()
        .is_none());
    assert!(!control
        .commit_tenant_storage_ticket(
            "tenant-1",
            &binding.ticket_id,
            "artifact-record",
            5,
            1,
            NOW + 2,
        )
        .unwrap());
    assert!(control
        .commit_tenant_storage_ticket(
            "tenant-1",
            &binding.ticket_id,
            "artifact-record",
            5,
            1,
            NOW + 2,
        )
        .unwrap());
    assert!(matches!(
        control.commit_tenant_storage_ticket(
            "tenant-1",
            &binding.ticket_id,
            "artifact-substitution",
            5,
            1,
            NOW + 2,
        ),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert_eq!(
        control.tenant_storage_usage("tenant-1").unwrap(),
        TenantStorageUsage {
            tenant_id: "tenant-1".to_owned(),
            active_bytes: 0,
            active_objects: 0,
            reserved_bytes: 6,
            reserved_objects: 1,
        }
    );
    assert!(!control
        .account_tenant_storage_ticket("tenant-1", &binding.ticket_id, "artifact-record", NOW + 3,)
        .unwrap());
    assert!(control
        .account_tenant_storage_ticket("tenant-1", &binding.ticket_id, "artifact-record", NOW + 4,)
        .unwrap());
    assert_eq!(
        control.tenant_storage_usage("tenant-1").unwrap(),
        TenantStorageUsage {
            tenant_id: "tenant-1".to_owned(),
            active_bytes: 5,
            active_objects: 1,
            reserved_bytes: 0,
            reserved_objects: 0,
        }
    );
    let overflow = TenantStorageReservation {
        id: "reservation-overflow-after-accounting".to_owned(),
        reserved_bytes: 6,
        ..reservation
    };
    assert!(matches!(
        control.reserve_tenant_storage(&overflow, NOW + 4),
        Err(ControlPlaneError::StorageQuotaExceeded)
    ));
}
