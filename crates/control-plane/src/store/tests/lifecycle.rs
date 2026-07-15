use super::*;

#[test]
fn gc_requires_two_marks_and_preserves_backup_pins() {
    let control = ControlPlane::open_in_memory("lifecycle-gc", NOW).unwrap();
    let pinned = ContentDigest::sha256(b"pinned");
    let orphan = ContentDigest::sha256(b"orphan");
    control
        .create_backup_pin(&BackupPinRecord {
            id: "backup-pin-1".to_owned(),
            tenant_id: Some("tenant-1".to_owned()),
            root_kind: "object".to_owned(),
            root_id: "backup-epoch-1".to_owned(),
            object_digest: pinned.clone(),
            created_unix_ms: NOW,
            expires_unix_ms: None,
            released_unix_ms: None,
        })
        .unwrap();

    let first = control
        .acquire_lifecycle_gc("gc-worker", "gc-token-1", NOW + 1, 1_000)
        .unwrap();
    let roots = control.lifecycle_gc_roots(&first, NOW + 1, 100).unwrap();
    assert!(roots.iter().any(|root| root.digest == pinned));
    control
        .record_lifecycle_gc_marks(&first, &roots, NOW + 2)
        .unwrap();
    assert!(control
        .observe_lifecycle_gc_inventory(
            &first,
            &[(orphan.clone(), 6, NOW.saturating_sub(10_000))],
            NOW + 3,
            1_000,
        )
        .unwrap()
        .is_empty());
    control.complete_lifecycle_gc(&first, &[], NOW + 4).unwrap();

    let second = control
        .acquire_lifecycle_gc("gc-worker", "gc-token-2", NOW + 5, 1_000)
        .unwrap();
    let roots = control.lifecycle_gc_roots(&second, NOW + 5, 100).unwrap();
    control
        .record_lifecycle_gc_marks(&second, &roots, NOW + 6)
        .unwrap();
    let eligible = control
        .observe_lifecycle_gc_inventory(
            &second,
            &[(orphan.clone(), 6, NOW.saturating_sub(10_000))],
            NOW + 7,
            1_000,
        )
        .unwrap();
    assert_eq!(eligible, vec![orphan.clone()]);
    assert!(!eligible.contains(&pinned));
    control
        .complete_lifecycle_gc(&second, &[(orphan, 6)], NOW + 8)
        .unwrap();
    let metrics = control.lifecycle_metrics().unwrap();
    assert_eq!(metrics.generation, 2);
    assert_eq!(metrics.swept_objects, 1);
    assert_eq!(metrics.swept_bytes, 6);
}
