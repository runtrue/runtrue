use super::*;

#[test]
fn corrupted_content_is_a_miss_before_destination_creation() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "source", b"trusted");
    let identity = identity(main_domain());
    let entry = store
        .commit_tree(
            &main_domain(),
            identity.clone(),
            source,
            None,
            1,
            producer(),
        )
        .unwrap();
    let manifest = store
        .cas()
        .load_tree_manifest(&entry.manifest.tree.manifest_digest)
        .unwrap();
    let digest = manifest
        .entries
        .into_iter()
        .find_map(|entry| match entry.kind {
            TreeEntryKind::File { digest, .. } => Some(digest),
            TreeEntryKind::Directory => None,
        })
        .unwrap();
    let path = object_path(store.cas(), &digest);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(path, b"tampered").unwrap();
    let destination = directory.path().join("restore");
    assert_eq!(
        store
            .restore(&main_domain(), &identity, &destination)
            .unwrap(),
        RestoreOutcome::Miss(CacheMiss::Corrupt)
    );
    assert!(!destination.exists());
}

#[test]

fn missing_or_corrupt_ticketed_cas_content_never_claims_or_reuses() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "missing", b"missing");
    let snapshot = store.cas().capture_tree(source).unwrap();
    let manifest = store
        .cas()
        .load_tree_manifest(&snapshot.manifest_digest)
        .unwrap();
    let blob = manifest
        .entries
        .into_iter()
        .find_map(|entry| match entry.kind {
            TreeEntryKind::File { digest, .. } => Some(digest),
            TreeEntryKind::Directory => None,
        })
        .unwrap();
    let ticket = store
        .issue_write_ticket(ticket_request(
            identity(main_domain()),
            &snapshot,
            None,
            snapshot.total_file_bytes,
        ))
        .unwrap();
    fs::remove_file(object_path(store.cas(), &blob)).unwrap();
    assert!(matches!(
        commit_ticket_snapshot(&store, &ticket, &snapshot),
        Err(CacheError::Storage(StorageError::NotFound(_)))
    ));
    assert_eq!(store.claimed_cache_entry(&ticket).unwrap(), None);

    let source = source_tree(directory.path(), "corrupt", b"corrupt");
    let snapshot = store.cas().capture_tree(source).unwrap();
    let manifest = store
        .cas()
        .load_tree_manifest(&snapshot.manifest_digest)
        .unwrap();
    let blob = manifest
        .entries
        .into_iter()
        .find_map(|entry| match entry.kind {
            TreeEntryKind::File { digest, .. } => Some(digest),
            TreeEntryKind::Directory => None,
        })
        .unwrap();
    let ticket = store
        .issue_write_ticket(ticket_request(
            identity(main_domain()),
            &snapshot,
            None,
            snapshot.total_file_bytes,
        ))
        .unwrap();
    let blob_path = object_path(store.cas(), &blob);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&blob_path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(blob_path, b"changed").unwrap();
    assert!(matches!(
        commit_ticket_snapshot(&store, &ticket, &snapshot),
        Err(CacheError::Storage(StorageError::CorruptBlob { .. }))
    ));
    assert_eq!(store.claimed_cache_entry(&ticket).unwrap(), None);

    let source = source_tree(
        directory.path(),
        "claimed-corrupt",
        b"claimed-corrupt-cache",
    );
    let snapshot = store.cas().capture_tree(source).unwrap();
    let manifest = store
        .cas()
        .load_tree_manifest(&snapshot.manifest_digest)
        .unwrap();
    let blob = manifest
        .entries
        .into_iter()
        .find_map(|entry| match entry.kind {
            TreeEntryKind::File { digest, .. } => Some(digest),
            TreeEntryKind::Directory => None,
        })
        .unwrap();
    let ticket = store
        .issue_write_ticket(ticket_request(
            identity(main_domain()),
            &snapshot,
            None,
            snapshot.total_file_bytes,
        ))
        .unwrap();
    commit_ticket_snapshot(&store, &ticket, &snapshot).unwrap();
    let blob_path = object_path(store.cas(), &blob);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&blob_path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(blob_path, b"tampered-after-claim").unwrap();
    assert!(matches!(
        store.claimed_cache_entry(&ticket),
        Err(CacheError::Storage(StorageError::CorruptBlob { .. }))
    ));
    assert!(matches!(
        commit_ticket_snapshot(&store, &ticket, &snapshot),
        Err(CacheError::Storage(StorageError::CorruptBlob { .. }))
    ));
}
