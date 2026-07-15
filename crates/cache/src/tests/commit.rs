use super::*;

#[test]
fn completion_id_binds_identity_scope_generation_tree_and_claim_ticket() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "completion-id", b"same bytes");
    let snapshot = store.cas().capture_tree(source).unwrap();
    let ticket = store
        .issue_write_ticket(ticket_request(
            identity(main_domain()),
            &snapshot,
            None,
            snapshot.total_file_bytes,
        ))
        .unwrap();
    let entry = commit_ticket_snapshot(&store, &ticket, &snapshot).unwrap();
    let first = entry.completion_id(&ticket.ticket_id).unwrap();
    assert_eq!(first, entry.completion_id(&ticket.ticket_id).unwrap());
    assert_ne!(first, entry.head.manifest_digest);
    assert!(matches!(
        entry.completion_id(&digest("substituted-ticket")),
        Err(CacheError::InvalidTicketClaim(_))
    ));
}

#[test]
fn trust_reads_are_directional_and_writes_never_escalate() {
    let main = main_domain();
    let branch = branch_domain();
    let quarantine = quarantine_domain();
    assert!(quarantine.can_read_from(&main));
    assert!(branch.can_read_from(&main));
    assert!(!main.can_read_from(&quarantine));
    assert!(!main.can_read_from(&branch));
    assert!(quarantine.can_write_to(&quarantine));
    assert!(!quarantine.can_write_to(&main));
    assert!(quarantine.can_promote_to(&main));
    assert!(!main.can_promote_to(&quarantine));
}

#[test]
fn commit_restore_and_generation_cas_round_trip() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "source-1", b"first");
    let identity = identity(main_domain());
    let first = store
        .commit_tree(
            &main_domain(),
            identity.clone(),
            &source,
            None,
            4,
            producer(),
        )
        .unwrap();
    assert_eq!(first.head.generation, 1);
    assert!(serde_json::to_value(&first.head)
        .unwrap()
        .get("claim_ticket_id")
        .is_none());
    assert!(serde_json::to_value(&first.manifest)
        .unwrap()
        .get("claim_ticket_id")
        .is_none());

    fs::write(source.join("output"), b"second").unwrap();
    let second = store
        .commit_tree(
            &main_domain(),
            identity.clone(),
            &source,
            Some(&first.head),
            4,
            producer(),
        )
        .unwrap();
    assert_eq!(second.head.generation, 2);
    assert!(matches!(
        store.commit_tree(
            &main_domain(),
            identity.clone(),
            &source,
            Some(&first.head),
            4,
            producer()
        ),
        Err(CacheError::HeadConflict { .. })
    ));

    let destination = directory.path().join("restore");
    let restored = store
        .restore(&main_domain(), &identity, &destination)
        .unwrap();
    assert!(matches!(restored, RestoreOutcome::Hit(_)));
    assert_eq!(fs::read(destination.join("output")).unwrap(), b"second");
}

#[test]
fn untrusted_writer_cannot_replace_verified_head() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "source", b"hostile");
    assert!(matches!(
        store.commit_tree(
            &quarantine_domain(),
            identity(main_domain()),
            source,
            None,
            1,
            producer()
        ),
        Err(CacheError::UnauthorizedWrite)
    ));
}

#[test]
fn fencing_generation_never_decreases() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "source", b"value");
    let identity = identity(main_domain());
    let first = store
        .commit_tree(
            &main_domain(),
            identity.clone(),
            &source,
            None,
            9,
            producer(),
        )
        .unwrap();
    assert!(matches!(
        store.commit_tree(
            &main_domain(),
            identity,
            source,
            Some(&first.head),
            8,
            producer()
        ),
        Err(CacheError::StaleFence {
            current: 9,
            attempted: 8
        })
    ));
}

#[test]
fn concurrent_successors_have_one_cas_winner() {
    let (directory, store) = test_store();
    let base_source = source_tree(directory.path(), "base", b"base");
    let identity = identity(main_domain());
    let first = store
        .commit_tree(
            &main_domain(),
            identity.clone(),
            base_source,
            None,
            5,
            producer(),
        )
        .unwrap();
    let left = source_tree(directory.path(), "left", b"left");
    let right = source_tree(directory.path(), "right", b"right");
    let store = Arc::new(store);
    let handles = [left, right]
        .into_iter()
        .map(|source| {
            let store = Arc::clone(&store);
            let identity = identity.clone();
            let expected = first.head.clone();
            thread::spawn(move || {
                store.commit_tree(
                    &main_domain(),
                    identity,
                    source,
                    Some(&expected),
                    5,
                    producer(),
                )
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(CacheError::HeadConflict { .. })))
            .count(),
        1
    );
}
