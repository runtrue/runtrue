use super::*;

#[test]
fn restore_ticket_is_server_bound_to_the_exact_head_attempt_and_fence() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "restore-ticket-source", b"cached");
    let identity = identity(main_domain());
    let committed = store
        .commit_tree(
            &main_domain(),
            identity.clone(),
            &source,
            None,
            6,
            producer(),
        )
        .unwrap();
    let mut request = ticket_request(identity, &committed.manifest.tree, None, 6);
    request.operation = CacheTicketOperation::Restore;
    request.expected_tree_manifest_digest = None;
    let ticket = store.issue_write_ticket(request).unwrap();
    assert_eq!(
        ticket.expected_tree_manifest_digest.as_ref(),
        Some(&committed.manifest.tree.manifest_digest)
    );
    assert_eq!(ticket.expected_head.as_ref(), Some(&committed.head));
    let restore = |attempt, fence, now| {
        store.ticketed_restore_entry(&CacheRestoreRequest {
            ticket: &ticket,
            active_tenant_id: "tenant",
            active_repository_id: "repository",
            active_job_id: "build",
            active_job_attempt: attempt,
            active_step_id: "compile",
            active_lease_id: "lease-1",
            active_fencing_generation: fence,
            now_unix_seconds: now,
        })
    };
    assert_eq!(restore(1, 7, TICKET_NOW + 1).unwrap(), Some(committed));
    assert!(restore(2, 7, TICKET_NOW + 1).is_err());
    assert!(restore(1, 8, TICKET_NOW + 1).is_err());
    assert!(restore(1, 7, TICKET_NOW + 61).is_err());
}

#[test]
fn ticketed_snapshot_commit_replays_and_recovers_exact_generation_after_restart() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "ticket-source", b"ticketed");
    let snapshot = store.cas().capture_tree(&source).unwrap();
    let cache_identity = identity(main_domain());
    let ticket = store
        .issue_write_ticket(ticket_request(
            cache_identity.clone(),
            &snapshot,
            None,
            snapshot.total_file_bytes,
        ))
        .unwrap();
    let committed = commit_ticket_snapshot(&store, &ticket, &snapshot).unwrap();
    assert_eq!(
        committed.head.claim_ticket_id.as_ref(),
        Some(&ticket.ticket_id)
    );
    assert_eq!(
        committed.manifest.claim_ticket_id.as_ref(),
        Some(&ticket.ticket_id)
    );
    assert!(matches!(
        commit_ticket_snapshot(&store, &ticket, &snapshot),
        Err(CacheError::TicketConsumed)
    ));

    let later_source = source_tree(directory.path(), "later", b"later");
    let later = store
        .commit_tree(
            &main_domain(),
            cache_identity,
            later_source,
            Some(&committed.head),
            7,
            producer(),
        )
        .unwrap();
    assert_eq!(later.head.generation, 2);

    let reopened =
        CacheStore::open(store.root(), store.cas().clone(), CacheLimits::default()).unwrap();
    let recovered = reopened.claimed_cache_entry(&ticket).unwrap().unwrap();
    assert_eq!(recovered, committed);
    assert_eq!(recovered.head.generation, 1);
}

#[test]
fn cache_ticket_rejects_expiry_fence_scope_and_tampering_without_claim() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "guarded", b"guarded");
    let snapshot = store.cas().capture_tree(source).unwrap();
    let ticket = store
        .issue_write_ticket(ticket_request(
            identity(main_domain()),
            &snapshot,
            None,
            snapshot.total_file_bytes,
        ))
        .unwrap();
    let second = store
        .issue_write_ticket(ticket_request(
            identity(main_domain()),
            &snapshot,
            None,
            snapshot.total_file_bytes,
        ))
        .unwrap();
    assert_ne!(ticket.nonce, second.nonce);
    assert_ne!(ticket.ticket_id, second.ticket_id);

    let mut overlong = ticket_request(
        identity(main_domain()),
        &snapshot,
        None,
        snapshot.total_file_bytes,
    );
    overlong.expires_at_unix_seconds =
        overlong.issued_at_unix_seconds + CacheLimits::default().max_ticket_lifetime_seconds + 1;
    assert!(matches!(
        store.issue_write_ticket(overlong),
        Err(CacheError::InvalidTicket(_))
    ));

    let mut cross_trust = ticket_request(
        identity(main_domain()),
        &snapshot,
        None,
        snapshot.total_file_bytes,
    );
    cross_trust.writer_trust_domain = quarantine_domain();
    assert!(matches!(
        store.issue_write_ticket(cross_trust),
        Err(CacheError::InvalidTicket(_))
    ));
    let request = |tenant, lease, fence, now| CacheSnapshotCommitRequest {
        ticket: &ticket,
        active_tenant_id: tenant,
        active_repository_id: "repository",
        active_job_id: "build",
        active_step_id: "compile",
        active_lease_id: lease,
        active_fencing_generation: fence,
        active_writer_trust_domain: &ticket.writer_trust_domain,
        now_unix_seconds: now,
        snapshot: &snapshot,
        producer: producer(),
    };
    assert!(matches!(
        store.commit_ticketed_snapshot(&request("tenant", "lease-1", 8, TICKET_NOW + 1)),
        Err(CacheError::StaleFence { .. })
    ));
    assert!(matches!(
        store.commit_ticketed_snapshot(&request("tenant", "lease-other", 7, TICKET_NOW + 1)),
        Err(CacheError::LeaseMismatch)
    ));
    assert!(matches!(
        store.commit_ticketed_snapshot(&request("other", "lease-1", 7, TICKET_NOW + 1)),
        Err(CacheError::TicketScopeMismatch)
    ));
    assert!(matches!(
        store.commit_ticketed_snapshot(&request(
            "tenant",
            "lease-1",
            7,
            ticket.expires_at_unix_seconds
        )),
        Err(CacheError::TicketExpired)
    ));
    assert_eq!(store.claimed_cache_entry(&ticket).unwrap(), None);

    let mut tampered = ticket.clone();
    tampered.repository_id = "other".to_owned();
    assert!(matches!(
        store.claimed_cache_entry(&tampered),
        Err(CacheError::InvalidTicket(_))
    ));
}

#[test]
fn cache_ticket_snapshot_digest_size_and_summary_are_exact() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "exact", b"12345");
    let snapshot = store.cas().capture_tree(source).unwrap();

    let too_small = store
        .issue_write_ticket(ticket_request(
            identity(main_domain()),
            &snapshot,
            None,
            snapshot.total_file_bytes - 1,
        ))
        .unwrap();
    assert!(matches!(
        commit_ticket_snapshot(&store, &too_small, &snapshot),
        Err(CacheError::CacheContentTooLarge { .. })
    ));

    let mut wrong_digest_request = ticket_request(
        identity(main_domain()),
        &snapshot,
        None,
        snapshot.total_file_bytes,
    );
    wrong_digest_request.expected_tree_manifest_digest = Some(digest("wrong-tree"));
    let wrong_digest = store.issue_write_ticket(wrong_digest_request).unwrap();
    assert!(matches!(
        commit_ticket_snapshot(&store, &wrong_digest, &snapshot),
        Err(CacheError::TicketContentMismatch)
    ));

    let summary_ticket = store
        .issue_write_ticket(ticket_request(
            identity(main_domain()),
            &snapshot,
            None,
            snapshot.total_file_bytes + 1,
        ))
        .unwrap();
    let mut wrong_summary = snapshot.clone();
    wrong_summary.total_file_bytes += 1;
    assert!(matches!(
        commit_ticket_snapshot(&store, &summary_ticket, &wrong_summary),
        Err(CacheError::InvalidManifest(_))
    ));
    assert_eq!(store.claimed_cache_entry(&summary_ticket).unwrap(), None);
}

#[test]
fn concurrent_cache_ticket_claims_have_one_winner() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "concurrent-ticket", b"one-winner");
    let snapshot = store.cas().capture_tree(source).unwrap();
    let ticket = store
        .issue_write_ticket(ticket_request(
            identity(main_domain()),
            &snapshot,
            None,
            snapshot.total_file_bytes,
        ))
        .unwrap();
    let store = Arc::new(store);
    let handles = (0..2)
        .map(|_| {
            let store = Arc::clone(&store);
            let ticket = ticket.clone();
            let snapshot = snapshot.clone();
            thread::spawn(move || commit_ticket_snapshot(&store, &ticket, &snapshot))
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
            .filter(|result| matches!(result, Err(CacheError::TicketConsumed)))
            .count(),
        1
    );
    assert!(store.claimed_cache_entry(&ticket).unwrap().is_some());
}
