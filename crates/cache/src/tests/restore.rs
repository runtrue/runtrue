use super::*;

#[test]

fn verified_reader_cannot_consume_quarantine_but_pr_can_read_main() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "source", b"quarantine");
    let quarantine_identity = identity(quarantine_domain());
    store
        .commit_tree(
            &quarantine_domain(),
            quarantine_identity.clone(),
            source,
            None,
            1,
            producer(),
        )
        .unwrap();
    assert!(matches!(
        store.restore(
            &main_domain(),
            &quarantine_identity,
            directory.path().join("denied")
        ),
        Err(CacheError::UnauthorizedRead)
    ));

    let main_source = source_tree(directory.path(), "main-source", b"verified");
    let main_identity = identity(main_domain());
    store
        .commit_tree(
            &main_domain(),
            main_identity.clone(),
            main_source,
            None,
            1,
            producer(),
        )
        .unwrap();
    let result = store
        .restore(
            &quarantine_domain(),
            &main_identity,
            directory.path().join("allowed"),
        )
        .unwrap();
    assert!(matches!(result, RestoreOutcome::Hit(_)));
}
