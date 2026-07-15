use super::*;
use std::{
    sync::{Arc, Barrier},
    thread,
};
use tempfile::tempdir;

#[test]
fn publication_never_replaces_an_existing_destination() {
    let temporary = tempdir().unwrap();
    let destination = temporary.path().join("entry");
    fs::write(&destination, b"original").unwrap();

    assert_eq!(
        atomic_write_private(&destination, b"replacement").unwrap(),
        Publication::Existing
    );
    assert_eq!(fs::read(destination).unwrap(), b"original");
}

#[test]
fn concurrent_publication_selects_one_complete_value_without_replacement() {
    const PUBLISHERS: usize = 16;
    let temporary = tempdir().unwrap();
    let destination = Arc::new(temporary.path().join("entry"));
    let barrier = Arc::new(Barrier::new(PUBLISHERS));
    let workers = (0..PUBLISHERS)
        .map(|index| {
            let destination = destination.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let value = format!("publisher-{index:02}-{}", "x".repeat(128));
                barrier.wait();
                let publication = atomic_write_private(&destination, value.as_bytes()).unwrap();
                (publication, value)
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        results
            .iter()
            .filter(|(status, _)| *status == Publication::Published)
            .count(),
        1
    );
    let stored = String::from_utf8(fs::read(destination.as_ref()).unwrap()).unwrap();
    assert!(results.iter().any(|(_, value)| value == &stored));
}

#[test]
fn authenticated_directory_scan_stops_at_the_configured_bound() {
    let temporary = tempdir().unwrap();
    let mut config = AotCacheConfig::new(
        temporary.path().join("cache"),
        AotAuthenticationKey::new([3; 32]),
    );
    config.max_entries = 1;
    config.max_entry_bytes = 1024;
    config.max_total_bytes = 1024 * 1024;
    let prepared = AotCache::prepare(config).unwrap();
    for index in 0..67 {
        let path = prepared
            .cache
            .authenticated_root
            .join(format!("junk-{index}"));
        assert_eq!(
            atomic_write_private(&path, b"x").unwrap(),
            Publication::Published
        );
    }

    assert!(matches!(
        prepared.cache.enforce_budget(1),
        Err(AotCacheError::BudgetExceeded)
    ));
}
