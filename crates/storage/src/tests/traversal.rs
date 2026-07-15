use super::*;

#[cfg(unix)]
#[test]
fn capture_path_swap_race_never_crosses_the_retained_root() {
    use std::{
        os::unix::fs::symlink,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
            Arc,
        },
        thread,
    };

    let (directory, cas) = test_cas();
    let workspace = directory.path().join("workspace");
    let outside = directory.path().join("outside");
    let holding = workspace.join("holding");
    let slot = workspace.join("slot");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::create_dir(&holding).unwrap();
    fs::write(holding.join("value"), b"inside").unwrap();
    fs::write(outside.join("value"), b"outside").unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let cycles = Arc::new(AtomicUsize::new(0));
    let attacker_stop = Arc::clone(&stop);
    let attacker_cycles = Arc::clone(&cycles);
    let attacker_holding = holding.clone();
    let attacker_slot = slot.clone();
    let attacker_outside = outside.clone();
    let attacker = thread::spawn(move || {
        while !attacker_stop.load(AtomicOrdering::Acquire) {
            if fs::rename(&attacker_holding, &attacker_slot).is_ok() {
                thread::yield_now();
                fs::rename(&attacker_slot, &attacker_holding).unwrap();
            }
            if symlink(&attacker_outside, &attacker_slot).is_ok() {
                thread::yield_now();
                fs::remove_file(&attacker_slot).unwrap();
            }
            attacker_cycles.fetch_add(1, AtomicOrdering::Release);
        }
    });

    while cycles.load(AtomicOrdering::Acquire) < 10 {
        thread::yield_now();
    }
    let safe_digest = ContentDigest::sha256(b"inside");
    let outside_digest = ContentDigest::sha256(b"outside");
    for _ in 0..1_000 {
        if let Ok(PathSnapshot::File { digest, .. }) = cas.capture_path(slot.join("value")) {
            assert_eq!(digest, safe_digest);
            assert_ne!(digest, outside_digest);
        }
    }
    stop.store(true, AtomicOrdering::Release);
    attacker.join().unwrap();
    assert!(cycles.load(AtomicOrdering::Acquire) >= 10);
}

#[test]
fn traversal_and_parent_type_conflicts_are_rejected() {
    let (_directory, cas) = test_cas();
    let digest = cas.put_bytes(b"x").unwrap().digest;
    let traversal = TreeManifest {
        version: TREE_MANIFEST_VERSION,
        entries: vec![TreeEntry {
            path: "../escape".to_owned(),
            kind: TreeEntryKind::File {
                digest: digest.clone(),
                size_bytes: 1,
                executable: false,
            },
        }],
    };
    assert!(cas.store_tree_manifest(&traversal).is_err());

    let conflict = TreeManifest {
        version: TREE_MANIFEST_VERSION,
        entries: vec![
            TreeEntry {
                path: "parent".to_owned(),
                kind: TreeEntryKind::File {
                    digest: digest.clone(),
                    size_bytes: 1,
                    executable: false,
                },
            },
            TreeEntry {
                path: "parent/child".to_owned(),
                kind: TreeEntryKind::File {
                    digest,
                    size_bytes: 1,
                    executable: false,
                },
            },
        ],
    };
    assert!(matches!(
        cas.store_tree_manifest(&conflict),
        Err(StorageError::Manifest(_))
    ));
}
