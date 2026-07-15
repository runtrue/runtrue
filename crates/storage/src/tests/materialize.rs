use super::*;

#[cfg(unix)]
#[test]
fn materialization_rehashes_staging_before_publication() {
    let directory = tempdir().unwrap();
    let parent_path = directory.path().join("parent");
    fs::create_dir(&parent_path).unwrap();
    let destination = parent_path.join("restored");
    let (parent, leaf) = securely_open_parent(&destination).unwrap();
    let expected = ContentDigest::sha256(b"expected");

    let result = write_new_materialized_file_at(
        &parent,
        &leaf,
        &destination,
        Cursor::new(b"tampered"),
        &expected,
        8,
        false,
    );

    assert!(matches!(result, Err(StorageError::CorruptBlob { .. })));
    assert!(
        !destination.exists(),
        "unverified staging bytes must never become public"
    );
    assert_eq!(
        fs::read_dir(&parent_path).unwrap().count(),
        0,
        "failed materialization must remove private staging"
    );
}

#[test]
fn materialization_refuses_nonempty_or_symlink_destinations() {
    let (directory, cas) = test_cas();
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), b"x").unwrap();
    let snapshot = cas.capture_tree(&source).unwrap();
    let destination = directory.path().join("destination");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("existing"), b"keep").unwrap();
    assert!(matches!(
        cas.materialize_tree(&snapshot.manifest_digest, &destination),
        Err(StorageError::DestinationNotEmpty(_))
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = directory.path().join("destination-link");
        symlink(&destination, &link).unwrap();
        let link_result = cas.materialize_tree(&snapshot.manifest_digest, &link);
        assert!(matches!(
            link_result,
            Err(StorageError::UnsafeFilesystemEntry {
                kind: "symlink",
                ..
            })
        ));
    }
}
