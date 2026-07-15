use super::*;

#[test]
fn tree_capture_and_materialization_are_deterministic() {
    let (directory, cas) = test_cas();
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("empty")).unwrap();
    fs::create_dir(source.join("nested")).unwrap();
    fs::write(source.join("z.txt"), b"z").unwrap();
    fs::write(source.join("nested/a.txt"), b"alpha").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            source.join("nested/a.txt"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    let first = cas.capture_tree(&source).unwrap();
    let second = cas.capture_tree(&source).unwrap();
    assert_eq!(first, second);
    let manifest = cas.load_tree_manifest(&first.manifest_digest).unwrap();
    let paths = manifest
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(paths, vec!["empty", "nested", "nested/a.txt", "z.txt"]);

    let destination = directory.path().join("restore");
    let restored = cas
        .materialize_tree(&first.manifest_digest, &destination)
        .unwrap();
    assert_eq!(restored, first);
    assert_eq!(
        fs::read(destination.join("nested/a.txt")).unwrap(),
        b"alpha"
    );
    assert!(destination.join("empty").is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            fs::metadata(destination.join("nested/a.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
}

#[test]
fn single_file_capture_and_materialization_preserve_metadata() {
    let (directory, cas) = test_cas();
    let source = directory.path().join("tool");
    fs::write(&source, b"binary bytes").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let snapshot = cas.capture_path(&source).unwrap();
    assert!(matches!(
        snapshot,
        PathSnapshot::File {
            size_bytes: 12,
            executable: true,
            ..
        }
    ));
    let destination = directory.path().join("restored-tool");
    cas.materialize_path(&snapshot, &destination).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"binary bytes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            fs::metadata(destination).unwrap().permissions().mode() & 0o111,
            0
        );
    }
}
