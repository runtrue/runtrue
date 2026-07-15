use super::*;

#[cfg(unix)]
#[test]
fn capture_path_rejects_a_symlink_root() {
    use std::os::unix::fs::symlink;
    let (directory, cas) = test_cas();
    let source = directory.path().join("source");
    fs::write(&source, b"value").unwrap();
    let link = directory.path().join("link");
    symlink(&source, &link).unwrap();
    assert!(matches!(
        cas.capture_path(&link),
        Err(StorageError::UnsafeFilesystemEntry {
            kind: "symlink",
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn capture_path_rejects_an_ancestor_symlink_escape() {
    use std::os::unix::fs::symlink;
    let (directory, cas) = test_cas();
    let workspace = directory.path().join("workspace");
    let outside = directory.path().join("outside");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret"), b"outside-secret").unwrap();
    symlink(&outside, workspace.join("linked")).unwrap();

    assert!(matches!(
        cas.capture_path(workspace.join("linked/secret")),
        Err(StorageError::UnsafeFilesystemEntry {
            kind: "symlink",
            ..
        })
    ));
    assert!(matches!(
        cas.capture_path_beneath(&workspace, "linked/secret"),
        Err(StorageError::UnsafeFilesystemEntry {
            kind: "symlink",
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn source_symlinks_and_special_files_are_rejected() {
    use std::os::unix::{fs::symlink, net::UnixListener};
    let (directory, cas) = test_cas();
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("real"), b"value").unwrap();
    symlink("real", source.join("link")).unwrap();
    let special_result = cas.capture_tree(&source);
    assert!(matches!(
        special_result,
        Err(StorageError::UnsafeFilesystemEntry {
            kind: "symlink",
            ..
        })
    ));
    fs::remove_file(source.join("link")).unwrap();
    let _listener = UnixListener::bind(source.join("socket")).unwrap();
    let socket_result = cas.capture_tree(&source);
    assert!(matches!(
        socket_result,
        Err(StorageError::UnsafeFilesystemEntry {
            kind: "special file",
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn materialization_rejects_destination_ancestor_symlink_escape() {
    use std::os::unix::fs::symlink;
    let (directory, cas) = test_cas();
    let source = directory.path().join("source");
    let destination_root = directory.path().join("destination-root");
    let outside = directory.path().join("outside");
    fs::write(&source, b"trusted").unwrap();
    fs::create_dir(&destination_root).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, destination_root.join("linked")).unwrap();
    let snapshot = cas.capture_path(&source).unwrap();
    let destination = destination_root.join("linked/restored");

    let ancestor_result = cas.materialize_path(&snapshot, &destination);
    assert!(matches!(
        ancestor_result,
        Err(StorageError::UnsafeFilesystemEntry {
            kind: "symlink",
            ..
        })
    ));
    assert!(!outside.join("restored").exists());
}

#[cfg(unix)]
#[test]
fn symlink_in_object_store_is_never_followed() {
    use std::os::unix::fs::symlink;
    let (directory, cas) = test_cas();
    let digest = ContentDigest::sha256(b"outside");
    let path = object_path(&cas, &digest);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let outside = directory.path().join("outside");
    fs::write(&outside, b"outside").unwrap();
    symlink(&outside, &path).unwrap();
    assert!(cas.read_blob(&digest).is_err());
    assert_eq!(fs::read(outside).unwrap(), b"outside");
}
