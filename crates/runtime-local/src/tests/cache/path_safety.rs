use super::*;

#[cfg(unix)]
#[test]
fn failed_directory_copy_removes_its_partial_root() {
    use std::os::unix::fs::symlink;

    let stage = tempdir().unwrap();
    let source = stage.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("a-file"), b"partial").unwrap();
    symlink(source.join("a-file"), source.join("z-symlink")).unwrap();
    let workspace = tempdir().unwrap();
    let destination = workspace.path().join("output");
    assert!(copy_new_tree(&source, &destination).is_err());
    assert!(!destination.exists());
}
