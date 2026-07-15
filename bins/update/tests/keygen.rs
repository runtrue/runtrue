#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn keygen_is_private_redacted_and_create_new() {
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let key_path = directory.path().join("targets.key");
    let binary = env!("CARGO_BIN_EXE_runtrue-update");
    let first = Command::new(binary)
        .args(["keygen", "--output", key_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let private = fs::read_to_string(&key_path).unwrap();
    assert!(!String::from_utf8_lossy(&first.stdout).contains(private.trim()));
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let second = Command::new(binary)
        .args(["keygen", "--output", key_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert_eq!(fs::read_to_string(key_path).unwrap(), private);
}
