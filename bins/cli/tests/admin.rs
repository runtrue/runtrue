use serde_json::Value;
use std::fs;
use tempfile::tempdir;

mod support;
use support::*;

#[cfg(unix)]
#[test]
fn secret_admin_lifecycle_never_prints_plaintext_and_uses_private_files() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempdir().unwrap();
    let first_value = b"first-secret-value\0with-binary";
    let mut set = runtrue();
    set.current_dir(directory.path())
        .args(["secrets", "set", "API_TOKEN", "--json"]);
    let created = output_with_stdin(set, first_value);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created_json: Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(created_json["operation"], "created");
    assert_eq!(created_json["metadata"]["name"], "API_TOKEN");
    assert_eq!(created_json["metadata"]["version"], 1);
    assert!(created_json.get("value").is_none());
    assert!(!created
        .stdout
        .windows(b"first-secret-value".len())
        .any(|window| window == b"first-secret-value"));
    assert!(!created
        .stderr
        .windows(b"first-secret-value".len())
        .any(|window| window == b"first-secret-value"));

    let secrets_dir = directory.path().join(".runtrue/secrets");
    let key_path = secrets_dir.join("master.key");
    let vault_path = secrets_dir.join("vault.json");
    assert_eq!(
        fs::metadata(&secrets_dir).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    for path in [&key_path, &vault_path] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
    assert!(fs::read_dir(&secrets_dir).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains(".tmp")));
    let vault_bytes = fs::read(&vault_path).unwrap();
    assert!(!vault_bytes
        .windows(b"first-secret-value".len())
        .any(|window| window == b"first-secret-value"));

    let metadata = runtrue()
        .current_dir(directory.path())
        .args(["secrets", "get", "API_TOKEN", "--json"])
        .output()
        .unwrap();
    assert!(metadata.status.success());
    let metadata_json: Value = serde_json::from_slice(&metadata.stdout).unwrap();
    assert_eq!(metadata_json["operation"], "metadata");
    assert_eq!(metadata_json["revealed_to"], Value::Null);
    assert!(!metadata
        .stdout
        .windows(b"first-secret-value".len())
        .any(|window| window == b"first-secret-value"));

    let reveal_path = directory.path().join("revealed.bin");
    let revealed = runtrue()
        .current_dir(directory.path())
        .args(["secrets", "get", "API_TOKEN", "--reveal-to"])
        .arg(&reveal_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        revealed.status.success(),
        "{}",
        String::from_utf8_lossy(&revealed.stderr)
    );
    assert_eq!(fs::read(&reveal_path).unwrap(), first_value);
    assert_eq!(
        fs::metadata(&reveal_path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert!(!revealed
        .stdout
        .windows(b"first-secret-value".len())
        .any(|window| window == b"first-secret-value"));

    let rotation_source = directory.path().join("rotation-input");
    fs::write(&rotation_source, b"rotated-secret-value").unwrap();
    let rotated = runtrue()
        .current_dir(directory.path())
        .args(["secrets", "rotate", "API_TOKEN", "--file"])
        .arg(&rotation_source)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        rotated.status.success(),
        "{}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    let rotated_json: Value = serde_json::from_slice(&rotated.stdout).unwrap();
    assert_eq!(rotated_json["metadata"]["version"], 2);
    assert!(!rotated
        .stdout
        .windows(b"rotated-secret-value".len())
        .any(|window| window == b"rotated-secret-value"));

    let second_reveal = directory.path().join("rotated.bin");
    let output = runtrue()
        .current_dir(directory.path())
        .args(["secrets", "get", "API_TOKEN", "--reveal-to"])
        .arg(&second_reveal)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(fs::read(second_reveal).unwrap(), b"rotated-secret-value");

    let deleted = runtrue()
        .current_dir(directory.path())
        .args(["secrets", "delete", "API_TOKEN", "--json"])
        .output()
        .unwrap();
    assert!(deleted.status.success());
    let deleted_json: Value = serde_json::from_slice(&deleted.stdout).unwrap();
    assert_eq!(deleted_json["metadata"]["status"], "tombstoned");
    let refused = runtrue()
        .current_dir(directory.path())
        .args(["secrets", "get", "API_TOKEN", "--reveal-to", "after-delete"])
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&refused.stderr).unwrap();
    assert_eq!(error["error"]["code"], "secret_operation_failed");
    assert!(!directory.path().join("after-delete").exists());
}

#[cfg(unix)]
#[test]
fn secret_admin_rejects_argv_values_symlinks_traversal_and_insecure_state() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let argv_workspace = tempdir().unwrap();
    let rejected = runtrue()
        .current_dir(argv_workspace.path())
        .args([
            "secrets",
            "set",
            "TOKEN",
            "must-not-appear-in-errors",
            "also-must-not-appear",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(10));
    assert!(!String::from_utf8_lossy(&rejected.stderr).contains("must-not-appear-in-errors"));
    assert!(!String::from_utf8_lossy(&rejected.stderr).contains("also-must-not-appear"));
    let error: Value = serde_json::from_slice(&rejected.stderr).unwrap();
    assert_eq!(error["error"]["code"], "secret_value_in_argv");
    assert!(!argv_workspace.path().join(".runtrue").exists());

    let oversized_workspace = tempdir().unwrap();
    let mut set = runtrue();
    set.current_dir(oversized_workspace.path())
        .args(["secrets", "set", "TOKEN", "--json"]);
    let rejected = output_with_stdin(set, &vec![b'x'; 1024 * 1024 + 1]);
    assert_eq!(rejected.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&rejected.stderr).unwrap();
    assert_eq!(error["error"]["code"], "secret_input_failed");
    assert!(!oversized_workspace.path().join(".runtrue").exists());

    let input_workspace = tempdir().unwrap();
    let victim = input_workspace.path().join("victim");
    fs::write(&victim, b"victim-secret").unwrap();
    let link = input_workspace.path().join("input-link");
    symlink(&victim, &link).unwrap();
    let rejected = runtrue()
        .current_dir(input_workspace.path())
        .args(["secrets", "set", "TOKEN", "--file"])
        .arg(&link)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(10));
    assert_eq!(fs::read(&victim).unwrap(), b"victim-secret");
    assert!(!input_workspace.path().join(".runtrue").exists());

    let nested = input_workspace.path().join("nested");
    fs::create_dir(&nested).unwrap();
    let rejected = runtrue()
        .current_dir(&nested)
        .args(["secrets", "set", "TOKEN", "--file", "../victim", "--json"])
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&rejected.stderr).unwrap();
    assert_eq!(error["error"]["code"], "unsafe_admin_path");

    let state_workspace = tempdir().unwrap();
    let mut set = runtrue();
    set.current_dir(state_workspace.path())
        .args(["secrets", "set", "TOKEN", "--json"]);
    assert!(output_with_stdin(set, b"stored-secret").status.success());
    let vault = state_workspace.path().join(".runtrue/secrets/vault.json");
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o644)).unwrap();
    let rejected = runtrue()
        .current_dir(state_workspace.path())
        .args(["secrets", "get", "TOKEN", "--json"])
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&rejected.stderr).unwrap();
    assert_eq!(error["error"]["code"], "unsafe_admin_path");
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o600)).unwrap();

    let reveal_victim = state_workspace.path().join("reveal-victim");
    fs::write(&reveal_victim, b"preserve").unwrap();
    let reveal_link = state_workspace.path().join("reveal-link");
    symlink(&reveal_victim, &reveal_link).unwrap();
    let rejected = runtrue()
        .current_dir(state_workspace.path())
        .args(["secrets", "get", "TOKEN", "--reveal-to"])
        .arg(&reveal_link)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(10));
    assert_eq!(fs::read(reveal_victim).unwrap(), b"preserve");
}

#[cfg(unix)]
#[test]
fn variable_admin_is_versioned_atomic_and_strict() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let directory = tempdir().unwrap();
    let created = runtrue()
        .current_dir(directory.path())
        .args(["vars", "set", "FEATURE_MODE", "disabled", "--json"])
        .output()
        .unwrap();
    assert!(created.status.success());
    let report: Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(report["operation"], "created");
    assert_eq!(report["metadata"]["version"], 1);
    assert_eq!(report["value"], "disabled");
    let state_path = directory.path().join(".runtrue/vars.json");
    assert_eq!(
        fs::metadata(state_path).unwrap().permissions().mode() & 0o7777,
        0o600
    );

    let read = runtrue()
        .current_dir(directory.path())
        .args(["vars", "get", "FEATURE_MODE"])
        .output()
        .unwrap();
    assert!(read.status.success());
    assert_eq!(read.stdout, b"disabled\n");

    let updated = runtrue()
        .current_dir(directory.path())
        .args(["vars", "set", "FEATURE_MODE", "enabled", "--json"])
        .output()
        .unwrap();
    assert!(updated.status.success());
    let report: Value = serde_json::from_slice(&updated.stdout).unwrap();
    assert_eq!(report["operation"], "updated");
    assert_eq!(report["metadata"]["version"], 2);
    assert_eq!(report["value"], "enabled");
    assert!(fs::read_dir(directory.path().join(".runtrue"))
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp")));

    let deleted = runtrue()
        .current_dir(directory.path())
        .args(["vars", "delete", "FEATURE_MODE", "--json"])
        .output()
        .unwrap();
    assert!(deleted.status.success());
    let report: Value = serde_json::from_slice(&deleted.stdout).unwrap();
    assert_eq!(report["operation"], "deleted");
    assert_eq!(report["value"], Value::Null);
    let missing = runtrue()
        .current_dir(directory.path())
        .args(["vars", "get", "FEATURE_MODE", "--json"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&missing.stderr).unwrap();
    assert_eq!(error["error"]["code"], "variable_not_found");

    let invalid_workspace = tempdir().unwrap();
    let invalid = runtrue()
        .current_dir(invalid_workspace.path())
        .args(["vars", "set", "../ESCAPE", "value", "--json"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(10));
    assert!(!invalid_workspace.path().join(".runtrue").exists());

    let symlink_workspace = tempdir().unwrap();
    fs::create_dir(symlink_workspace.path().join(".runtrue")).unwrap();
    let victim = symlink_workspace.path().join("victim-vars");
    fs::write(&victim, b"preserve").unwrap();
    symlink(&victim, symlink_workspace.path().join(".runtrue/vars.json")).unwrap();
    let rejected = runtrue()
        .current_dir(symlink_workspace.path())
        .args(["vars", "set", "SAFE_NAME", "value", "--json"])
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(10));
    assert_eq!(fs::read(victim).unwrap(), b"preserve");
}
