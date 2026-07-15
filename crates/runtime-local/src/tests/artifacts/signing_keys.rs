use super::*;

#[cfg(unix)]
#[test]
fn artifact_signing_key_symlink_is_never_followed() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let workspace = tempdir().unwrap();
    let artifact_root = workspace.path().join(".runtrue/artifacts");
    fs::create_dir_all(&artifact_root).unwrap();
    let victim = workspace.path().join("victim-key");
    fs::write(&victim, [7_u8; 32]).unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&victim, artifact_root.join("local-signing-key")).unwrap();

    let wrapper = LocalArtifactExecutor::new(
        FakeExecutor::new(workspace.path(), FakeAction::Noop),
        LocalArtifactConfig::for_workspace(workspace.path()),
    );
    assert!(wrapper.preflight(&artifact_capsule("write")).is_err());
    assert_eq!(fs::read(victim).unwrap(), [7_u8; 32]);
}
