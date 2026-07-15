use super::error::StartupError;
use runtrue_runner::{FirecrackerRuntimePaths, OciRuntimePaths, WasmRuntimePaths};
use std::path::PathBuf;

pub(super) fn complete_oci_configuration(
    values: [Option<PathBuf>; 7],
) -> Result<Option<OciRuntimePaths>, StartupError> {
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [Some(state_root), Some(podman), Some(seccomp_profile), Some(image_store), Some(runtime_environment), Some(manifest_directory), Some(keyring_directory)] =
        values
    else {
        return Err(StartupError::IncompleteOciConfiguration);
    };
    Ok(Some(OciRuntimePaths {
        state_root,
        podman,
        seccomp_profile,
        image_store,
        runtime_environment,
        manifest_directory,
        keyring_directory,
    }))
}

pub(super) fn complete_wasm_configuration(
    values: [Option<PathBuf>; 5],
) -> Result<Option<WasmRuntimePaths>, StartupError> {
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [Some(component_directory), Some(manifest_directory), Some(keyring_directory), Some(aot_cache), Some(runtime_key)] =
        values
    else {
        return Err(StartupError::IncompleteWasmConfiguration);
    };
    Ok(Some(WasmRuntimePaths {
        component_directory,
        manifest_directory,
        keyring_directory,
        aot_cache,
        runtime_key,
    }))
}

pub(super) fn complete_firecracker_configuration(
    values: [Option<PathBuf>; 11],
) -> Result<Option<FirecrackerRuntimePaths>, StartupError> {
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [Some(state_root), Some(jailer), Some(firecracker), Some(reflink_copy), Some(jail_root), Some(cgroup_parent), Some(cid_lock_directory), Some(image_payload_directory), Some(image_manifest_directory), Some(image_keyring_directory), Some(runtime_profile)] =
        values
    else {
        return Err(StartupError::IncompleteFirecrackerConfiguration);
    };
    Ok(Some(FirecrackerRuntimePaths {
        state_root,
        jailer,
        firecracker,
        reflink_copy,
        jail_root,
        cgroup_parent,
        cid_lock_directory,
        image_payload_directory,
        image_manifest_directory,
        image_keyring_directory,
        runtime_profile,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oci_configuration_is_strictly_all_or_none() {
        assert!(complete_oci_configuration(Default::default())
            .unwrap()
            .is_none());
        let mut partial: [Option<PathBuf>; 7] = Default::default();
        partial[0] = Some(PathBuf::from("state"));
        assert!(matches!(
            complete_oci_configuration(partial),
            Err(StartupError::IncompleteOciConfiguration)
        ));

        let values = [
            "state",
            "podman",
            "seccomp",
            "images",
            "environment",
            "manifests",
            "keys",
        ]
        .map(|value| Some(PathBuf::from(value)));
        let configured = complete_oci_configuration(values).unwrap().unwrap();
        assert_eq!(configured.podman, PathBuf::from("podman"));
        assert_eq!(configured.manifest_directory, PathBuf::from("manifests"));
    }

    #[test]
    fn wasm_configuration_is_strictly_all_or_none() {
        assert!(complete_wasm_configuration(Default::default())
            .unwrap()
            .is_none());
        let mut partial: [Option<PathBuf>; 5] = Default::default();
        partial[0] = Some(PathBuf::from("components"));
        assert!(matches!(
            complete_wasm_configuration(partial),
            Err(StartupError::IncompleteWasmConfiguration)
        ));

        let values = ["components", "manifests", "keys", "aot", "runtime-key"]
            .map(|value| Some(PathBuf::from(value)));
        let configured = complete_wasm_configuration(values).unwrap().unwrap();
        assert_eq!(configured.component_directory, PathBuf::from("components"));
        assert_eq!(configured.aot_cache, PathBuf::from("aot"));
        assert_eq!(configured.runtime_key, PathBuf::from("runtime-key"));
    }

    #[test]
    fn firecracker_configuration_is_strictly_all_or_none() {
        assert!(complete_firecracker_configuration(Default::default())
            .unwrap()
            .is_none());
        let mut partial: [Option<PathBuf>; 11] = Default::default();
        partial[0] = Some(PathBuf::from("state"));
        assert!(matches!(
            complete_firecracker_configuration(partial),
            Err(StartupError::IncompleteFirecrackerConfiguration)
        ));

        let values = [
            "state",
            "jailer",
            "firecracker",
            "cp",
            "jails",
            "runtrue/firecracker",
            "cids",
            "payloads",
            "manifests",
            "keys",
            "profile.json",
        ]
        .map(|value| Some(PathBuf::from(value)));
        let configured = complete_firecracker_configuration(values).unwrap().unwrap();
        assert_eq!(configured.firecracker, PathBuf::from("firecracker"));
        assert_eq!(
            configured.image_manifest_directory,
            PathBuf::from("manifests")
        );
    }
}
