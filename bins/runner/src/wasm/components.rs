pub(super) fn load_component_keys(
    directory: &Path,
) -> Result<BTreeMap<ContentDigest, ImageVerifyingKey>, RunnerError> {
    let paths = sorted_directory_files(directory)?;
    if paths.len() > MAX_COMPONENTS {
        return Err(RunnerError::WasmConfiguration(format!(
            "Wasm component key count exceeds {MAX_COMPONENTS}"
        )));
    }
    let mut keys = BTreeMap::new();
    for path in paths {
        let bytes = read_bounded_private_file(&path, MAX_KEY_BYTES)?;
        let decoded = decode_public_key(&bytes).ok_or_else(|| {
            RunnerError::WasmConfiguration(format!(
                "invalid Wasm component key `{}`",
                path.display()
            ))
        })?;
        let key = ImageVerifyingKey::from_bytes(&decoded)?;
        let key_id = key.key_id();
        if keys.insert(key_id.clone(), key).is_some() {
            return Err(RunnerError::WasmConfiguration(format!(
                "duplicate Wasm component key `{key_id}`"
            )));
        }
    }
    if keys.is_empty() {
        return Err(RunnerError::WasmConfiguration(
            "Wasm component keyring is empty".to_owned(),
        ));
    }
    Ok(keys)
}

pub(super) fn load_components(
    component_directory: &Path,
    manifest_directory: &Path,
    keys: &BTreeMap<ContentDigest, ImageVerifyingKey>,
) -> Result<BTreeMap<String, WasmComponentArtifact>, RunnerError> {
    let manifests = sorted_directory_files(manifest_directory)?;
    if manifests.is_empty() {
        return Err(RunnerError::WasmConfiguration(
            "Wasm manifest directory is empty".to_owned(),
        ));
    }
    if manifests.len() > MAX_COMPONENTS {
        return Err(RunnerError::WasmConfiguration(format!(
            "Wasm component manifest count exceeds {MAX_COMPONENTS}"
        )));
    }

    let mut total_bytes = 0_u64;
    let mut expected_payloads = BTreeSet::new();
    let mut artifacts = BTreeMap::new();
    for path in manifests {
        let manifest_bytes = read_bounded_private_file(&path, MAX_MANIFEST_BYTES)?;
        let signed: SignedImageManifest = strict_json(&manifest_bytes).map_err(|error| {
            RunnerError::WasmConfiguration(format!(
                "invalid Wasm component manifest `{}`: {error}",
                path.display()
            ))
        })?;
        let key = keys
            .get(&signed.key_id)
            .ok_or_else(|| RunnerError::UntrustedWasmComponentKey(signed.key_id.clone()))?;
        key.verify_manifest(&signed)?;

        // The signed manifest name is the exact immutable workflow reference.
        // This binds both the locator and digest instead of selecting by a
        // mutable filename or accepting any payload signed by a trusted key.
        let reference = signed.manifest.name.clone();
        let digest = exact_component_digest(&reference)?;
        if digest != signed.manifest.payload_digest {
            return Err(RunnerError::WasmManifestMismatch(format!(
                "signed component reference `{reference}` does not match its payload digest"
            )));
        }
        let digest_hex = digest.as_str().strip_prefix("sha256:").ok_or_else(|| {
            RunnerError::WasmManifestMismatch(
                "component reference uses an unsupported digest algorithm".to_owned(),
            )
        })?;
        let payload = component_directory.join(format!("{digest_hex}.wasm"));
        let bytes = read_bounded_private_file(&payload, MAX_COMPONENT_BYTES)?;
        total_bytes = total_bytes
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                RunnerError::WasmConfiguration("Wasm component byte total overflow".to_owned())
            })?;
        if total_bytes > MAX_COMPONENT_TOTAL_BYTES {
            return Err(RunnerError::WasmConfiguration(format!(
                "Wasm component byte total exceeds {MAX_COMPONENT_TOTAL_BYTES}"
            )));
        }
        expected_payloads.insert(payload);
        let artifact = WasmComponentArtifact::new(reference.clone(), bytes, signed, key.clone())?;
        if artifacts.insert(reference.clone(), artifact).is_some() {
            return Err(RunnerError::WasmManifestMismatch(format!(
                "duplicate signed Wasm component assignment `{reference}`"
            )));
        }
    }

    let actual_payloads = sorted_directory_files(component_directory)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual_payloads != expected_payloads {
        return Err(RunnerError::WasmConfiguration(
            "Wasm component directory contains a missing, stale, or misnamed payload".to_owned(),
        ));
    }
    Ok(artifacts)
}

pub(super) fn exact_component_digest(reference: &str) -> Result<ContentDigest, RunnerError> {
    let scheme = if reference.starts_with("wasm://") {
        "wasm://"
    } else if reference.starts_with("oci://") {
        "oci://"
    } else {
        ""
    };
    if reference.is_empty()
        || reference.len() > 4096
        || scheme.is_empty()
        || reference.chars().any(char::is_whitespace)
        || reference.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(RunnerError::WasmManifestMismatch(
            "component reference is not an exact wasm:// or oci:// digest reference".to_owned(),
        ));
    }
    let (locator, digest) = reference.rsplit_once('@').ok_or_else(|| {
        RunnerError::WasmManifestMismatch(
            "component reference is not an exact digest reference".to_owned(),
        )
    })?;
    if locator == scheme || locator.contains('@') {
        return Err(RunnerError::WasmManifestMismatch(
            "component reference locator is invalid".to_owned(),
        ));
    }
    ContentDigest::parse(digest).map_err(|_| {
        RunnerError::WasmManifestMismatch(
            "component reference digest is invalid or truncated".to_owned(),
        )
    })
}
use super::validation::{decode_public_key, sorted_directory_files};
use super::{
    read_bounded_private_file, strict_json, BTreeMap, BTreeSet, ContentDigest, ImageVerifyingKey,
    Path, RunnerError, SignedImageManifest, WasmComponentArtifact, MAX_COMPONENTS,
    MAX_COMPONENT_BYTES, MAX_COMPONENT_TOTAL_BYTES, MAX_KEY_BYTES, MAX_MANIFEST_BYTES,
};
