use crate::{
    digest::digest_file,
    error::ImageCliError,
    output::{self, StageComponentResult},
    secure_fs::{
        read_bounded_regular, read_private_registry_config, require_new_file_target, write_new_file,
    },
};
use runtrue_model::ContentDigest;
use serde::Deserialize;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

const MAX_ORAS_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REGISTRY_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_OCI_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_COMPONENT_BYTES: u64 = 64 * 1024 * 1024;
const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const RUNTRUE_COMPONENT_ARTIFACT_TYPE: &str = "application/vnd.runtrue.wasm.component.v1";
const WASM_LAYER_MEDIA_TYPE: &str = "application/wasm";

pub(crate) struct StageRequest {
    pub(crate) oras: PathBuf,
    pub(crate) oras_digest: String,
    pub(crate) reference: String,
    pub(crate) payload_digest: String,
    pub(crate) registry_config: Option<PathBuf>,
    pub(crate) output: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciManifest {
    schema_version: u32,
    media_type: String,
    artifact_type: String,
    layers: Vec<OciDescriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciDescriptor {
    media_type: String,
    digest: String,
    size: u64,
}

pub(crate) fn stage(request: StageRequest, json: bool) -> Result<(), ImageCliError> {
    require_new_file_target(&request.output)?;
    let (repository, manifest_digest) = exact_manifest_reference(&request.reference)?;
    let payload_digest = ContentDigest::parse(request.payload_digest)?;
    require_digest_named_output(&request.output, &payload_digest)?;

    let expected_oras_digest = ContentDigest::parse(request.oras_digest)?;
    let oras_bytes = read_bounded_regular(&request.oras, MAX_ORAS_BYTES, false)?;
    if ContentDigest::sha256(&oras_bytes) != expected_oras_digest {
        return Err(ImageCliError::OrasDigestMismatch);
    }

    // Copy both executable and credentials into a private directory. This pins
    // the exact bytes checked above and prevents either input from changing
    // between validation and registry access.
    let registry_config = request
        .registry_config
        .as_deref()
        .map(|path| read_private_registry_config(path, MAX_REGISTRY_CONFIG_BYTES))
        .transpose()?
        .map(Zeroizing::new);

    let staging = tempfile::Builder::new()
        .prefix("runtrue-registry-")
        .tempdir()?;
    let trusted_oras = staging.path().join("oras");
    let trusted_config = registry_config
        .as_ref()
        .map(|_| staging.path().join("registry-config.json"));
    let manifest_path = staging.path().join("manifest.json");
    let payload_path = staging.path().join("component.wasm");
    write_new_file(&trusted_oras, &oras_bytes, 0o700)?;
    if let (Some(path), Some(bytes)) = (&trusted_config, &registry_config) {
        write_new_file(path, bytes.as_slice(), 0o600)?;
    }

    let mut manifest_arguments = vec![
        OsString::from("manifest"),
        OsString::from("fetch"),
        OsString::from("--output"),
        manifest_path.as_os_str().to_owned(),
    ];
    append_registry_config(&mut manifest_arguments, trusted_config.as_deref());
    manifest_arguments.push(OsString::from(&request.reference));
    run_oras(&trusted_oras, "manifest fetch", &manifest_arguments)?;
    let manifest_bytes = read_bounded_regular(&manifest_path, MAX_OCI_MANIFEST_BYTES, false)?;
    if ContentDigest::sha256(&manifest_bytes) != manifest_digest {
        return Err(ImageCliError::InvalidOciManifest(
            "fetched bytes do not match the reference manifest digest".to_owned(),
        ));
    }
    let manifest: OciManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest, &payload_digest)?;

    let blob_reference = format!("{repository}@{payload_digest}");
    let mut blob_arguments = vec![
        OsString::from("blob"),
        OsString::from("fetch"),
        OsString::from("--output"),
        payload_path.as_os_str().to_owned(),
    ];
    append_registry_config(&mut blob_arguments, trusted_config.as_deref());
    blob_arguments.push(OsString::from(blob_reference));
    run_oras(&trusted_oras, "blob fetch", &blob_arguments)?;
    let (actual_payload_digest, payload_size_bytes) =
        digest_file(&payload_path, MAX_COMPONENT_BYTES)?;
    if actual_payload_digest != payload_digest || payload_size_bytes != manifest.layers[0].size {
        return Err(ImageCliError::PayloadMismatch);
    }
    let payload_bytes = read_bounded_regular(&payload_path, MAX_COMPONENT_BYTES, false)?;
    write_new_file(&request.output, &payload_bytes, 0o600)?;

    output::print(
        json,
        &StageComponentResult {
            reference: request.reference,
            manifest_digest,
            payload_digest,
            payload_size_bytes,
            output: request.output,
        },
        "staged verified private-registry component",
    )
}

fn append_registry_config(arguments: &mut Vec<OsString>, registry_config: Option<&Path>) {
    if let Some(path) = registry_config {
        arguments.push(OsString::from("--registry-config"));
        arguments.push(path.as_os_str().to_owned());
    }
}

fn run_oras(
    oras: &Path,
    operation: &'static str,
    arguments: &[OsString],
) -> Result<(), ImageCliError> {
    let status = Command::new(oras)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(ImageCliError::OrasFailed {
            operation,
            status: status.to_string(),
        });
    }
    Ok(())
}

fn exact_manifest_reference(reference: &str) -> Result<(String, ContentDigest), ImageCliError> {
    let invalid = || ImageCliError::InvalidOciReference(reference.to_owned());
    if reference.is_empty()
        || reference.len() > 4096
        || reference.contains("://")
        || reference.chars().any(char::is_whitespace)
        || reference.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid());
    }
    let mut parts = reference.split('@');
    let repository = parts.next().ok_or_else(invalid)?;
    let digest = parts.next().ok_or_else(invalid)?;
    if parts.next().is_some() || repository.is_empty() {
        return Err(invalid());
    }
    let mut repository_parts = repository.split('/');
    let registry = repository_parts.next().ok_or_else(invalid)?;
    let names = repository_parts.collect::<Vec<_>>();
    if registry.is_empty()
        || names.is_empty()
        || names
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
        || repository.bytes().any(|byte| {
            !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:/-".contains(&byte))
        })
        || names.iter().any(|part| part.contains(':'))
    {
        return Err(invalid());
    }
    let digest = ContentDigest::parse(digest.to_owned()).map_err(|_| invalid())?;
    Ok((repository.to_owned(), digest))
}

fn require_digest_named_output(
    output: &Path,
    payload_digest: &ContentDigest,
) -> Result<(), ImageCliError> {
    let digest_hex = payload_digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| ImageCliError::InvalidOciReference(payload_digest.to_string()))?;
    let expected = format!("{digest_hex}.wasm");
    if output.file_name().and_then(|name| name.to_str()) != Some(expected.as_str()) {
        return Err(ImageCliError::InvalidOciManifest(format!(
            "output must be named `{expected}` for runner preloading"
        )));
    }
    Ok(())
}

fn validate_manifest(
    manifest: &OciManifest,
    payload_digest: &ContentDigest,
) -> Result<(), ImageCliError> {
    if manifest.schema_version != 2
        || manifest.media_type != OCI_MANIFEST_MEDIA_TYPE
        || manifest.artifact_type != RUNTRUE_COMPONENT_ARTIFACT_TYPE
    {
        return Err(ImageCliError::InvalidOciManifest(
            "schema, manifest media type, or Runtrue artifact type is not supported".to_owned(),
        ));
    }
    if manifest.layers.len() != 1 {
        return Err(ImageCliError::InvalidOciManifest(
            "component artifact must contain exactly one layer".to_owned(),
        ));
    }
    let layer = &manifest.layers[0];
    let layer_digest = ContentDigest::parse(layer.digest.clone()).map_err(|_| {
        ImageCliError::InvalidOciManifest("component layer digest is invalid".to_owned())
    })?;
    if layer.media_type != WASM_LAYER_MEDIA_TYPE || layer_digest != *payload_digest {
        return Err(ImageCliError::InvalidOciManifest(
            "component layer media type or digest does not match the requested payload".to_owned(),
        ));
    }
    if layer.size == 0 || layer.size > MAX_COMPONENT_BYTES {
        return Err(ImageCliError::InvalidOciManifest(format!(
            "component layer size must be between 1 and {MAX_COMPONENT_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    use tempfile::TempDir;

    #[test]
    fn accepts_only_exact_registry_manifest_references() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(exact_manifest_reference(&format!("ghcr.io/runtrue/backport@{digest}")).is_ok());
        for reference in [
            "ghcr.io/runtrue/backport:latest",
            "oci://ghcr.io/runtrue/backport@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ghcr.io/runtrue/backport:tag@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ghcr.io/Runtrue/backport@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(exact_manifest_reference(reference).is_err(), "{reference}");
        }
    }

    #[test]
    fn manifest_requires_one_exact_wasm_layer() {
        let payload = ContentDigest::sha256(b"component");
        let valid = OciManifest {
            schema_version: 2,
            media_type: OCI_MANIFEST_MEDIA_TYPE.to_owned(),
            artifact_type: RUNTRUE_COMPONENT_ARTIFACT_TYPE.to_owned(),
            layers: vec![OciDescriptor {
                media_type: WASM_LAYER_MEDIA_TYPE.to_owned(),
                digest: payload.to_string(),
                size: 9,
            }],
        };
        assert!(validate_manifest(&valid, &payload).is_ok());

        let wrong = ContentDigest::sha256(b"different");
        assert!(validate_manifest(&valid, &wrong).is_err());
    }

    #[test]
    fn stages_verified_bytes_without_exposing_credentials_to_the_output() {
        let temp = TempDir::new().unwrap();
        let payload = b"component";
        let payload_digest = ContentDigest::sha256(payload);
        let manifest = format!(
            concat!(
                "{{\"schemaVersion\":2,",
                "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",",
                "\"artifactType\":\"application/vnd.runtrue.wasm.component.v1\",",
                "\"layers\":[{{\"mediaType\":\"application/wasm\",",
                "\"digest\":\"{}\",\"size\":9}}]}}"
            ),
            payload_digest
        );
        let manifest_digest = ContentDigest::sha256(manifest.as_bytes());
        let script = format!(
            concat!(
                "#!/bin/sh\nset -eu\n",
                "operation=\"$1 $2\"\nshift 2\nout=\nconfig=\n",
                "while [ \"$#\" -gt 1 ]; do\n",
                "  case \"$1\" in --output) out=$2;; --registry-config) config=$2;; *) exit 91;; esac\n",
                "  shift 2\ndone\n",
                "[ -f \"$config\" ] && grep -q private-test-token \"$config\"\n",
                "case \"$operation\" in\n",
                "  'manifest fetch') printf '%s' '{}' >\"$out\";;\n",
                "  'blob fetch') printf '%s' component >\"$out\";;\n",
                "  *) exit 92;;\nesac\n"
            ),
            manifest
        );
        let oras = temp.path().join("oras");
        fs::write(&oras, script.as_bytes()).unwrap();
        fs::set_permissions(&oras, fs::Permissions::from_mode(0o700)).unwrap();
        let config = temp.path().join("config.json");
        fs::write(
            &config,
            br#"{"auths":{"ghcr.io":{"auth":"private-test-token"}}}"#,
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let output = temp.path().join(format!(
            "{}.wasm",
            payload_digest.as_str().strip_prefix("sha256:").unwrap()
        ));

        stage(
            StageRequest {
                oras,
                oras_digest: ContentDigest::sha256(script.as_bytes()).to_string(),
                reference: format!("ghcr.io/runtrue/backport@{manifest_digest}"),
                payload_digest: payload_digest.to_string(),
                registry_config: Some(config),
                output: output.clone(),
            },
            true,
        )
        .unwrap();

        assert_eq!(fs::read(&output).unwrap(), payload);
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
