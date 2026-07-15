use runtrue_model::ContentDigest;
use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn provenance_and_sbom_are_canonical_digest_bound_and_create_new() {
    let directory = tempdir().unwrap();
    let artifact = directory.path().join("runtrue");
    let provenance = directory.path().join("runtrue.intoto.json");
    let sbom = directory.path().join("runtrue.cdx.json");
    let cargo_metadata = directory.path().join("cargo-metadata.json");
    let cargo_lock = directory.path().join("Cargo.lock");
    fs::write(&artifact, b"release-binary").unwrap();
    fs::write(
        &cargo_metadata,
        serde_json::to_vec(&serde_json::json!({
            "packages": [
                {"id": "path+file:///src#runtrue-cli@0.1.0", "name": "runtrue-cli", "version": "0.1.0", "source": null},
                {"id": "registry+https://example.invalid#index@1.2.3", "name": "locked-dependency", "version": "1.2.3", "source": "registry+https://example.invalid"}
            ],
            "workspace_members": ["path+file:///src#runtrue-cli@0.1.0"],
            "resolve": {"nodes": [
                {"id": "path+file:///src#runtrue-cli@0.1.0", "deps": [{"pkg": "registry+https://example.invalid#index@1.2.3", "dep_kinds": [{"kind": null}]}]},
                {"id": "registry+https://example.invalid#index@1.2.3", "deps": []}
            ]}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &cargo_lock,
        r#"version = 4

[[package]]
name = "runtrue-cli"
version = "0.1.0"

[[package]]
name = "locked-dependency"
version = "1.2.3"
source = "registry+https://example.invalid"
checksum = "abababababababababababababababababababababababababababababababab"
"#,
    )
    .unwrap();
    let component = format!("bin/runtrue={}", artifact.display());
    let binary = env!("CARGO_BIN_EXE_runtrue-update");

    let provenance_result = Command::new(binary)
        .args([
            "provenance",
            "--subject",
            &component,
            "--source-repository",
            "https://example.invalid/runtrue",
            "--source-commit",
            "0123456789abcdef",
            "--source-ref",
            "refs/tags/v0.1.0",
            "--builder-id",
            "https://example.invalid/builders/release",
            "--built-unix-seconds",
            "1000",
            "--output",
            provenance.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        provenance_result.status.success(),
        "{}",
        String::from_utf8_lossy(&provenance_result.stderr)
    );
    let provenance_bytes = fs::read(&provenance).unwrap();
    let provenance_json: serde_json::Value = serde_json::from_slice(&provenance_bytes).unwrap();
    assert_eq!(
        provenance_json["subject"][0]["digest"]["sha256"],
        ContentDigest::sha256(b"release-binary")
            .as_str()
            .strip_prefix("sha256:")
            .unwrap()
    );

    let sbom_result = Command::new(binary)
        .args([
            "sbom",
            "--component",
            &component,
            "--package",
            "runtrue-cli",
            "--cargo-metadata",
            cargo_metadata.to_str().unwrap(),
            "--cargo-lock",
            cargo_lock.to_str().unwrap(),
            "--version",
            "v0.1.0",
            "--output",
            sbom.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        sbom_result.status.success(),
        "{}",
        String::from_utf8_lossy(&sbom_result.stderr)
    );
    let sbom_json: serde_json::Value = serde_json::from_slice(&fs::read(&sbom).unwrap()).unwrap();
    assert_eq!(sbom_json["bomFormat"], "CycloneDX");
    let components = sbom_json["components"].as_array().unwrap();
    let release_file = components
        .iter()
        .find(|component| component["type"] == "file")
        .unwrap();
    assert_eq!(release_file["hashes"][0]["alg"], "SHA-256");
    assert_eq!(
        release_file["hashes"][0]["content"],
        provenance_json["subject"][0]["digest"]["sha256"]
    );
    let dependency = components
        .iter()
        .find(|component| {
            component["type"] == "library"
                && component["name"] == "locked-dependency"
                && component["version"] == "1.2.3"
        })
        .unwrap();
    assert_eq!(dependency["hashes"][0]["alg"], "SHA-256");
    assert_eq!(dependency["hashes"][0]["content"], "ab".repeat(32));

    let no_overwrite = Command::new(binary)
        .args([
            "sbom",
            "--component",
            &component,
            "--package",
            "runtrue-cli",
            "--cargo-metadata",
            cargo_metadata.to_str().unwrap(),
            "--cargo-lock",
            cargo_lock.to_str().unwrap(),
            "--version",
            "v0.1.0",
            "--output",
            sbom.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!no_overwrite.status.success());
}
