use super::*;
use crate::ProviderContractError;
use runtrue_model::ContentDigest;

struct RecordingFetcher {
    response: FetchedPackage,
    observed: Option<&'static str>,
}

impl PackageFetcher for RecordingFetcher {
    fn fetch(
        &mut self,
        _request: &PackagePullRequest,
        credential: Option<&RegistryCredential>,
    ) -> Result<FetchedPackage, PackageFetchError> {
        self.observed = Some(match credential.map(RegistryCredential::expose) {
            Some(RegistryCredentialRef::Basic {
                password: "container-secret",
                ..
            }) => "container",
            Some(RegistryCredentialRef::Bearer {
                token: "wasm-secret",
            }) => "wasm",
            Some(RegistryCredentialRef::Other {
                secret: "package-secret",
                ..
            }) => "custom",
            None => "anonymous",
            _ => "wrong",
        });
        Ok(self.response.clone())
    }
}

fn request(
    kind: PackageKind,
    reference: &str,
    bytes: &[u8],
    requirement: CredentialRequirement,
) -> PackagePullRequest {
    PackagePullRequest::new(
        kind,
        reference,
        ContentDigest::sha256(bytes),
        "application/octet-stream",
        1024,
        requirement,
    )
    .unwrap()
}

fn fetcher(reference: &str, bytes: &[u8]) -> RecordingFetcher {
    RecordingFetcher {
        response: FetchedPackage {
            reference: reference.to_owned(),
            media_type: "application/octet-stream".to_owned(),
            bytes: bytes.to_vec(),
        },
        observed: None,
    }
}

#[test]
fn selects_package_specific_credentials_for_container_and_wasm_pulls() {
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let container_reference = format!("registry.example/team/image@{digest}");
    let wasm_reference = format!("wasm://registry.example/team/action@{digest}");
    let mut credentials = RegistryCredentialSet::new();
    credentials
        .insert(
            RegistryCredentialScope::registry("registry.example").unwrap(),
            RegistryCredential::basic("runner", "container-secret").unwrap(),
        )
        .unwrap();
    credentials
        .insert(
            RegistryCredentialScope::package("registry.example", PackageKind::WasmComponent)
                .unwrap(),
            RegistryCredential::bearer("wasm-secret").unwrap(),
        )
        .unwrap();

    let container = request(
        PackageKind::ContainerImage,
        &container_reference,
        b"container",
        CredentialRequirement::Required,
    );
    let mut container_fetcher = fetcher(&container_reference, b"container");
    pull_package(&mut container_fetcher, &credentials, &container).unwrap();
    assert_eq!(container_fetcher.observed, Some("container"));

    let wasm = request(
        PackageKind::WasmComponent,
        &wasm_reference,
        b"component",
        CredentialRequirement::Required,
    );
    let mut wasm_fetcher = fetcher(&wasm_reference, b"component");
    pull_package(&mut wasm_fetcher, &credentials, &wasm).unwrap();
    assert_eq!(wasm_fetcher.observed, Some("wasm"));
}

#[test]
fn registry_scope_supports_future_package_kinds_without_secret_leakage() {
    let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let reference = format!("npm://packages.example/team/tool@{digest}");
    let kind = PackageKind::named("npm").unwrap();
    let mut credentials = RegistryCredentialSet::new();
    credentials
        .insert(
            RegistryCredentialScope::package("packages.example", kind.clone()).unwrap(),
            RegistryCredential::other("npm-token", Some("automation".to_owned()), "package-secret")
                .unwrap(),
        )
        .unwrap();
    let debug = format!("{credentials:?}");
    assert!(!debug.contains("package-secret"));
    assert!(
        !format!("{:?}", RegistryCredential::bearer("do-not-log").unwrap()).contains("do-not-log")
    );

    let package = request(
        kind,
        &reference,
        b"package",
        CredentialRequirement::Required,
    );
    let mut package_fetcher = fetcher(&reference, b"package");
    pull_package(&mut package_fetcher, &credentials, &package).unwrap();
    assert_eq!(package_fetcher.observed, Some("custom"));
}

#[test]
fn credentials_never_match_a_sibling_host_or_different_port() {
    let digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let mut credentials = RegistryCredentialSet::new();
    credentials
        .insert(
            RegistryCredentialScope::registry("registry.example:5000").unwrap(),
            RegistryCredential::bearer("port-secret").unwrap(),
        )
        .unwrap();

    for reference in [
        format!("registry.example/team/image@{digest}"),
        format!("other.registry.example:5000/team/image@{digest}"),
    ] {
        let request = request(
            PackageKind::ContainerImage,
            &reference,
            b"image",
            CredentialRequirement::Optional,
        );
        assert!(credentials.resolve(&request).is_none(), "{reference}");
    }

    let exact_reference = format!("registry.example:5000/team/image@{digest}");
    let exact = request(
        PackageKind::ContainerImage,
        &exact_reference,
        b"image",
        CredentialRequirement::Required,
    );
    assert!(credentials.resolve(&exact).is_some());
}

#[test]
fn rejects_noncanonical_oci_paths_and_duplicate_credential_scopes() {
    let digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    for reference in [
        format!("registry.example/Team/image@{digest}"),
        format!("wasm://registry.example/team/action?download=1@{digest}"),
        format!("registry.example/team/image:tag@{digest}"),
    ] {
        let kind = if reference.starts_with("wasm://") {
            PackageKind::WasmComponent
        } else {
            PackageKind::ContainerImage
        };
        assert!(
            PackagePullRequest::new(
                kind,
                &reference,
                ContentDigest::sha256(b"payload"),
                "application/octet-stream",
                1024,
                CredentialRequirement::Optional,
            )
            .is_err(),
            "{reference}"
        );
    }

    let scope = RegistryCredentialScope::registry("registry.example").unwrap();
    let mut credentials = RegistryCredentialSet::new();
    credentials
        .insert(scope.clone(), RegistryCredential::bearer("first").unwrap())
        .unwrap();
    assert_eq!(
        credentials.insert(scope, RegistryCredential::bearer("second").unwrap()),
        Err(ProviderContractError::DuplicateRegistryCredential)
    );
}

#[test]
fn rejects_mutable_references_missing_credentials_and_unverified_payloads() {
    assert!(PackagePullRequest::new(
        PackageKind::ContainerImage,
        "registry.example/team/image:latest",
        ContentDigest::sha256(b"image"),
        "application/octet-stream",
        1024,
        CredentialRequirement::Optional,
    )
    .is_err());

    let digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let reference = format!("registry.example/team/image@{digest}");
    let package = request(
        PackageKind::ContainerImage,
        &reference,
        b"image",
        CredentialRequirement::Required,
    );
    let mut missing_fetcher = fetcher(&reference, b"image");
    assert_eq!(
        pull_package(
            &mut missing_fetcher,
            &RegistryCredentialSet::new(),
            &package
        ),
        Err(ProviderContractError::MissingRegistryCredential)
    );
    assert_eq!(missing_fetcher.observed, None);

    let mut wrong_payload = fetcher(&reference, b"different");
    assert_eq!(
        pull_package(
            &mut wrong_payload,
            &RegistryCredentialSet::new(),
            &PackagePullRequest::new(
                PackageKind::ContainerImage,
                reference,
                ContentDigest::sha256(b"image"),
                "application/octet-stream",
                1024,
                CredentialRequirement::Optional,
            )
            .unwrap(),
        ),
        Err(ProviderContractError::InvalidFetchedPackage(
            "payload digest mismatch"
        ))
    );
}

#[test]
fn verifies_every_fetch_response_field_and_bound() {
    let digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let reference = format!("registry.example/team/image@{digest}");
    let package = request(
        PackageKind::ContainerImage,
        &reference,
        b"image",
        CredentialRequirement::Optional,
    );

    let cases = [
        (
            FetchedPackage {
                reference: format!("registry.example/team/other@{digest}"),
                media_type: "application/octet-stream".to_owned(),
                bytes: b"image".to_vec(),
            },
            "reference changed",
        ),
        (
            FetchedPackage {
                reference: reference.clone(),
                media_type: "application/wasm".to_owned(),
                bytes: b"image".to_vec(),
            },
            "media type changed",
        ),
        (
            FetchedPackage {
                reference: reference.clone(),
                media_type: "application/octet-stream".to_owned(),
                bytes: Vec::new(),
            },
            "payload is empty or exceeds its bound",
        ),
        (
            FetchedPackage {
                reference: reference.clone(),
                media_type: "application/octet-stream".to_owned(),
                bytes: vec![0; 1025],
            },
            "payload is empty or exceeds its bound",
        ),
    ];

    for (response, expected) in cases {
        let mut fetcher = RecordingFetcher {
            response,
            observed: None,
        };
        assert_eq!(
            pull_package(&mut fetcher, &RegistryCredentialSet::new(), &package),
            Err(ProviderContractError::InvalidFetchedPackage(expected))
        );
    }
}
