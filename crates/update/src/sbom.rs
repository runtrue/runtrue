#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    pub version: u32,
    pub metadata: CycloneDxMetadata,
    pub components: Vec<CycloneDxComponent>,
    pub dependencies: Vec<CycloneDxDependency>,
}

impl CycloneDxBom {
    pub fn from_cargo_graph(
        application_name: impl Into<String>,
        release_version: impl Into<String>,
        mut subjects: Vec<ReleaseSubject>,
        root_package_id: impl Into<String>,
        mut packages: Vec<CargoPackageNode>,
    ) -> Result<Self, UpdateError> {
        subjects.sort_by(|left, right| left.name.cmp(&right.name));
        if subjects.is_empty()
            || subjects.len() > MAX_TARGETS
            || subjects.windows(2).any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(UpdateError::InvalidCycloneDxBom);
        }
        for subject in &subjects {
            subject
                .validate()
                .map_err(|_| UpdateError::InvalidCycloneDxBom)?;
        }
        packages.sort_by(|left, right| left.package_id.cmp(&right.package_id));
        if packages.is_empty()
            || packages.len() > MAX_TARGETS
            || packages
                .windows(2)
                .any(|pair| pair[0].package_id >= pair[1].package_id)
        {
            return Err(UpdateError::InvalidCycloneDxBom);
        }
        let package_ids = packages
            .iter()
            .map(|package| package.package_id.as_str())
            .collect::<BTreeSet<_>>();
        for package in &packages {
            package.validate(&package_ids)?;
        }
        let root_package_id = root_package_id.into();
        if !package_ids.contains(root_package_id.as_str()) {
            return Err(UpdateError::InvalidCycloneDxBom);
        }

        let application_name = application_name.into();
        let release_version = release_version.into();
        let application_ref = cargo_bom_ref(&root_package_id);
        let mut components = subjects
            .into_iter()
            .map(|subject| CycloneDxComponent {
                bom_ref: release_bom_ref(&subject),
                component_type: "file".to_owned(),
                name: subject.name,
                version: release_version.clone(),
                hashes: vec![CycloneDxHash {
                    algorithm: "SHA-256".to_owned(),
                    content: subject.digest.sha256,
                }],
                purl: None,
                properties: Vec::new(),
            })
            .collect::<Vec<_>>();
        components.extend(
            packages
                .iter()
                .filter(|package| package.package_id != root_package_id)
                .map(|package| CycloneDxComponent {
                    bom_ref: cargo_bom_ref(&package.package_id),
                    component_type: "library".to_owned(),
                    name: package.name.clone(),
                    version: package.version.clone(),
                    hashes: package
                        .checksum_sha256
                        .iter()
                        .map(|checksum| CycloneDxHash {
                            algorithm: "SHA-256".to_owned(),
                            content: checksum.clone(),
                        })
                        .collect(),
                    purl: Some(format!("pkg:cargo/{}@{}", package.name, package.version)),
                    properties: cargo_properties(package),
                }),
        );
        components.sort_by(|left, right| left.bom_ref.cmp(&right.bom_ref));

        let mut dependencies = packages
            .iter()
            .map(|package| CycloneDxDependency {
                component_ref: if package.package_id == root_package_id {
                    application_ref.clone()
                } else {
                    cargo_bom_ref(&package.package_id)
                },
                depends_on: package
                    .dependencies
                    .iter()
                    .map(|dependency| {
                        if dependency == &root_package_id {
                            application_ref.clone()
                        } else {
                            cargo_bom_ref(dependency)
                        }
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        dependencies.extend(
            components
                .iter()
                .filter(|component| component.component_type == "file")
                .map(|component| CycloneDxDependency {
                    component_ref: component.bom_ref.clone(),
                    depends_on: Vec::new(),
                }),
        );
        dependencies.sort_by(|left, right| left.component_ref.cmp(&right.component_ref));

        let bom = Self {
            bom_format: "CycloneDX".to_owned(),
            spec_version: "1.5".to_owned(),
            version: 1,
            metadata: CycloneDxMetadata {
                component: CycloneDxApplication {
                    bom_ref: application_ref,
                    component_type: "application".to_owned(),
                    name: application_name,
                    version: release_version.clone(),
                    properties: cargo_properties(
                        packages
                            .iter()
                            .find(|package| package.package_id == root_package_id)
                            .ok_or(UpdateError::InvalidCycloneDxBom)?,
                    ),
                },
            },
            components,
            dependencies,
        };
        bom.validate()?;
        Ok(bom)
    }

    pub fn validate(&self) -> Result<(), UpdateError> {
        if self.bom_format != "CycloneDX"
            || self.spec_version != "1.5"
            || self.version != 1
            || !valid_text(&self.metadata.component.bom_ref)
            || self.metadata.component.component_type != "application"
            || !valid_text(&self.metadata.component.name)
            || !valid_text(&self.metadata.component.version)
            || !valid_properties(&self.metadata.component.properties)
            || self.components.is_empty()
            || self.components.len() > MAX_TARGETS
            || self
                .components
                .windows(2)
                .any(|pair| pair[0].bom_ref >= pair[1].bom_ref)
        {
            return Err(UpdateError::InvalidCycloneDxBom);
        }
        for component in &self.components {
            let file = component.component_type == "file";
            let library = component.component_type == "library";
            if !valid_text(&component.bom_ref)
                || (!file && !library)
                || (file
                    && normalize_relative_path(&component.name).ok().as_deref()
                        != Some(component.name.as_str()))
                || (library && !valid_text(&component.name))
                || !valid_text(&component.version)
                || (file && !valid_release_hashes(&component.hashes))
                || (library
                    && !component.hashes.is_empty()
                    && !valid_release_hashes(&component.hashes))
                || (file && component.purl.is_some())
                || (library
                    && component
                        .purl
                        .as_deref()
                        .is_none_or(|purl| !valid_text(purl)))
                || !valid_properties(&component.properties)
            {
                return Err(UpdateError::InvalidCycloneDxBom);
            }
        }
        let known_refs = std::iter::once(self.metadata.component.bom_ref.as_str())
            .chain(
                self.components
                    .iter()
                    .map(|component| component.bom_ref.as_str()),
            )
            .collect::<BTreeSet<_>>();
        if known_refs.len() != self.components.len() + 1
            || self.dependencies.len() != known_refs.len()
            || self
                .dependencies
                .windows(2)
                .any(|pair| pair[0].component_ref >= pair[1].component_ref)
        {
            return Err(UpdateError::InvalidCycloneDxBom);
        }
        for dependency in &self.dependencies {
            if !known_refs.contains(dependency.component_ref.as_str())
                || dependency
                    .depends_on
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || dependency.depends_on.iter().any(|component_ref| {
                    component_ref == &dependency.component_ref
                        || !known_refs.contains(component_ref.as_str())
                })
            {
                return Err(UpdateError::InvalidCycloneDxBom);
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        self.validate()?;
        canonical_bytes(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycloneDxMetadata {
    pub component: CycloneDxApplication,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycloneDxApplication {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    pub properties: Vec<CycloneDxProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycloneDxComponent {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<CycloneDxHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<CycloneDxProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycloneDxHash {
    #[serde(rename = "alg")]
    pub algorithm: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycloneDxProperty {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycloneDxDependency {
    #[serde(rename = "ref")]
    pub component_ref: String,
    #[serde(rename = "dependsOn")]
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoPackageNode {
    pub package_id: String,
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum_sha256: Option<String>,
    pub dependencies: Vec<String>,
}

impl CargoPackageNode {
    fn validate(&self, known: &BTreeSet<&str>) -> Result<(), UpdateError> {
        if !valid_text(&self.package_id)
            || !valid_text(&self.name)
            || !valid_text(&self.version)
            || self
                .source
                .as_deref()
                .is_some_and(|source| !valid_text(source))
            || self
                .checksum_sha256
                .as_deref()
                .is_some_and(|checksum| checksum.len() != 64 || !is_lower_hex(checksum))
            || self.source.as_deref().is_some_and(|source| {
                source.starts_with("registry+") && self.checksum_sha256.is_none()
            })
            || self.dependencies.windows(2).any(|pair| pair[0] >= pair[1])
            || self.dependencies.iter().any(|dependency| {
                dependency == &self.package_id || !known.contains(dependency.as_str())
            })
        {
            return Err(UpdateError::InvalidCycloneDxBom);
        }
        Ok(())
    }
}

fn cargo_properties(package: &CargoPackageNode) -> Vec<CycloneDxProperty> {
    let mut properties = vec![CycloneDxProperty {
        name: "runtrue:cargo-package-id".to_owned(),
        value: package.package_id.clone(),
    }];
    if let Some(source) = &package.source {
        properties.push(CycloneDxProperty {
            name: "runtrue:cargo-source".to_owned(),
            value: source.clone(),
        });
    }
    properties
}

fn cargo_bom_ref(package_id: &str) -> String {
    format!(
        "cargo:{}",
        digest_hex(&ContentDigest::sha256(package_id.as_bytes()))
    )
}

fn release_bom_ref(subject: &ReleaseSubject) -> String {
    let identity = format!("{}\0{}", subject.name, subject.digest.sha256);
    format!(
        "release-file:{}",
        digest_hex(&ContentDigest::sha256(identity.as_bytes()))
    )
}

fn valid_release_hashes(hashes: &[CycloneDxHash]) -> bool {
    hashes.len() == 1
        && hashes[0].algorithm == "SHA-256"
        && hashes[0].content.len() == 64
        && is_lower_hex(&hashes[0].content)
}

fn valid_properties(properties: &[CycloneDxProperty]) -> bool {
    properties.len() <= MAX_CUSTOM_FIELDS
        && properties
            .iter()
            .all(|property| valid_text(&property.name) && valid_text(&property.value))
        && !properties
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
}
use crate::{
    canonical_bytes, digest_hex, is_lower_hex, valid_text, ReleaseSubject, UpdateError,
    MAX_CUSTOM_FIELDS, MAX_TARGETS,
};
use runtrue_model::{normalize_relative_path, ContentDigest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
