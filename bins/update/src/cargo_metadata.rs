use crate::error::CliError;
use runtrue_update::{CargoPackageNode, MAX_TARGETS};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Deserialize)]
struct CargoMetadataDocument {
    packages: Vec<CargoMetadataPackage>,
    workspace_members: Vec<String>,
    resolve: Option<CargoMetadataResolve>,
}

#[derive(Deserialize)]
struct CargoMetadataPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
}

#[derive(Deserialize)]
struct CargoMetadataResolve {
    nodes: Vec<CargoMetadataNode>,
}

#[derive(Deserialize)]
struct CargoMetadataNode {
    id: String,
    deps: Vec<CargoMetadataDependency>,
}

#[derive(Deserialize)]
struct CargoMetadataDependency {
    pkg: String,
    dep_kinds: Vec<CargoMetadataDependencyKind>,
}

#[derive(Deserialize)]
struct CargoMetadataDependencyKind {
    kind: Option<String>,
}

#[derive(Deserialize)]
struct CargoLockDocument {
    package: Vec<CargoLockPackage>,
}

#[derive(Deserialize)]
struct CargoLockPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

pub(crate) fn cargo_dependency_graph(
    metadata_bytes: &[u8],
    lock_bytes: &[u8],
    root_name: &str,
) -> Result<(String, Vec<CargoPackageNode>), CliError> {
    let metadata: CargoMetadataDocument = serde_json::from_slice(metadata_bytes)
        .map_err(|error| CliError::InvalidCargoMetadata(error.to_string()))?;
    let lock: CargoLockDocument = toml::from_str(
        std::str::from_utf8(lock_bytes)
            .map_err(|error| CliError::InvalidCargoMetadata(error.to_string()))?,
    )
    .map_err(|error| CliError::InvalidCargoMetadata(error.to_string()))?;
    let lock_count = lock.package.len();
    let locked = lock
        .package
        .into_iter()
        .map(|package| {
            (
                (
                    package.name.clone(),
                    package.version.clone(),
                    package.source.clone(),
                ),
                package,
            )
        })
        .collect::<BTreeMap<_, _>>();
    if locked.len() != lock_count {
        return Err(CliError::InvalidCargoMetadata(
            "duplicate Cargo.lock package identity".to_owned(),
        ));
    }
    let workspace_members = metadata
        .workspace_members
        .into_iter()
        .collect::<BTreeSet<_>>();
    let roots = metadata
        .packages
        .iter()
        .filter(|package| {
            package.name == root_name
                && package.source.is_none()
                && workspace_members.contains(&package.id)
        })
        .map(|package| package.id.clone())
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(CliError::InvalidCargoMetadata(format!(
            "expected one workspace package named `{root_name}`"
        )));
    }
    let root = roots[0].clone();
    let package_count = metadata.packages.len();
    let packages = metadata
        .packages
        .into_iter()
        .map(|package| (package.id.clone(), package))
        .collect::<BTreeMap<_, _>>();
    if packages.len() != package_count {
        return Err(CliError::InvalidCargoMetadata(
            "duplicate Cargo package id".to_owned(),
        ));
    }
    let resolve = metadata
        .resolve
        .ok_or_else(|| CliError::InvalidCargoMetadata("missing resolve graph".to_owned()))?;
    let node_count = resolve.nodes.len();
    let nodes = resolve
        .nodes
        .into_iter()
        .map(|node| (node.id.clone(), node))
        .collect::<BTreeMap<_, _>>();
    if nodes.len() != node_count {
        return Err(CliError::InvalidCargoMetadata(
            "duplicate Cargo resolve-node id".to_owned(),
        ));
    }

    let mut queue = VecDeque::from([root.clone()]);
    let mut visited = BTreeSet::new();
    let mut graph = Vec::new();
    while let Some(package_id) = queue.pop_front() {
        if !visited.insert(package_id.clone()) {
            continue;
        }
        if visited.len() > MAX_TARGETS {
            return Err(CliError::InvalidCargoMetadata(
                "dependency graph exceeds its component bound".to_owned(),
            ));
        }
        let package = packages.get(&package_id).ok_or_else(|| {
            CliError::InvalidCargoMetadata(format!("missing package `{package_id}`"))
        })?;
        let node = nodes.get(&package_id).ok_or_else(|| {
            CliError::InvalidCargoMetadata(format!("missing resolve node `{package_id}`"))
        })?;
        let dependencies = node
            .deps
            .iter()
            .filter(|dependency| {
                dependency.dep_kinds.is_empty()
                    || dependency
                        .dep_kinds
                        .iter()
                        .any(|kind| kind.kind.as_deref() != Some("dev"))
            })
            .map(|dependency| dependency.pkg.clone())
            .collect::<BTreeSet<_>>();
        let locked_package = locked
            .get(&(
                package.name.clone(),
                package.version.clone(),
                package.source.clone(),
            ))
            .ok_or_else(|| {
                CliError::InvalidCargoMetadata(format!(
                    "package `{package_id}` is absent from Cargo.lock"
                ))
            })?;
        queue.extend(dependencies.iter().cloned());
        graph.push(CargoPackageNode {
            package_id,
            name: package.name.clone(),
            version: package.version.clone(),
            source: package.source.clone(),
            checksum_sha256: locked_package.checksum.clone(),
            dependencies: dependencies.into_iter().collect(),
        });
    }
    Ok((root, graph))
}
