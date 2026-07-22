#!/usr/bin/env python3
"""Verify the external workflow frontend pin and the kernel boundary."""

from __future__ import annotations

import sys
import tomllib
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
FRONTEND_REPOSITORY = "https://github.com/runtrue/github-actions-frontend"
FRONTEND_REVISION = "1064f9efe2e5b3a4229a4aee2454b2b07e3294e6"
CORE_REPOSITORY = "https://github.com/runtrue/runtrue"
CORE_PATCHES = {
    "runtrue-compiler": "crates/compiler",
    "runtrue-lock": "crates/lock",
    "runtrue-model": "crates/model",
    "runtrue-workflow-ast": "crates/workflow-ast",
    "runtrue-workflow-frontend": "crates/workflow-frontend",
}


def load(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def dependencies(manifest: dict) -> dict:
    result: dict = {}
    for table in DEPENDENCY_TABLES:
        result.update(manifest.get(table, {}))
    for target in manifest.get("target", {}).values():
        for table in DEPENDENCY_TABLES:
            result.update(target.get(table, {}))
    return result


def fail(message: str) -> None:
    raise AssertionError(message)


def require_optional_feature(manifest_path: Path) -> None:
    manifest = load(manifest_path)
    spec = manifest.get("dependencies", {}).get("runtrue-gha-import")
    if not isinstance(spec, dict) or spec.get("optional") is not True:
        fail(f"{manifest_path}: runtrue-gha-import must be optional")
    feature = manifest.get("features", {}).get("github-actions", [])
    if "dep:runtrue-gha-import" not in feature:
        fail(f"{manifest_path}: github-actions must select only the optional adapter")


def workspace_manifests(root_manifest: dict) -> dict[str, Path]:
    """Index workspace packages by Cargo package name, independent of layout."""

    manifests: dict[str, Path] = {}
    for member in root_manifest["workspace"]["members"]:
        matches = sorted(ROOT.glob(member))
        if not matches:
            fail(f"workspace member does not exist: {member}")
        for package_dir in matches:
            manifest_path = package_dir / "Cargo.toml"
            if not manifest_path.is_file():
                fail(f"workspace member has no Cargo.toml: {package_dir}")
            package_name = load(manifest_path).get("package", {}).get("name")
            if not isinstance(package_name, str):
                fail(f"workspace manifest has no package name: {manifest_path}")
            if package_name in manifests:
                fail(f"duplicate workspace package name: {package_name}")
            manifests[package_name] = manifest_path
    return manifests


def require_external_frontend(root_manifest: dict) -> None:
    frontend = root_manifest["workspace"]["dependencies"].get("runtrue-gha-import")
    expected = {"git": FRONTEND_REPOSITORY, "rev": FRONTEND_REVISION}
    if frontend != expected:
        fail(
            "runtrue-gha-import must use only the exact reviewed HTTPS git revision "
            f"{FRONTEND_REPOSITORY}@{FRONTEND_REVISION}"
        )

    for old_tree in (ROOT / "crates/gha-import", ROOT / "frontends/github-actions"):
        if old_tree.exists():
            fail(f"local GitHub Actions frontend tree must be absent: {old_tree}")

    for manifest_path in ROOT.rglob("Cargo.toml"):
        if ".git" in manifest_path.parts or "target" in manifest_path.parts:
            continue
        if load(manifest_path).get("package", {}).get("name") == "runtrue-gha-import":
            fail(f"local runtrue-gha-import package must be absent: {manifest_path}")


def require_core_patches(root_manifest: dict) -> None:
    expected = {name: {"path": path} for name, path in CORE_PATCHES.items()}
    actual = root_manifest.get("patch", {}).get(CORE_REPOSITORY)
    if actual != expected:
        fail(
            f"the {CORE_REPOSITORY} patch table must contain "
            "the exact five local mappings"
        )

    for name, path in CORE_PATCHES.items():
        workspace_spec = root_manifest["workspace"]["dependencies"].get(name)
        if workspace_spec != {"path": path}:
            fail(f"workspace dependency {name} must use the same local path as its patch")

    for repository, patches in root_manifest.get("patch", {}).items():
        if repository == CORE_REPOSITORY:
            continue
        leaked = sorted(set(patches) & CORE_PATCHES.keys())
        if leaked:
            fail(f"core packages are patched from an unexpected source: {', '.join(leaked)}")


def require_lockfile() -> None:
    lockfile = load(ROOT / "Cargo.lock")
    packages = lockfile.get("package", [])
    frontend_packages = [
        package for package in packages if package.get("name") == "runtrue-gha-import"
    ]
    if len(frontend_packages) != 1:
        fail("Cargo.lock must contain exactly one runtrue-gha-import package")

    expected_source = (
        f"git+{FRONTEND_REPOSITORY}?rev={FRONTEND_REVISION}#{FRONTEND_REVISION}"
    )
    frontend = frontend_packages[0]
    if frontend.get("source") != expected_source:
        fail("Cargo.lock frontend source does not match the exact manifest repository/revision")

    frontend_core_dependencies = {
        dependency
        for dependency in frontend.get("dependencies", [])
        if dependency.startswith("runtrue-")
    }
    if frontend_core_dependencies != set(CORE_PATCHES):
        fail("locked frontend must consume exactly the five locally patched core packages")

    core_identities: dict[str, list[dict]] = defaultdict(list)
    for package in packages:
        name = package.get("name", "")
        if name.startswith("runtrue-") and name != "runtrue-gha-import":
            core_identities[name].append(package)

    duplicates = sorted(
        name for name, entries in core_identities.items() if len(entries) != 1
    )
    if duplicates:
        fail(f"Cargo.lock contains duplicate core package identities: {', '.join(duplicates)}")

    git_sourced = sorted(
        name
        for name, entries in core_identities.items()
        if entries[0].get("source", "").startswith("git+")
    )
    if git_sourced:
        fail(f"core packages resolved from git instead of local patches: {', '.join(git_sourced)}")


def main() -> int:
    root_manifest = load(ROOT / "Cargo.toml")
    package_manifests = workspace_manifests(root_manifest)
    if "runtrue-workflow-frontend" not in package_manifests:
        fail("the generic workflow frontend contract is not a workspace member")
    if "runtrue-gha-import" in package_manifests:
        fail("the external GitHub Actions frontend must not be a workspace member")

    require_external_frontend(root_manifest)
    require_core_patches(root_manifest)
    require_lockfile()

    gha_allowed = {"runtrue-cli", "runtrue-server"}
    frontend_contract_allowed = {
        "runtrue-trusted-planner",
        "runtrue-server",
    }

    for package_name, manifest_path in package_manifests.items():
        names = dependencies(load(manifest_path))
        if "runtrue-gha-import" in names and package_name not in gha_allowed:
            fail(f"{manifest_path}: GitHub frontend dependency crosses the composition boundary")
        if (
            "runtrue-workflow-frontend" in names
            and package_name not in frontend_contract_allowed
        ):
            fail(f"{manifest_path}: frontend contract dependency crosses into the kernel")

    planner = dependencies(load(package_manifests["runtrue-trusted-planner"]))
    if "runtrue-workflow-frontend" not in planner or "runtrue-gha-import" in planner:
        fail("trusted planner must depend on the neutral contract, never the GitHub adapter")

    contract_manifest = package_manifests["runtrue-workflow-frontend"]
    contract_runtrue_dependencies = {
        name
        for name in dependencies(load(contract_manifest))
        if name.startswith("runtrue-")
    }
    if contract_runtrue_dependencies != {"runtrue-model"}:
        fail("workflow frontend contract may depend only on the generic model crate")

    require_optional_feature(package_manifests["runtrue-cli"])
    require_optional_feature(package_manifests["runtrue-server"])
    print("external workflow frontend pin and boundary are valid")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"frontend boundary check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
