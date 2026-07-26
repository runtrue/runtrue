#!/usr/bin/env python3
"""Verify that core exposes only the neutral workflow-frontend contract."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


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


def workspace_manifests(root_manifest: dict) -> dict[str, Path]:
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


def require_no_concrete_frontend(root_manifest: dict, manifests: dict[str, Path]) -> None:
    workspace_dependencies = root_manifest["workspace"].get("dependencies", {})
    forbidden = sorted(
        name
        for name in workspace_dependencies
        if name.endswith("-gha-import") or name.endswith("-github-actions")
    )
    if forbidden:
        fail(f"core workspace selects concrete frontends: {', '.join(forbidden)}")

    for package_name, manifest_path in manifests.items():
        selected = sorted(
            name
            for name in dependencies(load(manifest_path))
            if name.endswith("-gha-import") or name.endswith("-github-actions")
        )
        if selected:
            fail(f"{package_name} selects concrete frontends: {', '.join(selected)}")

    for package in load(ROOT / "Cargo.lock").get("package", []):
        if package.get("name", "").endswith("-gha-import"):
            fail("Cargo.lock contains a concrete workflow frontend package")


def require_neutral_contract(manifests: dict[str, Path]) -> None:
    if "runtrue-workflow-frontend" not in manifests:
        fail("the generic workflow frontend contract is not a workspace member")

    allowed = {"runtrue-trusted-planner", "runtrue-server"}
    for package_name, manifest_path in manifests.items():
        names = dependencies(load(manifest_path))
        if "runtrue-workflow-frontend" in names and package_name not in allowed:
            fail(f"{manifest_path}: neutral frontend contract crosses into the kernel")

    planner = dependencies(load(manifests["runtrue-trusted-planner"]))
    if "runtrue-workflow-frontend" not in planner:
        fail("trusted planner must depend on the neutral frontend contract")

    contract_manifest = manifests["runtrue-workflow-frontend"]
    contract_dependencies = {
        name
        for name in dependencies(load(contract_manifest))
        if name.startswith("runtrue-")
    }
    if contract_dependencies != {"runtrue-model"}:
        fail("workflow frontend contract may depend only on the generic model crate")


def main() -> int:
    root_manifest = load(ROOT / "Cargo.toml")
    manifests = workspace_manifests(root_manifest)
    require_no_concrete_frontend(root_manifest, manifests)
    require_neutral_contract(manifests)
    print("core has no concrete workflow frontend dependency")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"frontend boundary check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
