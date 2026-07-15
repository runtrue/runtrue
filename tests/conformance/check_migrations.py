#!/usr/bin/env python3
"""Offline contract checks for immutable, coordinated SQLite migrations."""

from __future__ import annotations

import hashlib
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "crates" / "control-plane" / "migrations"
STORE = ROOT / "crates" / "control-plane" / "src" / "store" / "database.rs"
BACKUP_DATABASE = ROOT / "crates" / "backup" / "src" / "database" / "schema.rs"
SHIPPED_CHECKSUMS = ROOT / "tests" / "conformance" / "shipped-migration-sha256.txt"
MIGRATION_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


class MigrationFailure(Exception):
    pass


def read(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise MigrationFailure(f"cannot read {path.relative_to(ROOT)}: {error}") from error


def migration_inventory() -> list[tuple[int, pathlib.Path, str]]:
    inventory: list[tuple[int, pathlib.Path, str]] = []
    for path in sorted(MIGRATIONS.glob("*.sql")):
        match = MIGRATION_NAME.fullmatch(path.name)
        if match is None:
            raise MigrationFailure(f"invalid migration filename {path.name!r}")
        version = int(match.group(1))
        source = read(path)
        declared = re.findall(r"(?im)^\s*PRAGMA\s+user_version\s*=\s*(\d+)\s*;\s*$", source)
        if declared != [str(version)]:
            raise MigrationFailure(
                f"{path.relative_to(ROOT)} must declare exactly PRAGMA user_version = {version}"
            )
        inventory.append((version, path, source))
    if not inventory:
        raise MigrationFailure("no control-plane migrations found")
    actual = [version for version, _, _ in inventory]
    expected = list(range(1, actual[-1] + 1))
    if actual != expected:
        raise MigrationFailure(f"migration versions are not contiguous: {actual!r}")
    return inventory


def check_store_registration(inventory: list[tuple[int, pathlib.Path, str]]) -> None:
    source = read(STORE)
    for version, path, _ in inventory:
        declaration = re.compile(
            rf"pub\(super\) const MIGRATION_{version}: &str\s*=\s*"
            rf'include_str!\("\.\./\.\./migrations/{re.escape(path.name)}"\);'
        )
        if len(declaration.findall(source)) != 1:
            raise MigrationFailure(
                f"store must register migration {version} from {path.name} exactly once"
            )

    array_match = re.search(
        r"let migrations = \[\s*(.*?)\s*\];",
        source,
        flags=re.DOTALL,
    )
    if array_match is None:
        raise MigrationFailure("store migration execution array was not found")
    registered = [int(value) for value in re.findall(r"MIGRATION_(\d+)", array_match.group(1))]
    expected = [version for version, _, _ in inventory]
    if registered != expected:
        raise MigrationFailure(
            f"store migration execution order {registered!r} does not match {expected!r}"
        )


def check_backup_head(latest: int) -> None:
    source = read(BACKUP_DATABASE)
    matches = re.findall(r"(?m)^pub\(crate\) const CURRENT_SCHEMA_VERSION: u32 = (\d+);$", source)
    if matches != [str(latest)]:
        raise MigrationFailure(
            "backup CURRENT_SCHEMA_VERSION must exactly match the control-plane migration head "
            f"({latest})"
        )


def check_shipped_checksums(inventory: list[tuple[int, pathlib.Path, str]]) -> int:
    lines = [line for line in read(SHIPPED_CHECKSUMS).splitlines() if line]
    frozen: list[tuple[str, str]] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (\d{4}_[a-z0-9_]+\.sql)", line)
        if match is None:
            raise MigrationFailure("invalid shipped migration checksum manifest")
        frozen.append((match.group(1), match.group(2)))
    if not frozen:
        raise MigrationFailure("shipped migration checksum manifest is empty")
    expected_names = [path.name for _, path, _ in inventory[: len(frozen)]]
    actual_names = [name for _, name in frozen]
    if actual_names != expected_names:
        raise MigrationFailure(
            "shipped migration checksum manifest must be a contiguous inventory prefix"
        )
    paths = {path.name: path for _, path, _ in inventory}
    for expected_digest, name in frozen:
        try:
            contents = paths[name].read_bytes()
        except OSError as error:
            raise MigrationFailure(f"cannot hash shipped migration {name}: {error}") from error
        actual_digest = hashlib.sha256(contents).hexdigest()
        if actual_digest != expected_digest:
            raise MigrationFailure(
                f"shipped migration {name} changed; add a new migration instead"
            )
    return len(frozen)


def main() -> int:
    try:
        inventory = migration_inventory()
        check_store_registration(inventory)
        check_backup_head(inventory[-1][0])
        frozen = check_shipped_checksums(inventory)
    except MigrationFailure as error:
        print(f"migration conformance failed: {error}", file=sys.stderr)
        return 1
    print(
        "migration inventory is contiguous and coordinated: "
        f"versions=1..{inventory[-1][0]} shipped_frozen={frozen}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
