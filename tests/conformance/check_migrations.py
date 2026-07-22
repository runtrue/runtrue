#!/usr/bin/env python3
"""Offline conformance checks for the unified migration catalog and frozen histories."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "crates" / "control-plane" / "migrations"
POSTGRES_MIGRATIONS = MIGRATIONS / "postgres"
UNIFIED_MIGRATIONS = MIGRATIONS / "unified"
STORE = ROOT / "crates" / "control-plane" / "src" / "store" / "database.rs"
PERSISTENCE = ROOT / "crates" / "control-plane" / "src" / "persistence.rs"
CONTROL_PLANE_SOURCE = ROOT / "crates" / "control-plane" / "src"
BACKUP_DATABASE = ROOT / "crates" / "backup" / "src" / "database" / "schema.rs"
SQLITE_CHECKSUMS = ROOT / "tests" / "conformance" / "shipped-migration-sha256.txt"
POSTGRES_CHECKSUMS = (
    ROOT / "tests" / "conformance" / "shipped-postgres-migration-sha256.txt"
)
UNIFIED_CHECKSUMS = (
    ROOT / "tests" / "conformance" / "shipped-unified-migration-sha256.txt"
)
MIGRATION_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")
LOGICAL_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+$")
HISTORY_DIGEST_DOMAIN = b"runtrue.migration.legacy-history.v1\0"


class MigrationFailure(Exception):
    pass


def read(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise MigrationFailure(f"cannot read {path.relative_to(ROOT)}: {error}") from error


def inventory(directory: pathlib.Path, require_pragma: bool) -> list[tuple[int, pathlib.Path, str]]:
    result: list[tuple[int, pathlib.Path, str]] = []
    for path in sorted(directory.glob("*.sql")):
        match = MIGRATION_NAME.fullmatch(path.name)
        if match is None:
            raise MigrationFailure(f"invalid migration filename {path.name!r}")
        version = int(match.group(1))
        source = read(path)
        if require_pragma:
            declared = re.findall(
                r"(?im)^\s*PRAGMA\s+user_version\s*=\s*(\d+)\s*;\s*$", source
            )
            if declared != [str(version)]:
                raise MigrationFailure(
                    f"{path.relative_to(ROOT)} must declare exactly "
                    f"PRAGMA user_version = {version}"
                )
        result.append((version, path, source))
    actual = [version for version, _, _ in result]
    if not actual or actual != list(range(1, actual[-1] + 1)):
        raise MigrationFailure(f"{directory.relative_to(ROOT)} history is not contiguous")
    return result


def check_sqlite_registration(items: list[tuple[int, pathlib.Path, str]]) -> None:
    source = read(STORE)
    for version, path, _ in items:
        declaration = re.compile(
            rf"MIGRATION_{version}: &str\s*=\s*"
            rf'include_str!\("\.\./\.\./migrations/{re.escape(path.name)}"\);'
        )
        if len(declaration.findall(source)) != 1:
            raise MigrationFailure(f"SQLite migration {path.name} is not registered exactly once")
    array = re.search(
        r"const SQLITE_LEGACY_MIGRATIONS:[^=]+?=\s*\[(.*?)\];", source, re.DOTALL
    )
    if array is None:
        raise MigrationFailure("SQLite frozen migration array was not found")
    registered = [int(value) for value in re.findall(r"MIGRATION_(\d+)", array.group(1))]
    if registered != [version for version, _, _ in items]:
        raise MigrationFailure("SQLite frozen migration array is reordered or incomplete")


def check_postgres_registration(items: list[tuple[int, pathlib.Path, str]]) -> None:
    source = read(PERSISTENCE)
    array = re.search(
        r"const POSTGRES_MIGRATIONS:[^=]+?=\s*\[(.*?)\];", source, re.DOTALL
    )
    if array is None:
        raise MigrationFailure("PostgreSQL frozen migration array was not found")
    registered = [
        (int(version), int(symbol))
        for version, symbol in re.findall(
            r"\((\d+),\s*POSTGRES_MIGRATION_(\d+)\)", array.group(1)
        )
    ]
    expected = [(version, version) for version, _, _ in items]
    if registered != expected:
        raise MigrationFailure("PostgreSQL frozen migration array is reordered or incomplete")
    rust = "\n".join(read(path) for path in CONTROL_PLANE_SOURCE.rglob("*.rs"))
    for _, path, _ in items:
        if len(re.findall(rf'include_str!\("[^"]*{re.escape(path.name)}"\)', rust)) != 1:
            raise MigrationFailure(
                f"PostgreSQL migration {path.name} is not registered exactly once"
            )


def check_checksum_manifest(
    items: list[tuple[int, pathlib.Path, str]], manifest: pathlib.Path
) -> None:
    lines = [line for line in read(manifest).splitlines() if line]
    frozen: list[tuple[str, str]] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (\d{4}_[a-z0-9_]+\.sql)", line)
        if match is None:
            raise MigrationFailure(f"invalid checksum line in {manifest.relative_to(ROOT)}")
        frozen.append((match.group(1), match.group(2)))
    if [name for _, name in frozen] != [path.name for _, path, _ in items]:
        raise MigrationFailure(f"{manifest.relative_to(ROOT)} must freeze the complete history")
    for (expected, _), (_, path, _) in zip(frozen, items, strict=True):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise MigrationFailure(f"shipped migration {path.name} changed; add a new migration")


def history_digest(backend: str, items: list[tuple[int, pathlib.Path, str]]) -> str:
    digest = hashlib.sha256()
    digest.update(HISTORY_DIGEST_DOMAIN)
    encoded_backend = backend.encode()
    digest.update(len(encoded_backend).to_bytes(8, "big"))
    digest.update(encoded_backend)
    for version, path, _ in items:
        contents = path.read_bytes()
        digest.update(version.to_bytes(4, "big"))
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def load_json(path: pathlib.Path) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise MigrationFailure(f"duplicate JSON key {key!r} in {path.relative_to(ROOT)}")
            result[key] = value
        return result

    try:
        value = json.loads(read(path), object_pairs_hook=unique)
    except json.JSONDecodeError as error:
        raise MigrationFailure(f"invalid JSON in {path.relative_to(ROOT)}: {error}") from error
    if not isinstance(value, dict):
        raise MigrationFailure(f"{path.relative_to(ROOT)} must contain one JSON object")
    return value


def check_unified_catalog(
    sqlite: list[tuple[int, pathlib.Path, str]],
    postgres: list[tuple[int, pathlib.Path, str]],
) -> int:
    directories = sorted(path for path in UNIFIED_MIGRATIONS.iterdir() if path.is_dir())
    sequences: list[int] = []
    migration_ids: set[str] = set()
    for path in directories:
        match = LOGICAL_NAME.fullmatch(path.name)
        if match is None:
            raise MigrationFailure(f"invalid logical migration directory {path.name!r}")
        sequence = int(match.group(1))
        sequences.append(sequence)
        definition_path = path / "definition.json"
        definition = load_json(definition_path)
        required_definition = {
            "sequence",
            "migration_id",
            "logical_schema_generation",
            "purpose",
            "preconditions",
            "postconditions",
        }
        if set(definition) != required_definition or definition["sequence"] != sequence:
            raise MigrationFailure(f"invalid shared definition in {path.relative_to(ROOT)}")
        migration_id = definition["migration_id"]
        if not isinstance(migration_id, str) or not migration_id or migration_id in migration_ids:
            raise MigrationFailure(f"invalid or duplicate migration ID in {path.relative_to(ROOT)}")
        migration_ids.add(migration_id)
        for field in ("preconditions", "postconditions"):
            values = definition[field]
            if not isinstance(values, list) or not values or not all(
                isinstance(value, str) and value for value in values
            ):
                raise MigrationFailure(f"{field} must be a non-empty string list")
        for backend, items in (("sqlite", sqlite), ("postgres", postgres)):
            payload = load_json(path / f"{backend}.json")
            expected_fields = (
                {"backend", "legacy_lineage", "legacy_head", "legacy_history_sha256", "schema_contract"}
                if sequence == 1
                else {"backend", "sql", "trust_sql", "post_sql"}
            )
            if set(payload) != expected_fields or payload["backend"] != backend:
                raise MigrationFailure(f"invalid {backend} payload in {path.relative_to(ROOT)}")
            if sequence == 1 and (
                payload["legacy_head"] != items[-1][0]
                or payload["legacy_history_sha256"] != history_digest(backend, items)
            ):
                raise MigrationFailure(f"{backend} baseline does not bind the frozen history")
            if sequence > 1 and (
                not isinstance(payload["sql"], str)
                or not payload["sql"].strip()
                or not isinstance(payload["post_sql"], str)
                or not payload["post_sql"].strip()
                or not isinstance(payload["trust_sql"], str)
                or not payload["trust_sql"].strip()
            ):
                raise MigrationFailure(f"{backend} forward migration has no SQL")
    if sequences != list(range(1, len(sequences) + 1)):
        raise MigrationFailure("unified logical migration sequences are not contiguous")
    if not directories:
        raise MigrationFailure("unified migration catalog is empty")
    return len(directories)


def check_unified_checksum_manifest() -> None:
    expected_paths = [
        path
        for directory in sorted(path for path in UNIFIED_MIGRATIONS.iterdir() if path.is_dir())
        for path in (directory / "definition.json", directory / "postgres.json", directory / "sqlite.json")
    ]
    frozen: list[tuple[str, str]] = []
    for line in (line for line in read(UNIFIED_CHECKSUMS).splitlines() if line):
        match = re.fullmatch(
            r"([0-9a-f]{64})  (\d{4}_[a-z0-9_]+/(?:definition|postgres|sqlite)\.json)",
            line,
        )
        if match is None:
            raise MigrationFailure("invalid unified migration checksum manifest")
        frozen.append((match.group(1), match.group(2)))
    expected_names = [str(path.relative_to(UNIFIED_MIGRATIONS)) for path in expected_paths]
    if [name for _, name in frozen] != expected_names:
        raise MigrationFailure("unified checksum manifest must freeze the complete catalog")
    for (expected_digest, _), path in zip(frozen, expected_paths, strict=True):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
            raise MigrationFailure(
                f"shipped logical migration {path.relative_to(UNIFIED_MIGRATIONS)} changed; "
                "add a new forward migration"
            )


def check_backup_head(sqlite_head: int) -> None:
    source = read(BACKUP_DATABASE)
    matches = re.findall(
        r"(?m)^pub\(crate\) const CURRENT_SCHEMA_VERSION: u32 = (\d+);$", source
    )
    if matches != [str(sqlite_head)]:
        raise MigrationFailure("backup physical schema head does not match SQLite legacy head")


def main() -> int:
    try:
        sqlite = inventory(MIGRATIONS, require_pragma=True)
        postgres = inventory(POSTGRES_MIGRATIONS, require_pragma=False)
        check_sqlite_registration(sqlite)
        check_postgres_registration(postgres)
        check_checksum_manifest(sqlite, SQLITE_CHECKSUMS)
        check_checksum_manifest(postgres, POSTGRES_CHECKSUMS)
        logical = check_unified_catalog(sqlite, postgres)
        check_unified_checksum_manifest()
        check_backup_head(sqlite[-1][0])
    except (MigrationFailure, OSError) as error:
        print(f"migration conformance failed: {error}", file=sys.stderr)
        return 1
    print(
        "migration histories and unified catalog are coordinated: "
        f"sqlite=1..{sqlite[-1][0]} postgres=1..{postgres[-1][0]} logical=1..{logical}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
