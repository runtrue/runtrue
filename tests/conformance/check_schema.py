#!/usr/bin/env python3
"""Offline structural checks for Runtrue's checked-in workflow schemas.

This intentionally uses only the Python standard library: release and
air-gapped builds can verify that schema JSON is unambiguous, every local
reference resolves, and security-relevant object shapes remain closed without
downloading a meta-schema or executing repository code.
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any, Iterable


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMAS = (
    ROOT / "schemas" / "reference" / "workflow.schema.json",
    ROOT / "schemas" / "workflow" / "v1.json",
)


class SchemaFailure(Exception):
    pass


def unique_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SchemaFailure(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def load_schema(path: pathlib.Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SchemaFailure(f"cannot read {path.relative_to(ROOT)}: {error}") from error
    if raw.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        raise SchemaFailure(f"{path.relative_to(ROOT)} must be BOM-free UTF-8")
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, SchemaFailure) as error:
        raise SchemaFailure(f"invalid {path.relative_to(ROOT)}: {error}") from error
    if not isinstance(value, dict):
        raise SchemaFailure(f"{path.relative_to(ROOT)} root must be an object")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    round_trip = json.loads(canonical, object_pairs_hook=unique_object)
    if round_trip != value:
        raise SchemaFailure(f"{path.relative_to(ROOT)} is not JSON round-trip stable")
    return value


def pointer(root: Any, reference: str, source: pathlib.Path) -> Any:
    if not reference.startswith("#/"):
        raise SchemaFailure(
            f"{source.relative_to(ROOT)} contains non-local $ref {reference!r}"
        )
    current = root
    for encoded in reference[2:].split("/"):
        part = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise SchemaFailure(
                f"{source.relative_to(ROOT)} contains unresolved $ref {reference!r}"
            )
    return current


def walk(value: Any, location: str = "#") -> Iterable[tuple[str, Any]]:
    yield location, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{location}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{location}/{index}")


def check_schema(path: pathlib.Path, schema: dict[str, Any]) -> tuple[int, int]:
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise SchemaFailure(
            f"{path.relative_to(ROOT)} must declare JSON Schema draft 2020-12"
        )
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise SchemaFailure(f"{path.relative_to(ROOT)} root shape must be a closed object")
    required = schema.get("required")
    if not isinstance(required, list) or "version" not in required or "jobs" not in required:
        raise SchemaFailure(
            f"{path.relative_to(ROOT)} must require workflow version and jobs"
        )

    references = 0
    closed_objects = 0
    for location, value in walk(schema):
        if not isinstance(value, dict):
            continue
        reference = value.get("$ref")
        if reference is not None:
            if not isinstance(reference, str):
                raise SchemaFailure(
                    f"{path.relative_to(ROOT)} {location}/$ref must be a string"
                )
            pointer(schema, reference, path)
            references += 1
        if value.get("type") == "object" and "properties" in value:
            properties = value["properties"]
            if not isinstance(properties, dict):
                raise SchemaFailure(
                    f"{path.relative_to(ROOT)} {location}/properties must be an object"
                )
            # Typed workflow objects must fail closed. Map-like objects use
            # patternProperties/additionalProperties and are intentionally open.
            if "patternProperties" not in value and not isinstance(
                value.get("additionalProperties"), dict
            ):
                if value.get("additionalProperties") is not False:
                    raise SchemaFailure(
                        f"{path.relative_to(ROOT)} {location} is a typed object but is not closed"
                    )
                closed_objects += 1
        for bound in ("maxLength", "maxItems", "maxProperties"):
            if bound in value and (
                not isinstance(value[bound], int) or value[bound] < 0
            ):
                raise SchemaFailure(
                    f"{path.relative_to(ROOT)} {location}/{bound} must be nonnegative"
                )
    if references == 0 or closed_objects == 0:
        raise SchemaFailure(
            f"{path.relative_to(ROOT)} must contain local references and closed object shapes"
        )
    return references, closed_objects


def main() -> int:
    summaries: list[str] = []
    try:
        for path in SCHEMAS:
            schema = load_schema(path)
            references, closed_objects = check_schema(path, schema)
            summaries.append(
                f"ok {path.relative_to(ROOT)} refs={references} closed_objects={closed_objects}"
            )
    except SchemaFailure as error:
        print(f"schema conformance failed: {error}", file=sys.stderr)
        return 1
    print("\n".join(summaries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
