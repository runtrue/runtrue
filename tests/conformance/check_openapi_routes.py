#!/usr/bin/env python3
"""Fail when the HTTP router and checked-in OpenAPI route inventory diverge.

The check is deliberately offline and uses only the Python standard library.
It compares paths and verbs, normalizing Rust ``:parameter`` segments and
OpenAPI ``{parameter}`` segments without treating their names as API behavior.
"""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
ROUTER_ROOT = ROOT / "bins" / "server" / "src" / "app"
OPENAPI = ROOT / "api" / "openapi.yaml"
HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})


class InventoryFailure(Exception):
    pass


def normalize_path(path: str) -> str:
    if not path.startswith("/"):
        raise InventoryFailure(f"route does not start with '/': {path!r}")
    segments = []
    for segment in path.split("/"):
        if segment.startswith(":") or (
            segment.startswith("{") and segment.endswith("}")
        ):
            segments.append("{}")
        else:
            segments.append(segment)
    return "/".join(segments)


def rust_route_calls(source: str, source_path: pathlib.Path) -> list[str]:
    calls: list[str] = []
    position = 0
    marker = ".route("
    while True:
        start = source.find(marker, position)
        if start < 0:
            return calls
        opening = start + len(marker) - 1
        depth = 0
        quote: str | None = None
        escaped = False
        index = opening
        while index < len(source):
            character = source[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
            elif character in {'"', "'"}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    calls.append(source[opening + 1 : index])
                    position = index + 1
                    break
            index += 1
        else:
            raise InventoryFailure(
                f"unterminated .route(...) call in {source_path.relative_to(ROOT)}"
            )


def router_inventory() -> dict[tuple[str, str], str]:
    sources = sorted(ROUTER_ROOT.rglob("*.rs"))
    if not sources:
        raise InventoryFailure(
            f"no Rust router sources under {ROUTER_ROOT.relative_to(ROOT)}"
        )
    inventory: dict[tuple[str, str], str] = {}
    for source_path in sources:
        try:
            source = source_path.read_text(encoding="utf-8")
        except OSError as error:
            raise InventoryFailure(
                f"cannot read {source_path.relative_to(ROOT)}: {error}"
            ) from error
        for call in rust_route_calls(source, source_path):
            path_match = re.match(r'\s*"([^"\\]+)"\s*,', call)
            if path_match is None:
                raise InventoryFailure(f"route path is not a static string: {call[:80]!r}")
            path = path_match.group(1)
            handler = call[path_match.end() :]
            methods = {
                match.group(1)
                for match in re.finditer(
                    r"(?<![A-Za-z0-9_])(get|post|put|patch|delete)\s*\(", handler
                )
            }
            if not methods:
                raise InventoryFailure(f"route {path!r} has no recognized HTTP method")
            for method in methods:
                key = (normalize_path(path), method)
                if key in inventory:
                    raise InventoryFailure(
                        f"duplicate normalized router route {method.upper()} {path}"
                    )
                inventory[key] = path
    return inventory


def openapi_inventory() -> dict[tuple[str, str], str]:
    try:
        lines = OPENAPI.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise InventoryFailure(f"cannot read {OPENAPI.relative_to(ROOT)}: {error}") from error
    inventory: dict[tuple[str, str], str] = {}
    current_path: str | None = None
    in_paths = False
    for line in lines:
        if line == "paths:":
            in_paths = True
            continue
        if in_paths and line == "components:":
            break
        if not in_paths:
            continue
        path_match = re.fullmatch(r"  (/[^:]*):", line)
        if path_match is not None:
            current_path = path_match.group(1)
            continue
        method_match = re.fullmatch(r"    (get|post|put|patch|delete):", line)
        if method_match is None:
            continue
        if current_path is None:
            raise InventoryFailure("OpenAPI method appeared before its path")
        method = method_match.group(1)
        key = (normalize_path(current_path), method)
        if key in inventory:
            raise InventoryFailure(
                f"duplicate normalized OpenAPI route {method.upper()} {current_path}"
            )
        inventory[key] = current_path
    return inventory


def render(key: tuple[str, str], source_path: str) -> str:
    _, method = key
    return f"{method.upper()} {source_path}"


def main() -> int:
    try:
        router = router_inventory()
        specification = openapi_inventory()
    except InventoryFailure as error:
        print(f"OpenAPI route conformance failed: {error}", file=sys.stderr)
        return 1

    missing = sorted(router.keys() - specification.keys())
    stale = sorted(specification.keys() - router.keys())
    if missing or stale:
        print("OpenAPI route conformance failed:", file=sys.stderr)
        for key in missing:
            print(f"  undocumented router route: {render(key, router[key])}", file=sys.stderr)
        for key in stale:
            print(
                f"  OpenAPI route has no router implementation: {render(key, specification[key])}",
                file=sys.stderr,
            )
        return 1

    verbs = sorted({method for _, method in router})
    if not verbs or not set(verbs).issubset(HTTP_METHODS):
        print("OpenAPI route conformance failed: invalid verb inventory", file=sys.stderr)
        return 1
    print(f"OpenAPI route inventory matches router: routes={len(router)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
