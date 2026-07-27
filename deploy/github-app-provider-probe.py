#!/usr/bin/env python3
"""Probe a Runtrue GitHub App JWT provider without reading its private key."""

import argparse
import base64
import json
import os
import socket
import stat
import struct
import sys
import time
from typing import NoReturn

MAX_FRAME_BYTES = 16 * 1024
TIMEOUT_SECONDS = 5


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def strict_object(payload: bytes) -> dict:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for name, value in pairs:
            if name in result:
                fail(f"duplicate JSON field: {name}")
            result[name] = value
        return result

    value = json.loads(payload, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        fail("response is not a JSON object")
    return value


def decode_segment(segment: str, label: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    try:
        return strict_object(
            base64.b64decode(segment + padding, altchars=b"-_", validate=True)
        )
    except (ValueError, json.JSONDecodeError) as error:
        fail(f"invalid JWT {label}: {error}")


def validate_socket(path: str) -> None:
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        fail("socket path must be absolute and canonical")
    metadata = os.lstat(path)
    if not stat.S_ISSOCK(metadata.st_mode):
        fail("provider path is not a Unix socket")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        fail("provider socket mode must be exactly 0600")
    if metadata.st_uid not in (0, os.geteuid()):
        fail("provider socket must be owned by root or the probing uid")


def read_exact(connection: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connection.recv(length - len(chunks))
        if not chunk:
            fail("provider closed an incomplete response")
        chunks.extend(chunk)
    return bytes(chunks)


def probe(path: str, app_id: int, credential_reference: str) -> None:
    validate_socket(path)
    now = int(time.time())
    request = json.dumps(
        {
            "version": 1,
            "operation": "github.app-jwt.mint",
            "app_id": app_id,
            "credential_reference": credential_reference,
            "now_unix_seconds": now,
        },
        separators=(",", ":"),
    ).encode()
    if not 0 < len(request) <= MAX_FRAME_BYTES:
        fail("request exceeds the protocol frame limit")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(TIMEOUT_SECONDS)
        connection.connect(path)
        connection.sendall(struct.pack(">I", len(request)) + request)
        response_length = struct.unpack(">I", read_exact(connection, 4))[0]
        if not 0 < response_length <= MAX_FRAME_BYTES:
            fail("provider returned an invalid frame length")
        response = strict_object(read_exact(connection, response_length))

    if set(response) != {"version", "jwt"} or response["version"] != 1:
        fail("provider returned an invalid response object")
    jwt = response["jwt"]
    if not isinstance(jwt, str):
        fail("provider returned a non-string JWT")
    parts = jwt.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        fail("provider returned a malformed JWT")
    header = decode_segment(parts[0], "header")
    claims = decode_segment(parts[1], "claims")
    if set(header) - {"alg", "typ"} or header.get("alg") != "RS256":
        fail("provider JWT must use RS256")
    if header.get("typ", "JWT") != "JWT":
        fail("provider JWT has an invalid typ")
    if set(claims) != {"iat", "exp", "iss"}:
        fail("provider JWT must contain exactly iat, exp, and iss")
    try:
        if isinstance(claims["iss"], bool):
            fail("provider JWT issuer is not the configured App id")
        issuer = int(claims["iss"])
    except (TypeError, ValueError):
        fail("provider JWT issuer is not the configured App id")
    issued_at = claims["iat"]
    expires_at = claims["exp"]
    if (
        issuer != app_id
        or not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or issued_at > now
        or issued_at + 60 < now
        or expires_at <= now + 30
        or expires_at > issued_at + 600
    ):
        fail("provider JWT claims are outside Runtrue's accepted bounds")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--app-id", required=True, type=int)
    parser.add_argument("--credential-reference", required=True)
    arguments = parser.parse_args()
    if arguments.app_id <= 0:
        parser.error("--app-id must be positive")
    try:
        probe(arguments.socket, arguments.app_id, arguments.credential_reference)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"github-app-provider probe: {error}", file=sys.stderr)
        return 1
    print("github-app-provider probe: ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
