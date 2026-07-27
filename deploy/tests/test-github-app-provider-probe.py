#!/usr/bin/env python3

import base64
import importlib.util
import json
import os
import pathlib
import socket
import struct
import tempfile
import threading
import time
import unittest

PROBE_PATH = pathlib.Path(__file__).parents[1] / "github-app-provider-probe.py"
SPEC = importlib.util.spec_from_file_location("github_app_provider_probe", PROBE_PATH)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def encode(value: dict) -> str:
    payload = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


class Provider:
    def __init__(self, path: str, response: dict):
        self.path = path
        self.response = response
        self.request = None
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(path)
        os.chmod(path, 0o600)
        self.listener.listen(1)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self) -> None:
        with self.listener.accept()[0] as connection:
            length = struct.unpack(">I", connection.recv(4))[0]
            self.request = json.loads(connection.recv(length))
            payload = json.dumps(self.response, separators=(",", ":")).encode()
            connection.sendall(struct.pack(">I", len(payload)) + payload)

    def close(self) -> None:
        self.thread.join()
        self.listener.close()


class ProbeTests(unittest.TestCase):
    def test_accepts_bounded_provider_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "provider.sock")
            now = int(time.time())
            jwt = ".".join(
                (
                    encode({"alg": "RS256", "typ": "JWT"}),
                    encode({"iat": now - 30, "exp": now + 540, "iss": 123}),
                    "signature",
                )
            )
            provider = Provider(path, {"version": 1, "jwt": jwt})
            try:
                PROBE.probe(path, 123, "provider://github-app/production")
            finally:
                provider.close()
            self.assertEqual(
                provider.request,
                {
                    "version": 1,
                    "operation": "github.app-jwt.mint",
                    "app_id": 123,
                    "credential_reference": "provider://github-app/production",
                    "now_unix_seconds": provider.request["now_unix_seconds"],
                },
            )

    def test_rejects_unexpected_response_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "provider.sock")
            provider = Provider(
                path, {"version": 1, "jwt": "header.claims.signature", "extra": True}
            )
            try:
                with self.assertRaisesRegex(ValueError, "invalid response object"):
                    PROBE.probe(path, 123, "provider://github-app/production")
            finally:
                provider.close()

    def test_rejects_insecure_socket_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "provider.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                os.chmod(path, 0o660)
                with self.assertRaisesRegex(ValueError, "mode must be exactly 0600"):
                    PROBE.validate_socket(path)


if __name__ == "__main__":
    unittest.main()
