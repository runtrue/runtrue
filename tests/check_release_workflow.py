#!/usr/bin/env python3
"""Fail closed when the runtime-image release boundary is weakened."""

from pathlib import Path


workflow = Path(".github/workflows/publish-images.yml").read_text()


def require(fragment: str) -> None:
    if fragment not in workflow:
        raise SystemExit(f"missing required release-workflow fragment: {fragment!r}")


def forbid(fragment: str, section: str) -> None:
    if fragment in section:
        raise SystemExit(f"forbidden release-workflow fragment: {fragment!r}")


require('      - "v*"')
require("  pull_request:")
require("            runner: ubuntu-24.04")
require("            runner: ubuntu-24.04-arm")
require("            platform: linux/amd64")
require("            platform: linux/arm64")
require("          platforms: ${{ matrix.platform }}")
require("          push: false")
require("    environment: release")
require("      packages: write")
require("      attestations: write")
require("      id-token: write")
require("            [[ \"$RELEASE_TAG\" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]")

if workflow.count("jobs:\n") != 1 or workflow.count("\n  promote:\n") != 1:
    raise SystemExit("release workflow must contain one distinct promotion job")

trigger, jobs = workflow.split("\njobs:\n", 1)
build, promote = jobs.split("\n  promote:\n", 1)

forbid("workflow_dispatch:", trigger)
forbid("branches:", trigger)
forbid("packages: write", trigger)
forbid("attestations: write", trigger)
forbid("id-token: write", trigger)
forbid("packages: write", build)
forbid("attestations: write", build)
forbid("id-token: write", build)
forbid("docker/login-action", build)
forbid("secrets.GITHUB_TOKEN", build)
forbid("push: true", build)
forbid("cache-to:", build)
forbid("setup-qemu-action", build)

for fragment in (
    "needs: build",
    "environment: release",
    "docker/login-action",
    "secrets.GITHUB_TOKEN",
    "github.event_name == 'push'",
    "github.repository_visibility == 'public'",
    "vars.RUNTIME_IMAGE_PROMOTION_ENABLED == 'true'",
):
    if fragment not in promote:
        raise SystemExit(f"promotion boundary missing: {fragment!r}")

print("release workflow boundary is valid")
