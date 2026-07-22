#!/bin/sh
# Fail-fast verification for the replaceable workflow-frontend boundary.

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

python3 tests/conformance/check_frontend_boundary.py
cargo test --locked \
  -p runtrue-workflow-frontend \
  -p runtrue-trusted-planner
cargo check --locked \
  -p runtrue-server \
  -p runtrue-cli \
  --all-targets
cargo check --locked \
  -p runtrue-server \
  -p runtrue-cli \
  --all-targets \
  --no-default-features
