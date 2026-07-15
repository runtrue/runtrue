#!/usr/bin/env bash
set -euo pipefail

example_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"${example_root}/scripts/build.sh"

artifact="${example_root}/dist/runtrue_wasi_0_3_hello.wasm"
digest="$(sha256sum "${artifact}" | cut -d ' ' -f 1)"
cp "${example_root}/fixtures/workflow.yaml" "${example_root}/dist/workflow.yaml"
sed "s/sha256:0000000000000000000000000000000000000000000000000000000000000000/sha256:${digest}/" \
  "${example_root}/fixtures/.runtrue.lock" \
  >"${example_root}/dist/.runtrue.lock"

cat <<EOF
Managed E2E bundle prepared under ${example_root}/dist:
  component: runtrue_wasi_0_3_hello.wasm
  workflow:  workflow.yaml
  lockfile:  .runtrue.lock
  digest:    sha256:${digest}

Sign and publish the component with the managed runner's trusted component
identity, then replace registry.example in the generated workflow and lockfile.
EOF
