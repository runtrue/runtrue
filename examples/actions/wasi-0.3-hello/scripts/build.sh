#!/usr/bin/env bash
set -euo pipefail

example_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="${example_root}/dist"
mkdir -p "${dist_dir}"

cargo run \
  --locked \
  --manifest-path "${example_root}/Cargo.toml" \
  --quiet \
  --bin build-component \
  -- "${example_root}/component.wat" "${dist_dir}/runtrue_wasi_0_3_hello.wasm"

sha256sum "${dist_dir}/runtrue_wasi_0_3_hello.wasm" \
  >"${dist_dir}/runtrue_wasi_0_3_hello.wasm.sha256"
