#!/usr/bin/env bash
set -euo pipefail

example_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "${example_root}/../../.." && pwd)"

"${example_root}/scripts/build.sh"
(
  cd "${repo_root}"
  cargo test --locked -p runtrue-executor-wasm wasi_03_example_executes_end_to_end
)

runtrue_bin="${RUNTRUE_BIN:-}"
if [[ -z "${runtrue_bin}" && -x "${repo_root}/target/debug/runtrue" ]]; then
  runtrue_bin="${repo_root}/target/debug/runtrue"
elif [[ -z "${runtrue_bin}" ]] && command -v runtrue >/dev/null 2>&1; then
  runtrue_bin="$(command -v runtrue)"
fi

if [[ -n "${runtrue_bin}" ]]; then
  (
    cd "${example_root}/fixtures"
    "${runtrue_bin}" validate --workflow workflow.yaml --json >/dev/null
  )
  printf 'Runtrue workflow validation: ok\n'
else
  printf 'Runtrue workflow validation: skipped (set RUNTRUE_BIN)\n'
fi
