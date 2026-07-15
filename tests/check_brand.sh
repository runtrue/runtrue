#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

legacy_pattern='[Aa]nvi''l|ANVI''L|Agent''Ops|agent''ops'

if git grep -n -I -E "$legacy_pattern" -- . ':!tests/check_brand.sh'; then
  echo "legacy public branding remains in tracked content" >&2
  exit 1
fi

legacy_paths=()
while IFS= read -r path; do
  if [[ -e "$path" ]]; then
    legacy_paths+=("$path")
  fi
done < <(git ls-files | grep -Ei "$legacy_pattern" || true)
if ((${#legacy_paths[@]})); then
  printf '%s\n' "${legacy_paths[@]}"
  echo "legacy public branding remains in tracked paths" >&2
  exit 1
fi

python3 - <<'PY'
import json
import subprocess

metadata = json.loads(
    subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        text=True,
    )
)
unexpected = sorted(
    package["name"]
    for package in metadata["packages"]
    if package["name"] != "runtrue" and not package["name"].startswith("runtrue-")
)
if unexpected:
    raise SystemExit(f"workspace packages outside the Runtrue namespace: {unexpected}")

binaries = {
    target["name"]
    for package in metadata["packages"]
    for target in package["targets"]
    if "bin" in target["kind"]
}
if "runtrue" not in binaries:
    raise SystemExit("the workspace does not provide the runtrue CLI binary")
PY

echo "Runtrue brand namespace validation passed"
