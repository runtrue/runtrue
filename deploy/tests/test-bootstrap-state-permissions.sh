#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT HUP INT TERM

if ((EUID == 0)); then
  runtime_uid=10001
  runtime_gid=10001
else
  runtime_uid=$(id -u)
  runtime_gid=$(id -g)
fi
runtime=(env RUNTRUE_RUNTIME_UID="$runtime_uid" RUNTRUE_RUNTIME_GID="$runtime_gid")
state="${TEST_ROOT}/state"

"${runtime[@]}" "${DEPLOY_DIR}/bootstrap.sh" \
  --state-dir "$state" --with-github-app >/dev/null

pack_directory="${state}/server/git-mirrors/mirrors/example/repo.git/objects/pack"
install -d -m 0700 -- "$pack_directory"
install -m 0400 -- /dev/null "${pack_directory}/pack-test.pack"
if ((EUID == 0)); then
  chown -R "${runtime_uid}:${runtime_gid}" -- "${state}/server/git-mirrors"
fi

"${runtime[@]}" "${DEPLOY_DIR}/bootstrap.sh" \
  --state-dir "$state" --with-github-app --check-only >/dev/null

chmod 0440 -- "${pack_directory}/pack-test.pack"
if "${runtime[@]}" "${DEPLOY_DIR}/bootstrap.sh" \
  --state-dir "$state" --with-github-app --check-only \
  >"${TEST_ROOT}/unsafe.out" 2>&1
then
  printf 'bootstrap state test: group-readable Git pack was accepted\n' >&2
  exit 1
fi
grep -q 'Git mirror file is not owner-private and readable' "${TEST_ROOT}/unsafe.out"

printf 'Bootstrap Git mirror permission validation passed\n'
