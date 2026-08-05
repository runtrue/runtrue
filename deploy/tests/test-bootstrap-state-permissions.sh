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
cas_directory="${state}/server/blobs/cas/objects/sha256/aa"
install -d -m 0700 -- "$cas_directory"
install -m 0444 -- /dev/null "${cas_directory}/immutable-object"
image_layer="${state}/autoscaler/runtime-assets/oci/image-store/overlay/example/diff1"
install -d -m 0700 -- "$image_layer" "${image_layer}/usr/lib64"
ln -s -- usr/lib64 "${image_layer}/lib64"
if ((EUID == 0)); then
  chown -R "${runtime_uid}:${runtime_gid}" -- \
    "${state}/server/git-mirrors" "${state}/server/blobs" \
    "${state}/autoscaler"
fi

"${runtime[@]}" "${DEPLOY_DIR}/bootstrap.sh" \
  --state-dir "$state" --with-github-app --check-only >/dev/null

ln -s -- ../../../../../../../../etc "${image_layer}/escaping-link"
if ((EUID == 0)); then
  chown -h "${runtime_uid}:${runtime_gid}" -- "${image_layer}/escaping-link"
fi
if "${runtime[@]}" "${DEPLOY_DIR}/bootstrap.sh" \
  --state-dir "$state" --with-github-app --check-only \
  >"${TEST_ROOT}/escaping.out" 2>&1
then
  printf 'bootstrap state test: escaping OCI image-store symlink was accepted\n' >&2
  exit 1
fi
grep -q 'escaping OCI image-store symbolic link rejected' "${TEST_ROOT}/escaping.out"
rm -- "${image_layer}/escaping-link"

chmod 0464 -- "${cas_directory}/immutable-object"
if "${runtime[@]}" "${DEPLOY_DIR}/bootstrap.sh" \
  --state-dir "$state" --with-github-app --check-only \
  >"${TEST_ROOT}/unsafe.out" 2>&1
then
  printf 'bootstrap state test: group-writable CAS object was accepted\n' >&2
  exit 1
fi
grep -q 'managed file is not owner-readable or is writable by group/other' \
  "${TEST_ROOT}/unsafe.out"

printf 'Bootstrap immutable state permission validation passed\n'
