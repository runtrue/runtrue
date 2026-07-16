#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly ROOT_DIR="$(cd -- "${DEPLOY_DIR}/.." && pwd -P)"
TEMPORARY_ROOT=''

cleanup() {
  if [[ -n "$TEMPORARY_ROOT" && -d "$TEMPORARY_ROOT" && ! -L "$TEMPORARY_ROOT" ]]; then
    rm -rf -- "$TEMPORARY_ROOT"
  fi
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'deploy validation: %s\n' "$*" >&2
  exit 1
}

bash -n "${DEPLOY_DIR}/bootstrap.sh"
bash -n "${DEPLOY_DIR}/healthcheck.sh"

command -v go >/dev/null 2>&1 || fail 'Go is required to verify the GitHub App signer'
(
  cd "${ROOT_DIR}/components/github-signer"
  go test ./...
)

[[ "$(stat -c '%a' "${DEPLOY_DIR}/bootstrap.sh")" == 700 ]] ||
  fail 'bootstrap.sh must have mode 0700'
[[ "$(stat -c '%a' "${DEPLOY_DIR}/healthcheck.sh")" == 555 ]] ||
  fail 'healthcheck.sh must have mode 0555'

grep -q '127.0.0.1:${RUNTRUE_HTTP_PORT:-8080}:8080' "${DEPLOY_DIR}/compose.yml" ||
  fail 'the HTTP publication is not explicitly loopback-only'
grep -q 'read_only: true' "${DEPLOY_DIR}/compose.yml" || fail 'read-only root is missing'
grep -q 'no-new-privileges:true' "${DEPLOY_DIR}/compose.yml" ||
  fail 'no-new-privileges is missing'
grep -q 'cap_drop:' "${DEPLOY_DIR}/compose.yml" || fail 'capability removal is missing'
grep -q 'internal: true' "${DEPLOY_DIR}/compose.yml" || fail 'internal network is missing'
grep -q 'target: /var/lib/runtrue/restores' "${DEPLOY_DIR}/compose.yml" ||
  fail 'the backup tool has no dedicated restore target mount'
grep -q 'source: "${RUNTRUE_STATE_DIR:?run deploy/bootstrap.sh first}/restores"' \
  "${DEPLOY_DIR}/compose.yml" || fail 'the restore target is not backed by managed host state'
grep -q 'source: "${RUNTRUE_STATE_DIR:?run deploy/bootstrap.sh first}/keys/security.key"' \
  "${DEPLOY_DIR}/compose.yml" || fail 'the installation key is not a separate file bind'
grep -q 'source: "${RUNTRUE_STATE_DIR:?run deploy/bootstrap.sh first}/tls/runner-ca.pem"' \
  "${DEPLOY_DIR}/compose.runner-tls.yml" ||
  fail 'runner trust is not a file-scoped public CA bind'
grep -Fq 'RUNTRUE_GIT_MIRROR_ROOT: /var/lib/runtrue/server/git-mirrors' \
  "${DEPLOY_DIR}/compose.github-app.yml" ||
  fail 'GitHub Compose overlay does not use the private persisted mirror root'
grep -Fq 'RUNTRUE_GITHUB_APP_JWT_PROVIDER_SOCKET: /run/runtrue-github-signer.sock' \
  "${DEPLOY_DIR}/compose.github-app.yml" ||
  fail 'GitHub Compose overlay does not use the fixed signer socket target'
grep -Fq 'create_host_path: false' "${DEPLOY_DIR}/compose.github-app.yml" ||
  fail 'GitHub signer bind may create a substitute host path'
grep -Fq 'scm-egress:' "${DEPLOY_DIR}/compose.github-app.yml" ||
  fail 'GitHub Compose overlay has no explicit outbound SCM network'
grep -Fq 'git --version' "${DEPLOY_DIR}/Containerfile.server" ||
  fail 'server image does not verify the runtime Git client'
grep -Fq 'RUNTRUE_DATA_ROOT: /var/lib/runtrue/server/blobs' "${DEPLOY_DIR}/compose.yml" ||
  fail 'the server does not use its authoritative mounted blob directory'
[[ "$(grep -Ec 'target: /var/lib/runtrue/server$' "${DEPLOY_DIR}/compose.yml")" == 2 ]] ||
  fail 'the server state is not mounted into both the server and backup tool'
grep -Fq 'RUNTRUE_DATA_ROOT=/var/lib/runtrue-server/blobs' \
  "${DEPLOY_DIR}/systemd/server.env.example" ||
  fail 'the systemd server example does not configure authoritative blobs'
grep -Fq -- '--blobs-dir /var/lib/runtrue-server/blobs' \
  "${DEPLOY_DIR}/systemd/runtrue-backup@.service" ||
  fail 'the systemd backup omits the authoritative blob directory'

if rg -n '(docker|podman)\.sock|privileged:[[:space:]]*true|network_mode:[[:space:]]*host' \
  "${DEPLOY_DIR}"/*.yml; then
  fail 'forbidden host runtime socket, privileged mode, or host network found'
fi

for containerfile in "${DEPLOY_DIR}"/Containerfile.*; do
  [[ "$containerfile" == *.dockerignore ]] && continue
  grep -q 'cargo build --locked --release' "$containerfile" ||
    fail "locked release build is missing from ${containerfile}"
  grep -Eq '^# syntax=docker/dockerfile:[^@]+@sha256:[0-9a-f]{64}$' "$containerfile" ||
    fail "digest-pinned Dockerfile frontend is missing from ${containerfile}"
  grep -Eq '^ARG (RUST|RUNTIME)_IMAGE=.*@sha256:[0-9a-f]{64}$' "$containerfile" ||
    fail "digest-pinned base image is missing from ${containerfile}"
  grep -Eq '^USER [1-9][0-9]*:[1-9][0-9]*$' "$containerfile" ||
    fail "non-root runtime user is missing from ${containerfile}"
done

TEMPORARY_ROOT=$(mktemp -d)
chmod 0700 "$TEMPORARY_ROOT"
cat >"${TEMPORARY_ROOT}/compose.env" <<EOF
RUNTRUE_RUNTIME_UID=10001
RUNTRUE_RUNTIME_GID=10001
RUNTRUE_STATE_DIR=${TEMPORARY_ROOT}
RUNTRUE_HTTP_PORT=8080
RUNTRUE_INSTALLATION_ID=deployment-test
RUNTRUE_IMAGE_REPOSITORY=local/runtrue
RUNTRUE_IMAGE_TAG=0.1.0
RUNTRUE_IMAGE_REVISION=test
EOF
chmod 0600 "${TEMPORARY_ROOT}/compose.env"

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  docker compose --env-file "${TEMPORARY_ROOT}/compose.env" \
    -f "${DEPLOY_DIR}/compose.yml" config --quiet
  docker compose --env-file "${TEMPORARY_ROOT}/compose.env" \
    -f "${DEPLOY_DIR}/compose.yml" -f "${DEPLOY_DIR}/compose.runner-tls.yml" \
    --profile runner-enroll --profile runner-native-eval config --quiet
  env \
    RUNTRUE_PUBLIC_ORIGIN=https://runtrue.example.com \
    RUNTRUE_GITHUB_APP_ID=123 \
    RUNTRUE_GITHUB_APP_SLUG=runtrue \
    RUNTRUE_GITHUB_WEB_ORIGIN=https://github.example.com \
    RUNTRUE_GITHUB_API_ORIGIN=https://github.example.com/api/v3 \
    RUNTRUE_GITHUB_APP_CREDENTIAL_REFERENCE=provider://github-app/production \
    RUNTRUE_GITHUB_SIGNER_SOCKET="${TEMPORARY_ROOT}/github-app-signer.sock" \
    docker compose --env-file "${TEMPORARY_ROOT}/compose.env" \
      -f "${DEPLOY_DIR}/compose.yml" -f "${DEPLOY_DIR}/compose.github-app.yml" \
      config --quiet
  command -v python3 >/dev/null 2>&1 ||
    fail 'python3 is required to inspect the rendered runner mount model'
  rendered_json="${TEMPORARY_ROOT}/compose.runner.rendered.json"
  docker compose --env-file "${TEMPORARY_ROOT}/compose.env" \
    -f "${DEPLOY_DIR}/compose.yml" -f "${DEPLOY_DIR}/compose.runner-tls.yml" \
    --profile runner-enroll --profile runner-native-eval config --format json >"$rendered_json"
  python3 - "$rendered_json" "$TEMPORARY_ROOT" <<'PY' ||
import json
import pathlib
import sys

model_path = pathlib.Path(sys.argv[1])
state_root = pathlib.Path(sys.argv[2])
model = json.loads(model_path.read_text(encoding="utf-8"))
expected_source = str(state_root / "tls" / "runner-ca.pem")
expected_target = "/run/runtrue-runner-ca.pem"
for service_name in ("runner", "runner-enroll"):
    service = model.get("services", {}).get(service_name)
    if not isinstance(service, dict):
        raise SystemExit(f"rendered Compose model is missing {service_name}")
    volumes = service.get("volumes", [])
    ca_mounts = []
    for volume in volumes:
        source = str(volume.get("source", ""))
        target = str(volume.get("target", ""))
        lowered = f"{source}\n{target}".lower()
        forbidden = (
            source == str(state_root / "tls")
            or target.rstrip("/") == "/run/runtrue-tls"
            or ".key" in pathlib.PurePath(source).name.lower()
            or ".key" in pathlib.PurePath(target).name.lower()
            or "runner-server.pem" in lowered
            or "runner-server.key" in lowered
            or "runner-ca.key" in lowered
        )
        if forbidden:
            raise SystemExit(
                f"{service_name} exposes private TLS material or a TLS directory: "
                f"{source} -> {target}"
            )
        if source == expected_source or target == expected_target:
            ca_mounts.append(volume)
    if len(ca_mounts) != 1:
        raise SystemExit(f"{service_name} must have exactly one public CA mount")
    ca_mount = ca_mounts[0]
    if (
        ca_mount.get("type") != "bind"
        or ca_mount.get("source") != expected_source
        or ca_mount.get("target") != expected_target
        or ca_mount.get("read_only") is not True
    ):
        raise SystemExit(f"{service_name} public CA mount is not exact and read-only")
    environment = service.get("environment", {})
    if environment.get("RUNTRUE_RUNNER_CA_CERTIFICATE") != expected_target:
        raise SystemExit(f"{service_name} does not consume the file-scoped public CA")
runner = model["services"]["runner"]
runner_volumes = runner.get("volumes", [])
if any(
    volume.get("source") == str(state_root / "runner-secrets")
    or str(volume.get("source", "")).startswith(str(state_root / "runner-secrets") + "/")
    or str(volume.get("target", "")).rstrip("/") == "/run/runtrue-runner-secrets"
    or str(volume.get("target", "")) == "/run/runtrue-enrollment.token"
    for volume in runner_volumes
):
    raise SystemExit("runner daemon exposes enrollment-token material")
if "RUNTRUE_RUNNER_ENROLLMENT_TOKEN_FILE" in runner.get("environment", {}):
    raise SystemExit("runner daemon retains the enrollment-token configuration")

enroller = model["services"]["runner-enroll"]
token_source = str(state_root / "runner-secrets" / "enrollment.token")
token_target = "/run/runtrue-enrollment.token"
token_mounts = [
    volume
    for volume in enroller.get("volumes", [])
    if volume.get("source") == token_source or volume.get("target") == token_target
]
if len(token_mounts) != 1:
    raise SystemExit("runner-enroll must have exactly one file-scoped token mount")
token_mount = token_mounts[0]
if (
    token_mount.get("type") != "bind"
    or token_mount.get("source") != token_source
    or token_mount.get("target") != token_target
    or token_mount.get("read_only") is not True
    or enroller.get("environment", {}).get("RUNTRUE_RUNNER_ENROLLMENT_TOKEN_FILE")
    != token_target
):
    raise SystemExit("runner-enroll token mount is not exact and read-only")
PY
  fail 'rendered runner services expose unsafe TLS material'
else
  printf 'deploy validation: Docker Compose unavailable; YAML model validation skipped\n' >&2
fi

if command -v systemd-analyze >/dev/null 2>&1; then
  systemd_output=$(systemd-analyze verify "${DEPLOY_DIR}"/systemd/*.service 2>&1 || true)
  unexpected=$(printf '%s\n' "$systemd_output" |
    grep -vE '(^$|Command /usr/libexec/runtrue/runtrue-(server|runner|backup|action-builder) is not executable: No such file or directory)' || true)
  [[ -z "$unexpected" ]] || fail "systemd unit verification failed: ${unexpected}"
fi

grep -q 'CREDENTIALS_DIRECTORY' "${ROOT_DIR}/bins/server/src/main.rs" ||
  fail 'server does not recognize the systemd credential directory'
grep -q 'RUNTRUE_DATA_ROOT' "${ROOT_DIR}/bins/server/src/main.rs" ||
  fail 'server does not recognize the authoritative blob directory setting'
grep -Rq 'CREDENTIALS_DIRECTORY' "${ROOT_DIR}/bins/runner/src/state" ||
  fail 'runner does not recognize the systemd credential directory'

if command -v systemd-run >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 &&
  systemctl is-system-running >/dev/null 2>&1 && id nobody >/dev/null 2>&1; then
  credential_probe_source="${TEMPORARY_ROOT}/systemd-credential-probe"
  printf 'credential-probe\n' >"$credential_probe_source"
  chmod 0600 "$credential_probe_source"
  probe_user=nobody
  probe_group=$(id -gn "$probe_user")
  if credential_stat=$(systemd-run --quiet --wait --pipe --collect \
    --property="User=${probe_user}" --property="Group=${probe_group}" \
    --property="LoadCredential=runtrue-probe:${credential_probe_source}" \
    /bin/sh -c 'test -r "$CREDENTIALS_DIRECTORY/runtrue-probe" && stat -c "%a:%u:%g:%h" "$CREDENTIALS_DIRECTORY/runtrue-probe"' \
    2>/dev/null); then
    IFS=: read -r credential_mode credential_uid credential_gid credential_links <<<"$credential_stat"
    [[ "$credential_mode" == 400 || "$credential_mode" == 440 ]] ||
      fail "systemd produced unsupported credential mode ${credential_mode}"
    [[ "$credential_links" == 1 ]] || fail 'systemd credential is unexpectedly hard-linked'
    nobody_uid=$(id -u "$probe_user")
    nobody_gid=$(id -g "$probe_user")
    [[ "$credential_uid" == 0 || "$credential_uid" == "$nobody_uid" ]] ||
      fail 'systemd credential has an unsafe owner'
    if [[ "$credential_mode" == 440 ]]; then
      [[ "$credential_gid" == 0 || "$credential_gid" == "$nobody_gid" ]] ||
        fail 'systemd credential has an unsafe readable group'
    fi
  else
    printf 'deploy validation: transient systemd credential smoke test unavailable; skipped\n' >&2
  fi
else
  printf 'deploy validation: running systemd manager unavailable; credential smoke test skipped\n' >&2
fi

if command -v docker >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 &&
  [[ "$(docker info --format '{{.OSType}}' 2>/dev/null || true)" == linux ]]; then
  rm -rf -- "$TEMPORARY_ROOT"
  TEMPORARY_ROOT=$(mktemp -u /tmp/runtrue-deploy-validation.XXXXXXXX)
  first_output=$("${DEPLOY_DIR}/bootstrap.sh" --state-dir "$TEMPORARY_ROOT" --with-runner-tls)
  token_digest=$(sha256sum "${TEMPORARY_ROOT}/secrets/bootstrap.token")
  key_digest=$(sha256sum "${TEMPORARY_ROOT}/keys/security.key")
  second_output=$("${DEPLOY_DIR}/bootstrap.sh" --state-dir "$TEMPORARY_ROOT" --with-runner-tls)
  [[ "$token_digest" == "$(sha256sum "${TEMPORARY_ROOT}/secrets/bootstrap.token")" ]] ||
    fail 'idempotent bootstrap replaced the bootstrap token'
  [[ "$key_digest" == "$(sha256sum "${TEMPORARY_ROOT}/keys/security.key")" ]] ||
    fail 'idempotent bootstrap replaced the installation key'
  token=$(<"${TEMPORARY_ROOT}/secrets/bootstrap.token")
  [[ "${first_output}${second_output}" != *"$token"* ]] || fail 'bootstrap printed a credential'
  unset token
  "${DEPLOY_DIR}/bootstrap.sh" --state-dir "$TEMPORARY_ROOT" \
    --with-runner-tls --check-only >/dev/null

  ln -s /tmp "${TEMPORARY_ROOT}/recovery-config/rejected-link"
  if "${DEPLOY_DIR}/bootstrap.sh" --state-dir "$TEMPORARY_ROOT" \
    --with-runner-tls --check-only >/dev/null 2>&1; then
    fail 'bootstrap accepted a symbolic link in managed state'
  fi
  rm -f "${TEMPORARY_ROOT}/recovery-config/rejected-link"
  chmod 0644 "${TEMPORARY_ROOT}/compose.env"
  if "${DEPLOY_DIR}/bootstrap.sh" --state-dir "$TEMPORARY_ROOT" \
    --with-runner-tls --check-only >/dev/null 2>&1; then
    fail 'bootstrap accepted insecure file permissions'
  fi
  chmod 0600 "${TEMPORARY_ROOT}/compose.env"
else
  printf 'deploy validation: Docker Engine unavailable; bootstrap integration checks skipped\n' >&2
fi

printf 'deployment assets validated\n'
